#pragma once

#include <KittyMemoryMgr.hpp>

#include <xdl.h>

#define SOINFO_OLD_NAME_SIZE 128

class SoInfoPatch
{
    friend class KittyInjector;

    KittyMemoryMgr *_kMgr;

    ElfScanner _linker_elf {};

    uintptr_t solist_offset = 0;
    uintptr_t sonext_offset = 0;

    uint soinfo_base_offset = 0;
    uint soinfo_next_offset = 0;

    SoInfoPatch() : _kMgr(nullptr) {}

    bool init(KittyMemoryMgr *kMgr)
    {
        if (!kMgr || !kMgr->isMemValid())
            return false;
        
        _kMgr = kMgr;

        _linker_elf = _kMgr->getMemElf("/linker");
        if (!_linker_elf.isValid())
            return false;

        void* dl_linker = xdl_open(_linker_elf.filePath().c_str(), XDL_TRY_FORCE_LOAD);

        ElfW(Sym) solist_sym{}, sonext_sym{};
        xdl_dsym(dl_linker, "__dl__ZL6solist", &solist_sym);
        xdl_dsym(dl_linker, "__dl__ZL6sonext", &sonext_sym);
        xdl_close(dl_linker);

        solist_offset = solist_sym.st_value;
        sonext_offset = sonext_sym.st_value;

        uintptr_t sonext_addr = _linker_elf.base() + sonext_offset;
        uintptr_t sonext = 0;
        _kMgr->readMem(sonext_addr, &sonext, sizeof(uintptr_t));

        find_soinfo_offsets_with_si(sonext, &soinfo_base_offset, &soinfo_next_offset);

        return true;
    }

    void find_soinfo_offsets_with_si(uintptr_t si, uint *base_offset, uint *next_offset)
    {
        if (!si)
            return;

        std::vector<char> buf(0x100, 0);
        _kMgr->readMem(si, buf.data(), 0x100);

        ElfScanner elf {};
        for (size_t i = 0; i < buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t value = *(uintptr_t*)&buf[i];

            if (!elf.isValid())
                elf = _kMgr->elfScanner.createWithBase(value);

            if (!elf.isValid())
                continue;

            if (value == elf.base())
                *base_offset = i;
            else if (value == elf.loadSize())
                continue;
            else if (value == elf.dynamic())
                continue;
            else if (value == elf.stringTable()) {
                *next_offset = i - (sizeof(uintptr_t) * 2);
                break;
            } else if (value == elf.symbolTable())
                break;
        }
    }

    template<typename T> T get_soinfo_value(uintptr_t si, uint offset)
    {
        if (!si) return 0;

        T val {};
        _kMgr->readMem(si + offset, &val, sizeof(T));
        return val;
    }

    bool linker_solist_remove_elf(const ElfScanner &elf)
    {
        KITTY_LOGE("SoInfoPatch: Trying to remove elf(%p) from solist...", (void*)elf.base());
        
        KITTY_LOGI("SoInfoPatch: soinfo->base offset = 0x%X.", soinfo_base_offset);
        KITTY_LOGI("SoInfoPatch: soinfo->next offset = 0x%X.", soinfo_next_offset);

        if (!soinfo_base_offset || !soinfo_next_offset)
        {
            KITTY_LOGE("SoInfoPatch: Failed to find all required offsets.");  
            return false;
        }

        uintptr_t solist_addr = _linker_elf.base() + solist_offset;
        uintptr_t solist = 0;
        _kMgr->readMem(solist_addr, &solist, sizeof(uintptr_t));
        KITTY_LOGI("SoInfoPatch: sohead = %p.", (void*)solist);

        uintptr_t sonext_addr = _linker_elf.base() + sonext_offset;
        uintptr_t sonext = 0;
        _kMgr->readMem(sonext_addr, &sonext, sizeof(uintptr_t));

        uintptr_t trav = solist, prev = 0;
        for(; trav;)
        {
            uintptr_t base = get_soinfo_value<uintptr_t>(trav, soinfo_base_offset);
            //KITTY_LOGI("si(%p) -> %p.", (void*)trav, (void*)base); 

            if (base == elf.base())
                break;

            prev = trav;
            trav = get_soinfo_value<uintptr_t>(trav, soinfo_next_offset);
        }

        if (!trav)
        {
            KITTY_LOGE("SoInfoPatch: elf(%p) is not in solist.", (void*)elf.base());  
            return false;
        }

        if (!prev)
        {
            KITTY_LOGE("SoInfoPatch: elf(%p) is first in solist.", (void*)elf.base());  
            return false;
        }

        uintptr_t next = get_soinfo_value<uintptr_t>(trav, soinfo_next_offset);
        if (_kMgr->memPatch.createWithBytes(prev + soinfo_next_offset, &next, sizeof(uintptr_t)).Modify()) {
            KITTY_LOGI("SoInfoPatch: Removed soinfo(%p) elf(%p) from solist.", (void*)trav, (void*)elf.base());
        } else {
            KITTY_LOGE("SoInfoPatch: Failed to remove soinfo(%p) elf(%p) from solist.", (void*)trav, (void*)elf.base());
            return false;
        }

        if (trav == sonext)
        {
            KITTY_LOGI("SoInfoPatch: sonext = %p.", (void*)sonext_addr);
            if (_kMgr->memPatch.createWithBytes(sonext_addr, &prev, sizeof(uintptr_t)).Modify()) {
                KITTY_LOGI("SoInfoPatch: Removed soinfo(%p) elf(%p) from sonext.", (void*)trav, (void*)elf.base());
            } else {
                KITTY_LOGE("SoInfoPatch: Failed to remove soinfo(%p) elf(%p) from sonext.", (void*)trav, (void*)elf.base());
                return false;
            }
        }

        return true;
    }

    uintptr_t nb_find_elf_soinfo(const ElfScanner &nb_impl_elf, const ElfScanner &elf)
    {
        struct {
            uintptr_t base = 0;
            size_t size = 0;
        } data = {};

        data.base = elf.base();
        data.size = elf.loadSize();
        
        auto maps = KittyMemoryEx::getAllMaps(_kMgr->processID());
        for (auto& it : maps)
        {
            if (!it.is_private || it.length < 0xFFFF)
                continue;

            // search in nb implementation .bss
            bool check1 = (it.is_rw && it.startAddress >= nb_impl_elf.bss() && it.endAddress <= (nb_impl_elf.bss()+nb_impl_elf.bssSize()));
            
            // search in "[anon:Mem_x]" read-only regions
            bool check2 = (it.is_ro && KittyUtils::String::StartsWith(it.pathname, "[anon:Mem_"));

            // search in "[anon:linker_alloc]" read-only regions
            bool check3 = (it.is_ro && it.pathname == "[anon:linker_alloc]");

            if (!check1 && !check2 && !check3)
                continue;

            auto res = _kMgr->memScanner.findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
            if (res)
            {
                //KITTY_LOGI("found res(%p) at %s", (void*)res, it.toString().c_str());
                res -= (sizeof(uintptr_t) * 2);
                uintptr_t val = 0;
                _kMgr->readMem(res, &val, sizeof(uintptr_t));
                return val == elf.phdr() ? res : (res - sizeof(uintptr_t) - SOINFO_OLD_NAME_SIZE);
            }
        }

        return 0;
    }

    std::vector<uintptr_t> nb_find_soinfo_refs(const ElfScanner &nb_impl_elf, uintptr_t si, uint si_base_offset)
    {
        std::vector<uintptr_t> refs;

        auto maps = KittyMemoryEx::getAllMaps(_kMgr->processID());

        auto si_map = KittyMemoryEx::getAddressMap(maps, si);
        if (si_map.pathname == "[anon:linker_alloc]")
        {
            auto results = _kMgr->memScanner.findDataAll(si_map.startAddress, si_map.endAddress, &si, sizeof(si));
            for (auto& res : results)
            {
                uintptr_t si = 0;
                _kMgr->readMem(res, &si, sizeof(uintptr_t));
                if (_kMgr->isValidELF(get_soinfo_value<uintptr_t>(si, si_base_offset)))
                    refs.push_back(res);
            }

            if (results.size() > 0)
                return results;
        }
        
        // search in nb implementation rw regions
        for (auto& it : nb_impl_elf.segments())
        {
            if (!it.is_private || !it.is_rw)
                continue;

            auto results = _kMgr->memScanner.findDataAll(it.startAddress, it.endAddress, &si, sizeof(si));
            for (auto& res : results)
            {
                uintptr_t si = 0;
                _kMgr->readMem(res, &si, sizeof(uintptr_t));
                if (_kMgr->isValidELF(get_soinfo_value<uintptr_t>(si, si_base_offset)))
                    refs.push_back(res);
            }
        }

        return refs;
    }

    bool nb_solist_remove_elf(const ElfScanner &nb_impl_elf, const ElfScanner &elf)
    {
        KITTY_LOGI("SoInfoPatch: Trying to remove elf(%p) from solist...", (void*)elf.base());

        // NativeBridge implementation isn't open source
        // We will try to find solist by memory scanning

        static uintptr_t sohead = 0;
        static ElfScanner sohead_elf {};
        static uint si_base_offset = 0;
        static uint si_next_offset = 0;   

        if (!sohead)
        {
            // init once

            std::string arch;
            if (elf.header().e_machine == EM_ARM)
                arch = "/arm/";
            else if (elf.header().e_machine == EM_AARCH64)
                arch = "/arm64/";
            else if (elf.header().e_machine == EM_386)
                arch = "/x86/";
            else if (elf.header().e_machine == EM_X86_64)
                arch = "/X86_64/";

            // find nb libc or app_process to use as sohead

            auto allMaps = KittyMemoryEx::getAllMaps(_kMgr->processID());
            for (auto& it : allMaps)
            {
                if (!it.is_private || it.offset != 0 || it.inode == 0 || it.isUnknown())
                    continue;

                if (sohead_elf.isValid() && it.startAddress >= sohead_elf.base())
                    continue;

                if (!KittyUtils::String::Contains(it.pathname, arch))
                    continue;

                auto fileName = KittyUtils::fileNameFromPath(it.pathname);
                auto fileExtension = KittyUtils::fileExtension(it.pathname);

                bool is_libc = fileName == "libc.so";
                bool is_app_process = fileExtension.empty() && KittyUtils::String::StartsWith(fileName, "app_process");

                if (!is_libc && !is_app_process)
                    continue;

                ElfScanner tmp = _kMgr->elfScanner.createWithMap(it);
                if (!tmp.isValid())
                    continue;

                //KITTY_LOGI("%s", it.toString().c_str());

                sohead_elf = tmp;
            }

            // nb libc / app_process not loaded yet.
            if (!sohead_elf.isValid())
            {
                // don't have solution for this yet, increase injection delay for now
                KITTY_LOGE("SoInfoPatch: Failed to find sohead ELF.");
                return false;
            }

            KITTY_LOGI("SoInfoPatch: Finding offsets from soinfo of \"%s\"...", sohead_elf.filePath().c_str());

            sohead = nb_find_elf_soinfo(nb_impl_elf, sohead_elf);

            // offsets could be different to the native linker
            find_soinfo_offsets_with_si(sohead, &si_base_offset, &si_next_offset);
        }
        
        if (!sohead)
        {
            KITTY_LOGE("SoInfoPatch: Couldn't find soinfo of \"%s\".", sohead_elf.filePath().c_str());
            return false;
        }

        KITTY_LOGI("SoInfoPatch: sohead = %p.", (void*)sohead);

        KITTY_LOGI("SoInfoPatch: soinfo->base offset = 0x%X.", si_base_offset);
        KITTY_LOGI("SoInfoPatch: soinfo->next offset = 0x%X.", si_next_offset);

        if (!si_base_offset || !si_next_offset)
        {
            KITTY_LOGE("SoInfoPatch: Failed to find all required offsets.");
            return false;
        }

        uintptr_t sonext = 0;
        for (uintptr_t curr = sohead; curr;)
        {
            curr = get_soinfo_value<uintptr_t>(curr, si_next_offset);
            if (curr)
                sonext = curr;
        }

        uintptr_t trav = sohead, prev = 0;
        for(; trav;)
        {
            uintptr_t base = get_soinfo_value<uintptr_t>(trav, si_base_offset);
            //KITTY_LOGI("si(%p) -> %p.", (void*)trav, (void*)base); 

            if (base == elf.base())    
                break;

            prev = trav;
            trav = get_soinfo_value<uintptr_t>(trav, si_next_offset);
        }

        if (!trav)
        {
            KITTY_LOGE("SoInfoPatch: elf(%p) is not in solist or was loaded before sohead.", (void*)elf.base());  
            return false;
        }

        uintptr_t next = get_soinfo_value<uintptr_t>(trav, si_next_offset);
        if (_kMgr->memPatch.createWithBytes(prev + si_next_offset, &next, sizeof(uintptr_t)).Modify()) {
            KITTY_LOGI("SoInfoPatch: Removed soinfo(%p) elf(%p) from solist.", (void*)trav, (void*)elf.base());
        } else {
            KITTY_LOGE("SoInfoPatch: Failed to remove soinfo(%p) elf(%p) from solist.", (void*)trav, (void*)elf.base());
            return false;
        }

        if (trav == sonext)
        {
            // refs are 2 if soinfo is in both solist and sonext
            // since we removed one ref from solist, now refs should be equal to one
            // this one ref should be the one to sonext
            auto sonext_refs = nb_find_soinfo_refs(nb_impl_elf, sonext, si_base_offset);
            if (sonext_refs.size() == 1)
            {
                KITTY_LOGI("SoInfoPatch: sonext = %p.", (void*)sonext_refs[0]);
                if (_kMgr->memPatch.createWithBytes(sonext_refs[0], &prev, sizeof(uintptr_t)).Modify()) {
                    KITTY_LOGI("SoInfoPatch: Removed soinfo(%p) elf(%p) from sonext.", (void*)trav, (void*)elf.base());
                } else {
                    KITTY_LOGE("SoInfoPatch: Failed to remove soinfo(%p) elf(%p) from sonext.", (void*)trav, (void*)elf.base());
                    return false;
                }
            }
            else
            {
                KITTY_LOGE("SoInfoPatch: Unexpected sonext refs count (%d).", int(sonext_refs.size()));
                return false;
            }
        }

        return true;
    }

};