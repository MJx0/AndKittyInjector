#pragma once

#include <KittyMemoryMgr.hpp>

#include <xdl.h>

#if !defined(__LP64__)
#define __work_around_b_24465209_t__
#endif

struct soinfo_t
{
#if defined(__work_around_b_24465209_t__)
    char old_name_[128];
#endif
    const uintptr_t phdr;
    size_t phnum;
#if defined(__work_around_b_24465209_t__)
    uintptr_t unused0; // DO NOT USE, maintained for compatibility.
#endif
    uintptr_t base;
    size_t size;
#if defined(__work_around_b_24465209_t__)
    uint32_t unused1; // DO NOT USE, maintained for compatibility.
#endif
    uintptr_t dynamic;
#if defined(__work_around_b_24465209_t__)
    uint32_t unused2; // DO NOT USE, maintained for compatibility
    uint32_t unused3; // DO NOT USE, maintained for compatibility
#endif
    uintptr_t next;
};

struct soinfo_backup_t
{
    MemoryBackup ptr = {}, code = {};

    inline bool is_valid() { return ptr.isValid() && code.isValid(); }
    inline bool restore() { return ptr.Restore() && code.Restore(); }
};

class SoInfoPatch
{
    friend class KittyInjector;

    KittyMemoryMgr *_kMgr;

    ProcMap _linker_map {};

    uintptr_t solist_offset = 0;
    uintptr_t sonext_offset = 0;

    uint soinfo_base_offset = 0;
    uint soinfo_next_offset = 0;

    soinfo_backup_t sonext_bkup;

    SoInfoPatch() : _kMgr(nullptr) {}

    bool init(KittyMemoryMgr *kMgr)
    {
        if (!kMgr || !kMgr->isMemValid())
            return false;
        
        _kMgr = kMgr;

        _linker_map = _kMgr->getBaseElfMap("/linker").map;
        if (!_linker_map.isValid())
            return false;

        void* dl_linker = xdl_open(_linker_map.pathname.c_str(), XDL_TRY_FORCE_LOAD);

        ElfW(Sym) solist_sym{}, sonext_sym{};
        xdl_dsym(dl_linker, "__dl__ZL6solist", &solist_sym);
        xdl_dsym(dl_linker, "__dl__ZL6sonext", &sonext_sym);
        xdl_close(dl_linker);

        solist_offset = solist_sym.st_value;
        sonext_offset = sonext_sym.st_value;

        soinfo_base_offset = offsetof(soinfo_t, base);
        soinfo_next_offset = offsetof(soinfo_t, next);

        KITTY_LOGI("SoInfoPatch: soinfo->base offset = 0x%X.", soinfo_base_offset);
        KITTY_LOGI("SoInfoPatch: soinfo->next offset = 0x%X.", soinfo_next_offset);

#if 0
        uintptr_t sonext_addr = _linker_map.startAddress + sonext_offset;
        uintptr_t sonext = 0;
        if (!_kMgr->readMem(sonext_addr, &sonext, sizeof(uintptr_t)) || !sonext)
        {
            KITTY_LOGW("SoInfoPatch: Failed to read sonext pointer.");
            KITTY_LOGW("SoInfoPatch: Won't be able to hide lib from solist.");
            return false;
        }

        // find soinfo->base offset
        soinfo_base_offset = find_soinfo_base_offset(sonext);
        if (soinfo_base_offset == 0)
        {
            KITTY_LOGW("SoInfoPatch: soinfo->base offset not found.");
            KITTY_LOGW("SoInfoPatch: Won't be able to hide lib from solist.");
            return false;
        }

        KITTY_LOGI("SoInfoPatch: soinfo->base offset = 0x%X. | 0x%X", soinfo_base_offset, offsetof(soinfo_t, base));

        soinfo_next_offset = soinfo_base_offset + (3 * sizeof(uintptr_t));
#ifdef __work_around_b_24465209_t__
        soinfo_next_offset += (3 * sizeof(uint32_t));
#endif

        KITTY_LOGI("SoInfoPatch: soinfo->next offset = 0x%X.", soinfo_next_offset, offsetof(soinfo_t, next));
#endif

        return true;
    }

    void before_dlopen_patch()
    {
        if (!soinfo_next_offset)
        {
            KITTY_LOGE("SoInfoPatch: No patches available.");
            return;
        }

        KITTY_LOGI("SoInfoPatch: Using sonext patch");

        uintptr_t sonext_addr = _linker_map.startAddress + sonext_offset;
        sonext_bkup.ptr = _kMgr->memBackup.createBackup(sonext_addr, sizeof(uintptr_t));
        
        uintptr_t sonext_ptr = 0;
        _kMgr->readMem(sonext_addr, &sonext_ptr, sizeof(uintptr_t));

        sonext_bkup.code = _kMgr->memBackup.createBackup(sonext_ptr + soinfo_next_offset, sizeof(uintptr_t));

        if (sonext_bkup.is_valid())
            KITTY_LOGI("SoInfoPatch: Backed up current sonext successfully.");
        else
            KITTY_LOGE("SoInfoPatch: Couldn't backup current sonext.");
    }

    void after_dlopen_patch()
    {
        if (!sonext_bkup.is_valid())
        {
            KITTY_LOGI("SoInfoPatch: Nothing to restore.");
            return;
        }

        if (sonext_bkup.restore())
            KITTY_LOGI("SoInfoPatch: sonext backup restored successfully.");
        else
            KITTY_LOGE("SoInfoPatch: Couldn't restore sonext backup.");
    }

    uint find_soinfo_base_offset(uintptr_t si)
    {
        for (uint off = 0; off < 0x100; off += sizeof(uintptr_t))
        {
            uintptr_t tmp = 0;
            if (_kMgr->readMem(si + off, &tmp, sizeof(uintptr_t)) && _kMgr->isValidELF(tmp))
                return off;
        }
        return 0;
    }

    uintptr_t get_soinfo_base(uintptr_t si)
    {
        if (!si) return 0;

        uintptr_t si_base = 0;
        _kMgr->readMem(si + soinfo_base_offset, &si_base, sizeof(uintptr_t));
        return si_base;
    }

    bool solist_remove_lib(uintptr_t lib_base)
    {
        uintptr_t solist_addr = _linker_map.startAddress + solist_offset;
        uintptr_t solist = 0;
        _kMgr->readMem(solist_addr, &solist, sizeof(uintptr_t));

        uintptr_t sonext_addr = _linker_map.startAddress + sonext_offset;
        uintptr_t sonext = 0;
        _kMgr->readMem(sonext_addr, &sonext, sizeof(uintptr_t));

        uintptr_t trav = solist, prev = 0;
        for(; trav;)
        {
            if (get_soinfo_base(trav) == lib_base)
                break;

            prev = trav;
            if (!_kMgr->readMem(trav + soinfo_next_offset, &trav, sizeof(uintptr_t)))
            {
                trav = 0;
                break;
            }
        }

        if (!trav)
        {
            KITTY_LOGE("SoInfoPatch: %p not in solist.", (void*)lib_base);  
            return false;
        }

        uintptr_t next = 0;
        _kMgr->readMem(trav + soinfo_next_offset, &next, sizeof(uintptr_t));
        bool m = _kMgr->memPatch.createWithBytes(prev + soinfo_next_offset, &next, sizeof(uintptr_t)).Modify();
        
        if (m && trav == sonext)
            m &= _kMgr->memPatch.createWithBytes(sonext_addr, &prev, sizeof(uintptr_t)).Modify();

        if (m)
            KITTY_LOGI("SoInfoPatch: Removed soinfo(%p) base(%p) from solist.", (void*)trav, (void*)lib_base);
        else
            KITTY_LOGE("SoInfoPatch: Failed to remove soinfo(%p) base(%p) from solist.", (void*)trav, (void*)lib_base);

        return m;
    }

};