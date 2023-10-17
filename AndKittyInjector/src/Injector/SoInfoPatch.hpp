#pragma once

#include <KittyMemoryMgr.hpp>

#include <xdl.h>

class SoInfoPatch
{
    friend class KittyInjector;

    KittyMemoryMgr *_kMgr;

    ProcMap _linker_map {};

    ElfW(Sym) sym_solist_add_soinfo {};
    ElfW(Sym) sym_soinfo_sonext {};

    MemoryPatch solist_add_soinfo_patch {};
    uintptr_t sonext_ptr_bkup = 0;

    SoInfoPatch() : _kMgr(nullptr), sonext_ptr_bkup(0) {}

    bool init(KittyMemoryMgr *kMgr)
    {
        if (!kMgr || !kMgr->isMemValid())
            return false;
        
        _kMgr = kMgr;

        _linker_map = _kMgr->getElfBaseMap("/linker").map;
        if (!_linker_map.isValid())
            return false;

        void* dl_linker = xdl_open(_linker_map.pathname.c_str(), XDL_TRY_FORCE_LOAD);
        xdl_dsym(dl_linker, "__dl__Z17solist_add_soinfoP6soinfo", &sym_solist_add_soinfo);
        xdl_dsym(dl_linker, "__dl__ZL6sonext", &sym_soinfo_sonext);
        xdl_close(dl_linker);

        return true;
    }

    void before_dlopen_patch()
    {
        if (!_linker_map.isValid())
        {
            KITTY_LOGE("SoInfoPatch: Linker not found.");
            return;
        }

        if (!sym_solist_add_soinfo.st_value && !sym_soinfo_sonext.st_value)
        {
            KITTY_LOGE("SoInfoPatch: No patches available.");
            return;
        }

        if (sym_solist_add_soinfo.st_value)
        {
            KITTY_LOGI("SoInfoPatch: Using solist_add_soinfo patch");

            uintptr_t patch_addr = _linker_map.startAddress + sym_solist_add_soinfo.st_value;
#if defined(__i386__) || defined(__x86_64__)
            solist_add_soinfo_patch = _kMgr->memPatch.createWithBytes(patch_addr, "\xC3", 1);
#elif defined(__arm__)
            solist_add_soinfo_patch = _kMgr->memPatch.createWithBytes(patch_addr, "\x1e\xff\x2f\xe1", 4);
#elif defined(__aarch64__)
            solist_add_soinfo_patch = _kMgr->memPatch.createWithBytes(patch_addr, "\xc0\x03\x5f\xd6", 4);
#endif
            if (solist_add_soinfo_patch.Modify())
                KITTY_LOGI("SoInfoPatch: solist_add_soinfo patched successfully.");
            else
                KITTY_LOGE("SoInfoPatch: solist_add_soinfo patch failed.");
        }
        else if (sym_soinfo_sonext.st_value)
        {
            KITTY_LOGI("SoInfoPatch: Using sonext patch");

            uintptr_t bk_addr = _linker_map.startAddress + sym_soinfo_sonext.st_value;
            _kMgr->readMem(bk_addr, &sonext_ptr_bkup, sizeof(uintptr_t));
        }
    }

    void after_dlopen_patch()
    {
        if (sym_solist_add_soinfo.st_value && solist_add_soinfo_patch.Restore())
        {
            KITTY_LOGI("SoInfoPatch: solist_add_soinfo patch restored.");
            return;
        }

        if (sym_soinfo_sonext.st_value && sonext_ptr_bkup)
        {
            uintptr_t bk_addr = _linker_map.startAddress + sym_soinfo_sonext.st_value;

            // current sonext
            uintptr_t current_sonext = 0;
            _kMgr->readMem(bk_addr, &current_sonext, sizeof(uintptr_t));
            KITTY_LOGI("SoInfoPatch: current sonext %p.", (void*)current_sonext);

            // find soinfo->next offset
            auto sonext_next = _kMgr->memScanner.findDataFirst(sonext_ptr_bkup, sonext_ptr_bkup + 0xff, &current_sonext, sizeof(uintptr_t));

            // restore previus sonext
            _kMgr->writeMem(bk_addr, &sonext_ptr_bkup, sizeof(uintptr_t));
            KITTY_LOGI("SoInfoPatch: sonext restored to %p.", (void*)sonext_ptr_bkup);

            if (sonext_next)
            {
                KITTY_LOGI("SoInfoPatch: soinfo->next offset = %p", (void*)(sonext_next - sonext_ptr_bkup));
                
                // pop our soinfo from previus soinfo->next
                uintptr_t next = 0;
                _kMgr->writeMem(sonext_next, &next, sizeof(uintptr_t));
                KITTY_LOGI("SoInfoPatch: sonext->next restored to null.");
            } 
            else
            {
                KITTY_LOGW("SoInfoPatch: soinfo->next offset not found.");
            }
        }
    }
};