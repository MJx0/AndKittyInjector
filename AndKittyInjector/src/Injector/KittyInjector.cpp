#include "KittyInjector.hpp"

bool KittyInjector::init(pid_t pid, EKittyMemOP eMemOp)
{
    if (_kMgr.get())
        _kMgr.reset();

    _kMgr = std::make_unique<KittyMemoryMgr>();

    if (!_kMgr->initialize(pid, eMemOp, true))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize kittyMgr.");
        return false;
    }

    _kMgr->trace.setAutoRestoreRegs(false);

    bool isLocal64bit = !KittyMemoryEx::getMapsContain(getpid(), "/lib64/").empty();
    bool isRemote64bit = !KittyMemoryEx::getMapsContain(pid, "/lib64/").empty();
    if (isLocal64bit != isRemote64bit)
    {
        KITTY_LOGE("KittyInjector: Injector is %sbit but target app is %sbit.", isLocal64bit ? "64" : "32", isRemote64bit ? "64" : "32");
        return false;
    }

    if (!_remote_syscall.init(_kMgr.get()))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize remote syscall.");
        return false;
    }

    _soinfo_patch.init(_kMgr.get());

    _remote_dlopen = _kMgr->findRemoteOf("dlopen", (uintptr_t)&dlopen);
    if (!_remote_dlopen)
    {
        KITTY_LOGE("KittyInjector: remote dlopen not found.");
        return false;
    }

    _remote_dlopen_ext = _kMgr->findRemoteOf("android_dlopen_ext", (uintptr_t)&android_dlopen_ext);
    
    _remote_dlclose = _kMgr->findRemoteOf("dlclose", (uintptr_t)&dlclose);
    
    _remote_dlerror = _kMgr->findRemoteOf("dlerror", (uintptr_t)&dlerror);

    // check houdini for emulators
    _houdiniElf = _kMgr->getElfBaseMap(kNativeBridgeLib);
    if (_houdiniElf.isValid())
    {
        // find and read native bridge interface
        uintptr_t pNativeBridgeItf = _houdiniElf.elfScan.findSymbol(kNativeBridgeSymbol);
        if (pNativeBridgeItf)
        {
            _kMgr->readMem(pNativeBridgeItf, &_nativeBridgeItf.version, sizeof(uint32_t));

            size_t bridgeCallbacksSize = NativeBridgeCallbacks::getStructSize(_nativeBridgeItf.version);
            _kMgr->readMem(pNativeBridgeItf, &_nativeBridgeItf, bridgeCallbacksSize);
        }
    }

    return true;
}

injected_info_t KittyInjector::injectLibrary(std::string libPath, int flags, bool use_memfd_dl, bool hide)
{
    if (!_kMgr.get() || !_kMgr->isMemValid())
    {
        KITTY_LOGE("injectLibrary: Not initialized.");
        return {};
    }

    if (!_kMgr->trace.isAttached())
    {
        KITTY_LOGE("injectLibrary: Not attached.");
        return {};
    }

    errno = 0;
    bool canUseMemfd = use_memfd_dl && _remote_dlopen_ext && !(syscall(syscall_memfd_create_n) < 0 && errno == ENOSYS);

    if (!_remote_dlopen && !canUseMemfd)
    {
        KITTY_LOGE("injectLibrary: remote dlopen not found.");
        return {};
    }

    ElfW_(Ehdr) libHdr = {};

    KittyIOFile libFile(libPath, O_RDONLY);
    if (!libFile.Open())
    {
        KITTY_LOGE("injectLibrary: Library path not accessible. error=\"%s\"", libFile.lastStrError().c_str());
        return {};
    }
    libFile.Read(0, &libHdr, sizeof(libHdr));

    if (memcmp(libHdr.e_ident, "\177ELF", 4) != 0)
    {
        KITTY_LOGE("injectLibrary: library is not a valid ELF.");
        return {};
    }

    // check if need emulation
    if (libHdr.e_machine != kNativeEM)
    {
        KITTY_LOGW("injectLibrary: Library EMachine is not native.");
        KITTY_LOGI("injectLibrary: [native=0x%x | lib=0x%x].", kNativeEM, libHdr.e_machine);
        KITTY_LOGI("injectLibrary: Searching for houdini emulation...");

        if (!_houdiniElf.isValid())
        {
            KITTY_LOGW("injectLibrary: houdini not available.");
            return {};
        }

        KITTY_LOGI("injectLibrary: Found houdini version %d.", _nativeBridgeItf.version);

        // x86_64 emulates arm64, x86 emulates arm
        if (_houdiniElf.elfScan.header().e_machine == EM_X86_64 && libHdr.e_machine != EM_AARCH64)
        {
            KITTY_LOGE("injectLibrary: EM_X86_64 should emualte EM_AARCH64.");
            return {};
        }
        else if (_houdiniElf.elfScan.header().e_machine == EM_386 && libHdr.e_machine != EM_ARM)
        {
            KITTY_LOGE("injectLibrary: EM_386 should emualte EM_ARM.");
            return {};
        }

        // version check
        if (_nativeBridgeItf.version < NativeBridgeVersion::kMIN_VERSION || _nativeBridgeItf.version > NativeBridgeVersion::kMAX_VERSION)
        {
            KITTY_LOGE("injectLibrary: invalid houdini version. [Min=%d | Max=%d]", NativeBridgeVersion::kMIN_VERSION, NativeBridgeVersion::kMAX_VERSION);
            return {};
        }
    }

    pt_regs bkup_regs;
    memset(&bkup_regs, 0, sizeof(bkup_regs));

    if (!_kMgr->trace.getRegs(&bkup_regs))
    {
        KITTY_LOGE("injectLibrary: failed to backup registers.");
        return {};
    }

    injected_info_t injected {};

    if (libHdr.e_machine == kNativeEM)
    {
        if (hide)
            _soinfo_patch.before_dlopen_patch();

        injected = nativeInject(libFile, flags, canUseMemfd);

        if (hide)
            _soinfo_patch.after_dlopen_patch();
    }
    else
    {
        injected = emuInject(libFile, flags);
    }

    KITTY_LOGI("lib handle = %p", (void*)injected.dl_handle);

    if (injected.is_valid())
    {
        if (libHdr.e_machine == kNativeEM && hide)
        {
            hideSegmentsFromMaps(injected);

            uintptr_t hide_init = injected.elfMap.elfScan.findSymbol("hide_init");
            KITTY_LOGI("Calling hide_init -> %p", (void*)hide_init);
            _kMgr->trace.callFunction(hide_init, 0);
        }
    }
    else
    {
        KITTY_LOGE("injectLibrary: failed )':");
        KITTY_LOGE("injectLibrary: calling dlerror...");

        uintptr_t error_ret = 0;

        if (libHdr.e_machine == kNativeEM)
            error_ret = _kMgr->trace.callFunction(_remote_dlerror, 0);
        else if (_nativeBridgeItf.version >= NativeBridgeVersion::kNAMESPACE_VERSION)
            error_ret = _kMgr->trace.callFunction((uintptr_t)_nativeBridgeItf.getError, 0);
        else
            KITTY_LOGW("injectLibrary: dlerror not available.");

        if (error_ret)
        {
            std::string error_str = _kMgr->readMemStr(error_ret, 0xff);
            if (!error_str.empty())
                KITTY_LOGE("injectLibrary: %s", error_str.c_str());
        }
    }

    // cleanup
    _remote_syscall.clearAllocatedMaps();

    if (!_kMgr->trace.setRegs(&bkup_regs))
        KITTY_LOGE("injectLibrary: failed to restore registers.");

    return injected;
}

injected_info_t KittyInjector::nativeInject(KittyIOFile& lib, int flags, bool use_dl_memfd)
{
    injected_info_t info {};
    info.is_native = true;

    auto legacy_dlopen = [&]() -> bool
    {
        info.name = lib.Path();

        uintptr_t remoteLibPath = _remote_syscall.rmmap_str(info.name);
        if (!remoteLibPath)
        {
            KITTY_LOGE("nativeInject: mmaping lib name failed, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        info.dl_handle = _kMgr->trace.callFunction(_remote_dlopen, 2, remoteLibPath, flags);
        kINJ_WAIT;

        info.elfMap = _kMgr->getElfBaseMap(lib.Path());

        return info.elfMap.isValid();
    };

    auto memfd_dlopen = [&]() -> bool
    {
        std::string memfd_rand = KittyUtils::random_string(KittyUtils::randInt(5, 12));

        info.name = "/memfd:" + memfd_rand;

        uintptr_t rmemfd_name = _remote_syscall.rmmap_str(memfd_rand);
        if (!rmemfd_name)
        {
            KITTY_LOGE("nativeInject: failed to map memfd_name, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        auto libBuf = lib.toBuffer();

        int rmemfd = _remote_syscall.rmemfd_create(rmemfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("nativeInject: memfd_create failed, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        std::string rmemfdPath = KittyUtils::strfmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
        KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
        if (!rmemfdFile.Open())
        {
            KITTY_LOGE("nativeInject: Failed to open remote memfd file, errno = %s.", rmemfdFile.lastStrError().c_str());
            return false;
        }

        lib.writeToFd(rmemfdFile.FD());

        // restrict further modifications to remote memfd
        _remote_syscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

        android_dlextinfo extinfo;
        extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        extinfo.library_fd = rmemfd;

        uintptr_t rdlextinfo = _remote_syscall.rmmap_anon(0, sizeof(android_dlextinfo), PROT_READ | PROT_WRITE);
        _kMgr->writeMem(rdlextinfo, &extinfo, sizeof(extinfo));

        info.dl_handle = _kMgr->trace.callFunction(_remote_dlopen_ext, 3, rmemfd_name, flags, rdlextinfo);
        kINJ_WAIT;

        info.elfMap = _kMgr->getElfBaseMap(info.name);

        return info.elfMap.isValid();
    };


    errno = 0;
    bool canUseMemfd = use_dl_memfd && _remote_dlopen_ext && !(syscall(syscall_memfd_create_n) < 0 && errno == ENOSYS);

    if (canUseMemfd)
    {
        if (!memfd_dlopen())
        {
            KITTY_LOGW("android_dlopen_ext failed.");
            uintptr_t error_ret = _kMgr->trace.callFunction(_remote_dlerror, 0);
            if (IsValidRetPtr(error_ret))
            {
                std::string error_str = _kMgr->readMemStr(error_ret, 0xff);
                if (!error_str.empty())
                    KITTY_LOGE("error %s.", error_str.c_str());
            }
            KITTY_LOGI("Will try legacy dlopen...");
            legacy_dlopen();
        }
    }
    else
    {
        legacy_dlopen();
    }

    return info;
}

injected_info_t KittyInjector::emuInject(KittyIOFile& lib, int flags)
{
    injected_info_t info {};
    info.is_native = false;
    info.name = lib.Path();

    uintptr_t remoteLibPath = _remote_syscall.rmmap_str(info.name);
    if (!remoteLibPath)
    {
        KITTY_LOGE("emuInject: mmaping lib name failed, errno = %s.", _remote_syscall.getRemoteError().c_str());
        return info;
    }

    if (_nativeBridgeItf.version >= NativeBridgeVersion::kNAMESPACE_VERSION)
    {
        // houdini version 3 or above will need to check which namespace will work between 1 to 25.
        // if (ns && ns <= 25)
        //    return (char *)&unk_64DF10 + 0xC670 * ns + qword_80C6C8;
        auto tryRemoteloadLibraryExt = [&](uint8_t ns_start, uint8_t ns_end) -> uintptr_t
        {
            for (uint8_t i = ns_start; i <= ns_end; i++)
            {
                uintptr_t h = _kMgr->trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibraryExt, 3, remoteLibPath, flags, i);
                kINJ_WAIT;

                if (remoteContainsMap(lib.Path()))
                    return h;
            }
            return 0;
        };

        switch (_nativeBridgeItf.version)
        {
            case NativeBridgeVersion::kVENDOR_NAMESPACE_VERSION: // not tested
            case NativeBridgeVersion::kRUNTIME_NAMESPACE_VERSION: // not tested
            case NativeBridgeVersion::kPRE_ZYGOTE_FORK_VERSION:
                // namespace 4-5 works mostly
                info.dl_handle = tryRemoteloadLibraryExt(1, 5);
                break;
            case NativeBridgeVersion::kNAMESPACE_VERSION:
                // namespace 1-3 works mostly
                info.dl_handle = tryRemoteloadLibraryExt(1, 3);
                break;
        }
    }
    else if (_nativeBridgeItf.version == NativeBridgeVersion::kSIGNAL_VERSION)
    {
        // more reliable on older version of houdini
        auto libNB = _kMgr->getElfBaseMap("libnativebridge.so");
        if (libNB.isValid())
        {
            uintptr_t pNbLoadLibrary = libNB.elfScan.findSymbol("_ZN7android23NativeBridgeLoadLibraryEPKci");
            if (pNbLoadLibrary)
            {
                info.dl_handle = _kMgr->trace.callFunction((uintptr_t)pNbLoadLibrary, 2, remoteLibPath, flags);
                kINJ_WAIT;
            }
        }

        // fallback
        if (!remoteContainsMap(lib.Path()))
        {
            info.dl_handle = _kMgr->trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibrary, 2, remoteLibPath, flags);
            kINJ_WAIT;
        }
    }

    info.elfMap = _kMgr->getElfBaseMap(lib.Path());

    return info;
}

bool KittyInjector::hideSegmentsFromMaps(injected_info_t &inj_info)
{
    if (!inj_info.is_valid())
    {
        KITTY_LOGE("hideSegmentsFromMaps: Invalid info.");
        return false;
    }

    if (inj_info.is_hidden || inj_info.elfMap.map.pathname.empty())
        return true;

    // idea from https://github.com/RikkaApps/Riru/blob/master/riru/src/main/cpp/hide/hide.cpp

    auto maps = KittyMemoryEx::getMapsContain(_kMgr->processID(), inj_info.elfMap.map.pathname);
    for (auto& it : maps)
    {
        KITTY_LOGI("hideSegmentsFromMaps: Hiding segment %p - %p", (void*)it.startAddress, (void*)it.endAddress);

        // backup segment code
        auto bkup = _kMgr->memBackup.createBackup(it.startAddress, it.length);

        _remote_syscall.rmunmap(it.startAddress, it.length);
        uintptr_t segment_new_map = _remote_syscall.rmmap_anon(it.startAddress, it.length, it.protection, false);

        if (!IsValidRetPtr(segment_new_map))
        {
            KITTY_LOGE("hideSegmentsFromMaps: Failed to re-map segment %p, error = %s", (void*)it.startAddress, _remote_syscall.getRemoteError().c_str());
            return false;
        }
        
        // restore segment code
        bkup.Restore();
    }

    inj_info.name.clear();
    inj_info.name.shrink_to_fit();

    inj_info.elfMap.map.pathname.clear();
    inj_info.elfMap.map.pathname.shrink_to_fit();

    inj_info.is_hidden = true;

    return true;
}