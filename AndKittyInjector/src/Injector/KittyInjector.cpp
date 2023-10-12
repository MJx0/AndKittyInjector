#include "KittyInjector.hpp"

bool KittyInjector::init(pid_t pid, EKittyMemOP eMemOp)
{
    bool isLocal64bit = !KittyMemoryEx::getMapsContain(getpid(), "/lib64/").empty();
    bool isRemote64bit = !KittyMemoryEx::getMapsContain(pid, "/lib64/").empty();
    if (isLocal64bit != isRemote64bit)
    {
        KITTY_LOGE("KittyInjector: Injector is %sbit but target app is %sbit.",
                   isLocal64bit ? "64" : "32", isRemote64bit ? "64" : "32");
        return false;
    }

    if (_kMgr.get())
        _kMgr.reset();

    _kMgr = std::make_unique<KittyMemoryMgr>();

    if (!_kMgr->initialize(pid, eMemOp, false))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize kittyMgr.");
        return false;
    }

    if (!_remote_syscall.init(_kMgr.get()))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize remote syscall.");
        return false;
    }

    _remote_dlopen = _kMgr->findRemoteOf("dlopen", (uintptr_t)&dlopen);
    if (!_remote_dlopen)
    {
        KITTY_LOGE("KittyInjector: remote dlopen not found.");
        return false;
    }

    _remote_dlopen_ext = _kMgr->findRemoteOf("android_dlopen_ext", (uintptr_t)&android_dlopen_ext);

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

uintptr_t KittyInjector::injectLibrary(std::string libPath, int flags)
{
    if (!_kMgr.get() || !_kMgr->isMemValid())
    {
        KITTY_LOGE("injectLibrary: Not initialized.");
        return 0;
    }

    errno = 0;
    bool useMemfd = _remote_dlopen_ext && !(syscall(syscall_memfd_create_n) < 0 && errno == ENOSYS);

    if (!_remote_dlopen && !useMemfd)
    {
        KITTY_LOGE("injectLibrary: remote dlopen not found.");
        return 0;
    }

    ElfW_(Ehdr) libHdr = {};

    KittyIOFile libFile(libPath, O_RDONLY);
    if (!libFile.Open())
    {
        KITTY_LOGE("injectLibrary: Library path not accessible. error=\"%s\"", libFile.lastStrError().c_str());
        return 0;
    }
    libFile.Read(0, &libHdr, sizeof(libHdr));

    if (memcmp(libHdr.e_ident, "\177ELF", 4) != 0)
    {
        KITTY_LOGE("injectLibrary: library is not a valid ELF.");
        return 0;
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
            return 0;
        }

        KITTY_LOGI("injectLibrary: Found houdini version %d.", _nativeBridgeItf.version);

        // x86_64 emulates arm64, x86 emulates arm
        if (_houdiniElf.elfScan.header().e_machine == EM_X86_64 && libHdr.e_machine != EM_AARCH64)
        {
            KITTY_LOGE("injectLibrary: EM_X86_64 should emualte EM_AARCH64.");
            return 0;
        }
        else if (_houdiniElf.elfScan.header().e_machine == EM_386 && libHdr.e_machine != EM_ARM)
        {
            KITTY_LOGE("injectLibrary: EM_386 should emualte EM_ARM.");
            return 0;
        }

        // version check
        if (_nativeBridgeItf.version < NativeBridgeVersion::kMIN_VERSION || _nativeBridgeItf.version > NativeBridgeVersion::kMAX_VERSION)
        {
            KITTY_LOGW("injectLibrary: invalid houdini version. [Min=%d | Max=%d]",
                       NativeBridgeVersion::kMIN_VERSION, NativeBridgeVersion::kMAX_VERSION);
            return 0;
        }
    }

    if (!_kMgr->trace.Attach())
    {
        KITTY_LOGE("injectLibrary: Failed to attach.");
        return 0;
    }

    uintptr_t remoteLibPath = _remote_syscall.rmmap_str(libPath);
    if (!remoteLibPath)
    {
        KITTY_LOGE("injectLibrary: mmaping lib name failed, errno = %s.",
                   _remote_syscall.getRemoteError().c_str());
        return 0;
    }

    std::string memfd_rand = KittyUtils::random_string(KittyUtils::randInt(5, 12));

    // native dlopen
    if (libHdr.e_machine == kNativeEM)
    {
        if (useMemfd)
        {
            do
            {
                uintptr_t rmemfd_name = _remote_syscall.rmmap_str(memfd_rand);
                if (!rmemfd_name)
                {
                    KITTY_LOGE("injectLibrary: failed to map memfd_name, errno = %s.",
                               _remote_syscall.getRemoteError().c_str());
                    break;
                }

                auto libBuf = libFile.toBuffer();

                int rmemfd = _remote_syscall.rmemfd_create(rmemfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING, libBuf.size());
                if (rmemfd <= 0)
                {
                    KITTY_LOGE("injectLibrary: memfd_create failed, errno = %s.",
                               _remote_syscall.getRemoteError().c_str());
                    break;
                }

                std::string rmemfdPath = KittyUtils::strfmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
                KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
                if (!rmemfdFile.Open())
                {
                    KITTY_LOGE("injectLibrary: Failed to open remote memfd file, errno = %s.",
                               rmemfdFile.lastStrError().c_str());
                    break;
                }

                // mmap remote memfd in our process
                void *rshmem = mmap(nullptr, libBuf.size(), PROT_READ | PROT_WRITE, MAP_SHARED, rmemfdFile.FD(), 0);
                if (!rshmem)
                {
                    KITTY_LOGE("injectLibrary: Failed to map shared memfd file, errno = %s.", strerror(errno));
                    break;
                }
                // copy lib to remote memfd
                memcpy(rshmem, libBuf.data(), libBuf.size());
                munmap(rshmem, libBuf.size());

                // restrict further modifications to remote memfd
                _remote_syscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

                android_dlextinfo extinfo;
                extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
                extinfo.library_fd = rmemfd;

                uintptr_t rdlextinfo = _remote_syscall.rmmap_anon(sizeof(android_dlextinfo), PROT_READ | PROT_WRITE);
                _kMgr->writeMem(rdlextinfo, &extinfo, sizeof(extinfo));

                _kMgr->trace.callFunction(_remote_dlopen_ext, 3, rmemfd_name, flags, rdlextinfo);
                kINJ_WAIT;

            } while (false);
        }

        if (!remoteContainsMap(memfd_rand))
        {
            if (useMemfd)
                KITTY_LOGW("android_dlopen_ext failed, using legacy dlopen...");

            _kMgr->trace.callFunction(_remote_dlopen, 2, remoteLibPath, flags);
            kINJ_WAIT;
        }
    }
    // bridge dlopen
    else if (_nativeBridgeItf.version >= NativeBridgeVersion::kNAMESPACE_VERSION)
    {
        // houdini version 3 or above will need to check which namespace will work between 1 to 25.
        // if (ns && ns <= 25)
        //    return (char *)&unk_64DF10 + 0xC670 * ns + qword_80C6C8;
        auto tryRemoteloadLibraryExt = [&](uint8_t ns_start, uint8_t ns_end)
        {
            for (uint8_t i = ns_start; i <= ns_end; i++)
            {
                _kMgr->trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibraryExt, 3, remoteLibPath, flags, i);
                kINJ_WAIT;

                if (remoteContainsMap(libPath))
                    break;
            }
        };
        switch (_nativeBridgeItf.version)
        {
        case NativeBridgeVersion::kVENDOR_NAMESPACE_VERSION:  // not tested
        case NativeBridgeVersion::kRUNTIME_NAMESPACE_VERSION: // not tested
        case NativeBridgeVersion::kPRE_ZYGOTE_FORK_VERSION:
            // namespace 4-5 works mostly
            tryRemoteloadLibraryExt(1, 5);
            break;
        case NativeBridgeVersion::kNAMESPACE_VERSION:
            // namespace 1-3 works mostly
            tryRemoteloadLibraryExt(1, 3);
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
                _kMgr->trace.callFunction((uintptr_t)pNbLoadLibrary, 2, remoteLibPath, flags);
                kINJ_WAIT;
            }
        }

        // fallback
        if (!remoteContainsMap(libPath))
        {
            _kMgr->trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibrary, 2, remoteLibPath, flags);
            kINJ_WAIT;
        }
    }

    uintptr_t libBase = 0;

    if (remoteContainsMap(libPath))
    {
        auto mps = KittyMemoryEx::getMapsContain(_kMgr->processID(), libPath);
        if (!mps.empty())
            libBase = mps.front().startAddress;
    }
    else if (remoteContainsMap(memfd_rand))
    {
        auto mps = KittyMemoryEx::getMapsContain(_kMgr->processID(), memfd_rand);
        if (!mps.empty())
            libBase = mps.front().startAddress;
    }

    if (!libBase)
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

    _kMgr->trace.Detach();

    return libBase;
}