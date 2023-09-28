#include "KittyInjector.hpp"

bool KittyInjector::init(pid_t pid, EKittyMemOP eMemOp)
{
    _init = false;

    bool isLocal64bit = !KittyMemoryEx::getMapsContain(getpid(), "/lib64/").empty();
    bool isRemote64bit = !KittyMemoryEx::getMapsContain(pid, "/lib64/").empty();
    if (isLocal64bit != isRemote64bit)
    {
        KITTY_LOGE("KittyInjector: Injector is %sbit but target app is %sbit.",
                   isLocal64bit ? "64" : "32", isRemote64bit ? "64" : "32");
        return false;
    }

    if (!_pkMgr.initialize(pid, eMemOp, false))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize kittyMgr.");
        return false;
    }

    _remote_syscall = _pkMgr.findRemoteOf("syscall", (uintptr_t)&syscall);
    if (!_remote_syscall)
    {
        KITTY_LOGE("KittyInjector: remote syscall not found.");
        return false;
    }

    _remote_dlopen = _pkMgr.findRemoteOf("dlopen", (uintptr_t)&dlopen);
    if (!_remote_dlopen)
    {
        KITTY_LOGE("KittyInjector: remote dlopen not found.");
        return false;
    }

    _remote_dlerror = _pkMgr.findRemoteOf("dlerror", (uintptr_t)&dlerror);

    _init = true;

    // check houdini for emulators
    _houdiniElf = _pkMgr.getElfBaseMap(kNativeBridgeLib);
    if (!_houdiniElf.isValid())
        return true;

    // find and read native bridge interface
    uintptr_t pNativeBridgeItf = _houdiniElf.elfScan.findSymbol(kNativeBridgeSymbol);
    if (!pNativeBridgeItf)
        return true;

    _pkMgr.readMem(pNativeBridgeItf, &_nativeBridgeItf.version, sizeof(uint32_t));

    size_t bridgeCallbacksSize = NativeBridgeCallbacks::getStructSize(_nativeBridgeItf.version);
    _pkMgr.readMem(pNativeBridgeItf, &_nativeBridgeItf, bridgeCallbacksSize);

    return true;
}

uintptr_t KittyInjector::injectLibrary(std::string libPath, int flags) const
{
    if (!_init || !_pkMgr.isMemValid())
    {
        KITTY_LOGE("injectLibrary: Not initialized.");
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
    libFile.Close();

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

    if (!_pkMgr.trace.Attach())
    {
        KITTY_LOGE("injectLibrary: Failed to attach.");
        return 0;
    }

    // allocate remote memory for lib path
    uintptr_t remoteLibPath = _pkMgr.trace.callFunction(_remote_syscall, 7, syscall_mmap_n,
                                                        nullptr, libPath.length() + 1,
                                                        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!remoteLibPath)
    {
        KITTY_LOGE("injectLibrary: mmap failed.");
        return 0;
    }

    if (!_pkMgr.writeMemStr(remoteLibPath, libPath))
    {
        KITTY_LOGE("injectLibrary: Failed to write lib path.");
        _pkMgr.trace.callFunction(_remote_syscall, 3, syscall_munmap_n, remoteLibPath, libPath.length() + 1);
        return 0;
    }

    uintptr_t ret = 0;

    // native dlopen
    if (libHdr.e_machine == kNativeEM)
    {
        ret = _pkMgr.trace.callFunction(_remote_dlopen, 2, remoteLibPath, flags);
    }
    // bridge dlopen
    else if (_nativeBridgeItf.version >= NativeBridgeVersion::kNAMESPACE_VERSION)
    {
        // houdini version 3 or above will need to check which namespace will work between 1 to 25.
        // if (ns && ns <= 25)
        //    return (char *)&unk_64DF10 + 0xC670 * ns + qword_80C6C8;
        auto tryRemoteloadLibraryExt = [&](uint8_t ns_start, uint8_t ns_end) -> uintptr_t
        {
            for (uint8_t i = ns_start; i <= ns_end; i++)
            {
                uintptr_t result = _pkMgr.trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibraryExt, 3, remoteLibPath, flags, i);
                if (result && !KittyMemoryEx::getMapsEqual(_pkMgr.processID(), libPath).empty())
                    return result;
            }
            return 0;
        };
        switch (_nativeBridgeItf.version)
        {
        case NativeBridgeVersion::kVENDOR_NAMESPACE_VERSION:  // not tested
        case NativeBridgeVersion::kRUNTIME_NAMESPACE_VERSION: // not tested
        case NativeBridgeVersion::kPRE_ZYGOTE_FORK_VERSION:
            // namespace 4-5 works mostly
            ret = tryRemoteloadLibraryExt(1, 5);
            break;
        case NativeBridgeVersion::kNAMESPACE_VERSION:
            // namespace 1-3 works mostly
            ret = tryRemoteloadLibraryExt(1, 3);
            break;
        }
    }
    else if (_nativeBridgeItf.version == NativeBridgeVersion::kSIGNAL_VERSION)
    {
        // more reliable on older version of houdini
        auto libNB = _pkMgr.getElfBaseMap("libnativebridge.so");
        if (libNB.isValid())
        {
            uintptr_t pNbLoadLibrary = libNB.elfScan.findSymbol("_ZN7android23NativeBridgeLoadLibraryEPKci");
            if (pNbLoadLibrary)
                ret = _pkMgr.trace.callFunction((uintptr_t)pNbLoadLibrary, 2, remoteLibPath, flags);
        }

        // fallback
        if (!ret || KittyMemoryEx::getMapsEqual(_pkMgr.processID(), libPath).empty())
            ret = _pkMgr.trace.callFunction((uintptr_t)_nativeBridgeItf.loadLibrary, 2, remoteLibPath, flags);
    }

    // check if our lib is in remote process maps
    if (!ret || KittyMemoryEx::getMapsEqual(_pkMgr.processID(), libPath).empty())
    {
        ret = 0;

        KITTY_LOGI("injectLibrary: failed )':");
        KITTY_LOGI("injectLibrary: calling dlerror...");

        uintptr_t error_ret = 0;

        if (libHdr.e_machine == kNativeEM)
            error_ret = _pkMgr.trace.callFunction(_remote_dlerror, 0);
        else if (_nativeBridgeItf.version >= NativeBridgeVersion::kNAMESPACE_VERSION)
            error_ret = _pkMgr.trace.callFunction((uintptr_t)_nativeBridgeItf.getError, 0);
        else
            KITTY_LOGI("injectLibrary: dlerror not available.");

        if (error_ret)
        {
            std::string error_str = _pkMgr.readMemStr(error_ret, 0xff);
            if (!error_str.empty())
                KITTY_LOGI("injectLibrary: %s", error_str.c_str());
        }
    }

    // cleanup
    _pkMgr.trace.callFunction(_remote_syscall, 3, syscall_munmap_n, remoteLibPath, libPath.length() + 1);

    _pkMgr.trace.Detach();

    return ret;
}
