#include "KittyInjector.hpp"
#include <jni.h>

std::string EMachineToStr(int16_t em)
{
    switch (em)
    {
    case EM_AARCH64:
        return "arm64";
    case EM_ARM:
        return "arm";
    case EM_386:
        return "x86";
    case EM_X86_64:
        return "x86_64";
    }
    return "Unknown";
}

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

    auto targetEM = _kMgr->getMemElfExe().header().e_machine;
    if (kInjectorEM != targetEM)
    {
        KITTY_LOGE("KittyInjector: Injector is %s but target app is %s.", EMachineToStr(kInjectorEM).c_str(), EMachineToStr(targetEM).c_str());
        KITTY_LOGE("KittyInjector: Please use %s version of the injector.", EMachineToStr(targetEM).c_str());
        return false;
    }

    if (!_remote_syscall.init(_kMgr.get()))
    {
        KITTY_LOGE("KittyInjector: Failed to initialize remote syscall.");
        return false;
    }

    _remote_dlopen = _kMgr->findRemoteOfSymbol(KT_LOCAL_SYMBOL(dlopen));
    if (!_remote_dlopen)
    {
        KITTY_LOGE("KittyInjector: remote dlopen not found.");
        return false;
    }

    _remote_dlopen_ext = _kMgr->findRemoteOfSymbol(KT_LOCAL_SYMBOL(android_dlopen_ext));
    
    _remote_dlclose = _kMgr->findRemoteOfSymbol(KT_LOCAL_SYMBOL(dlclose));
    
    _remote_dlerror = _kMgr->findRemoteOfSymbol(KT_LOCAL_SYMBOL(dlerror));

    // check houdini/ndk_translation for emulators
    _nbImplElf = _kMgr->getMemElf(kNB_Impl_Houdini);
    if (!_nbImplElf.isValid())
        _nbImplElf = _kMgr->getMemElf(kNB_Impl_NdkTr);

    if (_nbImplElf.isValid())
    {
        _nbElf = _kMgr->getMemElf(kNB_Lib);

        // find and read NativeBridge interface
        uintptr_t pNativeBridgeItf = _nbImplElf.findSymbol(kNativeBridgeSymbol);
        if (pNativeBridgeItf)
        {
            _kMgr->readMem(pNativeBridgeItf, &_nbItf.version, sizeof(uint32_t));

            size_t bridgeCallbacksSize = NativeBridgeCallbacks::getStructSize(_nbItf.version);
            _kMgr->readMem(pNativeBridgeItf, &_nbItf, bridgeCallbacksSize);
        }
    }

    _soinfo_patch.init(_kMgr.get());

    return true;
}

injected_info_t KittyInjector::injectLibrary(std::string libPath, int flags,
    bool use_memfd_dl, bool hide_maps, bool hide_solist, std::function<void(injected_info_t& injected)> beforeEntryPoint)
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

    KITTY_LOGI("injectLibrary: [native=%s | lib=%s].", EMachineToStr(kInjectorEM).c_str(), EMachineToStr(libHdr.e_machine).c_str());

    // check if need emulation
    if (libHdr.e_machine != kInjectorEM)
    {
        KITTY_LOGW("injectLibrary: Library EMachine is not native.");
        KITTY_LOGI("injectLibrary: Searching for NativeBridge implementation...");

        if (!_nbImplElf.isValid())
        {
            KITTY_LOGW("injectLibrary: No supported NativeBridge found.");
            return {};
        }

        KITTY_LOGI("injectLibrary: Found NativeBridge \"%s\" version %d.", KittyUtils::fileNameFromPath(_nbImplElf.filePath()).c_str(), _nbItf.version);

        // x86_64 emulates arm64, x86 emulates arm
        if (_nbImplElf.header().e_machine == EM_X86_64 && libHdr.e_machine != EM_AARCH64)
        {
            KITTY_LOGE("injectLibrary: x86_64 should emualte arm64 not %s.", EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }
        else if (_nbImplElf.header().e_machine == EM_386 && libHdr.e_machine != EM_ARM)
        {
            KITTY_LOGE("injectLibrary: x86 should emualte arm not %s.", EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }

        // version check
        if (_nbItf.version < NB_MIN_VERSION || _nbItf.version > NB_MAX_VERSION)
        {
            KITTY_LOGE("injectLibrary: Invalid NativeBridge version. [Min=%d | Max=%d]", NB_MIN_VERSION, NB_MAX_VERSION);
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

    if (libHdr.e_machine == kInjectorEM)
        injected = nativeInject(libFile, flags, canUseMemfd);
    else
        injected = emuInject(libFile, flags, canUseMemfd);

    KITTY_LOGI("injectLibrary: lib handle = %p.", (void*)injected.dl_handle);
    KITTY_LOGI("injectLibrary: lib Base = %p.", (void*)injected.elf.base());

    if (injected.is_valid())
    {
        if (hide_solist)
        {
            if (libHdr.e_machine == kInjectorEM)
                _soinfo_patch.linker_solist_remove_elf(injected.elf);
            else
                _soinfo_patch.nb_solist_remove_elf(_nbImplElf, injected.elf);
        }

        if (hide_maps && !hideSegmentsFromMaps(injected))
            KITTY_LOGW("injectLibrary: Failed to hide lib segments from /maps.");

        if (beforeEntryPoint)
            beforeEntryPoint(injected);

        callEntryPoint(injected);
    }
    else
    {
        KITTY_LOGE("injectLibrary: failed )':");
        KITTY_LOGE("injectLibrary: calling dlerror...");

        uintptr_t error_ret = 0;

        if (libHdr.e_machine == kInjectorEM)
            error_ret = _kMgr->trace.callFunction(_remote_dlerror, 0);
        else if (_nbItf.version >= NB_NAMESPACE_VERSION)
            error_ret = _kMgr->trace.callFunction((uintptr_t)_nbItf.getError, 0);
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
        uintptr_t remoteLibPath = _remote_syscall.rmmap_str(lib.Path());
        if (!remoteLibPath)
        {
            KITTY_LOGE("nativeInject: Failed to map lib path, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        info.dl_handle = _kMgr->trace.callFunction(_remote_dlopen, 2, remoteLibPath, flags);

        info.elf = _kMgr->getMemElf(lib.Path());

        return info.elf.isValid();
    };

    auto memfd_dlopen = [&]() -> bool
    {
        std::string memfd_rand = KittyUtils::String::Random(KittyUtils::randInt(5, 12));
        KITTY_LOGI("nativeInject: memfd_rand(%d) = %s.", int(memfd_rand.length()), memfd_rand.c_str());

        uintptr_t rmemfd_name = _remote_syscall.rmmap_str(memfd_rand);
        if (!rmemfd_name)
        {
            KITTY_LOGE("nativeInject: Failed to map memfd_name, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        int rmemfd = _remote_syscall.rmemfd_create(rmemfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("nativeInject: memfd_create failed, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        std::string rmemfdPath = KittyUtils::String::Fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
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

        info.elf = _kMgr->getMemElf("/memfd:" + memfd_rand);

        return info.elf.isValid();
    };

    if (use_dl_memfd)
    {
        if (!memfd_dlopen())
        {
            KITTY_LOGW("nativeInject: android_dlopen_ext failed.");
            uintptr_t error_ret = _kMgr->trace.callFunction(_remote_dlerror, 0);
            if (IsValidRetPtr(error_ret))
            {
                std::string error_str = _kMgr->readMemStr(error_ret, 0xff);
                if (!error_str.empty())
                    KITTY_LOGE("error %s.", error_str.c_str());
            }
            KITTY_LOGI("nativeInject: falling back to legacy dlopen.");
            legacy_dlopen();
        }
    }
    else
    {
        legacy_dlopen();
    }

    if (info.is_valid())
    {
        info.secretKey = kINJ_SECRET_KEY;
        info.pJvm = getJavaVM(info);
        info.pJNI_OnLoad = info.elf.findSymbol("JNI_OnLoad");
    }

    return info;
}

injected_info_t KittyInjector::emuInject(KittyIOFile& lib, int flags, bool use_dl_memfd)
{
    uintptr_t pNbInitialized = _nbElf.findSymbol("NativeBridgeInitialized");
    if (!pNbInitialized)
        pNbInitialized = _nbElf.findSymbol("_ZN7android23NativeBridgeInitializedEv");

    bool NbInitialized = _kMgr->trace.callFunction(pNbInitialized, 0);
    if (pNbInitialized && !NbInitialized)
    {
        KITTY_LOGE("emuInject: NativeBridge is not initialized yet, Maybe add -delay.");
        return {};
    }

    injected_info_t info {};
    info.is_native = false;

    std::string libPath = lib.Path();
    std::string memfdName = "/memfd:";
    
    if (use_dl_memfd)
    {
        do {
            std::string memfd_rand = KittyUtils::String::Random(KittyUtils::randInt(5, 12));
            memfdName = "/memfd:" + memfd_rand;
            KITTY_LOGI("emuInject: memfd_rand(%d) = %s.", int(memfd_rand.length()), memfd_rand.c_str());

            uintptr_t rmemfd_name = _remote_syscall.rmmap_str(memfd_rand);
            if (!rmemfd_name)
            {
                KITTY_LOGE("emuInject: Failed to map memfd_name, errno = %s.", _remote_syscall.getRemoteError().c_str());
                break;
            }

            int rmemfd = _remote_syscall.rmemfd_create(rmemfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
            if (rmemfd <= 0)
            {
                KITTY_LOGE("emuInject: memfd_create failed, errno = %s.", _remote_syscall.getRemoteError().c_str());
                break;
            }

            std::string rmemfdPath = KittyUtils::String::Fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
            KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
            if (!rmemfdFile.Open())
            {
                KITTY_LOGE("emuInject: Failed to open remote memfd file, errno = %s.", rmemfdFile.lastStrError().c_str());
                break;
            }

            lib.writeToFd(rmemfdFile.FD());

            // restrict further modifications to remote memfd
            _remote_syscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

            libPath = rmemfdPath;
        } while (false);
    }

    auto emuLoadLibrary = [&](const std::string& path) -> bool
    {
        uintptr_t remoteLibPath = _remote_syscall.rmmap_str(path);
        if (!remoteLibPath)
        {
            KITTY_LOGE("emuInject: Failed to map lib path, errno = %s.", _remote_syscall.getRemoteError().c_str());
            return false;
        }

        if (_nbItf.version >= NB_NAMESPACE_VERSION)
        {
            bool isHoudini = KittyUtils::fileNameFromPath(_nbImplElf.filePath()) == kNB_Impl_Houdini;
            if (isHoudini)
            {
                // houdini version 3 or above will need to check which namespace will work between 1 to 25.
                // if (ns && ns <= 25)
                //    return (char *)&unk_64DF10 + 0xC670 * ns + qword_80C6C8;

                /* 
                Logged from houdini v6
                I: [1]: default
                I: [2]: com_android_art
                I: [3]: com_android_neuralnetworks
                I: [4]: com_android_i18n
                I: [5]: classloader-namespace (usually game libs loaded here)
                I: [6]: classloader-namespace-shared
                ...
                */

                uint8_t ns = 3; // older versions < 5, hardcoded classloader-namespace id
                if (_nbItf.version >= NB_RUNTIME_NAMESPACE_VERSION)
                {
                    // new
                    uintptr_t remote_ns_str = _remote_syscall.rmmap_str("classloader-namespace");
                    uint8_t cls_ns = _kMgr->trace.callFunction((uintptr_t)_nbItf.getExportedNamespace, 1, remote_ns_str);
                    if (cls_ns > 0 && cls_ns <= 25)
                        ns = cls_ns;
                }

                KITTY_LOGI("emuInject: Using NativeBridge namespace (%d).", ns);
                info.dl_handle = _kMgr->trace.callFunction((uintptr_t)_nbItf.loadLibraryExt, 3, remoteLibPath, flags, ns);
            }
            else
            {
                // libndk_translation.so
                uintptr_t ns = 0;
                if (_nbItf.getExportedNamespace) {
                    uintptr_t remote_ns_str = _remote_syscall.rmmap_str("default");
                    ns = _kMgr->trace.callFunction((uintptr_t)_nbItf.getExportedNamespace, 1, remote_ns_str);
                } else if (_nbItf.getVendorNamespace) {
                    ns = _kMgr->trace.callFunction((uintptr_t)_nbItf.getVendorNamespace, 0);
                }

                KITTY_LOGI("emuInject: Using NativeBridge namespace (%p).", (void*)ns);
                info.dl_handle = _kMgr->trace.callFunction((uintptr_t)_nbItf.loadLibraryExt, 3, remoteLibPath, flags, ns);
            }
        }
        else
        {
            // more reliable on NativeBridge version < 3
            uintptr_t pNbLoadLibrary = _nbElf.findSymbol("NativeBridgeLoadLibrary");
            if (!pNbLoadLibrary)
                pNbLoadLibrary = _nbElf.findSymbol("_ZN7android23NativeBridgeLoadLibraryEPKci");

            if (pNbLoadLibrary)
                info.dl_handle = _kMgr->trace.callFunction(pNbLoadLibrary, 2, remoteLibPath, flags);

            // fallback
            if (!remoteContainsMap(path) && !remoteContainsMap(memfdName))
                info.dl_handle = _kMgr->trace.callFunction((uintptr_t)_nbItf.loadLibrary, 2, remoteLibPath, flags);
        }

        info.elf = _kMgr->getMemElf(path);
        if (!info.elf.isValid())
            info.elf = _kMgr->getMemElf(memfdName);

        return info.is_valid();
    };

    if (use_dl_memfd && libPath == lib.Path())
        KITTY_LOGI("emuInject: memfd failed, falling back to legacy dlopen.");

    if (!emuLoadLibrary(libPath))
    {
        if (use_dl_memfd && libPath != lib.Path())
        {
            KITTY_LOGW("emuInject: memfd failed.");
            uintptr_t error_ret = _kMgr->trace.callFunction(uintptr_t(_nbItf.getError), 0);
            if (IsValidRetPtr(error_ret))
            {
                std::string error_str = _kMgr->readMemStr(error_ret, 0xff);
                if (!error_str.empty())
                    KITTY_LOGE("error %s.", error_str.c_str());
            }

            KITTY_LOGI("emuInject: falling back to legacy dlopen.");
            emuLoadLibrary(lib.Path());
        }
    }

    if (info.is_valid())
    {
        info.secretKey = kINJ_SECRET_KEY;
        info.pJvm = getJavaVM(info);

        uintptr_t entryName = _remote_syscall.rmmap_str("JNI_OnLoad");
        uintptr_t fakeCaller = info.pJvm;

        if (_nbItf.version < NB_CRITICAL_NATIVE_SUPPORT_VERSION)
        {
            uintptr_t pNbGetTrampoline = _nbElf.findSymbol("NativeBridgeGetTrampoline");
            if (!pNbGetTrampoline)
                pNbGetTrampoline = _nbElf.findSymbol("_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");

            if (pNbGetTrampoline)
                info.pJNI_OnLoad = _kMgr->trace.callFunctionFrom(fakeCaller, pNbGetTrampoline, 4, info.dl_handle, entryName, 0, 0);
        }

        if (!IsValidRetPtr(info.pJNI_OnLoad))
        {
            if (!_nbItf.getTrampoline && !_nbItf.getTrampolineWithJNICallType)
            {
                KITTY_LOGE("emuInject: getTrampoline is NULL, Won't be able to call JNI_OnLoad!");
                return info;
            }

            if (_nbItf.version != NB_CRITICAL_NATIVE_SUPPORT_VERSION || !_nbItf.getTrampolineWithJNICallType)
                info.pJNI_OnLoad = _kMgr->trace.callFunctionFrom(fakeCaller, uintptr_t(_nbItf.getTrampoline), 4, info.dl_handle, entryName, 0, 0);
            else
                info.pJNI_OnLoad = _kMgr->trace.callFunctionFrom(fakeCaller, uintptr_t(_nbItf.getTrampolineWithJNICallType), 5, info.dl_handle, entryName, 0, 0, kJNICallTypeRegular);
        }
    }

    return info;
}

uintptr_t KittyInjector::getJavaVM(injected_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("getJavaVM: Invalid info.");
        return false;
    }

    auto libart = _kMgr->getMemElf("libart.so");
    uintptr_t pJNI_GetCreatedJavaVMs = libart.findSymbol("JNI_GetCreatedJavaVMs");
    if (!pJNI_GetCreatedJavaVMs)
    {
        KITTY_LOGE("getJavaVM: Couldn't find function \"JNI_GetCreatedJavaVMs\".");
        return false;
    }

    KITTY_LOGI("getJavaVM: JNI_GetCreatedJavaVMs = %p.", (void*)pJNI_GetCreatedJavaVMs);

    uintptr_t rGetJvmsBuf = _remote_syscall.rmmap_anon(0, sizeof(uintptr_t)+sizeof(jsize), PROT_READ|PROT_WRITE);
    jint status = _kMgr->trace.callFunction(pJNI_GetCreatedJavaVMs, 3, rGetJvmsBuf, 1, rGetJvmsBuf+sizeof(uintptr_t));

    uintptr_t pJvm = 0;
    jsize nJvms = 0;
    _kMgr->readMem(rGetJvmsBuf, &pJvm, sizeof(pJvm));
    _kMgr->readMem(rGetJvmsBuf+sizeof(uintptr_t), &nJvms, sizeof(nJvms));

    if (status != 0 || !pJvm || nJvms != 1)
    {
        KITTY_LOGE("getJavaVM: Failed to get JavaVM err(%d).", status);
        return 0;
    }

    return pJvm;
}

bool KittyInjector::callEntryPoint(injected_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("callEntryPoint: Invalid info.");
        return false;
    }

    if (!IsValidRetPtr(injected.pJvm))
    {
        KITTY_LOGE("callEntryPoint: \"JavaVM\" is NULL!");
        return false;
    }

    if (!IsValidRetPtr(injected.pJNI_OnLoad))
    {
        KITTY_LOGW("callEntryPoint: \"JNI_OnLoad\" not found.");
        return false;
    }

    KITTY_LOGI("callEntryPoint: JavaVM(%p) | SecretKey(%d) | JNI_OnLoad(%p).",
        (void*)injected.pJvm, injected.secretKey, (void*)injected.pJNI_OnLoad);

    uintptr_t fakeCaller = injected.pJvm;
    jint ret = _kMgr->trace.callFunctionFrom(fakeCaller,
        injected.pJNI_OnLoad, 4, injected.pJvm, injected.secretKey);

    KITTY_LOGI("callEntryPoint: Calling JNI_OnLoad(%p, %d) returned %x.",
        (void*)injected.pJvm, injected.secretKey, ret);

    if (ret < JNI_VERSION_1_1 || ret > JNI_VERSION_1_6)
    {
        // warn
        KITTY_LOGW("callEntryPoint: Unexpected returned value %x.", ret);  
    }

    return true;
}

bool KittyInjector::hideSegmentsFromMaps(injected_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("hideSegments: Invalid info.");
        return false;
    }

    if (injected.is_hidden)
        return true;

    if (injected.elf.segments().empty())
        return false;

    // idea from https://github.com/RikkaApps/Riru/blob/master/riru/src/main/cpp/hide/hide.cpp

    for (auto& it : injected.elf.segments())
    {
        if (it.pathname.empty()) continue;
        
        /* if (KittyUtils::String::Contains(it.pathname, ".bss]"))
        {
            KITTY_LOGI("hideSegments: Spoofing .bss %p - %p", (void*)it.startAddress, (void*)it.endAddress);
            uintptr_t rstr = _remote_syscall.rmmap_str("anon:Mem_0x10000004");
            _remote_syscall.rprctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, it.startAddress, it.length, rstr);
            continue;
        } */

        KITTY_LOGI("hideSegments: Hiding segment %p - %p", (void*)it.startAddress, (void*)it.endAddress);

        // backup segment code
        auto bkup = _kMgr->memBackup.createBackup(it.startAddress, it.length);

        _remote_syscall.rmunmap(it.startAddress, it.length);
        uintptr_t segment_new_map = _remote_syscall.rmmap_anon(it.startAddress, it.length, it.protection, false);

        if (!IsValidRetPtr(segment_new_map))
        {
            KITTY_LOGE("hideSegments: Failed to re-map segment %p, error = %s", (void*)it.startAddress, _remote_syscall.getRemoteError().c_str());
            return false;
        }
        
        // restore segment code
        bkup.Restore();
    }

    injected.is_hidden = true;

    return true;
}

/*void nb_hexdump_namespace(KittyMemoryMgr* kMgr, const ElfScanner &nbImplElf, int idx)
{
    int id = idx == 0 ? 1 : idx + 1;
    static constexpr uintptr_t ns_map_off = 0x8236C0;
    static constexpr uintptr_t ns_array_entry = 0x666580;
    static constexpr size_t ns_entry_size = 50816;

    static uintptr_t ns_map_addr = 0;
    if (!ns_map_addr)
        kMgr->readMem(nbImplElf.base() + ns_map_off, &ns_map_addr, sizeof(ns_map_addr));

    if (!ns_map_addr) return;

    std::string ns_name = kMgr->readMemStr(ns_map_addr + ns_array_entry + (id * ns_entry_size), 33);
    KITTY_LOGI("[%d] Name: %s", idx, ns_name.c_str());

    std::vector<char> buf(ns_entry_size, 0);
    kMgr->readMem(ns_map_addr + ns_array_entry + (id * ns_entry_size), buf.data(), buf.size());
    KITTY_LOGI("[%d] Hex: \n%s", id, KittyUtils::HexDump<32, true>(buf.data(), buf.size()).c_str());
}*/