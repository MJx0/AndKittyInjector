#include "KittyInjector.hpp"
#include <thread>

#define kUSE_STACK_BUFFER 1

#if kUSE_STACK_BUFFER
#define kREMOTE_BUFF_SIZE (19 * 8)
#else
#define kREMOTE_BUFF_SIZE (KT_PAGE_SIZE)
#endif

#define kGET_ALIGIN_UP(p) ((uintptr_t(p) + sizeof(uintptr_t)) & ~(sizeof(uintptr_t) - 1))

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

bool KittyInjector::init(KittyMemoryMgr *kmgr, const inject_elf_config_t &cfg)
{
    if (!kmgr || !kmgr->isMemValid())
    {
        KITTY_LOGE("Injector: KittyMemoryMgr is not initialized!.");
        return false;
    }

    _cfg = cfg;

    _kMgr = kmgr;
    _kMgr->trace.setAutoRestoreRegs(true);
    _kMgr->trace.setDefaultCaller(0);

    int sdk = KittyUtils::getAndroidSDK();
    if (!(sdk > 0 && sdk < 24))
    {
        std::vector<std::string> caller_libs = {"/libRS.so", "/libc.so"};
        for (auto &lib : caller_libs)
        {
            auto segs = _kMgr->elfScanner.findElf(lib.c_str(), EScanElfType::Native, EScanElfFilter::System).segments();
            for (auto &it : segs)
            {
                // non exec to receive SIGSEGV on return
                if (!it.executable)
                {
                    _dl_caller = it.startAddress;
                    KITTY_LOGI("Injector: dl default caller set to %p.", (void *)_dl_caller);
                    break;
                }
            }
            if (_dl_caller)
                break;
        }
    }

    auto targetEM = _kMgr->elfScanner.getProgramElf().header().e_machine;
    if (kInjectorEM != targetEM)
    {
        KITTY_LOGE("Injector: Injector is %s but target app is %s!",
                   EMachineToStr(kInjectorEM).c_str(),
                   EMachineToStr(targetEM).c_str());
        KITTY_LOGE("Injector: Please use %s version of the injector!", EMachineToStr(targetEM).c_str());
        return false;
    }

    if (!_kMgr->linkerScanner.init())
    {
        KITTY_LOGE("Injector: Failed to initialize linker scanner!");
        return {};
    }

    if (!_rsyscall.init(_kMgr))
    {
        KITTY_LOGE("Injector: Failed to initialize remote syscall!");
        return false;
    }

    _rdlopen = _kMgr->elfScanner.findRemoteSymbol("dlopen", uintptr_t(dlopen));
    if (_rdlopen)
    {
        _rdlclose = _kMgr->elfScanner.findRemoteSymbol("dlclose", uintptr_t(dlclose));
        _rdlerror = _kMgr->elfScanner.findRemoteSymbol("dlerror", uintptr_t(dlerror));
        _rdlsym = _kMgr->elfScanner.findRemoteSymbol("dlsym", uintptr_t(dlsym));
        _rdlopen_ext = _kMgr->elfScanner.findRemoteSymbol("android_dlopen_ext", uintptr_t(android_dlopen_ext));
    }
    else
    {
        _rdlopen = _kMgr->linkerScanner.findSymbol("__loader_dlopen");
        _rdlclose = _kMgr->linkerScanner.findSymbol("__loader_dlclose");
        _rdlerror = _kMgr->linkerScanner.findSymbol("__loader_dlerror");
        _rdlsym = _kMgr->linkerScanner.findSymbol("__loader_dlsym");
        _rdlopen_ext = _kMgr->linkerScanner.findSymbol("__loader_android_dlopen_ext");
    }

    if (!_rdlopen)
    {
        KITTY_LOGE("Injector: remote \"dlopen\" not found!");
        return false;
    }

    if (!_rdlclose)
    {
        KITTY_LOGE("Injector: remote \"dlclose\" not found!");
        return false;
    }

    if (_cfg.memfd)
    {
        if (!canUseMemfd())
        {
            KITTY_LOGE("Injector: --memfd is used but \"memfd_create\" syscall failed!");
            return false;
        }
        if (!_rdlopen_ext)
        {
            KITTY_LOGE("Injector: --memfd is used but \"android_dlopen_ext\" not found!");
            return false;
        }
    }

    return true;
}

bool KittyInjector::validateElf(const std::string &elfPath, KT_ElfW(Ehdr) * hdr, bool *needsNB)
{
    KT_ElfW(Ehdr) libHdr = {};

    KittyIOFile libFile(elfPath, O_RDONLY | O_CLOEXEC);
    if (!libFile.open())
    {
        KITTY_LOGE("Injector: %s not accessible. (\"%s\")", elfPath.c_str(), libFile.lastStrError().c_str());
        return false;
    }

    libFile.pread(0, &libHdr, sizeof(libHdr));
    libFile.close();

    if (hdr)
        memcpy(hdr, &libHdr, sizeof(libHdr));

    if (memcmp(libHdr.e_ident, "\177ELF", 4) != 0)
    {
        KITTY_LOGE("Injector: %s is not a valid ELF!", elfPath.c_str());
        return false;
    }

    if (libHdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
    {
        KITTY_LOGE("Injector: %s is %dbit but Injector is %dbit!",
                   elfPath.c_str(),
                   (libHdr.e_ident[EI_CLASS] == ELFCLASS32 ? 32 : 64),
                   KT_ELFCLASS_BITS);
        return false;
    }

    if (needsNB)
        *needsNB = libHdr.e_machine != kInjectorEM;

    return true;
}

bool KittyInjector::waitBreakpoint(bool needsNB)
{
    uintptr_t bp_addr = 0;
    if (!needsNB)
    {
        bp_addr = _rdlopen;
        // bp_addr = _rdlclose;
        // bp_addr = _rdlsym;
        // bp_addr = _rdlerror;
        // bp_addr = _kMgr->elfScanner.findRemoteSymbol("getpid", uintptr_t(getpid));
        // bp_addr = _kMgr->elfScanner.findRemoteSymbol("gettid", uintptr_t(gettid));
    }
    else
    {
        nbItf_data_t callbacks{};
        if (!findNbCallbacks(&callbacks))
        {
            KITTY_LOGE("Injector: Couldn't find nb callbacks!");
        }
        else
        {
            bp_addr = callbacks.version < KT_NB_NAMESPACE_VERSION ? uintptr_t(callbacks.loadLibrary)
                                                                  : uintptr_t(callbacks.loadLibraryExt);
        }
    }

    if (bp_addr == 0)
    {
        KITTY_LOGI("Injector: Couldn't find a breakpoint target!");
        return false;
    }

    KITTY_LOGI("Injector: Creating breakpoint at %p...", (void *)bp_addr);

    auto bp_ok = [&](user_regs_struct *regs) -> bool {
        uintptr_t arg0 = _kMgr->trace.getArgFromRegs<uintptr_t>(regs, 0);
        uintptr_t arg1 = _kMgr->trace.getArgFromRegs<uintptr_t>(regs, 1);

        std::string filePath = _kMgr->readMemStr(arg0, 0xff);
        int flags = arg1;

        KITTY_LOGI("bp]: dlopen(%s, %d)", filePath.c_str(), flags);

        std::string pc_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), regs->KT_REG_PC).toString();
        KITTY_LOGI("bp]: PC(%p) -> %s", (void *)regs->KT_REG_PC, pc_map.c_str());

        uintptr_t ret_addr = _kMgr->trace.getReturnAddressFromRegs(regs);
        std::string ret_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), ret_addr).toString();
        KITTY_LOGI("bp]: Return Address (%p) -> %s", (void *)ret_addr, ret_map.c_str());

        return !KittyUtils::String::contains(filePath, "nativebridge");
    };

#if 0
    KITTY_LOGI("Injector: Trying software breakpoint...");
    return _kMgr->trace.setSoftBreakpointAndWait(
               bp_addr,
               [&](user_regs_struct bp_regs) -> bool { return bp_ok(&bp_regs); },
               5000) == KT_BP_SUCCESS;
#else
    KITTY_LOGI("Injector: Trying hardware breakpoint...");
    return _kMgr->trace.setHardBreakpointAndWait(
               bp_addr,
               KT_HW_BP_EXECUTE,
               KT_HW_BP_SIZE_EXEC,
               0,
               [&](user_regs_struct bp_regs) -> bool { return bp_ok(&bp_regs); },
               5000) == KT_BP_SUCCESS;
#endif
}

inject_elf_info_t KittyInjector::inject(const std::string &elfPath)
{
    if (!_kMgr || !_kMgr->isMemValid())
    {
        KITTY_LOGE("Injector: Not initialized!");
        return {};
    }

    if (!_kMgr->trace.isAttached())
    {
        KITTY_LOGE("Injector: Not attached!");
        return {};
    }

    if (!_rdlopen)
    {
        KITTY_LOGE("Injector: remote dlopen not found!");
        return {};
    }

    KT_ElfW(Ehdr) libHdr = {};
    bool emulate = false;
    if (!validateElf(elfPath, &libHdr, &emulate))
    {
        KITTY_LOGI("Injector: Failed to validate %s!", elfPath.c_str());
        return {};
    }

    if (emulate)
    {
#if defined(__arm__) || defined(__aarch64__)
        KITTY_LOGE("Injector: Emulation only available in x86 and x86_64.");
        return {};
#else

        // x86_64 emulates arm64, x86 emulates arm
        if (_kMgr->elfScanner.getProgramElf().header().e_machine == EM_X86_64 && libHdr.e_machine != EM_AARCH64)
        {
            KITTY_LOGE("Injector: x86_64 should emulate arm64 not %s.", EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }
        else if (_kMgr->elfScanner.getProgramElf().header().e_machine == EM_386 && libHdr.e_machine != EM_ARM)
        {
            KITTY_LOGE("Injector: x86 should emulate arm not %s.", EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }
#endif
    }

    KittyIOFile libFile(elfPath, O_RDONLY | O_CLOEXEC);
    if (!libFile.open())
    {
        KITTY_LOGE("Injector: Library path not accessible. (\"%s\")", libFile.lastStrError().c_str());
        return {};
    }

    user_regs_struct backup_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));

    if (!_kMgr->trace.getRegs(&backup_regs))
    {
        KITTY_LOGE("Injector: Failed to backup registers.");
        return {};
    }

    auto cleanUp = [this, &backup_regs]() {
#if kUSE_STACK_BUFFER
        if (_backup_rbuffer.size())
        {
            _kMgr->writeMem(_rbuffer, _backup_rbuffer.data(), _backup_rbuffer.size());
        }
#else
        _rsyscall.rmunmap(_rbuffer, kREMOTE_BUFF_SIZE);
#endif

        if (!_kMgr->trace.setRegs(&backup_regs))
            KITTY_LOGE("Injector: Failed to restore registers.");
    };

    // test to clear remote syscall
    if (!_rsyscall.testSyscall())
    {
        cleanUp();
        KITTY_LOGE("Injector: Remote syscall test failed. errno(\"%s\").", _rsyscall.lastError().c_str());
        return {};
    }

    // remote buffer
    {
#if kUSE_STACK_BUFFER
        uintptr_t backup_sp = backup_regs.KT_REG_SP;
        backup_regs.KT_REG_SP = KT_PAGE_START(backup_sp);

        if (!_kMgr->trace.setRegs(&backup_regs))
        {
            cleanUp();
            KITTY_LOGE("Injector: Failed to reserve stack buffer.");
            return {};
        }

        _rbuffer = backup_regs.KT_REG_SP;
        backup_regs.KT_REG_SP = backup_sp;

        std::vector<uint8_t> temp_buffer(kREMOTE_BUFF_SIZE, 0);
        size_t nread = _kMgr->readMem(_rbuffer, temp_buffer.data(), temp_buffer.size());
        if (nread > 0)
        {
            _backup_rbuffer.resize(nread);
            memcpy(_backup_rbuffer.data(), temp_buffer.data(), nread);
        }

        memset(temp_buffer.data(), 0, temp_buffer.size());
        _kMgr->writeMem(_rbuffer, temp_buffer.data(), temp_buffer.size());
#else
        _rbuffer = _rsyscall.rmmap(0, kREMOTE_BUFF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
#endif
    }

    inject_elf_info_t injected{};
    bool bCalldlerror = false;

    if (!emulate)
    {
        KITTY_LOGI("Injector: using nativeInject...");
        injected = nativeInject(libFile, &bCalldlerror);
    }
    else
    {
        KITTY_LOGI("Injector: using emuInject...");
        injected = emuInject(libFile, &bCalldlerror);
    }

    KITTY_LOGI("Injector: Library Handle (%p).", (void *)injected.dl_handle);
    KITTY_LOGI("Injector: Library Base (%p).", (void *)injected.elf.base());

    if (injected.is_valid())
    {
        if (injected.pJNI_OnLoad)
        {
            KITTY_LOGI("Injector: Getting JavaVM...");
            injected.pJvm = getJavaVM(injected);
            KITTY_LOGI("Injector: JavaVM (%p).", (void *)(injected.pJvm));
        }

        if (_cfg.hide)
        {
            injected.is_hidden = hideLibrary(injected);
            if (!injected.is_hidden)
            {
                KITTY_LOGE("Injector: Failed to hide %s!", injected.elf.filePath().c_str());
                KITTY_LOGI("Unloading %s...", injected.elf.filePath().c_str());
                if (unloadLibrary(injected))
                    KITTY_LOGI("Injector: Library unloaded successfully.");
                else
                    KITTY_LOGW("Injector: Failed to unload library!");

                cleanUp();
                return {};
            }
        }

        if (_cfg.beforeEntryPoint)
            _cfg.beforeEntryPoint(injected);

        if (injected.pJNI_OnLoad && injected.pJvm)
        {
            injected.secretKey = kINJ_SECRET_KEY;
            callEntryPoint(injected);
        }
        else
        {
            if (!injected.pJNI_OnLoad)
                KITTY_LOGW("Injector: Couldn't find JNI_OnLoad symbol.");

            if (!injected.pJvm)
                KITTY_LOGW("Injector: Couldn't find JavaVM.");

            KITTY_LOGW("Injector: Skipping EntryPoint");
        }

        if (_cfg.afterEntryPoint)
            _cfg.afterEntryPoint(injected);

        if (_cfg.free)
        {
            KITTY_LOGI("Injector: Unloading library...");
            if (unloadLibrary(injected))
                KITTY_LOGI("Injector: Library unloaded successfully.");
            else
                KITTY_LOGW("Injector: Failed to unload library!");
        }
    }
    else if (bCalldlerror)
    {
        KITTY_LOGE("Injector: dlopen failed )':");
        KITTY_LOGI("Injector: Calling dlerror...");

        kitty_rp_call_t error_ret;

        if (!(emulate && _kMgr->nbScanner.nbItfData().version < KT_NB_NAMESPACE_VERSION))
        {
            if (!emulate)
            {
                error_ret = _kMgr->trace.callFunctionFrom(emulate ? 0 : _dl_caller, _rdlerror);
            }
            else
            {
                error_ret = _kMgr->trace.callFunction((uintptr_t)_kMgr->nbScanner.nbItfData().getError);
            }

            if (error_ret.status == KT_RP_CALL_SUCCESS && error_ret.result.ptr != 0)
            {
                std::string error_str = _kMgr->readMemStr(error_ret.result.ptr, 0xff);
                if (!error_str.empty())
                {
                    KITTY_LOGE("Injector: %s", error_str.c_str());

                    if (_cfg.memfd && KittyUtils::String::contains(error_str, "library", false) &&
                        KittyUtils::String::endsWith(error_str, "not found", false))
                    {
                        KITTY_LOGI("Injector: memfd dlopen might not be supported.");
                    }

                    else if (!_cfg.memfd && KittyUtils::String::contains(error_str, "couldn't map", false) &&
                             KittyUtils::String::endsWith(error_str, "Permission denied", false))
                    {
                        KITTY_LOGI("Injector: Maybe use memfd or disable SELinux.");
                    }
                }
                else
                {
                    KITTY_LOGE("Injector: Failed to read dlerror string.");
                }
            }
            else if (error_ret.status != KT_RP_CALL_SUCCESS)
            {
                KITTY_LOGE("Injector: Failed to call dlerror.");
            }
            else if (error_ret.result.ptr == 0)
            {
                KITTY_LOGE("Injector: dlerror returned 0.");
            }
        }
        else
        {
            KITTY_LOGW("Injector: dlerror not available.");
        }
    }

    cleanUp();

    return injected;
}

inject_elf_info_t KittyInjector::nativeInject(KittyIOFile &elfFile, bool *bCalldlerror)
{
    inject_elf_info_t info{};
    info.is_native = true;

    auto do_legacy_dlopen = [&]() -> void {
        if (!_kMgr->writeMemStr(_rbuffer, elfFile.path()))
        {
            KITTY_LOGE("nativeInject: Failed to write lib path into stack!");
            return;
        }

        auto ret = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlopen, _rbuffer, _cfg.rtdl_flags);
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("nativeInject: Failed to call dlopen.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            info.soinfo = _kMgr->linkerScanner.findSoInfo(elfFile.path());
            info.elf = _kMgr->elfScanner.findElf(elfFile.path(), EScanElfType::Native);
            if (!info.elf.isValid())
            {
                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    auto do_memfd_dlopen = [&]() -> void {
        std::string memfd_rand = KittyUtils::String::random(KittyUtils::randInt(5, 12));
        KITTY_LOGI("nativeInject: memfd Name (\"%s\").", memfd_rand.c_str());

        if (!_kMgr->writeMemStr(_rbuffer, memfd_rand))
        {
            KITTY_LOGE("nativeInject: Failed to write memfd name into stack!");
            return;
        }

        int rmemfd = _rsyscall.rmemfd_create(_rbuffer, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("nativeInject: memfd_create failed, errno (\"%s\").", _rsyscall.lastError().c_str());
            return;
        }

        std::string rmemfdPath = KittyUtils::String::fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
        KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
        if (!rmemfdFile.open())
        {
            KITTY_LOGE("nativeInject: Failed to open remote memfd file, errno (\"%s\").",
                       rmemfdFile.lastStrError().c_str());
            return;
        }

        elfFile.writeToFd(rmemfdFile.fd());

        // restrict further modifications to remote memfd
        _rsyscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

        android_dlextinfo extinfo = {};
        extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        extinfo.library_fd = rmemfd;

        uintptr_t rdlextinfo = kGET_ALIGIN_UP(_rbuffer + memfd_rand.size() + 1);
        if (!_kMgr->writeMem(rdlextinfo, &extinfo, sizeof(extinfo)))
        {
            KITTY_LOGE("nativeInject: Failed to write dlextinfo into stack!");
            return;
        }

        auto ret = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlopen_ext, _rbuffer, _cfg.rtdl_flags, rdlextinfo);
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("nativeInject: Failed to call dlopen_ext.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            info.soinfo = _kMgr->linkerScanner.findSoInfo("/memfd:" + memfd_rand);
            info.elf = _kMgr->elfScanner.findElf("/memfd:" + memfd_rand, EScanElfType::Native);
            if (!info.elf.isValid())
            {
                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    if (_cfg.memfd)
    {
        do_memfd_dlopen();
    }
    else
    {
        do_legacy_dlopen();
    }

    if (info.is_valid())
    {
        info.pJNI_OnLoad = info.elf.findSymbol("JNI_OnLoad");
    }

    return info;
}

inject_elf_info_t KittyInjector::emuInject(KittyIOFile &elfFile, bool *bCalldlerror)
{
    _kMgr->nbScanner.init();

    auto &nb = _kMgr->nbScanner;
    auto nbData = nb.nbItfData();

    KITTY_LOGI("emuInject: NativeBridge version %d.", nbData.version);

    uintptr_t pNbInitialized = uintptr_t(nb.fnNativeBridgeInitialized);
    if (pNbInitialized == 0 || _kMgr->trace.callFunction(pNbInitialized).result.val == 0)
    {
        KITTY_LOGE("emuInject: NativeBridge is not initialized yet, maybe use --bp or --delay.");
        return {};
    }

    if ((nbData.version < KT_NB_NAMESPACE_VERSION && !nbData.loadLibrary) ||
        (nbData.version >= KT_NB_NAMESPACE_VERSION && !nbData.loadLibraryExt))
    {
        findNbCallbacks(&nbData);
    }

    if (!nbData.loadLibrary && !nbData.loadLibraryExt)
    {
        KITTY_LOGE("emuInject: NativeBridge callbacks data is not valid!");
        return {};
    }

    // returns dl handle on success
    auto emu_dlopen = [&](const std::string &path) -> kitty_rp_call_t {
        if (nbData.version < KT_NB_NAMESPACE_VERSION)
        {
            if (!_kMgr->writeMemStr(_rbuffer, path))
            {
                KITTY_LOGE("emuInject: Failed to write lib path into stack!");
                return {KT_RP_CALL_MEM_FAILED, {0}};
            }
            return _kMgr->trace.callFunction((uintptr_t)nbData.loadLibrary, _rbuffer, _cfg.rtdl_flags);
        }
        else
        {
            uintptr_t ns = 0;
            if (nb.isHoudini())
            {
                // houdini version 3 or above will need to check which namespace
                // will work between 1 to 25. if (ns && ns <= 25)
                // return (char *)&unk_64DF10 + 0xC670 * ns + qword_80C6C8;

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

                // on nb versions < 5, hardcoded classloader-namespace id (3)
                ns = 3;
                if (nbData.version >= KT_NB_RUNTIME_NAMESPACE_VERSION)
                {
                    if (!_kMgr->writeMemStr(_rbuffer, "classloader-namespace"))
                    {
                        KITTY_LOGE("emuInject: Failed to write classloader name into stack!");
                        return {KT_RP_CALL_MEM_FAILED, {0}};
                    }
                    auto cls_ns = _kMgr->trace.callFunction((uintptr_t)nbData.getExportedNamespace, _rbuffer);
                    if (cls_ns.status != KT_RP_CALL_SUCCESS)
                    {
                        KITTY_LOGE("emuInject: Failed to call getExportedNamespace.");
                        return cls_ns;
                    }

                    if (cls_ns.result.ptr > 0 && cls_ns.result.ptr <= 25)
                        ns = cls_ns.result.ptr;
                }
            }
            else
            {
                // libndk_translation.so
                if (nbData.getExportedNamespace)
                {
                    if (!_kMgr->writeMemStr(_rbuffer, "default"))
                    {
                        KITTY_LOGE("emuInject: Failed to write classloader default into stack!");
                        return {KT_RP_CALL_MEM_FAILED, {0}};
                    }

                    auto cls_ns = _kMgr->trace.callFunction((uintptr_t)nbData.getExportedNamespace, _rbuffer);
                    if (cls_ns.status != KT_RP_CALL_SUCCESS)
                    {
                        KITTY_LOGE("emuInject: Failed to call getExportedNamespace.");
                        return cls_ns;
                    }

                    ns = cls_ns.result.ptr;
                }
                else if (nbData.getVendorNamespace)
                {
                    auto cls_ns = _kMgr->trace.callFunction((uintptr_t)nbData.getVendorNamespace);
                    if (cls_ns.status != KT_RP_CALL_SUCCESS)
                    {
                        KITTY_LOGE("emuInject: Failed to call getVendorNamespace.");
                        return cls_ns;
                    }

                    ns = cls_ns.result.ptr;
                }
            }

            KITTY_LOGI("emuInject: Using NativeBridge namespace (%p).", (void *)ns);

            if (!_kMgr->writeMemStr(_rbuffer, path))
            {
                KITTY_LOGE("emuInject: Failed to write lib path into stack!");
                return {KT_RP_CALL_MEM_FAILED, {0}};
            }

            return _kMgr->trace.callFunction((uintptr_t)nbData.loadLibraryExt, _rbuffer, _cfg.rtdl_flags, ns);
        }

        return {KT_RP_CALL_FAILED, {0}};
    };

    inject_elf_info_t info{};
    info.is_native = false;

    auto do_legacy_dlopen = [&]() -> void {
        auto ret = emu_dlopen(elfFile.path());
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("nativeInject: Failed to call native bridge loadLibary.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            // init nb scanner after emu dlopen
            _kMgr->nbScanner.init();

            info.soinfo = _kMgr->nbScanner.findSoInfo(elfFile.path());
            info.elf = _kMgr->elfScanner.findElf(elfFile.path(), EScanElfType::Emulated);
            if (!info.elf.isValid())
            {
                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    auto do_memfd_dlopen = [&]() -> void {
        std::string memfd_rand = KittyUtils::String::random(KittyUtils::randInt(5, 12));
        KITTY_LOGI("emuInject: memfd Name (\"%s\").", memfd_rand.c_str());

        if (!_kMgr->writeMemStr(_rbuffer, memfd_rand))
        {
            KITTY_LOGE("emuInject: Failed to write memfd name into stack!");
            return;
        }

        int rmemfd = _rsyscall.rmemfd_create(_rbuffer, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("emuInject: memfd_create failed, errno = %s.", _rsyscall.lastError().c_str());
            return;
        }

        std::string rmemfdPath = KittyUtils::String::fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
        KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
        if (!rmemfdFile.open())
        {
            KITTY_LOGE("emuInject: Failed to open remote memfd file, errno = %s.", rmemfdFile.lastStrError().c_str());
            return;
        }

        elfFile.writeToFd(rmemfdFile.fd());

        // restrict further modifications to remote memfd
        _rsyscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

        auto ret = emu_dlopen(rmemfdPath);
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("nativeInject: Failed to call native bridge loadLibaryExt.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            // init nb scanner after emu dlopen
            _kMgr->nbScanner.init();

            info.soinfo = _kMgr->nbScanner.findSoInfo("/memfd:" + memfd_rand);
            info.elf = _kMgr->elfScanner.findElf("/memfd:" + memfd_rand, EScanElfType::Emulated);
            if (!info.elf.isValid())
            {
                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    if (_cfg.memfd)
    {
        do_memfd_dlopen();
    }
    else
    {
        do_legacy_dlopen();
    }

    if (info.is_valid())
    {
        if (!_kMgr->writeMemStr(_rbuffer, "JNI_OnLoad"))
        {
            KITTY_LOGE("emuInject: Failed to write \"JNI_OnLoad\"into stack!");
            return info;
        }

        if (!nbData.getTrampoline && !nbData.getTrampolineWithJNICallType)
        {
            KITTY_LOGE("emuInject: getTrampoline is NULL, Won't be able to find and call JNI_OnLoad!");
            return info;
        }

        if (nbData.version < KT_NB_CRITICAL_NATIVE_SUPPORT_VERSION || !nbData.getTrampolineWithJNICallType)
        {
            info.pJNI_OnLoad = _kMgr->trace
                                   .callFunction((uintptr_t)(nbData.getTrampoline), info.dl_handle, _rbuffer, 0, 0)
                                   .result.ptr;
        }
        else
        {
            info.pJNI_OnLoad = _kMgr->trace
                                   .callFunction((uintptr_t)(nbData.getTrampolineWithJNICallType),
                                                 info.dl_handle,
                                                 _rbuffer,
                                                 0,
                                                 0,
                                                 KT_JNICallTypeRegular)
                                   .result.ptr;
        }
    }

    return info;
}

bool KittyInjector::unloadLibrary(inject_elf_info_t &injected)
{
    if (!injected.is_valid())
        return false;

    kitty_rp_call_t freed;

    if (injected.is_native)
    {
        freed = _kMgr->trace.callFunction(_rdlclose, injected.dl_handle);
    }
    else if (_kMgr->nbScanner.nbItfData().unloadLibrary)
    {
        freed = _kMgr->trace.callFunction((uintptr_t)(_kMgr->nbScanner.nbItfData().unloadLibrary), injected.dl_handle);
    }

    return freed.status == KT_RP_CALL_SUCCESS && freed.result.val == 0;
}

bool KittyInjector::hideLibrary(inject_elf_info_t &injected)
{
    if (!injected.soinfo.ptr)
    {
        KITTY_LOGE("hideLibrary: soinfo pointer not found!");
        return false;
    }

    if (injected.is_native)
    {
        KITTY_LOGI("Injector: Removing soinfo %p...", (void *)(injected.soinfo.ptr));

        // uintptr_t removesoinfo = _kMgr->linkerScanner.findDebugSymbol("_dl__Z20solist_remove_soinfoP6soinfo");
        // _kMgr->trace.callFunction(removesoinfo, injected.soinfo.ptr);

        auto solist = _kMgr->linkerScanner.allSoInfo();
        if (solist.empty())
        {
            KITTY_LOGE("hideLibrary: Linker solist is empty!");
            return false;
        }

        kitty_soinfo_t prev = {};
        for (auto &it : solist)
        {
            if (it.next == injected.soinfo.ptr)
            {
                prev = it;
                break;
            }
        }

        if (!prev.ptr)
        {
            KITTY_LOGE("hideLibrary: Failed to find linker prev soinfo!");
            return false;
        }

        uintptr_t si_next_offset = _kMgr->linkerScanner.soinfo_offsets().next;
        if (!si_next_offset)
        {
            KITTY_LOGE("hideLibrary: Failed to find linker soinfo next offset!");
            return false;
        }

        if (!_kMgr->memPatch
                 .createWithBytes(prev.ptr + si_next_offset, &injected.soinfo.next, sizeof(injected.soinfo.next))
                 .Modify())
        {
            KITTY_LOGE("SoInfoPatch: Failed to patch emulated prev soinfo next!");
            return false;
        }

        if (_kMgr->linkerScanner.sonext() == injected.soinfo.ptr &&
            !_kMgr->memPatch.createWithBytes(_kMgr->linkerScanner.linker_offsets().sonext, &prev.ptr, sizeof(prev.ptr))
                 .Modify())
        {
            KITTY_LOGE("SoInfoPatch: Failed to patch linker sonext!");
            return false;
        }

        KITTY_LOGI("Injector: Successfully Removed soinfo %p.", (void *)(injected.soinfo.ptr));
    }
    else
    {
        KITTY_LOGI("Injector: Removing emulated soinfo %p...", (void *)(injected.soinfo.ptr));

        auto solist = _kMgr->nbScanner.allSoInfo();
        if (solist.empty())
        {
            KITTY_LOGE("hideLibrary: Emulated solist is empty!");
            return false;
        }

        uintptr_t soinfo_replace_ptr = 0;
        if (solist[0].ptr == injected.soinfo.ptr)
        {
            soinfo_replace_ptr = injected.soinfo.next;
        }
        else
        {
            for (auto &it : solist)
            {
                if (it.next == injected.soinfo.ptr)
                {
                    soinfo_replace_ptr = it.ptr;
                    break;
                }
            }

            if (!soinfo_replace_ptr)
            {
                KITTY_LOGE("hideLibrary: Failed to find emulated prev soinfo!");
                return false;
            }

            uintptr_t si_next_offset = _kMgr->nbScanner.soinfo_offsets().next;
            if (!si_next_offset)
            {
                KITTY_LOGE("hideLibrary: Emulated soinfo next offset not found!");
                return false;
            }

            if (!_kMgr->memPatch
                     .createWithBytes(soinfo_replace_ptr + si_next_offset,
                                      &injected.soinfo.next,
                                      sizeof(injected.soinfo.next))
                     .Modify())
            {
                KITTY_LOGE("SoInfoPatch: Failed to patch emulated prev soinfo next!");
                return false;
            }
        }

        auto sonext_refs = findNbSoInfoRefs(injected.soinfo);
        if (sonext_refs.empty())
        {
            KITTY_LOGE("SoInfoPatch: Failed to find emulated sonext refs!");
            return false;
        }

        for (auto &ref : sonext_refs)
        {
            if (!_kMgr->memPatch.createWithBytes(ref, &soinfo_replace_ptr, sizeof(soinfo_replace_ptr)).Modify())
            {
                KITTY_LOGE("SoInfoPatch: Failed to patch emulated sonext!");
                return false;
            }
        }

        KITTY_LOGI("Injector: Successfully Removed emulated soinfo %p.", (void *)(injected.soinfo.ptr));
    }

    KITTY_LOGI("Injector: Remapping segments %p - %p...", (void *)(injected.elf.base()), (void *)(injected.elf.end()));

    if (injected.elf.segments().empty())
    {
        KITTY_LOGE("hideLibrary: Elf segments are empty!");
        return false;
    }

    // idea from https://github.com/RikkaApps/Riru/blob/master/riru/src/main/cpp/hide/hide.cpp

    for (auto &it : injected.elf.segments())
    {
        if (it.pathname.empty())
            continue;

        auto backup = _kMgr->memBackup.createBackup(it.startAddress, it.length);

        if (!_rsyscall.rmunmap(it.startAddress, it.length))
        {
            KITTY_LOGE("hideLibrary: Failed to unmap segment %p, \"%s\".",
                       (void *)it.startAddress,
                       _rsyscall.lastError().c_str());
            return false;
        }

        uintptr_t segment_new_map = _rsyscall.rmmap(it.startAddress,
                                                    it.length,
                                                    it.protection,
                                                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                                    0,
                                                    0);
        if (segment_new_map != it.startAddress)
        {
            KITTY_LOGE("hideLibrary: Failed to remap segment %p, \"%s\".",
                       (void *)it.startAddress,
                       _rsyscall.lastError().c_str());
            return false;
        }

        backup.Restore();
    }

    KITTY_LOGI("Injector: Successfully remapped segments %p - %p.",
               (void *)(injected.elf.base()),
               (void *)(injected.elf.end()));

    return true;
}


uintptr_t KittyInjector::getJavaVM(inject_elf_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("getJavaVM: Invalid info.");
        return false;
    }

    auto libart = _kMgr->elfScanner.findElf("libart.so", EScanElfType::Native, EScanElfFilter::System);
    uintptr_t pJNI_GetCreatedJavaVMs = libart.findSymbol("JNI_GetCreatedJavaVMs");
    if (!pJNI_GetCreatedJavaVMs)
    {
        KITTY_LOGE("getJavaVM: Couldn't find function \"JNI_GetCreatedJavaVMs\".");
        return false;
    }

    jint status = _kMgr->trace.callFunction(pJNI_GetCreatedJavaVMs, _rbuffer, 1, _rbuffer + sizeof(uintptr_t))
                      .result.val;

    uintptr_t pJvm = 0;
    jsize nJvms = 0;
    _kMgr->readMem(_rbuffer, &pJvm, sizeof(pJvm));
    _kMgr->readMem(_rbuffer + sizeof(uintptr_t), &nJvms, sizeof(nJvms));

    if (status != 0 || !pJvm || nJvms != 1)
    {
        KITTY_LOGE("getJavaVM: %p JNI_GetCreatedJavaVMs Failed to get JavaVM err(%d).",
                   (void *)pJNI_GetCreatedJavaVMs,
                   status);
        return 0;
    }

    return pJvm;
}

bool KittyInjector::callEntryPoint(inject_elf_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("callEntryPoint: Invalid info.");
        return false;
    }

    KittyPtrValidator ptrValidator(_kMgr->processID(), true);

    if (!ptrValidator.isPtrExecutable(injected.pJNI_OnLoad))
    {
        KITTY_LOGW("callEntryPoint: \"JNI_OnLoad\" (%p) not valid executable address.", (void *)(injected.pJNI_OnLoad));
        return false;
    }

    if (!ptrValidator.isPtrReadable(injected.pJvm))
    {
        KITTY_LOGE("callEntryPoint: \"JavaVM\" (%p) is not valid readable address.", (void *)(injected.pJvm));
        return false;
    }

    KITTY_LOGI("callEntryPoint: JNI_OnLoad(%p) | JavaVM(%p) | SecretKey(%d).",
               (void *)injected.pJNI_OnLoad,
               (void *)injected.pJvm,
               injected.secretKey);

    jint ret = _kMgr->trace.callFunction(injected.pJNI_OnLoad, injected.pJvm, injected.secretKey).result.val;

    KITTY_LOGI("callEntryPoint: Calling JNI_OnLoad(%p, %d) returned 0x%x.",
               (void *)injected.pJvm,
               injected.secretKey,
               ret);

    if (ret < JNI_VERSION_1_1 || ret > JNI_VERSION_1_6)
    {
        // warn
        KITTY_LOGW("callEntryPoint: Unexpected return value (0x%x) for JNI version.", ret);
    }

    return true;
}

bool KittyInjector::findNbCallbacks(nbItf_data_t *out)
{
    if (out)
        *out = {};

#if !defined(__i386__) && !defined(__x86_64__)
    return false;
#else

    if (!_kMgr || !_kMgr->isMemValid())
        return false;

    if (_kMgr->nbScanner.init())
    {
        if (out)
        {
            *out = _kMgr->nbScanner.nbItfData();
        }
        return true;
    }

    uintptr_t nb_get_ver = _kMgr->nbScanner.nbElf().findSymbol("NativeBridgeGetVersion");
    if (nb_get_ver == 0)
        nb_get_ver = _kMgr->nbScanner.nbElf().findSymbol("_ZN7android22NativeBridgeGetVersionEv");

    if (nb_get_ver == 0)
        return false;

    uintptr_t callbacks_addr = 0;

#ifdef __x86_64__
    uintptr_t mov = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver, nb_get_ver + 0x20, "48 8B 05 ? ? ? ? 8B 00");
    if (mov == 0)
        return false;

    uint32_t rel = 0;
    _kMgr->readMem(mov + 3, &rel, sizeof(rel));

    callbacks_addr = mov + 7 + rel;

#elif __i386__
    uintptr_t pop = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver, nb_get_ver + 0x28, "59");
    if (pop == 0)
        return false;

    uintptr_t add = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver, nb_get_ver + 0x28, "81 C1");
    if (add == 0)
        return false;

    uintptr_t mov = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver, nb_get_ver + 0x28, "8B 81 ? ? ? ? 8B 00");
    if (mov == 0)
        return false;

    uint32_t off, disp = 0;
    _kMgr->readMem(add + 2, &off, sizeof(off));
    _kMgr->readMem(mov + 2, &disp, sizeof(disp));

    callbacks_addr = pop + off + disp;
#endif

    uintptr_t callbacks = 0;
    _kMgr->readMem(callbacks_addr, &callbacks, sizeof(uintptr_t));
    if (callbacks == 0)
        return false;

    int ver = 0;
    _kMgr->readMem(callbacks, &ver, sizeof(int));
    if (ver < 2 || ver > 25)
        return false;

    if (out)
    {
        _kMgr->readMem(callbacks, out, nbItf_data_t::GetStructSize(ver));
    }

    return true;

#endif
}

std::vector<uintptr_t> KittyInjector::findNbSoInfoRefs(const kitty_soinfo_t &soinfo)
{
    auto maps = KittyMemoryEx::getAllMaps(_kMgr->processID());

    auto si_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), soinfo.ptr, maps);
    if (si_map.pathname == "[anon:linker_alloc]")
    {
        auto results = _kMgr->memScanner.findDataAll(si_map.startAddress,
                                                     si_map.endAddress,
                                                     &soinfo.ptr,
                                                     sizeof(soinfo.ptr));
        if (results.size() > 0)
        {
            return results;
        }
    }

    for (auto &it : _kMgr->nbScanner.nbImplElf().segments())
    {
        if (it.is_rw)
        {
            auto results = _kMgr->memScanner.findDataAll(it.startAddress,
                                                         it.endAddress,
                                                         &soinfo.ptr,
                                                         sizeof(soinfo.ptr));
            if (results.size() > 0)
            {
                return results;
            }
        }
    }

    for (auto &it : maps)
    {
        bool check1 = (it.readable && KittyUtils::String::startsWith(it.pathname, "[anon:Mem_"));
        bool check2 = (it.readable && it.pathname == "[anon:linker_alloc]");
        if (!check1 && !check2)
            continue;

        auto results = _kMgr->memScanner.findDataAll(it.startAddress, it.endAddress, &soinfo.ptr, sizeof(soinfo.ptr));
        if (results.size() > 0)
        {
            if (results.size() > 0)
                return results;
        }
    }

    return {};
}

/*
void nb_hexdump_namespace(KittyMemoryMgr *kMgr, const ElfScanner &nbImplElf, int idx)
{
    int id = idx == 0 ? 1 : idx + 1;
    static constexpr uintptr_t ns_map_off = 0x8236C0;
    static constexpr uintptr_t ns_array_entry = 0x666580;
    static constexpr size_t ns_entry_size = 50816;

    static uintptr_t ns_map_addr = 0;
    if (!ns_map_addr)
        kMgr->readMem(nbImplElf.base() + ns_map_off, &ns_map_addr, sizeof(ns_map_addr));

    if (!ns_map_addr)
        return;

    std::string ns_name = kMgr->readMemStr(ns_map_addr + ns_array_entry + (id * ns_entry_size), 33);
    KITTY_LOGI("[%d] Name: %s", idx, ns_name.c_str());

    std::vector<char> buf(ns_entry_size, 0);
    kMgr->readMem(ns_map_addr + ns_array_entry + (id * ns_entry_size), buf.data(), buf.size());

    KITTY_LOGI("[%d] Hex: \n%s", id, KittyUtils::HexDump<32, true>(buf.data(), buf.size()).c_str());
}
*/
