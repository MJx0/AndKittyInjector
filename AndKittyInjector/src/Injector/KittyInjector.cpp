#include "KittyInjector.hpp"

// It's safer to use new mmap than using stack as remote before
#define kUSE_STACK_BUFFER 0
#define kREMOTE_BUFF_SIZE (KT_PAGE_SIZE)

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

std::string findMapPathEndsWith(int pid, const std::string &map)
{
    std::vector<ProcMap> memfd_maps = KittyMemoryEx::getMaps(pid, KittyMemoryEx::EProcMapFilter::EndWith, map);
    if (memfd_maps.empty())
    {
        memfd_maps = KittyMemoryEx::getMaps(pid, KittyMemoryEx::EProcMapFilter::EndWith, map + "]");
    }
    if (memfd_maps.empty())
    {
        memfd_maps = KittyMemoryEx::getMaps(pid, KittyMemoryEx::EProcMapFilter::EndWith, map + " (deleted)");
    }
    if (memfd_maps.empty())
    {
        memfd_maps = KittyMemoryEx::getMaps(pid, KittyMemoryEx::EProcMapFilter::EndWith, map + " (deleted)]");
    }
    return memfd_maps.empty() ? std::string() : memfd_maps[0].pathname;
}

bool KittyInjector::init(KittyMemoryMgr *kmgr, const inject_elf_config_t &cfg)
{
    if (!kmgr || !kmgr->isMemValid())
    {
        KITTY_LOGE("KittyInjector::init: KittyMemoryMgr is not initialized!.");
        return false;
    }

    _cfg = cfg;

    _kMgr = kmgr;
    _kMgr->trace.setAutoRestoreRegs(true);
    _kMgr->trace.setDefaultCaller(0);
    _kMgr->trace.setRemoteCallTimeout(_cfg.timeout);

    int sdk = KittyUtils::Android::getSDK();
    if (!(sdk > 0 && sdk < 24))
    {
        // libRs.so seem to cause issues in some devices specifically on Android 7
        std::vector<std::string> caller_libs = {"/libc.so", "/libnativebridge.so", "/libart.so"};
        for (auto &lib : caller_libs)
        {
            auto segs = _kMgr->elfScanner.findElf(lib.c_str(), EScanElfType::Native, EScanElfFilter::System).segments();
            for (auto &it : segs)
            {
                // non exec to receive SIGSEGV on return
                if (!it.executable)
                {
                    _dl_caller = it.startAddress;
                    KITTY_LOGI("KittyInjector::init: Native dl default caller set to %p from %s.",
                               (void *)_dl_caller,
                               it.toString().c_str());
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
        KITTY_LOGE("KittyInjector::init: Injector is %s but target app is %s!",
                   EMachineToStr(kInjectorEM).c_str(),
                   EMachineToStr(targetEM).c_str());
        KITTY_LOGE("KittyInjector::init: Please use %s version of the injector!", EMachineToStr(targetEM).c_str());
        return false;
    }

    if (!_kMgr->linkerScanner.init())
    {
        KITTY_LOGE("KittyInjector::init: Failed to initialize linker scanner!");
        return {};
    }

    if (!_rsyscall.init(_kMgr))
    {
        KITTY_LOGE("KittyInjector::init: Failed to initialize remote syscall!");
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
        KITTY_LOGE("KittyInjector::init: remote \"dlopen\" not found!");
        return false;
    }

    if (!_rdlclose)
    {
        KITTY_LOGE("KittyInjector::init: remote \"dlclose\" not found!");
        return false;
    }

    if (_cfg.memfd)
    {
        if (!canUseMemfd())
        {
            KITTY_LOGE("KittyInjector::init: --memfd is used but \"memfd_create\" syscall failed!");
            return false;
        }
        if (!_rdlopen_ext)
        {
            KITTY_LOGE("KittyInjector::init: --memfd is used but \"android_dlopen_ext\" not found!");
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
        KITTY_LOGE("KittyInjector::validateElf: %s not accessible. strerror=\"%s\".",
                   elfPath.c_str(),
                   libFile.lastStrError().c_str());
        return false;
    }

    libFile.pread(0, &libHdr, sizeof(libHdr));
    libFile.close();

    if (hdr)
        memcpy(hdr, &libHdr, sizeof(libHdr));

    if (memcmp(libHdr.e_ident, "\177ELF", 4) != 0)
    {
        KITTY_LOGE("KittyInjector::validateElf: %s is not a valid ELF!", elfPath.c_str());
        return false;
    }

    if (libHdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
    {
        KITTY_LOGE("KittyInjector::validateElf: %s is %dbit but Injector is %dbit!",
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
    std::vector<uintptr_t> bp_addrs;

    if (!_cfg.bp_args.empty())
    {
        std::string bp_binary = _cfg.bp_args[0];
        std::string bp_symbol = _cfg.bp_args[1];

        uintptr_t bp_addr = 0;
        auto elf = _kMgr->elfScanner.findElf(bp_binary);
        if (elf.isValid())
        {
            bp_addr = elf.findSymbol(bp_symbol);
            if (bp_addr == 0)
                bp_addr = elf.findDebugSymbol(bp_symbol);
        }

        if (bp_addr == 0)
        {
            KITTY_LOGI("KittyInjector::waitBreakpoint: Couldn't find the specified breakpoint target symbol!");
            return false;
        }
        bp_addrs.push_back(bp_addr);
    }
    else if (!needsNB)
    {
        // Break on both loadlibrary entry points and take whichever fires
        if (_rdlopen_ext)
            bp_addrs.push_back(_rdlopen_ext);
        if (_rdlopen && _rdlopen != _rdlopen_ext)
            bp_addrs.push_back(_rdlopen);
    }
    else
    {
        nbItf_data_t callbacks{};
        if (!findNativeBridgeData(&callbacks, nullptr))
            KITTY_LOGE("KittyInjector::waitBreakpoint: Couldn't find NativeBridge callbacks!");
        else
        {
            uintptr_t nb = callbacks.version < KT_NB_NAMESPACE_VERSION ? uintptr_t(callbacks.loadLibrary)
                                                                       : uintptr_t(callbacks.loadLibraryExt);
            if (nb)
                bp_addrs.push_back(nb);
        }
    }

    if (bp_addrs.empty())
    {
        KITTY_LOGI("KittyInjector::waitBreakpoint: Couldn't find a breakpoint target!");
        return false;
    }

    std::unordered_map<uintptr_t, int> hits;
    hits.reserve(bp_addrs.size());
    for (uintptr_t a : bp_addrs)
    {
        KITTY_LOGI("KittyInjector::waitBreakpoint: Creating breakpoint at %p...", (void *)a);
        hits[a] = 0;
    }

    auto dl_flags_to_string = [](int flags) -> std::string {
        std::string result;

        auto append = [&](const char *name) {
            if (!result.empty())
                result += '|';
            result += name;
        };

        if (flags & RTLD_LAZY)
            append("RTLD_LAZY");

        if (flags & RTLD_NOW)
            append("RTLD_NOW");

        if (flags & RTLD_GLOBAL)
            append("RTLD_GLOBAL");
        else
            append("RTLD_LOCAL");

#ifdef RTLD_NODELETE
        if (flags & RTLD_NODELETE)
            append("RTLD_NODELETE");
#endif

#ifdef RTLD_NOLOAD
        if (flags & RTLD_NOLOAD)
            append("RTLD_NOLOAD");
#endif

#ifdef RTLD_DEEPBIND
        if (flags & RTLD_DEEPBIND)
            append("RTLD_DEEPBIND");
#endif

        return result;
    };

    auto bp_ok = [&](uintptr_t bp_addr, user_regs_struct *regs) -> bool {
        hits[bp_addr]++;

        auto pc_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), regs->KT_REG_PC);
        KITTY_LOGI("KittyInjector::waitBreakpoint] Hit[addr=%p|num=%d]: PC(%p) -> %s",
                   (void *)bp_addr,
                   hits[bp_addr],
                   (void *)regs->KT_REG_PC,
                   pc_map.toString().c_str());

        uintptr_t ret_addr = _kMgr->trace.getReturnAddressFromRegs(regs);
        auto ret_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), ret_addr);
        KITTY_LOGI("KittyInjector::waitBreakpoint] Hit[addr=%p|num=%d]: Return Address (%p) -> %s",
                   (void *)bp_addr,
                   hits[bp_addr],
                   (void *)ret_addr,
                   ret_map.toString().c_str());

        // --bp-dl
        if (_cfg.bp_args.empty())
        {
            uintptr_t arg0 = _kMgr->trace.getArgFromRegs<uintptr_t>(regs, 0);
            uintptr_t arg1 = _kMgr->trace.getArgFromRegs<uintptr_t>(regs, 1);

            std::string filePath = _kMgr->readMemStr(arg0, 0xff);
            int flags = arg1;

            KITTY_LOGI("KittyInjector::waitBreakpoint] Hit[addr=%p|num=%d]: dlopen(%s, %s)",
                       (void *)bp_addr,
                       hits[bp_addr],
                       filePath.c_str(),
                       dl_flags_to_string(flags).c_str());
        }

        return true;
    };

    KITTY_LOGI("KittyInjector::waitBreakpoint: Waiting on hardware breakpoint(s)...");
    return _kMgr->trace.setHardExecBreakpointsAndWait(
               bp_addrs,
               [&](uintptr_t bp_addr, user_regs_struct bp_regs) -> bool { return bp_ok(bp_addr, &bp_regs); },
               5000) == KT_BP_SUCCESS;
}

bool KittyInjector::waitNbInit()
{
    nbItf_data_t callbacks{};
    uintptr_t state_ptr = 0;
    if (!findNativeBridgeData(&callbacks, &state_ptr))
    {
        KITTY_LOGE("KittyInjector::waitNbInit: Couldn't find NativeBridge data!");
        return false;
    }

    auto nb_state_tostr = [](int state) -> std::string {
        switch (state)
        {
        case 0:
            return "NotSetup";
        case 1:
            return "Opened";
        case 2:
            return "PreInitialized";
        case 3:
            return "Initialized";
        case 4:
            return "Closed";
        default:
            return "Unknown";
        }
    };

    KITTY_LOGI("KittyInjector::waitNbInit: Detected NativeBrdge version %d", callbacks.version);

    int nb_state = 0;
    _kMgr->readMem(state_ptr, &nb_state, sizeof(nb_state));
    KITTY_LOGI("KittyInjector::waitNbInit: Current NativeBridgeState <%s>.", nb_state_tostr(nb_state).c_str());

    if (nb_state == 3)
        return true;

    KITTY_LOGW("KittyInjector::waitNbInit: NativeBridgeState has to be <Initialized> before injecting!");

    if (callbacks.version < 3)
    {
        KITTY_LOGI("KittyInjector::waitNbInit: Creating write watchpoint at %p...", (void *)state_ptr);
        KITTY_LOGI("KittyInjector::waitNbInit: Waiting on hardware watchpoint...");

        int hits = 0;
        auto bp_ok = [&](uintptr_t bp_addr, user_regs_struct *regs) -> bool {
            hits++;

            auto pc_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), regs->KT_REG_PC);
            KITTY_LOGI("KittyInjector::waitNbInit] Hit[addr=%p|num=%d]: PC(%p) -> %s",
                       (void *)bp_addr,
                       hits,
                       (void *)regs->KT_REG_PC,
                       pc_map.toString().c_str());

            _kMgr->readMem(state_ptr, &nb_state, sizeof(nb_state));
            KITTY_LOGI("KittyInjector::waitNbInit] Hit[addr=%p|num=%d]: Current NativeBridgeState <%s>.",
                       (void *)bp_addr,
                       hits,
                       nb_state_tostr(nb_state).c_str());

            return nb_state == 3;
        };

        return _kMgr->trace.setHardBreakpointAndWait(
                   state_ptr,
                   KT_HW_BP_WRITE,
                   KT_HW_BP_SIZE_4,
                   0,
                   [&](uintptr_t bp_addr, user_regs_struct regs) -> bool { return bp_ok(bp_addr, &regs); },
                   5000) == KT_BP_SUCCESS;
    }

    // breakpoint on createNamespace or loadLibraryExt to make sure at least default namespace is initialized
    // and it's safe to call loadLibraryExt at this point
    std::vector<uintptr_t> bp_addrs;
    if (callbacks.createNamespace)
        bp_addrs.push_back(uintptr_t(callbacks.createNamespace));
    if (callbacks.loadLibraryExt)
        bp_addrs.push_back(uintptr_t(callbacks.loadLibraryExt));

    std::unordered_map<uintptr_t, int> hits;
    hits.reserve(bp_addrs.size());
    for (uintptr_t a : bp_addrs)
    {
        KITTY_LOGI("KittyInjector::waitBreakpoint: Creating breakpoint at %p...", (void *)a);
        hits[a] = 0;
    }

    auto bp_ok = [&](uintptr_t bp_addr, user_regs_struct *regs) -> bool {
        hits[bp_addr]++;

        auto pc_map = KittyMemoryEx::getAddressMap(_kMgr->processID(), regs->KT_REG_PC);
        KITTY_LOGI("KittyInjector::waitNbInit] Hit[addr=%p|num=%d]: PC(%p) -> %s",
                   (void *)bp_addr,
                   hits[bp_addr],
                   (void *)regs->KT_REG_PC,
                   pc_map.toString().c_str());

        _kMgr->readMem(state_ptr, &nb_state, sizeof(nb_state));
        KITTY_LOGI("KittyInjector::waitNbInit] Hit[addr=%p|num=%d]: Current NativeBridgeState <%s>.",
                   (void *)bp_addr,
                   hits[bp_addr],
                   nb_state_tostr(nb_state).c_str());

        return nb_state == 3;
    };

    KITTY_LOGI("KittyInjector::waitNbInit: Waiting on hardware breakpoint(s)...");
    return _kMgr->trace.setHardExecBreakpointsAndWait(
               bp_addrs,
               [&](uintptr_t bp_addr, user_regs_struct bp_regs) -> bool { return bp_ok(bp_addr, &bp_regs); },
               5000) == KT_BP_SUCCESS;
}

inject_elf_info_t KittyInjector::inject(const std::string &elfPath)
{
    if (!_kMgr || !_kMgr->isMemValid())
    {
        KITTY_LOGE("KittyInjector::inject: Not initialized!");
        return {};
    }

    if (!_kMgr->trace.isAttached())
    {
        KITTY_LOGE("KittyInjector::inject: Not attached to target process!");
        return {};
    }

    if (!_rdlopen)
    {
        KITTY_LOGE("KittyInjector::inject: Remote dlopen not found!");
        return {};
    }

    KT_ElfW(Ehdr) libHdr = {};
    bool emulate = false;
    if (!validateElf(elfPath, &libHdr, &emulate))
    {
        KITTY_LOGI("KittyInjector::inject: Failed to validate %s!", elfPath.c_str());
        return {};
    }

    if (emulate)
    {
#if defined(__arm__) || defined(__aarch64__)
        KITTY_LOGE("KittyInjector::inject: Emulation only available in x86 and x86_64.");
        return {};
#else
        // x86_64 emulates arm64, x86 emulates arm
        if (_kMgr->elfScanner.getProgramElf().header().e_machine == EM_X86_64 && libHdr.e_machine != EM_AARCH64)
        {
            KITTY_LOGE("KittyInjector::inject: x86_64 should emulate arm64 not %s.",
                       EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }
        else if (_kMgr->elfScanner.getProgramElf().header().e_machine == EM_386 && libHdr.e_machine != EM_ARM)
        {
            KITTY_LOGE("KittyInjector::inject: x86 should emulate arm not %s.",
                       EMachineToStr(libHdr.e_machine).c_str());
            return {};
        }
#endif
    }

    KittyIOFile libFile(elfPath, O_RDONLY | O_CLOEXEC);
    if (!libFile.open())
    {
        KITTY_LOGE("KittyInjector::inject: Library path not accessible. strerror=\"%s\".",
                   libFile.lastStrError().c_str());
        return {};
    }

    user_regs_struct backup_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));

    if (!_kMgr->trace.getRegs(&backup_regs))
    {
        KITTY_LOGE("KittyInjector::inject: Failed to backup registers.");
        return {};
    }

    auto cleanUp = [this, &backup_regs]() -> bool {
#if kUSE_STACK_BUFFER
        if (_rbuffer && !_backup_rbuffer.empty())
        {
            const size_t nwritten = _kMgr->writeMem(_rbuffer, _backup_rbuffer.data(), _backup_rbuffer.size());

            if (nwritten != _backup_rbuffer.size())
            {
                KITTY_LOGW("KittyInjector::inject: Failed to restore stack buffer "
                           "(written=%zu expected=%zu).",
                           nwritten,
                           _backup_rbuffer.size());
            }
        }

        _backup_rbuffer.clear();

#else
        if (_rbuffer)
        {
            if (_rsyscall.rmunmap(_rbuffer, kREMOTE_BUFF_SIZE))
            {
                KITTY_LOGI("KittyInjector::inject: Unmapped remote buffer successfully.");
            }
            else
            {
                KITTY_LOGW("KittyInjector::inject: Failed to unmap remote buffer, strerror=\"%s\".",
                           _rsyscall.lastError().c_str());
            }

            _rbuffer = 0;
        }
#endif

        if (!_kMgr->trace.setRegs(&backup_regs))
        {
            KITTY_LOGE("KittyInjector::inject: Failed to restore registers.");
            return false;
        }

        return true;
    };

    // test to clear remote syscall
    if (!_rsyscall.testSyscall())
    {
        cleanUp();
        KITTY_LOGE("KittyInjector::inject: Remote syscall test failed. errno(\"%s\").", _rsyscall.lastError().c_str());
        return {};
    }

    // remote buffer
    {
#if kUSE_STACK_BUFFER

        const uintptr_t backup_sp = backup_regs.KT_REG_SP;

        backup_regs.KT_REG_SP = KT_PAGE_START(backup_sp);

        if (!_kMgr->trace.setRegs(&backup_regs))
        {
            cleanUp();
            KITTY_LOGE("Failed to set temporary stack pointer.");
            return {};
        }

        _rbuffer = backup_regs.KT_REG_SP;

        backup_regs.KT_REG_SP = backup_sp;

        std::vector<uint8_t> temp_buffer(kREMOTE_BUFF_SIZE);

        const size_t nread = _kMgr->readMem(_rbuffer, temp_buffer.data(), temp_buffer.size());

        if (nread != temp_buffer.size())
        {
            cleanUp();
            KITTY_LOGE("KittyInjector::inject: Failed to backup stack buffer "
                       "(read=%zu expected=%zu).",
                       nread,
                       temp_buffer.size());
            return {};
        }

        _backup_rbuffer = std::move(temp_buffer);

        std::vector<uint8_t> zero_buffer(kREMOTE_BUFF_SIZE, 0);

        const size_t nwritten = _kMgr->writeMem(_rbuffer, zero_buffer.data(), zero_buffer.size());

        if (nwritten != zero_buffer.size())
        {
            cleanUp();
            KITTY_LOGE("KittyInjector::inject: Failed to clear remote stack buffer "
                       "(written=%zu expected=%zu).",
                       nwritten,
                       zero_buffer.size());
            return {};
        }

#else
        _rbuffer = _rsyscall.rmmap(0, kREMOTE_BUFF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (!_rbuffer)
        {
            KITTY_LOGE("KittyInjector::inject: Failed to allocate remote buffer.");
            return {};
        }
#endif

        KITTY_LOGI("KittyInjector::inject: Established remote buffer at %p.", (void *)_rbuffer);
    }


    inject_elf_info_t injected{};
    bool bCalldlerror = false;

    if (!emulate)
    {
        KITTY_LOGI("KittyInjector::inject: Using nativeInject...");
        injected = nativeInject(libFile, &bCalldlerror);
    }
    else
    {
        KITTY_LOGI("KittyInjector::inject: Using emuInject...");
        injected = emuInject(libFile, &bCalldlerror);
    }

    KITTY_LOGI("KittyInjector::inject: Library Handle -> %p.", (void *)injected.dl_handle);
    KITTY_LOGI("KittyInjector::inject: Library Base -> %p.", (void *)injected.elf.base());
    for (size_t i = 0; i < injected.elf.segments().size(); i++)
    {
        auto segs = injected.elf.segments();
        KITTY_LOGI("KittyInjector::inject: Library Segment[%d] -> %s", int(i), segs[i].toString().c_str());
    }

    if (injected.is_valid())
    {
        if (injected.pJNI_OnLoad)
        {
            KITTY_LOGI("KittyInjector::inject: Getting JavaVM...");
            injected.pJvm = getJavaVM(injected);
            KITTY_LOGI("KittyInjector::inject: JavaVM -> %p.", (void *)(injected.pJvm));
        }

        if (_cfg.hide)
        {
            if (_cfg.free)
            {
                KITTY_LOGW("KittyInjector::inject: Skipping --hide because --free is enabled!");
            }
            else
            {
                // Injector only stops main thread
                {
                    // kill(_kMgr->processID(), SIGSTOP);
                    {
                        injected.is_hidden = hideLibrary(injected);
                    }
                    // kill(_kMgr->processID(), SIGCONT);
                }

                if (!injected.is_hidden)
                {
                    KITTY_LOGE("KittyInjector::inject: Failed to hide %s!", injected.elf.filePath().c_str());
                    KITTY_LOGI("KittyInjector::inject: Unloading %s...", injected.elf.filePath().c_str());
                    if (unloadLibrary(injected))
                        KITTY_LOGI("KittyInjector::inject: Library unloaded successfully.");
                    else
                        KITTY_LOGW("KittyInjector::inject: Failed to unload library!");

                    cleanUp();
                    return {};
                }
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
                KITTY_LOGW("KittyInjector::inject: Couldn't find JNI_OnLoad symbol.");
            else if (!injected.pJvm)
                KITTY_LOGW("KittyInjector::inject: Couldn't find JavaVM.");

            KITTY_LOGW("KittyInjector::inject: Skipping EntryPoint");
        }

        if (_cfg.afterEntryPoint)
            _cfg.afterEntryPoint(injected);

        if (_cfg.free)
        {
            KITTY_LOGI("KittyInjector::inject: --free is used, Unloading library...");
            if (unloadLibrary(injected))
            {
                KITTY_LOGI("KittyInjector::inject: Library unloaded successfully.");
            }
            else
            {
                KITTY_LOGE("KittyInjector::inject: Failed to unload library!");
                cleanUp();
                return {};
            }
        }
    }
    else if (bCalldlerror)
    {
        KITTY_LOGE("KittyInjector::inject: dlopen failed )':");
        KITTY_LOGI("KittyInjector::inject: Calling dlerror...");

        kitty_rp_call_t error_ret;

        if (!(emulate && _kMgr->nbScanner.nbItfData().version < KT_NB_NAMESPACE_VERSION))
        {
            if (!emulate)
            {
                error_ret = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlerror);
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
                    KITTY_LOGE("KittyInjector::inject: %s", error_str.c_str());

                    if (_cfg.memfd && KittyUtils::String::contains(error_str, "library", false) &&
                        KittyUtils::String::contains(error_str, "not found", false))
                    {
                        KITTY_LOGE("KittyInjector::inject: Memfd dlopen might not be supported.");
                    }

                    else if (!_cfg.memfd && KittyUtils::String::contains(error_str, "couldn't map", false) &&
                             KittyUtils::String::contains(error_str, "Permission denied", false))
                    {
                        KITTY_LOGE("KittyInjector::inject: Maybe use memfd or disable SELinux.");
                    }
                }
                else
                {
                    KITTY_LOGE("KittyInjector::inject: Failed to read dlerror string.");
                }
            }
            else if (error_ret.status != KT_RP_CALL_SUCCESS)
            {
                KITTY_LOGE("KittyInjector::inject: Failed to call dlerror.");
            }
            else if (error_ret.result.ptr == 0)
            {
                KITTY_LOGE("KittyInjector::inject: dlerror returned 0.");
            }
        }
        else
        {
            KITTY_LOGW("KittyInjector::inject: dlerror not available.");
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
            KITTY_LOGE("KittyInjector::nativeInject: Failed to write library path into stack!");
            return;
        }

        auto ret = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlopen, _rbuffer, _cfg.rtdl_flags);
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("KittyInjector::nativeInject: Failed to call dlopen.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            std::string lib_to_find = findMapPathEndsWith(_kMgr->processID(), elfFile.path());
            if (!lib_to_find.empty())
            {
                info.soinfo = _kMgr->linkerScanner.findSoInfo(lib_to_find);
                info.elf = _kMgr->elfScanner.findElf(lib_to_find, EScanElfType::Native);
                if (!info.elf.isValid())
                {
                    info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
                }
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    auto cleanup_memfd = [&](int fd) -> void {
        KITTY_LOGI("KittyInjector::nativeInject: Closing memfd file (%d)...", fd);

        if (_rsyscall.rclose(fd))
        {
            KITTY_LOGI("KittyInjector::nativeInject: Closed memfd file successfully.");
        }
        else
        {
            KITTY_LOGW("KittyInjector::nativeInject: Failed to close memfd file (%d), errno (\"%s\").",
                       fd,
                       _rsyscall.lastError().c_str());
        }
    };

    auto do_memfd_dlopen = [&]() -> void {
        std::string memfd_name = !_cfg.memfd_name.empty() ? _cfg.memfd_name
                                                          : KittyUtils::randomString(KittyUtils::randInt(5, 12));
        KITTY_LOGI("KittyInjector::nativeInject: memfd Name (\"%s\").", memfd_name.c_str());

        if (!_kMgr->writeMemStr(_rbuffer, memfd_name))
        {
            KITTY_LOGE("KittyInjector::nativeInject: Failed to write memfd name into stack!");
            return;
        }

        int rmemfd = _rsyscall.rmemfd_create(_rbuffer, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("KittyInjector::nativeInject: memfd_create failed, errno (\"%s\").",
                       _rsyscall.lastError().c_str());
            return;
        }

        std::string rmemfdPath = KittyUtils::String::fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
        {
            KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
            if (!rmemfdFile.open())
            {
                KITTY_LOGE("KittyInjector::nativeInject: Failed to open remote memfd file, strerror=\"%s\".",
                           rmemfdFile.lastStrError().c_str());
                cleanup_memfd(rmemfd);
                return;
            }

            elfFile.copyToFd(rmemfdFile.fd());
        }

        // restrict further modifications to remote memfd
        _rsyscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

        android_dlextinfo extinfo = {};
        extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        extinfo.library_fd = rmemfd;

        uintptr_t rdlextinfo = KT_ALIGN_UP(_rbuffer + memfd_name.size() + 1, sizeof(uintptr_t));
        if (!_kMgr->writeMem(rdlextinfo, &extinfo, sizeof(extinfo)))
        {
            KITTY_LOGE("KittyInjector::nativeInject: Failed to write dlextinfo into stack!");
            cleanup_memfd(rmemfd);
            return;
        }

        auto oldSoInfos = _kMgr->linkerScanner.allSoInfo();
        {
            auto ret = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlopen_ext, _rbuffer, _cfg.rtdl_flags, rdlextinfo);

            cleanup_memfd(rmemfd);

            if (ret.status != KT_RP_CALL_SUCCESS)
            {
                KITTY_LOGE("KittyInjector::nativeInject: Failed to call dlopen_ext.");
                return;
            }
            info.dl_handle = ret.result.ptr;
        }
        auto newSoInfos = _kMgr->linkerScanner.allSoInfo();

        if (info.dl_handle != 0)
        {
            std::string memfd_to_find = findMapPathEndsWith(_kMgr->processID(), "/memfd:" + memfd_name);
            if (!memfd_to_find.empty())
            {
                for (auto &new_so : newSoInfos)
                {
                    if (new_so.realpath == memfd_to_find)
                    {
                        bool is_old = false;
                        for (auto &old_so : oldSoInfos)
                        {
                            if (old_so.base == new_so.base)
                            {
                                is_old = true;
                                break;
                            }
                        }

                        if (!is_old)
                        {
                            info.soinfo = new_so;
                            break;
                        }
                    }
                }

                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
                if (!info.elf.isValid())
                {
                    info.elf = _kMgr->elfScanner.findElf(memfd_to_find, EScanElfType::Native);
                }
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
    nbItf_data_t nbData = nb.nbItfData();

    if ((nbData.version < KT_NB_NAMESPACE_VERSION && !nbData.loadLibrary) ||
        (nbData.version >= KT_NB_NAMESPACE_VERSION && !nbData.loadLibraryExt))
    {
        findNativeBridgeData(&nbData, nullptr);
    }

    if (!nbData.loadLibrary && !nbData.loadLibraryExt)
    {
        KITTY_LOGE("KittyInjector::emuInject: NativeBridge callbacks data is not valid!");
        return {};
    }

    KITTY_LOGI("KittyInjector::emuInject: NativeBridge version %d.", nbData.version);

    uintptr_t pNbInitialized = uintptr_t(nb.fnNativeBridgeInitialized);
    if (pNbInitialized == 0 || _kMgr->trace.callFunction(pNbInitialized).result.val == 0)
    {
        KITTY_LOGE("KittyInjector::emuInject: NativeBridge is not initialized yet, maybe use --bp-ld/sym or --delay.");
        return {};
    }

    // returns dl handle on success
    auto emu_dlopen = [&](const std::string &path) -> kitty_rp_call_t {
        if (nbData.version < KT_NB_NAMESPACE_VERSION)
        {
            if (!_kMgr->writeMemStr(_rbuffer, path))
            {
                KITTY_LOGE("KittyInjector::emuInject: Failed to write library path into stack!");
                return {KT_RP_CALL_MEM_FAILED, {0}};
            }
            return _kMgr->trace.callFunction((uintptr_t)nbData.loadLibrary, _rbuffer, _cfg.rtdl_flags);
        }

        uintptr_t ns = 0x1;
        std::string ns_name = "default";
        std::string ns_names[] = {"default", "classloader-namespace", "classloader-namespace-shared"};

        if (nbData.getExportedNamespace)
        {
            for (auto &nm : ns_names)
            {
                if (!_kMgr->writeMemStr(_rbuffer, nm))
                {
                    KITTY_LOGE("KittyInjector::emuInject: Failed to write classloader <%s> into stack!", nm.c_str());
                    return {KT_RP_CALL_MEM_FAILED, {0}};
                }

                auto cls_ns = _kMgr->trace.callFunction((uintptr_t)nbData.getExportedNamespace, _rbuffer);
                if (cls_ns.status != KT_RP_CALL_SUCCESS)
                {
                    KITTY_LOGE("KittyInjector::emuInject: Failed to call getExportedNamespace.");
                    return cls_ns;
                }

                if (cls_ns.result.ptr)
                {
                    ns = cls_ns.result.ptr;
                    ns_name = nm;
                    break;
                }
            }
        }
        else if (nbData.getVendorNamespace)
        {
            auto cls_ns = _kMgr->trace.callFunction((uintptr_t)nbData.getVendorNamespace);
            if (cls_ns.status != KT_RP_CALL_SUCCESS)
            {
                KITTY_LOGE("KittyInjector::emuInject: Failed to call getVendorNamespace.");
                return cls_ns;
            }

            ns = cls_ns.result.ptr;
            ns_name = "vendor";
        }

        KITTY_LOGI("KittyInjector::emuInject: Using NativeBridge namespace <%s> -> %p.", ns_name.c_str(), (void *)ns);

        if (!_kMgr->writeMemStr(_rbuffer, path))
        {
            KITTY_LOGE("KittyInjector::emuInject: Failed to write library path into stack!");
            return {KT_RP_CALL_MEM_FAILED, {0}};
        }

        return _kMgr->trace.callFunction((uintptr_t)nbData.loadLibraryExt, _rbuffer, _cfg.rtdl_flags, ns);
    };

    inject_elf_info_t info{};
    info.is_native = false;

    auto do_legacy_dlopen = [&]() -> void {
        auto ret = emu_dlopen(elfFile.path());
        if (ret.status != KT_RP_CALL_SUCCESS)
        {
            KITTY_LOGE("KittyInjector::emuInject: Failed to call native bridge loadLibary.");
            return;
        }

        info.dl_handle = ret.result.ptr;
        if (info.dl_handle != 0)
        {
            // init nb scanner after emu dlopen
            _kMgr->nbScanner.init();

            std::string lib_to_find = findMapPathEndsWith(_kMgr->processID(), elfFile.path());
            if (!lib_to_find.empty())
            {
                info.soinfo = _kMgr->nbScanner.findSoInfo(lib_to_find);
                info.elf = _kMgr->elfScanner.findElf(lib_to_find, EScanElfType::Emulated);
                if (!info.elf.isValid())
                {
                    info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
                }
            }
        }

        if (!info.elf.isValid() && bCalldlerror)
        {
            *bCalldlerror = true;
        }
    };

    auto cleanup_memfd = [&](int fd) -> void {
        KITTY_LOGI("KittyInjector::emuInject: Closing memfd file (%d)...", fd);

        if (_rsyscall.rclose(fd))
        {
            KITTY_LOGI("KittyInjector::emuInject: Closed memfd file successfully.");
        }
        else
        {
            KITTY_LOGW("KittyInjector::emuInject: Failed to close memfd file (%d), errno (\"%s\").",
                       fd,
                       _rsyscall.lastError().c_str());
        }
    };

    auto do_memfd_dlopen = [&]() -> void {
        std::string memfd_name = !_cfg.memfd_name.empty() ? _cfg.memfd_name
                                                          : KittyUtils::randomString(KittyUtils::randInt(5, 12));
        KITTY_LOGI("KittyInjector::emuInject: Memfd Name (\"%s\").", memfd_name.c_str());

        if (!_kMgr->writeMemStr(_rbuffer, memfd_name))
        {
            KITTY_LOGE("KittyInjector::emuInject: Failed to write memfd name into stack!");
            return;
        }

        int rmemfd = _rsyscall.rmemfd_create(_rbuffer, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (rmemfd <= 0)
        {
            KITTY_LOGE("KittyInjector::emuInject: memfd_create failed, errno = \"%s\".", _rsyscall.lastError().c_str());
            return;
        }

        std::string rmemfdPath = KittyUtils::String::fmt("/proc/%d/fd/%d", _kMgr->processID(), rmemfd);
        {
            KittyIOFile rmemfdFile(rmemfdPath, O_RDWR);
            if (!rmemfdFile.open())
            {
                KITTY_LOGE("KittyInjector::emuInject: Failed to open remote memfd file, strerror=\"%s\".",
                           rmemfdFile.lastStrError().c_str());
                cleanup_memfd(rmemfd);
                return;
            }

            elfFile.copyToFd(rmemfdFile.fd());
        }

        // restrict further modifications to remote memfd
        _rsyscall.rmemfd_seal(rmemfd, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);

        auto oldSoInfos = _kMgr->nbScanner.allSoInfo();
        {
            auto ret = emu_dlopen(rmemfdPath);

            cleanup_memfd(rmemfd);

            if (ret.status != KT_RP_CALL_SUCCESS)
            {
                KITTY_LOGE("KittyInjector::emuInject: Failed to call native bridge loadLibary.");
                return;
            }

            info.dl_handle = ret.result.ptr;
        }
        auto newSoInfos = _kMgr->nbScanner.allSoInfo();

        if (info.dl_handle != 0)
        {
            std::string memfd_to_find = findMapPathEndsWith(_kMgr->processID(), "/memfd:" + memfd_name);
            if (!memfd_to_find.empty())
            {
                for (auto &new_so : newSoInfos)
                {
                    if (new_so.realpath == memfd_to_find)
                    {
                        bool is_old = false;
                        for (auto &old_so : oldSoInfos)
                        {
                            if (old_so.base == new_so.base)
                            {
                                is_old = true;
                                break;
                            }
                        }

                        if (!is_old)
                        {
                            info.soinfo = new_so;
                            break;
                        }
                    }
                }

                info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
                if (!info.elf.isValid())
                {
                    info.elf = _kMgr->elfScanner.findElf(memfd_to_find, EScanElfType::Emulated);
                }
            }
        }

        if (info.dl_handle != 0)
        {
            // init nb scanner after emu dlopen
            _kMgr->nbScanner.init();

            auto memfd_maps = KittyMemoryEx::getMaps(_kMgr->processID(),
                                                     KittyMemoryEx::EProcMapFilter::Contains,
                                                     "/memfd:" + memfd_name);
            if (!memfd_maps.empty())
            {
                std::string memfd_to_find = memfd_maps[0].pathname;

                info.soinfo = _kMgr->nbScanner.findSoInfo(memfd_to_find);
                info.elf = _kMgr->elfScanner.findElf(memfd_name, EScanElfType::Emulated);
                if (!info.elf.isValid())
                {
                    info.elf = _kMgr->elfScanner.createWithSoInfo(info.soinfo);
                }
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
            KITTY_LOGE("KittyInjector::emuInject: Failed to write \"JNI_OnLoad\"into stack!");
            return info;
        }

        if (!nbData.getTrampoline && !nbData.getTrampolineWithJNICallType)
        {
            KITTY_LOGE("KittyInjector::emuInject: getTrampoline is NULL, Won't be able to find and call JNI_OnLoad!");
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
    {
        KITTY_LOGE("KittyInjector::unloadLibrary: Invalid injected info!");
        return false;
    }

    kitty_rp_call_t freed;

    if (injected.is_native)
    {
        freed = _kMgr->trace.callFunctionFrom(_dl_caller, _rdlclose, injected.dl_handle);
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
        KITTY_LOGE("KittyInjector::hideLibrary: \'soinfo\' pointer not found!");
        return false;
    }

    if (injected.is_native)
    {
        KITTY_LOGI("KittyInjector::hideLibrary: Removing soinfo %p...", (void *)(injected.soinfo.ptr));

        // uintptr_t removesoinfo = _kMgr->linkerScanner.findDebugSymbol("_dl__Z20solist_remove_soinfoP6soinfo");
        // _kMgr->trace.callFunction(removesoinfo, injected.soinfo.ptr);

        auto solist = _kMgr->linkerScanner.allSoInfo();
        if (solist.empty())
        {
            KITTY_LOGE("KittyInjector::hideLibrary: Linker solist is empty, Failed to detect!");
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
            KITTY_LOGE("KittyInjector::hideLibrary: Failed to find linker prev soinfo!");
            return false;
        }

        uintptr_t si_next_offset = _kMgr->linkerScanner.soinfo_offsets().next;
        if (si_next_offset == kitty_soinfo_offsets_t::noff)
        {
            KITTY_LOGE("KittyInjector::hideLibrary: Failed to find linker soinfo next offset!");
            return false;
        }

        if (!_kMgr->memPatch
                 .createWithBytes(prev.ptr + si_next_offset, &injected.soinfo.next, sizeof(injected.soinfo.next))
                 .Modify())
        {
            KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch linker prev soinfo next!");
            return false;
        }

        KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed soinfo %p from solist.",
                   (void *)(injected.soinfo.ptr));

        if (_kMgr->linkerScanner.sonext() == injected.soinfo.ptr)
        {
            if (!_kMgr->memPatch
                     .createWithBytes(_kMgr->linkerScanner.linker_offsets().sonext, &prev.ptr, sizeof(prev.ptr))
                     .Modify())
            {
                KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch linker sonext!");
                return false;
            }

            KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed soinfo %p from sonext.",
                       (void *)(injected.soinfo.ptr));
        }
    }
    else
    {
        KITTY_LOGI("KittyInjector::hideLibrary: Removing emulated soinfo %p...", (void *)(injected.soinfo.ptr));

        // emulated linker for google emulators
#ifdef __LP64__
        LinkerScannerMgr emulinker = LinkerScannerMgr(_kMgr->memOp(),
                                                      _kMgr->elfScanner.findElf("/linker64",
                                                                                EScanElfType::Emulated,
                                                                                EScanElfFilter::System));
#else
        LinkerScannerMgr emulinker = LinkerScannerMgr(_kMgr->memOp(),
                                                      _kMgr->elfScanner.findElf("/linker",
                                                                                EScanElfType::Emulated,
                                                                                EScanElfFilter::System));
#endif

        bool isEmuLinker = emulinker.init();

        auto solist = isEmuLinker ? emulinker.allSoInfo() : _kMgr->nbScanner.allSoInfo();
        if (solist.empty())
        {
            KITTY_LOGE("KittyInjector::hideLibrary: Emulated solist is empty!");
            return false;
        }

        if (isEmuLinker)
        {
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
                KITTY_LOGE("KittyInjector::hideLibrary: Failed to find emulated linker prev soinfo!");
                return false;
            }

            uintptr_t si_next_offset = emulinker.soinfo_offsets().next;
            if (si_next_offset == kitty_soinfo_offsets_t::noff)
            {
                KITTY_LOGE("KittyInjector::hideLibrary: Failed to find emulated linker soinfo next offset!");
                return false;
            }

            if (!_kMgr->memPatch
                     .createWithBytes(prev.ptr + si_next_offset, &injected.soinfo.next, sizeof(injected.soinfo.next))
                     .Modify())
            {
                KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch emulated linker prev soinfo next!");
                return false;
            }

            KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed emulated soinfo %p from solist.",
                       (void *)(injected.soinfo.ptr));

            if (emulinker.sonext() == injected.soinfo.ptr)
            {
                if (!_kMgr->memPatch.createWithBytes(emulinker.linker_offsets().sonext, &prev.ptr, sizeof(prev.ptr))
                         .Modify())
                {
                    KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch emulated linker sonext!");
                    return false;
                }

                KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed emulated soinfo %p from sonext.",
                           (void *)(injected.soinfo.ptr));
            }
        }
        else
        {
            kitty_soinfo_t prev = {};
            if (solist[0].ptr != injected.soinfo.ptr)
            {
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
                    KITTY_LOGE("KittyInjector::hideLibrary: Failed to find emulated prev soinfo!");
                    return false;
                }
            }

            // solist patch
            {
                if (solist[0].ptr != injected.soinfo.ptr)
                {
                    uintptr_t si_next_offset = _kMgr->nbScanner.soinfo_offsets().next;
                    if (si_next_offset == kitty_soinfo_offsets_t::noff)
                    {
                        KITTY_LOGE("KittyInjector::hideLibrary: Failed to find emulated soinfo next offset!");
                        return false;
                    }

                    if (!_kMgr->memPatch
                             .createWithBytes(prev.ptr + si_next_offset,
                                              &injected.soinfo.next,
                                              sizeof(injected.soinfo.next))
                             .Modify())
                    {
                        KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch emulated prev soinfo next!");
                        return false;
                    }

                    KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed soinfo %p from emulated solist.",
                               (void *)(injected.soinfo.ptr));
                }
            }

            // soinfo refs patch
            {
                uintptr_t soinfo_replace_ptr = solist[0].ptr != injected.soinfo.ptr ? prev.ptr : injected.soinfo.next;

                if (solist.back().ptr == injected.soinfo.ptr)
                {
                    KITTY_LOGI("KittyInjector::hideLibrary: Injected emulated soinfo is sonext.");
                }

                // Houdini find sonext refs in .bss
                std::vector<uintptr_t> soinfo_refs;
                for (auto &it : _kMgr->nbScanner.nbImplElf().segments())
                {
                    if (it.is_rw)
                    {
                        soinfo_refs = _kMgr->memScanner.findDataAll(it.startAddress,
                                                                    it.endAddress,
                                                                    &injected.soinfo.ptr,
                                                                    sizeof(injected.soinfo.ptr));
                        if (soinfo_refs.size() > 0)
                        {
                            KITTY_LOGI("KittyInjector::hideLibrary: Found (%d) emulated soinfo refs at %s",
                                       int(soinfo_refs.size()),
                                       it.toString().c_str());
                            break;
                        }
                    }
                }

                std::unordered_map<uintptr_t, std::vector<uintptr_t>> soinfo_refs_map;
                if (soinfo_refs.empty())
                {
                    auto maps = KittyMemoryEx::getAllMaps(_kMgr->processID());
                    for (auto &it : maps)
                    {
                        if (!it.readable || it.executable || !it.is_private)
                            continue;

                        bool check1 = (KittyUtils::String::startsWith(it.pathname, "[anon:Mem_"));
                        bool check2 = (it.pathname == "[anon:linker_alloc]");
                        if (!check1 && !check2)
                            continue;

                        auto results = _kMgr->memScanner.findDataAll(it.startAddress,
                                                                     it.endAddress,
                                                                     &injected.soinfo.ptr,
                                                                     sizeof(injected.soinfo.ptr));
                        if (results.size() > 0 && results.size() <= 5)
                        {
                            soinfo_refs_map[it.startAddress] = results;
                        }
                    }

                    // check if other soinfo refs exist in found maps
                    for (auto &map : maps)
                    {
                        if (soinfo_refs_map.count(map.startAddress) > 0)
                        {
                            for (auto &so : solist)
                            {
                                if (so.ptr != injected.soinfo.ptr)
                                {
                                    auto results = _kMgr->memScanner.findDataAll(map.startAddress,
                                                                                 map.endAddress,
                                                                                 &so.ptr,
                                                                                 sizeof(so.ptr));
                                    if (results.size() > 0)
                                    {
                                        auto &refs = soinfo_refs_map[map.startAddress];
                                        soinfo_refs.insert(soinfo_refs.end(), refs.begin(), refs.end());
                                        KITTY_LOGI("KittyInjector::hideLibrary: Found (%d) emulated soinfo refs at %s",
                                                   int(refs.size()),
                                                   map.toString().c_str());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if (soinfo_refs.empty() && solist.back().ptr == injected.soinfo.ptr)
                {
                    KITTY_LOGE("KittyInjector::hideLibrary: Failed to find emulated sonext refs!");
                    return false;
                }

                usleep(50000);

                for (auto &ref : soinfo_refs)
                {
                    // Filter volatile
                    {
                        uintptr_t tmp = 0;
                        if (!_kMgr->readMem(ref, &tmp, sizeof(tmp)) || tmp != injected.soinfo.ptr)
                            continue;
                    }

                    if (!_kMgr->memPatch.createWithBytes(ref, &soinfo_replace_ptr, sizeof(soinfo_replace_ptr)).Modify())
                    {
                        KITTY_LOGE("KittyInjector::hideLibrary: Failed to patch emulated soinfo ref at (%p)!",
                                   (void *)ref);
                        return false;
                    }

                    KITTY_LOGI("KittyInjector::hideLibrary: Successfully Removed emulated soinfo %p from ref at %p.",
                               (void *)(injected.soinfo.ptr),
                               (void *)ref);
                }
            }
        }
    }

    // idea from https://github.com/RikkaApps/Riru/blob/master/riru/src/main/cpp/hide/hide.cpp

    KITTY_LOGI("KittyInjector::hideLibrary: Remapping segments %p - %p...",
               (void *)(injected.elf.base()),
               (void *)(injected.elf.end()));

    if (injected.elf.segments().empty())
    {
        KITTY_LOGE("KittyInjector::hideLibrary: ELF segments are empty!");
        return false;
    }

    for (auto &it : KittyMemoryEx::getAllMaps(_kMgr->processID()))
    {
        if (it.pathname.empty() || it.startAddress < injected.elf.base())
            continue;
        if (it.endAddress > injected.elf.end())
            break;

        auto backup = _kMgr->memBackup.createBackup(it.startAddress, it.length);

        if (!_rsyscall.rmunmap(it.startAddress, it.length))
        {
            KITTY_LOGE("KittyInjector::hideLibrary: Failed to unmap segment %p, strerror=\"%s\".",
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
            KITTY_LOGE("KittyInjector::hideLibrary: Failed to remap segment %p, \"%s\".",
                       (void *)it.startAddress,
                       _rsyscall.lastError().c_str());
            return false;
        }

        backup.Restore();
    }

    KITTY_LOGI("KittyInjector::hideLibrary: Successfully remapped segments %p - %p.",
               (void *)(injected.elf.base()),
               (void *)(injected.elf.end()));

    // randomize header
    std::vector<uint8_t> buffer = KittyUtils::randomBytes(sizeof(KT_ElfW(Ehdr)));
    if (_kMgr->memPatch.createWithBytes(injected.elf.base(), buffer.data(), buffer.size()).Modify())
    {
        KITTY_LOGI("KittyInjector::hideLibrary: Successfully randomized ELF header at %p.",
                   (void *)(injected.elf.base()));
    }

    return true;
}


uintptr_t KittyInjector::getJavaVM(inject_elf_info_t &injected)
{
    if (!injected.is_valid())
    {
        KITTY_LOGE("KittyInjector::getJavaVM: Invalid injected info!");
        return false;
    }

    auto libart = _kMgr->elfScanner.findElf("libart.so", EScanElfType::Native, EScanElfFilter::System);
    uintptr_t pJNI_GetCreatedJavaVMs = libart.findSymbol("JNI_GetCreatedJavaVMs");
    if (!pJNI_GetCreatedJavaVMs)
    {
        KITTY_LOGE("KittyInjector::getJavaVM: Couldn't find function \"JNI_GetCreatedJavaVMs\".");
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
        KITTY_LOGE("KittyInjector::getJavaVM: %p JNI_GetCreatedJavaVMs Failed to get JavaVM err(%d).",
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
        KITTY_LOGE("KittyInjector::callEntryPoint: Invalid injected info.");
        return false;
    }

    KittyPtrValidator ptrValidator(_kMgr->processID(), true);

    if (!ptrValidator.isPtrExecutable(injected.pJNI_OnLoad))
    {
        KITTY_LOGW("KittyInjector::callEntryPoint: \"JNI_OnLoad\" (%p) not valid executable address.",
                   (void *)(injected.pJNI_OnLoad));
        return false;
    }

    if (!ptrValidator.isPtrReadable(injected.pJvm))
    {
        KITTY_LOGE("KittyInjector::callEntryPoint: \"JavaVM\" (%p) is not valid readable address.",
                   (void *)(injected.pJvm));
        return false;
    }

    KITTY_LOGI("KittyInjector::callEntryPoint: JNI_OnLoad(%p) | JavaVM(%p) | SecretKey(%d).",
               (void *)injected.pJNI_OnLoad,
               (void *)injected.pJvm,
               injected.secretKey);

    jint ret = _kMgr->trace.callFunction(injected.pJNI_OnLoad, injected.pJvm, injected.secretKey).result.val;

    KITTY_LOGI("KittyInjector::callEntryPoint: Calling JNI_OnLoad(%p, %d) returned 0x%x.",
               (void *)injected.pJvm,
               injected.secretKey,
               ret);

    if (ret < JNI_VERSION_1_1 || ret > JNI_VERSION_1_6)
    {
        // warn
        KITTY_LOGW("KittyInjector::callEntryPoint: Unexpected return value (0x%x) for JNI version.", ret);
    }

    return true;
}

bool KittyInjector::findNativeBridgeData(nbItf_data_t *out_callbacks, uintptr_t *out_state_ptr)
{
    if (out_callbacks)
        *out_callbacks = {};

    if (out_state_ptr)
        *out_state_ptr = 0;

#if !defined(__i386__) && !defined(__x86_64__)
    return false;
#else

    if (!_kMgr || !_kMgr->isMemValid())
        return false;

    auto &elf = _kMgr->nbScanner.nbElf();

    auto findNativeBridgeSymbol = [&](const char *mangled, const char *plain) -> uintptr_t {
        uintptr_t addr = elf.findSymbol(mangled);
        if (!addr)
            addr = elf.findSymbol(plain);
        return addr;
    };

    const uintptr_t nb_get_ver = findNativeBridgeSymbol("_ZN7android22NativeBridgeGetVersionEv",
                                                        "NativeBridgeGetVersion");

    const uintptr_t nb_initialized = findNativeBridgeSymbol("_ZN7android23NativeBridgeInitializedEv",
                                                            "NativeBridgeInitialized");

    if (!nb_get_ver || !nb_initialized)
        return false;

    uintptr_t callbacks_addr = 0;
    uintptr_t state_addr = 0;

    // =========================================================
    // NativeBridgeGetVersion -> callbacks pointer
    // =========================================================

#if defined(__x86_64__)

    {
        constexpr size_t SEARCH_SIZE = 0x40;

        //
        // mov rax, [rip + rel32]
        //
        // 48 8B 05 xx xx xx xx
        //
        // We intentionally don't require the following "mov eax,[rax]".
        // The RIP-relative MOV itself is enough to identify the global.
        //

        const uintptr_t mov = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver,
                                                                    nb_get_ver + SEARCH_SIZE,
                                                                    "48 8B 05 ? ? ? ?");

        if (!mov)
            return false;

        uint8_t insn[7]{};

        if (!_kMgr->readMem(mov, insn, sizeof(insn)))
            return false;

        if (insn[0] != 0x48 || insn[1] != 0x8B || insn[2] != 0x05)
        {
            return false;
        }

        int32_t rel = 0;

        if (!_kMgr->readMem(mov + 3, &rel, sizeof(rel)))
        {
            return false;
        }

        //
        // RIP-relative address:
        //
        //     address = next_instruction + sign_extended(rel32)
        //
        callbacks_addr = static_cast<uintptr_t>(static_cast<intptr_t>(mov + 7) + static_cast<intptr_t>(rel));
    }

#elif defined(__i386__)

    {
        constexpr size_t SEARCH_SIZE = 0x40;

        //
        // Expected PIC sequence:
        //
        //     call $+5
        //     pop  ecx
        //     ...
        //
        // The exact sequence from your binary is:
        //
        //     E8 00 00 00 00
        //     59
        //

        uintptr_t pop = 0;

        const uintptr_t call_pop = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver,
                                                                         nb_get_ver + SEARCH_SIZE,
                                                                         "E8 00 00 00 00 59");

        if (call_pop)
        {
            pop = call_pop + 5;
        }
        else
        {
            //
            // Fallback for binaries where the CALL immediate isn't
            // literally encoded as zero.
            //
            pop = _kMgr->memScanner.findIdaPatternFirst(nb_get_ver, nb_get_ver + SEARCH_SIZE, "59");

            if (!pop)
                return false;
        }

        //
        // add ecx, imm32
        //
        const uintptr_t add = _kMgr->memScanner.findIdaPatternFirst(pop, nb_get_ver + SEARCH_SIZE, "81 C1 ? ? ? ?");

        if (!add)
            return false;

        uint32_t add_imm = 0;

        if (!_kMgr->readMem(add + 2, &add_imm, sizeof(add_imm)))
        {
            return false;
        }

        //
        // mov eax, [ecx + disp32]
        //
        // mov eax, [eax]
        //
        const uintptr_t mov_callbacks = _kMgr->memScanner.findIdaPatternFirst(add,
                                                                              nb_get_ver + SEARCH_SIZE,
                                                                              "8B 81 ? ? ? ? 8B 00");

        if (!mov_callbacks)
            return false;

        uint32_t callbacks_disp = 0;

        if (!_kMgr->readMem(mov_callbacks + 2, &callbacks_disp, sizeof(callbacks_disp)))
        {
            return false;
        }

        //
        // After:
        //
        //     pop ecx
        //     add ecx, add_imm
        //
        // ECX = pop + add_imm
        //
        // The global is:
        //
        //     ECX + callbacks_disp
        //
        callbacks_addr = static_cast<uintptr_t>(static_cast<uint32_t>(pop) + add_imm + callbacks_disp);
    }

#endif

    if (!callbacks_addr)
        return false;

    // =========================================================
    // NativeBridgeInitialized -> state pointer
    // =========================================================

#if defined(__x86_64__)

    {
        constexpr size_t SEARCH_SIZE = 0x30;

        //
        // cmp dword ptr [rip + rel32], 3
        //
        // 83 3D xx xx xx xx 03
        //

        const uintptr_t cmp = _kMgr->memScanner.findIdaPatternFirst(nb_initialized,
                                                                    nb_initialized + SEARCH_SIZE,
                                                                    "? 3D ? ? ? ? 03");

        if (!cmp)
            return false;

        uint8_t insn[7]{};

        if (!_kMgr->readMem(cmp, insn, sizeof(insn)))
            return false;

        if (insn[0] != 0x83 || insn[1] != 0x3D || insn[6] != 0x03)
        {
            return false;
        }

        int32_t rel = 0;

        if (!_kMgr->readMem(cmp + 2, &rel, sizeof(rel)))
        {
            return false;
        }

        //
        // IMPORTANT:
        //
        // 83 3D rel32 imm8
        // ^             ^
        // |             |
        // start         +7 = next RIP
        //
        state_addr = static_cast<uintptr_t>(static_cast<intptr_t>(cmp + 7) + static_cast<intptr_t>(rel));
    }

#elif defined(__i386__)

    {
        constexpr size_t SEARCH_SIZE = 0x30;

        //
        // Expected:
        //
        //     call $+5
        //     pop eax
        //

        uintptr_t pop = 0;

        const uintptr_t call_pop = _kMgr->memScanner.findIdaPatternFirst(nb_initialized,
                                                                         nb_initialized + SEARCH_SIZE,
                                                                         "E8 00 00 00 00 58");

        if (call_pop)
        {
            pop = call_pop + 5;
        }
        else
        {
            pop = _kMgr->memScanner.findIdaPatternFirst(nb_initialized, nb_initialized + SEARCH_SIZE, "58");

            if (!pop)
                return false;
        }

        //
        // add eax, imm32
        //
        const uintptr_t add = _kMgr->memScanner.findIdaPatternFirst(pop, nb_initialized + SEARCH_SIZE, "81 C0 ? ? ? ?");

        if (!add)
            return false;

        uint32_t add_imm = 0;

        if (!_kMgr->readMem(add + 2, &add_imm, sizeof(add_imm)))
        {
            return false;
        }

        //
        // cmp dword ptr [eax + disp32], 3
        //
        const uintptr_t cmp = _kMgr->memScanner.findIdaPatternFirst(add,
                                                                    nb_initialized + SEARCH_SIZE,
                                                                    "? B8 ? ? ? ? 03");

        if (!cmp)
            return false;

        uint32_t state_disp = 0;

        if (!_kMgr->readMem(cmp + 2, &state_disp, sizeof(state_disp)))
        {
            return false;
        }

        //
        // EAX = pop + add_imm
        //
        // state = EAX + state_disp
        //

        state_addr = static_cast<uintptr_t>(static_cast<uint32_t>(pop) + add_imm + state_disp);
    }

#endif

    if (!state_addr)
        return false;

    // =========================================================
    // Validate callbacks pointer
    // =========================================================

    uintptr_t callbacks = 0;

    if (!_kMgr->readMem(callbacks_addr, &callbacks, sizeof(callbacks)))
    {
        return false;
    }

    if (!callbacks)
        return false;

    int32_t version = 0;

    if (!_kMgr->readMem(callbacks, &version, sizeof(version)))
    {
        return false;
    }

    if (version < 2)
        return false;

    const size_t callbacks_size = nbItf_data_t::GetStructSize(version);

    if (callbacks_size == 0)
        return false;

    if (out_callbacks)
    {
        nbItf_data_t tmp{};

        if (!_kMgr->readMem(callbacks, &tmp, callbacks_size))
        {
            return false;
        }

        *out_callbacks = tmp;
    }

    if (out_state_ptr)
        *out_state_ptr = state_addr;

    return true;

#endif
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
