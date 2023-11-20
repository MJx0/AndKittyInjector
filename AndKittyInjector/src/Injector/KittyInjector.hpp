#pragma once

#include <KittyMemoryMgr.hpp>

#include <dlfcn.h>
#include <android/dlext.h>

#include "../NativeBridge/NativeBridge.hpp"

#include "RemoteSyscall.hpp"
#include "SoInfoPatch.hpp"

#ifdef __aarch64__
static constexpr ElfW_(Half) kInjectorEM = EM_AARCH64;
#elif __arm__
static constexpr ElfW_(Half) kInjectorEM = EM_ARM;
#elif __i386__
static constexpr ElfW_(Half) kInjectorEM = EM_386;
#elif __x86_64__
static constexpr ElfW_(Half) kInjectorEM = EM_X86_64;
#else
#error "Unsupported ABI"
#endif

std::string EMachineToStr(int16_t);

#define kINJ_SECRET_KEY 1337

struct injected_info_t
{
    bool is_native = false, is_hidden = false;
    uintptr_t dl_handle = 0;
    ElfScanner elf;

    uintptr_t pJvm = 0;
    int secretKey = kINJ_SECRET_KEY;
    uintptr_t pJNI_OnLoad = 0;

    injected_info_t() = default;

    inline bool is_valid() const { return elf.isValid(); }
};

class KittyInjector
{
private:
    std::unique_ptr<KittyMemoryMgr> _kMgr;

    RemoteSyscall _remote_syscall;

    uintptr_t _remote_dlopen, _remote_dlopen_ext, _remote_dlclose, _remote_dlerror;

    ElfScanner _nbElf, _nbImplElf;
    NativeBridgeCallbacks _nbItf;

    SoInfoPatch _soinfo_patch;

public:
    KittyInjector() : _remote_dlopen(0), _remote_dlopen_ext(0), _remote_dlclose(0), _remote_dlerror(0)
    {
        memset(&_nbItf, 0, sizeof(NativeBridgeCallbacks));
    }

    inline bool remoteContainsMap(const std::string &name) const
    {
        return !name.empty() && _kMgr.get() && _kMgr->isMemValid() && !KittyMemoryEx::getMapsContain(_kMgr->processID(), name).empty();
    }

    /**
     * Initialize injector
     * @param pid remote process ID
     * @param eMemOp: Memory read & write operation type [ EK_MEM_OP_SYSCALL / EK_MEM_OP_IO ]
     */
    bool init(pid_t pid, EKittyMemOP eMemOp);

    inline bool attach() { return _kMgr.get() && _kMgr->isMemValid() && _kMgr->trace.Attach(); };
    inline bool detach() { return _kMgr.get() && _kMgr->isMemValid() && _kMgr->trace.Detach(); }

    injected_info_t injectLibrary(std::string libPath, int flags,
        bool use_memfd_dl, bool hide_maps, bool hide_solist, std::function<void(injected_info_t& injected)> beforeEntryPoint);

private:
    injected_info_t nativeInject(KittyIOFile& lib, int flags, bool use_dl_memfd);
    injected_info_t emuInject(KittyIOFile& lib, int flags, bool use_dl_memfd);
    
    uintptr_t getJavaVM(injected_info_t &injected);
    bool callEntryPoint(injected_info_t &injected);
    bool hideSegmentsFromMaps(injected_info_t &injected);
};