#pragma once

#include <KittyMemoryMgr.hpp>

#include <dlfcn.h>
#include <android/dlext.h>

#include "../NativeBridge/NativeBridge.hpp"

#include "RemoteSyscall.hpp"

#ifdef __aarch64__
static constexpr ElfW_(Half) kNativeEM = EM_AARCH64;
#elif __arm__
static constexpr ElfW_(Half) kNativeEM = EM_ARM;
#elif __i386__
static constexpr ElfW_(Half) kNativeEM = EM_386;
#elif __x86_64__
static constexpr ElfW_(Half) kNativeEM = EM_X86_64;
#else
#error "Unsupported ABI"
#endif

#define kINJ_WAIT usleep(1000)

struct injected_info_t
{
    bool is_native, is_hidden;
    uintptr_t dl_handle;
    std::string name;
    ElfBaseMap elfMap;

    injected_info_t() = default;

    inline bool is_valid() const { return elfMap.isValid(); }
};

class KittyInjector
{
private:
    std::unique_ptr<KittyMemoryMgr> _kMgr;

    RemoteSyscall _remote_syscall;

    uintptr_t _remote_dlopen, _remote_dlopen_ext, _remote_dlclose, _remote_dlerror;

    ElfBaseMap _houdiniElf;
    NativeBridgeCallbacks _nativeBridgeItf;

public:
    KittyInjector() : _remote_dlopen(0), _remote_dlopen_ext(0), _remote_dlclose(0), _remote_dlerror(0)
    {
        memset(&_nativeBridgeItf, 0, sizeof(NativeBridgeCallbacks));
    }

    inline bool remoteContainsMap(std::string name) const
    {
        return _kMgr.get() && _kMgr->isMemValid() && !KittyMemoryEx::getMapsContain(_kMgr->processID(), name).empty();
    }

    /**
     * Initialize injector
     * @param pid remote process ID
     * @param eMemOp: Memory read & write operation type [ EK_MEM_OP_SYSCALL / EK_MEM_OP_IO ]
     */
    bool init(pid_t pid, EKittyMemOP eMemOp);

    inline bool attach() { return _kMgr.get() && _kMgr->isMemValid() && _kMgr->trace.Attach(); };
    inline bool detach() { return _kMgr.get() && _kMgr->isMemValid() && _kMgr->trace.Detach(); }

    injected_info_t injectLibrary(std::string libPath, int flags, bool use_dl_memfd);

private:
    injected_info_t nativeInject(KittyIOFile& lib, int flags, bool use_dl_memfd);
    injected_info_t emuInject(KittyIOFile& lib, int flags);
};