#pragma once

#include <KittyMemoryEx/KittyMemoryMgr.hpp>

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

class KittyInjector
{
private:
    std::unique_ptr<KittyMemoryMgr> _kMgr;

    RemoteSyscall _remote_syscall;

    uintptr_t _remote_dlopen;
    uintptr_t _remote_dlopen_ext;
    uintptr_t _remote_dlerror;

    ElfBaseMap _houdiniElf;
    NativeBridgeCallbacks _nativeBridgeItf;

public:
    KittyInjector() : _remote_dlopen(0), _remote_dlopen_ext(0), _remote_dlerror(0)
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

    uintptr_t injectLibrary(std::string libPath, int flags);
};