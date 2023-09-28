#pragma once

#include <KittyMemoryEx/KittyMemoryMgr.hpp>

#include "dlfcn.h"
#include "../NativeBridge/NativeBridge.hpp"

// https://syscall.sh/

#ifdef __aarch64__
#define syscall_mmap_n 222
#define syscall_munmap_n 215
#elif __arm__
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#elif __i386__
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#elif __x86_64__
#define syscall_mmap_n 9
#define syscall_munmap_n 11
#else
#error "Unsupported ABI"
#endif

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

class KittyInjector
{
private:
    KittyMemoryMgr _pkMgr;

    uintptr_t _remote_syscall;
    uintptr_t _remote_dlopen;
    uintptr_t _remote_dlerror;

    ElfBaseMap _houdiniElf;
    NativeBridgeCallbacks _nativeBridgeItf;

    bool _init;

public:
    KittyInjector() : _remote_syscall(0),
                      _remote_dlopen(0), _remote_dlerror(0), _init(false)
    {
        memset(&_nativeBridgeItf, 0, sizeof(NativeBridgeCallbacks));
    }

    /**
     * Initialize injector
     * @param pid remote process ID
     * @param eMemOp: Memory read & write operation type [ EK_MEM_OP_SYSCALL / EK_MEM_OP_IO ]
     */
    bool init(pid_t pid, EKittyMemOP eMemOp);

    uintptr_t injectLibrary(std::string libPath, int flags) const;
};