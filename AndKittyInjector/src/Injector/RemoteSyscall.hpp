#pragma once

// https://syscall.sh/

#ifdef __aarch64__
#define syscall_fcntl_n 25
#define syscall_mprotect_n 226
#define syscall_mmap_n 222
#define syscall_munmap_n 215
#define syscall_memfd_create_n 279
#elif __arm__
#define syscall_fcntl_n 221 // fcntl64
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 385
#elif __i386__
#define syscall_fcntl_n 55
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 356
#elif __x86_64__
#define syscall_fcntl_n 72
#define syscall_mprotect_n 10
#define syscall_mmap_n 9
#define syscall_munmap_n 11
#define syscall_memfd_create_n 319
#else
#error "Unsupported ABI"
#endif

#include <KittyMemoryMgr.hpp>

#define IsValidRetPtr(x) (uintptr_t(x) > 0 && uintptr_t(x) != uintptr_t(-1) && uintptr_t(x) != uintptr_t(-4) && uintptr_t(x) != uintptr_t(-8))

class RemoteSyscall
{
    friend class KittyInjector;

    KittyMemoryMgr *_kMgr;

    uintptr_t _remote_syscall, _remote_errno;

    RemoteSyscall() : _kMgr(nullptr), _remote_syscall(0), _remote_errno(0) {}

    std::map<uintptr_t, size_t> vAllocatedMaps;

    bool init(KittyMemoryMgr *kMgr)
    {
        if (!kMgr || !kMgr->isMemValid())
            return false;
        
        _kMgr = kMgr;

        _remote_syscall = _kMgr->findRemoteOf("syscall", (uintptr_t)&syscall);
        if (!_remote_syscall)
            return false;

        _remote_errno = _kMgr->findRemoteOf("__errno", (uintptr_t)&__errno);

        return true;
    }

    void clearAllocatedMaps()
    {
        auto maps = vAllocatedMaps;
        for (auto it : maps)
            if (it.first && it.second)
                rmunmap(it.first, it.second);

        vAllocatedMaps.clear();
    }

    uintptr_t rmmap_anon(uintptr_t addr, size_t size, int prot, bool deleteOnClear=true)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        int flags = MAP_PRIVATE | MAP_ANONYMOUS;
        if (addr)
            flags |= MAP_FIXED;

        intptr_t remoteMem = _kMgr->trace.callFunction(_remote_syscall, 7, syscall_mmap_n, addr, size, prot, flags, 0, 0);
        if (!IsValidRetPtr(remoteMem))
            return 0;

        if (deleteOnClear)
            vAllocatedMaps[remoteMem] = size;

        return remoteMem;
    }

    uintptr_t rmmap_shared(uintptr_t addr, size_t size, int prot, int fd, bool deleteOnClear=true)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        int flags = MAP_SHARED;
        if (addr)
            flags |= MAP_FIXED;

        intptr_t remoteMem = _kMgr->trace.callFunction(_remote_syscall, 7, syscall_mmap_n, addr, size, prot, flags, fd, 0);
        if (!IsValidRetPtr(remoteMem))
            return 0;

        if (deleteOnClear)
            vAllocatedMaps[remoteMem] = size;

        return remoteMem;
    }

    void rmunmap(uintptr_t ptr, size_t size)
    {
        if (!ptr || !size || !_kMgr || !_kMgr->isMemValid())
            return;

        auto iter = vAllocatedMaps.find(ptr);
        if (iter != vAllocatedMaps.end())
            vAllocatedMaps.erase(iter);

        _kMgr->trace.callFunction(_remote_syscall, 3, syscall_munmap_n, ptr, size);
    }

    int rmprotect(uintptr_t ptr, size_t size, int prot)
    {
        if (!ptr || !size || !_kMgr || !_kMgr->isMemValid())
            return 0;

        return _kMgr->trace.callFunction(_remote_syscall, 4, syscall_mprotect_n, ptr, size, prot);
    }

    uintptr_t rmmap_str(std::string str)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return false;

        intptr_t remoteMem = _kMgr->trace.callFunction(_remote_syscall, 7, syscall_mmap_n,
                                                       nullptr, str.size() + 1,
                                                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (!IsValidRetPtr(remoteMem))
            return 0;
        
        if (!_kMgr->writeMemStr(remoteMem, str))
        {
            _kMgr->trace.callFunction(_remote_syscall, 3, syscall_munmap_n, remoteMem, str.size() + 1);
            return 0;
        }

        vAllocatedMaps[remoteMem] = str.size() + 1;
        return remoteMem;
    }

    int rmemfd_create(uintptr_t rname, unsigned int flags)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        return _kMgr->trace.callFunction(_remote_syscall, 3, syscall_memfd_create_n, rname, flags);
    }

    int rmemfd_seal(int rmemfd, unsigned long seals)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        return _kMgr->trace.callFunction(_remote_syscall, 4, syscall_fcntl_n, rmemfd, F_ADD_SEALS, seals);
    }

    std::string getRemoteError()
    {
        std::string error;

        if (!_kMgr || !_kMgr->isMemValid())
            return error;

        intptr_t err = _kMgr->trace.callFunction(_remote_errno, 0);
        if (err > 0)
            error = std::string(strerror(err));
        return error;
    }
};