#pragma once

// https://syscall.sh/

#ifdef __aarch64__
#define syscall_getpid_n 172
#define syscall_prctl_n 167
#define syscall_fcntl_n 25
#define syscall_mprotect_n 226
#define syscall_mmap_n 222
#define syscall_munmap_n 215
#define syscall_memfd_create_n 279
#elif __arm__
#define syscall_getpid_n 20
#define syscall_prctl_n 172
#define syscall_fcntl_n 221 // fcntl64
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 385
#elif __i386__
#define syscall_getpid_n 20
#define syscall_prctl_n 172
#define syscall_fcntl_n 55
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 356
#elif __x86_64__
#define syscall_getpid_n 39
#define syscall_prctl_n 157
#define syscall_fcntl_n 72
#define syscall_mprotect_n 10
#define syscall_mmap_n 9
#define syscall_munmap_n 11
#define syscall_memfd_create_n 319
#else
#error "Unsupported ABI"
#endif

#include <sys/prctl.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstring>

#include <KittyMemoryMgr.hpp>

class KittyRemoteSys
{
    KittyMemoryMgr *_kMgr;
    KittyPtrValidator _ptrValidator;

    std::string _lastError;

public:
    KittyRemoteSys() : _kMgr(nullptr)
    {
    }

    inline bool init(KittyMemoryMgr *kMgr)
    {
        if (!kMgr || !kMgr->isMemValid())
            return false;

        _kMgr = kMgr;

        _ptrValidator.setUseCache(false);
        _ptrValidator.setPID(kMgr->processID());

        return true;
    }

    inline bool testSyscall()
    {
        _kMgr->trace.callSyscall(0);
        return rgetpid() == _kMgr->processID();
    }

    inline int rgetpid()
    {
        int ret = _kMgr->trace.callSyscall(syscall_getpid_n).result.val;
        if (ret < 0)
        {
            _lastError = strerror(-ret);
        }
        return ret;
    }

    inline uintptr_t rmmap(uintptr_t addr, size_t size, int prot, int flags, int fd, uintptr_t offset)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        auto ret = _kMgr->trace.callSyscall(syscall_mmap_n, addr, size, prot, flags, fd, offset);
        if (ret.status != KT_RP_CALL_SUCCESS || !_ptrValidator.isPtrInAddressSpace(ret.result.ptr))
        {
            if (ret.result.val < 0)
            {
                _lastError = strerror(-int(ret.result.val));
            }
            return 0;
        }

        return ret.result.ptr;
    }

    inline bool rmunmap(uintptr_t ptr, uintptr_t size)
    {
        if (!ptr || !size || !_kMgr || !_kMgr->isMemValid())
            return false;

        auto ret = _kMgr->trace.callSyscall(syscall_munmap_n, ptr, size);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.status == KT_RP_CALL_SUCCESS && ret.result.val == 0;
    }

    inline bool rmprotect(uintptr_t ptr, size_t size, int prot)
    {
        if (!ptr || !size || !_kMgr || !_kMgr->isMemValid())
            return false;

        auto ret = _kMgr->trace.callSyscall(syscall_mprotect_n, ptr, size, prot);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.status == KT_RP_CALL_SUCCESS && ret.result.val == 0;
    }

    inline int rmemfd_create(uintptr_t rname, unsigned int flags)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        auto ret = _kMgr->trace.callSyscall(syscall_memfd_create_n, rname, flags);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.result.val;
    }

    inline bool rmemfd_seal(int rmemfd, unsigned long seals)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        auto ret = _kMgr->trace.callSyscall(syscall_fcntl_n, rmemfd, F_ADD_SEALS, seals);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.status == KT_RP_CALL_SUCCESS && ret.result.val == 0;
    }

    inline int rprctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return 0;

        auto ret = _kMgr->trace.callSyscall(syscall_prctl_n, option, arg2, arg3, arg4, arg5);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.result.val;
    }

    inline void clearLastError()
    {
        _lastError.clear();
        _lastError.shrink_to_fit();
    }

    inline std::string lastError() const
    {
        return _lastError.empty() ? "null" : _lastError;
    }
};