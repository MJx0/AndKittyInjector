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
#define syscall_close_n 57
#elif __arm__
#define syscall_getpid_n 20
#define syscall_prctl_n 172
#define syscall_fcntl_n 221 // fcntl64
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 385
#define syscall_close_n 6
#elif __i386__
#define syscall_getpid_n 20
#define syscall_prctl_n 172
#define syscall_fcntl_n 55
#define syscall_mprotect_n 125
#define syscall_mmap_n 192 // mmap2
#define syscall_munmap_n 91
#define syscall_memfd_create_n 356
#define syscall_close_n 6
#elif __x86_64__
#define syscall_getpid_n 39
#define syscall_prctl_n 157
#define syscall_fcntl_n 72
#define syscall_mprotect_n 10
#define syscall_mmap_n 9
#define syscall_munmap_n 11
#define syscall_memfd_create_n 319
#define syscall_close_n 3
#else
#error "Unsupported ABI"
#endif

#include <sys/prctl.h>
#include <sys/mman.h>

#include <cstdint>
#include <cstring>
#include <algorithm>

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

        setupSyscallGadget();

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
            return false;

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

    inline bool rclose(int fd)
    {
        if (!_kMgr || !_kMgr->isMemValid())
            return false;

        auto ret = _kMgr->trace.callSyscall(syscall_close_n, fd);
        if (ret.result.val < 0)
        {
            _lastError = strerror(-ret.result.val);
        }
        return ret.status == KT_RP_CALL_SUCCESS && ret.result.val == 0;
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

    inline void setupSyscallGadget() const
    {
        struct SigConfig
        {
            std::vector<uint8_t> signature;
            size_t alignment;
            uintptr_t bias;
        };

#if defined(__aarch64__)
        const std::vector<SigConfig> ARCH_SIGS = {
            {{0x01, 0x00, 0x00, 0xd4}, 4, 0} // svc #0
        };
#elif defined(__arm__)
        const std::vector<SigConfig> ARCH_SIGS = {
            {{0x00, 0x00, 0x00, 0xef}, 4, 0}, // 1st Choice: ARM Mode svc #0
            {{0x00, 0xdf}, 2, 1}              // 2nd Choice: Thumb Mode svc #0
        };
#elif defined(__x86_64__)
        const std::vector<SigConfig> ARCH_SIGS = {
            {{0x0f, 0x05}, 1, 0} // syscall
        };
#elif defined(__i386__)
        const std::vector<SigConfig> ARCH_SIGS = {
            {{0xcd, 0x80}, 1, 0} // int 0x80
        };
#endif

        auto getMapPriority = [](const std::string &path) -> int {
            if (path == "[vdso]")
                return 1;

            if (path.find("/arm/") == std::string::npos && path.find("/arm64/") == std::string::npos)
            {
                if (path.find("/libc.so") != std::string::npos)
                    return 2;

                if (path.rfind("/system/", 0) == 0)
                {
                    if (path.find(".so") != std::string::npos)
                    {
                        return 3;
                    }
                }
            }

            if (path.find("/libc.so") != std::string::npos)
                return 4;

            if (path.rfind("/system/", 0) == 0)
            {
                if (path.find(".so") != std::string::npos)
                {
                    return 5;
                }
            }

            return 6;
        };

        auto maps = KittyMemoryEx::getMaps(_kMgr->processID(),
                                           KittyMemoryEx::EProcMapFilter::Regex,
                                           "(^\\[vdso\\]$)|(^/system/.*\\.so$)");

        std::stable_sort(maps.begin(),
                         maps.end(),
                         [&](const KittyMemoryEx::ProcMap &a, const KittyMemoryEx::ProcMap &b) {
                             int priorityA = getMapPriority(a.pathname);
                             int priorityB = getMapPriority(b.pathname);

                             // If priorities are different, sort by priority (lower number comes first)
                             if (priorityA != priorityB)
                             {
                                 return priorityA < priorityB;
                             }

                             // If they have the same priority (e.g., both are segments of libc),
                             // keep them ordered by their start address
                             return a.startAddress < b.startAddress;
                         });

        for (auto &it : maps)
        {
            if (!it.readable || !it.executable || !it.is_private)
                continue;

            for (const auto &config : ARCH_SIGS)
            {
                auto results = _kMgr->memScanner.findDataAll(it.startAddress,
                                                             it.endAddress,
                                                             config.signature.data(),
                                                             config.signature.size());
                for (auto &res : results)
                {
                    if (res == 0 || (res % config.alignment) != 0)
                        continue;

                    KITTY_LOGI("KittyRemoteSys: Using syscall gadget at %p from %s",
                               (void *)(res + config.bias),
                               it.toString().c_str());

                    _kMgr->trace.setSyscallGadget(res + config.bias);
                    return;
                }
            }
        }
    }
};