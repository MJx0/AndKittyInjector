#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <functional>

#include <dlfcn.h>
#include <android/dlext.h>

#include <jni.h>

#include "KittyInjectorSyscall.hpp"

#include <KittyMemoryMgr.hpp>

#ifdef __aarch64__
static constexpr KT_ElfW(Half) kInjectorEM = EM_AARCH64;
#elif __arm__
static constexpr KT_ElfW(Half) kInjectorEM = EM_ARM;
#elif __i386__
static constexpr KT_ElfW(Half) kInjectorEM = EM_386;
#elif __x86_64__
static constexpr KT_ElfW(Half) kInjectorEM = EM_X86_64;
#else
#error "Unsupported ABI"
#endif

std::string EMachineToStr(int16_t);

#define kINJ_SECRET_KEY 1337

struct inject_elf_info_t
{
    bool is_native, is_hidden;
    uintptr_t dl_handle;
    kitty_soinfo_t soinfo;
    ElfScanner elf;

    uintptr_t pJvm;
    int secretKey;
    uintptr_t pJNI_OnLoad;

    inject_elf_info_t()
        : is_native(false), is_hidden(false), dl_handle(0), pJvm(0), secretKey(kINJ_SECRET_KEY), pJNI_OnLoad(0)
    {
    }

    inline bool is_valid() const
    {
        return elf.isValid();
    }
};

struct inject_elf_config_t
{
    int sdk, rtdl_flags, delay;
    bool watch, launch, seize, bp, memfd, free, hide;
    std::string package, memfd_name;
    std::function<void(inject_elf_info_t &injected)> beforeEntryPoint, afterEntryPoint;

    inject_elf_config_t()
        : sdk(0), rtdl_flags(RTLD_LOCAL | RTLD_NOW), delay(0), watch(false), launch(false), seize(false), bp(false),
          memfd(false), free(false), hide(false), beforeEntryPoint(nullptr), afterEntryPoint(nullptr)
    {
    }
};

class KittyInjector
{
public:
    KittyMemoryMgr *_kMgr;

    KittyRemoteSys _rsyscall;

    uintptr_t _rbuffer;
    std::vector<uint8_t> _backup_rbuffer;

    uintptr_t _rdlopen, _rdlclose, _rdlerror, _rdlsym, _rdlopen_ext;
    inject_elf_config_t _cfg;

    uintptr_t _dl_caller;

public:
    KittyInjector()
        : _kMgr(nullptr), _rbuffer(0), _rdlopen(0), _rdlclose(0), _rdlerror(0), _rdlsym(0), _rdlopen_ext(0),
          _dl_caller(0)
    {
    }

    /**
     * Initialize injector
     * @param KittyMemoryMgr KittyMemory manager
     * @param options Injection options
     */
    bool init(KittyMemoryMgr *kmgr, const inject_elf_config_t &cfg);

    inline KittyMemoryMgr *KMgr() const
    {
        return _kMgr;
    }

    bool validateElf(const std::string &elfPath, KT_ElfW(Ehdr) * hdr, bool *needsNB);
    bool waitBreakpoint(bool needsNB);
    inject_elf_info_t inject(const std::string &elfPath);

private:
    inject_elf_info_t nativeInject(KittyIOFile &elfFile, bool *bCalldlerror = nullptr);
    inject_elf_info_t emuInject(KittyIOFile &elfFile, bool *bCalldlerror = nullptr);

    bool unloadLibrary(inject_elf_info_t &injected);
    bool hideLibrary(inject_elf_info_t &injected);

    uintptr_t getJavaVM(inject_elf_info_t &injected);
    bool callEntryPoint(inject_elf_info_t &injected);

    inline bool canUseMemfd()
    {
        errno = 0;
        return !(syscall(syscall_memfd_create_n) < 0 && errno == ENOSYS);
    }

    // preinit callbacks
    bool findNbCallbacks(nbItf_data_t *out);

    std::vector<uintptr_t> findNbSoInfoRefs(const kitty_soinfo_t &soinfo);
};