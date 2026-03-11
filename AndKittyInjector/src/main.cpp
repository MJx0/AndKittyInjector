#include <cstring>
#include <signal.h>
#include <thread>

#include <unistd.h>

#include <cstdint>
#include <string>

#include <sys/inotify.h>
#include <sys/types.h>

#include <chrono>
#include <vector>

#include "KittyMemoryMgr.hpp"

#include "Utils.hpp"
#include <KittyUtils.hpp>

#include "argsparse.hpp"

#include "Injector/KittyInjector.hpp"

#define SLEEP_MICROS(x)                                                                                                \
    {                                                                                                                  \
        std::this_thread::sleep_for(std::chrono::microseconds(x));                                                     \
    }
#define SLEEP_SECONDS(x)                                                                                               \
    {                                                                                                                  \
        std::this_thread::sleep_for(std::chrono::seconds(x));                                                          \
    }

#define kPROGRAM_NAME "AndKittyInjector"
#define kPROGRAM_VER "5.0.2"

bool inject(int pid,
            const std::vector<std::string> &libs,
            inject_elf_config_t &cfg,
            std::vector<inject_elf_info_t> *out);
bool inject_watch(const std::vector<std::string> &libs, inject_elf_config_t &cfg, std::vector<inject_elf_info_t> *out);

std::chrono::duration<double, std::milli> inj_ms{};

int main(int argc, char *args[])
{
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    setbuf(stdin, nullptr);

    argparse::ArgumentParser program(kPROGRAM_NAME, kPROGRAM_VER);

    inject_elf_config_t inj_cfg = {};

    inj_cfg.sdk = KittyUtils::getAndroidSDK();
    inj_cfg.seize = inj_cfg.sdk >= 24;
    inj_cfg.rtdl_flags = RTLD_LOCAL | RTLD_NOW;

    program.add_argument("--package")
        .help("Target package name to inject into.")
        .required()
        .store_into(inj_cfg.package)
        .metavar("<name>");

    std::vector<std::string> libs;
    program.add_argument("--libs")
        .help("Libraries path to be injected.")
        .required()
        .nargs(argparse::nargs_pattern::at_least_one)
        .store_into(libs)
        .metavar("<paths>");

    program.add_argument("--launch").help("Launch process and inject.").store_into(inj_cfg.launch);

    program.add_argument("--watch").help("Monitor process start then inject.").store_into(inj_cfg.watch);

    program.add_argument("--bp").help("Inject after breakpoint hit.").store_into(inj_cfg.bp);

    program.add_argument("--delay")
        .help("Delay injection in microseconds.")
        .store_into(inj_cfg.delay)
        .metavar("<micros>");

    program.add_argument("--memfd").help("Use memfd dlopen.").store_into(inj_cfg.memfd);

    program.add_argument("--free").help("Unload library after entry point execution.").store_into(inj_cfg.free);

    program.add_argument("--hide")
        .help("Remove soinfo and remap library to anonymouse memory.")
        .store_into(inj_cfg.hide);

    try
    {
        program.parse_args(argc, args);
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    KITTY_LOGI("======== INJECTION ARGS ========");
    KITTY_LOGI("package: %s", inj_cfg.package.c_str());
    KITTY_LOGI("sdk: %d", inj_cfg.sdk);
    KITTY_LOGI("launch: %d", inj_cfg.launch ? 1 : 0);
    KITTY_LOGI("watch: %d", inj_cfg.watch ? 1 : 0);
    KITTY_LOGI("bp: %d", inj_cfg.bp);
    KITTY_LOGI("delay: %d", inj_cfg.delay);
    KITTY_LOGI("memfd: %d", inj_cfg.memfd ? 1 : 0);
    KITTY_LOGI("free: %d", inj_cfg.free);
    KITTY_LOGI("hide: %d", inj_cfg.hide ? 1 : 0);
    for (size_t i = 0; i < libs.size(); i++)
    {
        KITTY_LOGI("lib[%d]: %s", int(i + 1), libs[i].c_str());
    }
    KITTY_LOGI("================================");

    std::vector<inject_elf_info_t> injected_libs_info = {};
    bool injection_ok = false;

    if (inj_cfg.launch || inj_cfg.watch)
    {
        if (KittyMemoryEx::getProcessID(inj_cfg.package) > 0)
        {
            Utils::android_stop_app(inj_cfg.package);

            if (KittyMemoryEx::getProcessID(inj_cfg.package) > 0)
            {
                KITTY_LOGE("--%s is used but the target process is already alive.",
                           inj_cfg.launch ? "launch" : "watch");
                exit(1);
            }
        }

        if (inj_cfg.launch)
        {
            std::thread([&inj_cfg]() -> void {
                // wait for process monitor to execute
                SLEEP_SECONDS(1);
                if (!Utils::android_launch_app(inj_cfg.package))
                {
                    KITTY_LOGE("Failed to launch app %s!", inj_cfg.package.c_str());
                    exit(1);
                }
            }).detach();
        }

        KITTY_LOGI("Monitoring %s...", inj_cfg.package.c_str());

        injection_ok = inject_watch(libs, inj_cfg, &injected_libs_info);
    }
    else
    {
        if (inj_cfg.delay > 0)
            SLEEP_MICROS(inj_cfg.delay);

        int app_pid = KittyMemoryEx::getProcessID(inj_cfg.package);
        if (app_pid <= 0)
        {
            KITTY_LOGE("Couldn't find process ID of %s.", inj_cfg.package.c_str());
            exit(1);
        }

        injection_ok = inject(app_pid, libs, inj_cfg, &injected_libs_info);
    }

    if (!injection_ok)
    {
        KITTY_LOGE("Injection failed.");
        Utils::android_stop_app(inj_cfg.package);
        int pid = KittyMemoryEx::getProcessID(inj_cfg.package);
        if (pid > 0)
        {
            kill(pid, SIGKILL);
        }
        KITTY_LOGI("Killed target process.");
        exit(1);
    }

    KITTY_LOGI("Injected %d %s successfully.",
               int(injected_libs_info.size()),
               injected_libs_info.size() == 1 ? "lib" : "libs");

    KITTY_LOGI("Injection succeeded.");

    if (inj_ms.count() > 0)
        KITTY_LOGI("Injection took %f MS.", inj_ms.count());

    return 0;
}

bool inject(int pid,
            const std::vector<std::string> &libs,
            inject_elf_config_t &cfg,
            std::vector<inject_elf_info_t> *out)
{
    if (pid <= 0)
    {
        KITTY_LOGE("Invalid PID.");
        return false;
    }

    KittyMemoryMgr kmgr{};

    // Manually initialize tracer to seize and interrupt as soon as possible
    kmgr.trace = KittyTraceMgr(pid, 0, true);

    errno = 0;
    bool attached = cfg.seize = cfg.sdk >= 24 && kmgr.trace.seize(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    if (!attached)
    {
        attached = kmgr.trace.attach(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    }

    if (!attached)
    {
        KITTY_LOGE("Failed to attach to process.");
        return false;
    }

    KITTY_LOGI("Attached to process successfully.");

    if ((cfg.seize && !kmgr.trace.interrupt()) || !kmgr.trace.waitSyscall())
    {
        KITTY_LOGE("Failed to interrupt process.");
        kmgr.trace.detach();
        return false;
    }

    KITTY_LOGI("Interrupted process successfully.");

    KITTY_LOGI("Initializing Injector...");

    bool isLocal64bit = !KittyMemoryEx::getMaps(getpid(), EProcMapFilter::Contains, "/lib64/").empty();
    bool isRemote64bit = !KittyMemoryEx::getMaps(pid, EProcMapFilter::Contains, "/lib64/").empty();
    if (isLocal64bit != isRemote64bit)
    {
        KITTY_LOGE("Injector is %sbit but target app is %sbit!",
                   isLocal64bit ? "64" : "32",
                   isRemote64bit ? "64" : "32");
        kmgr.trace.detach();
        return false;
    }

    // after interrupting early, we can take out time to initialze the injector.
    KittyInjector injector{};
    if (!kmgr.initialize(pid, EK_MEM_OP_SYSCALL, true) || !injector.init(&kmgr, cfg))
    {
        KITTY_LOGE("Couldn't initialize injector.");
        kmgr.trace.detach();
        return false;
    }

    KITTY_LOGI("Injector Initialized.");

    bool emulate = false;
    for (auto &it : libs)
    {
        if (!injector.validateElf(it, nullptr, emulate ? nullptr : &emulate))
        {
            KITTY_LOGI("Injector: Failed to validate %s!", it.c_str());
            kmgr.trace.detach();
            return false;
        }
    }

    auto tm_start = std::chrono::high_resolution_clock::now();

    if (cfg.bp)
    {
        KITTY_LOGI("Injector: Setting up breakpoint...");

        if (!injector.waitBreakpoint(emulate))
        {
            KITTY_LOGE("Injector: Failed to wait for breakpoint!");
            kmgr.trace.detach();
            return false;
        }

        KITTY_LOGI("Injector: Breakpoint triggered successfully.");
    }

    std::string cmdline;
    std::string cmdlinePath = KittyUtils::String::fmt("/proc/%d/cmdline", pid);
    KittyIOFile::readFileToString(cmdlinePath, &cmdline);
    KITTY_LOGI("Proccess current cmdline (\"%s\").", cmdline.c_str());

    for (auto &it : libs)
    {
        KITTY_LOGI("===== Injecting %s...", it.c_str());

        auto info = injector.inject(it);
        if (!info.is_valid())
        {
            KITTY_LOGE("===== Failed to inject %s!", it.c_str());
            kmgr.trace.detach();
            return false;
        }

        KITTY_LOGI("===== Successfully injected %s.", it.c_str());

        out->push_back(info);
    }

    inj_ms = std::chrono::high_resolution_clock::now() - tm_start;

    kmgr.trace.waitSyscall();
    kmgr.trace.detach();

    return true;
}

bool inject_watch(const std::vector<std::string> &libs, inject_elf_config_t &cfg, std::vector<inject_elf_info_t> *out)
{
    bool result = false;
    int pid = 0;
    errno = 0;
    Utils::am_process_start([&](const android_event_am_proc_start *event) -> bool {
        if (int(cfg.package.length()) != event->process_name.length)
            return false;
        if (strncmp(event->process_name.data, cfg.package.c_str(), cfg.package.length()))
            return false;

        pid = event->pid.data;

        // inject on any event that isn't related to fd or timer
        // this delays injection for linker init
        // not used when --bp is used

        if (!cfg.bp)
        {
            int inotifyFd = inotify_init1(IN_CLOEXEC);
            if (inotifyFd < 0)
            {
                KITTY_LOGE("Failed to initialize inotify. \"%s\".", strerror(errno));
                exit(1);
            }

            auto proc_dir = KittyUtils::String::fmt("/proc/%d", pid);
            bool proc_dir_watch = Utils::inotify_watch_directory(inotifyFd,
                                                                 proc_dir,
                                                                 IN_ALL_EVENTS,
                                                                 [&](int, struct inotify_event *iev) -> bool {
                                                                     /*KITTY_LOGI("mask=0x%x | event=%s",
                                                                                iev->mask,
                                                                                iev->len > 0 ? iev->name : "null");*/

                                                                     // skip fd event
                                                                     if (iev->len >= 2 &&
                                                                         *(uint16_t *)iev->name == 0x6466)
                                                                         return false;

                                                                     // skip timerslack event
                                                                     if (iev->len >= 4 &&
                                                                         *(uint32_t *)iev->name == 0x656d6974)
                                                                         return false;

                                                                     return true;
                                                                 });

            close(inotifyFd);

            if (!proc_dir_watch)
            {
                KITTY_LOGE("Failed to add watch on process directory. last error = %s.", strerror(errno));
                exit(1);
            }
        }

        if (cfg.delay > 0)
            SLEEP_MICROS(cfg.delay);

        result = inject(pid, libs, cfg, out);

        return true;
    });

    if (pid <= 0)
    {
        KITTY_LOGE("Failed to monitor process start. (\"%s\").", strerror(errno));
        exit(1);
    }

    return result;
}
