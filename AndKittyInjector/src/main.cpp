#include <cstring>
#include <signal.h>
#include <thread>

#include <unistd.h>

#include <cstdint>
#include <string>

#include <sys/types.h>
#include <sched.h>

#include <chrono>
#include <vector>

#include "KittyMemoryMgr.hpp"

#include "Utils/Utils.hpp"
#include <KittyUtils.hpp>

#include "Utils/argsparse.hpp"

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
#define kPROGRAM_VER "6.0.0"

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

    int target_pid = 0;
    inject_elf_config_t inj_cfg = {};

    inj_cfg.selinux_state = Utils::selinux_state();
    inj_cfg.sdk = KittyUtils::Android::getSDK();
    inj_cfg.seize = inj_cfg.sdk >= 24;
    inj_cfg.rtdl_flags = RTLD_LOCAL | RTLD_NOW;

    auto &proc_group = program.add_mutually_exclusive_group(true);
    {
        proc_group.add_argument("--pid")
            .help("Target process ID to inject into.")
            .store_into(target_pid)
            .metavar("<id>");

        proc_group.add_argument("--package")
            .help("Target package name to inject into.")
            .store_into(inj_cfg.package)
            .metavar("<name>");
    }

    std::vector<std::string> libs;
    program.add_argument("--libs")
        .help("Libraries path to be injected.")
        .required()
        .nargs(argparse::nargs_pattern::at_least_one)
        .store_into(libs)
        .metavar("<paths>");

    auto &pmon_group = program.add_mutually_exclusive_group(false);
    {
        pmon_group.add_argument("--launch").help("Launch process and inject.").store_into(inj_cfg.launch);

        pmon_group.add_argument("--watch").help("Watch for process start then inject.").store_into(inj_cfg.watch);
    }

    auto &bp_group = program.add_mutually_exclusive_group(false);
    {
        bp_group.add_argument("--bp-ld")
            .help("Inject after first native/emulated loadlibrary breakpoint hit.")
            .store_into(inj_cfg.bp);

        bp_group.add_argument("--bp-sym")
            .nargs(2)
            .metavar("<binary> <symbol>")
            .store_into(inj_cfg.bp_args)
            .help("Inject after first breakpoint on binary path and symbol name. (e.g., /libc.so malloc)");
    }

    program.add_argument("--delay")
        .help("Delay injection in microseconds.")
        .store_into(inj_cfg.delay)
        .metavar("<micros>");

    program.add_argument("--timeout")
        .help("Timeout for ptrace remote calls in milliseconds.")
        .store_into(inj_cfg.timeout)
        .metavar("<ms>");

    program.add_argument("--memfd").help("Use memfd dlopen.").store_into(inj_cfg.memfd);

    program.add_argument("--memfd-name").help("Custom memfd name instead of random.").store_into(inj_cfg.memfd_name);

    auto &free_hide_group = program.add_mutually_exclusive_group(false);
    {
        free_hide_group.add_argument("--free")
            .help("Unload library after entry point execution.")
            .store_into(inj_cfg.free);

        free_hide_group.add_argument("--hide")
            .help("Remove soinfo from solist/sonext, remap library to anonymouse memory and randomize ELF header.")
            .store_into(inj_cfg.hide);
    }

    program.add_argument("--free").help("Unload library after entry point execution.").store_into(inj_cfg.free);

    program.add_argument("--hide")
        .help("Remove soinfo from solist/sonext, remap library to anonymouse memory and randomize ELF header.")
        .store_into(inj_cfg.hide);

    try
    {
        program.parse_args(argc, args);

        if ((inj_cfg.launch || inj_cfg.watch) && target_pid != 0)
        {
            KITTY_LOGE("Can't use --pid with --launch or --watch");
            return 1;
        }

        if (target_pid != 0 && inj_cfg.package.empty())
        {
            inj_cfg.package = KittyMemoryEx::getProcessName(target_pid);
        }

        if (!inj_cfg.memfd && !inj_cfg.memfd_name.empty())
        {
            KITTY_LOGE("--memfd-name requires --memfd to be enabled!");
            return 1;
        }

        inj_cfg.bp |= (inj_cfg.bp_args.size() == 2);
    }
    catch (const std::exception &err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    KITTY_LOGI("======== INJECTION ARGS ========");
    {
        KITTY_LOGI("SELinux: %s", Utils::selinux_state_tostr(inj_cfg.selinux_state).c_str());
        KITTY_LOGI("Arch: %s", EMachineToStr(kInjectorEM).c_str());
        if (target_pid != 0)
        {
            KITTY_LOGI("ProcessId: %d", target_pid);
        }
        KITTY_LOGI("Package: %s", inj_cfg.package.c_str());
        KITTY_LOGI("SDK: %d", inj_cfg.sdk);
        KITTY_LOGI("Launch: %d", inj_cfg.launch ? 1 : 0);
        KITTY_LOGI("Watch: %d", inj_cfg.watch ? 1 : 0);
        KITTY_LOGI("Memfd: %d", inj_cfg.memfd ? 1 : 0);
        KITTY_LOGI("Free: %d", inj_cfg.free);
        KITTY_LOGI("Hide: %d", inj_cfg.hide ? 1 : 0);
        KITTY_LOGI("Breakpoint-ld: %d", (inj_cfg.bp && inj_cfg.bp_args.empty()) ? 1 : 0);
        KITTY_LOGI("Breakpoint-sym: %s",
                   inj_cfg.bp_args.empty() ? "0"
                                           : KittyUtils::String::fmt("[Bin=\"%s\"|Sym=\"%s\"]",
                                                                     inj_cfg.bp_args[0].c_str(),
                                                                     inj_cfg.bp_args[1].c_str())
                                                 .c_str());
        KITTY_LOGI("Delay: %dus", inj_cfg.delay);
        KITTY_LOGI("Timeout: %dms", inj_cfg.timeout);
        for (size_t i = 0; i < libs.size(); i++)
        {
            KITTY_LOGI("Library[%d]: %s", int(i + 1), libs[i].c_str());
        }
    }
    KITTY_LOGI("================================");

    std::vector<inject_elf_info_t> injected_libs_info = {};
    bool injection_ok = false;

    if (inj_cfg.launch || inj_cfg.watch)
    {
        KITTY_LOGI("Monitoring %s...", inj_cfg.package.c_str());

        injection_ok = inject_watch(libs, inj_cfg, &injected_libs_info);
    }
    else
    {
        if (inj_cfg.delay > 0)
            SLEEP_MICROS(inj_cfg.delay);

        int app_pid = target_pid != 0 ? target_pid : KittyMemoryEx::getProcessID(inj_cfg.package);
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

        if (inj_cfg.launch || inj_cfg.watch)
        {
            if (Utils::android_stop_app(inj_cfg.package))
            {
                KITTY_LOGI("Force stopped target process.");
            }
        }

        exit(1);
    }

    KITTY_LOGI("Injected %d %s successfully.",
               int(injected_libs_info.size()),
               injected_libs_info.size() > 1 ? "libraries" : "library");

    KITTY_LOGI("Injection succeeded.");

    if (inj_ms.count() > 0)
        KITTY_LOGI("Injection took %.2f MS.", inj_ms.count());

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

    // Stop only the main thread (seize + interrupt).
    // A whole-process SIGSTOP would freeze a sibling that holds g_dl_mutex,
    // after which our  remote dlopen on the main thread blocks forever on that lock.
    // Leaving siblings running lets the lock holder finish and release it.
    errno = 0;
    bool attached = cfg.seize = cfg.sdk >= 21 && kmgr.trace.seize(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    if (!attached)
    {
        attached = kmgr.trace.attach(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
    }

    if (!attached)
    {
        KITTY_LOGE("Failed to attach to target process.");
        return false;
    }

    if (cfg.seize && !kmgr.trace.stop())
    {
        KITTY_LOGE("Failed to interrupt target process.");
        kmgr.trace.detach();
        return false;
    }

    KITTY_LOGI("Attached to target process successfully.");

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

    // After interrupting early, we can take our time to initialze the injector.
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
            KITTY_LOGI("Failed to validate [%s]!", it.c_str());
            kmgr.trace.detach();
            return false;
        }
    }

    auto tm_start = std::chrono::high_resolution_clock::now();

    if (cfg.bp || emulate)
    {
        if (!cfg.bp && emulate)
        {
            KITTY_LOGI("Checking NativeBridgestate...");

            if (!injector.waitNbInit())
            {
                KITTY_LOGE("Failed to wait for NativeBridge initialization!");
                return false;
            }

            KITTY_LOGI("NativeBridgeState checked successfully.");
        }
        else
        {
            KITTY_LOGI("Setting up breakpoint...");

            if (!injector.waitBreakpoint(emulate))
            {
                KITTY_LOGE("Failed to wait for breakpoint!");
                kmgr.trace.detach();
                return false;
            }

            KITTY_LOGI("Breakpoint triggered successfully.");
        }
    }

    std::string cmdline, ctx;
    KittyIOFile::readFileToString(KittyUtils::String::fmt("/proc/%d/attr/current", pid), &ctx);
    KittyIOFile::readFileToString(KittyUtils::String::fmt("/proc/%d/cmdline", pid), &cmdline);
    KITTY_LOGI("Process current [cmdline=\"%s\" | context=\"%s\"].",
               cmdline.empty() ? "" : cmdline.c_str(),
               ctx.empty() ? "" : ctx.c_str());

    for (auto &it : libs)
    {
        KITTY_LOGI("===== Injecting [%s]...", it.c_str());

        auto info = injector.inject(it);
        if (!info.is_valid())
        {
            KITTY_LOGE("===== Failed to inject [%s]!", it.c_str());
            kmgr.trace.detach();
            return false;
        }

        KITTY_LOGI("===== Successfully injected [%s].", it.c_str());

        out->push_back(info);
    }

    inj_ms = std::chrono::high_resolution_clock::now() - tm_start;

    if (!kmgr.trace.waitSyscall())
    {
        KITTY_LOGE("Failed to wait syscall for detach!");
        return false;
    }

    if (!kmgr.trace.detach())
    {
        KITTY_LOGE("Failed to detach!");
        return false;
    }

    KITTY_LOGI("Detached from target process successfully.");

    return true;
}

bool inject_watch(const std::vector<std::string> &libs, inject_elf_config_t &cfg, std::vector<inject_elf_info_t> *out)
{
    bool result = false;
    int pid = 0;
    int launchTries = 0;
    errno = 0;

    auto launchFresh = [&cfg]() {
        std::thread([&cfg]() -> void {
            if (!KittyMemoryEx::getProcessIDs(cfg.package).empty())
            {
                Utils::android_stop_app(cfg.package);
                SLEEP_SECONDS(1); // 1s settle after a force-stop
            }
            if (cfg.launch && !Utils::android_launch_app(cfg.package))
            {
                KITTY_LOGE("Failed to launch app [%s]!", cfg.package.c_str());
                exit(1);
            }
        }).detach();
    };

    Utils::am_process_start_callback(
        // init: monitor is live here, so stop/launch can't race the spawn event.
        [&] { launchFresh(); },
        // process start callback
        [&](const android_event_am_proc_start *event) -> bool {
            if (int(cfg.package.length()) != event->process_name.length)
                return false;

            if (strncmp(event->process_name.data, cfg.package.c_str(), cfg.package.length()))
                return false;

            pid = event->pid.data;

            if (cfg.delay > 0)
            {
                KITTY_LOGI("Waiting for the delay...");
                SLEEP_MICROS(cfg.delay);
            }

            auto spec_begin = std::chrono::steady_clock::now();
            bool canLog = true;
            while (true)
            {
                bool dead = kill(pid, 0) != 0;
                bool stuck = std::chrono::steady_clock::now() - spec_begin > std::chrono::seconds(5);
                if (dead || stuck)
                {
                    canLog = true;

                    KITTY_LOGW("Process %d %s before injection, Still monitoring...", pid, dead ? "exited" : "stalled");

                    pid = 0;

                    if (cfg.launch && ++launchTries <= 5)
                        launchFresh();

                    return false; // keep monitoring for the next spawn
                }

                if (cfg.selinux_state == SELinuxState::Disabled)
                    break;

                if (canLog)
                {
                    KITTY_LOGI("Waiting for app to leave zygote domain...");
                    canLog = false;
                }

                if (Utils::is_app_specialized(pid))
                    break;

                sched_yield();
            }

            result = inject(pid, libs, cfg, out);

            return true;
        });

    if (pid <= 0)
    {
        KITTY_LOGE("Failed to monitor process start. strerror=\"%s\".", strerror(errno));
        exit(1);
    }

    return result;
}
