# AndKittyInjector

AndKittyInjector is a modern ptrace-based Android shared-library injector, built on top of [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx).

Requires C++17 or newer.<br/>Inject from `/data` on Android.

## Support

- [x] Tested on Android 5.0 ~ 17
- [x] ABI arm, arm64, x86, x86_64
- [x] Inject emulated arm64 & arm32 via libhoudini.so or libndk_translation.so
- [x] Inject multiple libs at once
- [x] Bypass android linker namespace restrictions
- [x] memfd dlopen support
- [x] Watch app launch and inject
- [x] Auto launch app and inject
- [x] Inject on dlopen breakpoint, or on a specific `<binary, symbol>` breakpoint
- [x] Inject & unload lib after entry point execution
- [x] Hide lib segments from /maps
- [x] Hide lib from native or emulated linker solist (`dladdr` & `dl_iterate_phdr`)
- [x] Randomize ELF header

## How to use

Make sure to `chmod +x` or `755` the pushed binary.

```text
Usage: AndKittyInjector [--help] [--version] (--pid <id> | --package <name>) --libs <paths>...
                         [--launch | --watch] [--bp-ld | --bp-sym <binary> <symbol>]
                         [--delay <micros>] [--timeout <ms>] [--memfd] [--memfd-name <name>]
                         [--free] [--hide]

Optional arguments:
  -h, --help              shows help message and exits
  -v, --version           prints version information and exits
  --pid <id>              Target process ID to inject into. Mutually exclusive with --package,
                           and cannot be combined with --launch/--watch.
  --package <name>        Target package name to inject into. If --pid is given without
                           --package, the package name is auto-resolved from the pid.
  --libs <paths>...       Library path(s) to be injected. [nargs: 1 or more] [required]
  --launch                Launch the process, then inject.
  --watch                 Wait for the process to start, then inject.
  --bp-ld                 Inject after the first native/emulated dlopen breakpoint hit.
  --bp-sym <binary> <sym> Inject after the first breakpoint hit on `symbol` inside `binary`
                           (e.g. `/libc.so malloc`).
  --delay <micros>        Delay injection by this many microseconds.
  --timeout <ms>          Timeout for ptrace remote calls, in milliseconds.
  --memfd                 Use memfd-backed dlopen (Bypasses SELinux path restrictions).
  --memfd-name <name>     Custom name for the memfd instead of a random one. Requires --memfd.
  --free                  Unload the library after its entry point returns.
  --hide                  Remove the lib's soinfo from solist/sonext, remap its segments to
                           anonymous memory, and randomize its ELF header.
```

One of `--pid` or `--package` is required. `--libs` accepts one or more paths and each is injected in order.

### Examples

```shell
# Inject into an already-running process by PID.
./AndKittyInjector --pid 12345 --libs /data/local/tmp/libtest.so

# Launch the app, then inject two libs, using memfd dlopen, with a 1s delay and 3s remote-call timeout.
./AndKittyInjector --package com.target.package --launch --memfd --delay 1000000 --timeout 3000 --libs /data/local/tmp/lib1.so /data/local/tmp/lib2.so

# Wait for the app to be launched (by the user or the system) and inject as soon as it appears using memfd dlopen.
./AndKittyInjector --package com.target.package --watch --memfd --libs /data/local/tmp/libtest.so

# Inject as soon as the first native/emulated dlopen call happens after launch.
./AndKittyInjector --package com.target.package --launch --memfd --bp-ld --libs /data/local/tmp/libtest.so

# Inject on a breakpoint at a specific symbol in a specific binary.
./AndKittyInjector --package com.target.package --launch --memfd --libs /data/local/tmp/libtest.so --bp-sym /libc.so malloc
```

## Embedding as a library

`KittyInjector` can be used directly instead of through the CLI, e.g. from your own tool:

```cpp
#include "Injector/KittyInjector.hpp"

inject_elf_config_t cfg{};
// init config

KittyMemoryMgr kMgr;
// manual early init of kMgr.trace to stop process then take our time to kMgr.initialize(...)
kMgr.trace = KittyTraceMgr(targetPid, 0, true);
kMgr.trace.seize();      // or .attach() on older SDKs
kMgr.trace.stop();
kMgr.initialize(targetPid, EK_MEM_OP_SYSCALL, true);

KittyInjector injector;
injector.init(&kMgr, cfg);


bool needsEmulation = false;
if (!injector.validateElf("/data/local/tmp/libtest.so", nullptr, &needsEmulation))
{
    // Failed to validate lib
}

inject_elf_info_t result = injector.inject("/data/local/tmp/libtest.so");
if (result.is_valid())
{
    // result.dl_handle, result.soinfo, result.pJvm, result.pJNI_OnLoad are populated
}

kMgr.trace.detach();
```

`inject_elf_config_t` also exposes `beforeEntryPoint` / `afterEntryPoint` callbacks (invoked around the remote `JNI_OnLoad` call) if you need to run code between attach and detach.

## Notes

- Do not start a thread in the library constructor — use `JNI_OnLoad` instead:

```cpp
extern "C" jint JNIEXPORT JNI_OnLoad(JavaVM* vm, void *key)
{
    // key 1337 is passed by the injector to confirm this call came from it.
    if (key != (void*)1337)
        return JNI_VERSION_1_6;

    KITTY_LOGI("JNI_OnLoad called by injector.");

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK)
    {
        KITTY_LOGI("JavaEnv: %p.", env);
        // ...
    }

    std::thread(thread_function).detach();

    return JNI_VERSION_1_6;
}
```

- When using `--launch` or `--watch` to inject as soon as the target app launches, you may also need `--bp-ld` / `--bp-sym` or `--delay`, especially when injecting into an emulated (cross-ISA) library.
- If injection fails, the target app will be force-stopped.

## Compile

- Make sure NDK, CMake, and MAKE are installed and added to your OS's environment path.
- Set `NDK_HOME` to point to your NDK folder.

```shell
git clone --recursive https://github.com/MJx0/AndKittyInjector.git
cd AndKittyInjector/AndKittyInjector
./build.sh # or build.bat on Windows
```

`--recursive` is required for `KittyMemoryEx`.

## Credits

[arminject](https://github.com/evilsocket/arminject)

[injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack)

[TinyInjector](https://github.com/shunix/TinyInjector)

[am_proc_start](https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp)

[ReZygisk](https://github.com/PerformanC/ReZygisk)
