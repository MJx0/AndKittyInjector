# AndKittyInjector

Android shared library injector based on ptrace with help of [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx).

Requires C++17 or above.</br>
Inject from /data for Android

<h2> Support: </h2>

- [x] Tested on Android 5.0 ~ 16
- [x] ABI arm, arm64, x86, x86_64
- [x] Inject emulated arm64 & arm32 via libhoudini.so or libndk_translation.so
- [x] Inject multiple libs at once
- [x] Bypass android linker namespace restrictions
- [x] memfd dlopen support
- [x] Watch app launch and inject
- [x] Auto launch app and inject
- [x] Inject on dlopen breakpoint
- [x] Inject & Unload lib after entry point execution
- [x] Hide lib segments from /maps
- [x] Hide lib from native or emu linker solist ( dladdr & dl_iterate_phdr )

<h2> How to use: </h2>

Make sure to chmod +x or 755

```text
Usage: AndKittyInjector [--help] [--version] --package <name> --libs <paths>... [--launch] [--watch] [--bp] [--delay <micros>] [--memfd] [--memfd-name <name>] [--free] [--hide]

Optional arguments:
  -h, --help           shows help message and exits
  -v, --version        prints version information and exits
  --package <name>     Target package name to inject into. [required]
  --libs               Libraries path to be injected. [nargs: 1 or more] [required]
  --launch             Launch process and inject.
  --watch              Monitor process start then inject.
  --bp                 Inject after breakpoint hit.
  --delay <micros>     Delay injection in microseconds.
  --memfd              Use memfd dlopen.
  --memfd-name <name>  Set a specific name for the created memfd.
  --free               Unload library after entry point execution.
  --hide               Remove soinfo and remap library to anonymouse memory.
```

Example:
```shell
# launching app and injecting 2 libs with 1 second delay
./AndKittyInjector --package com.target.package --libs path/to/lib1 path/to/lib2 --memfd --launch --delay 1000000
```

<h2>Notes: </h2>

- Do not start a thread in library constructor, instead use JNI_OnLoad:

```cpp
extern "C" jint JNIEXPORT JNI_OnLoad(JavaVM* vm, void *key)
{
    // key 1337 is passed by injector
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

- When using --launch or --watch to inject as soon as the target app launches, you may need to use --bp or --delay as well, especially when injecting emulated lib.

- If injection fails, target app will be force stopped.

<h2> Compile: </h2>

- Make sure to have NDK, cmake and make installed and added to OS environment path.
- Set NDK_HOME to point to NDK folder

```shell
git clone --recursive https://github.com/MJx0/AndKittyInjector.git
cd AndKittyInjector/AndKittyInjector
ndk-build.bat
```

<h2>Credits: </h2>

[arminject](https://github.com/evilsocket/arminject)

[injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack)

[TinyInjector](https://github.com/shunix/TinyInjector)

[am_proc_start](https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp)
