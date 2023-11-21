# AndKittyInjector

Android shared library injector based on ptrace with help of [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx).

Requires C++11 or above.</br>
Inject from /data for Android

<h2> Support: </h2>

- [x] Tested on Android 5.0  ~ 14
- [x] ABI arm, arm64, x86, x86_64
- [x] Inject emulated arm64 & arm32 via libhoudini.so or libndk_translation.so
- [x] Bypass android linker namespace restrictions
- [x] memfd dlopen support
- [x] App launch monitor
- [x] Hide lib segments from /maps
- [x] Hide lib from linker solist ( dladdr & dl_iterate_phdr )

<h2> How to use: </h2>

Make sure to chmod +x or 755

```text
Usage: ./path/to/AndKittyInjector [-h] [-pkg] [-pid] [-lib] [ options ]

Required arguments:
   -pkg                Target app package.
   
   -lib                Library path to inject.

Optional arguments:
   -h, --help          show available arguments.
   
   -pid                Target app pid.
   
   -dl_memfd           Use memfd_create & dlopen_ext to inject library, useful to bypass path restrictions.

   -hide_maps          Try to hide lib segments from /proc/[pid]/maps.

   -hide_solist        Try to remove lib from linker or NativeBridge solist.
   
   -watch              Monitor process launch then inject, useful if you want to inject as fast as possible.
   
   -delay              Set a delay in microseconds before injecting.
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

- When using -watch to inject as soon as the target app launches, you may need to use -delay as well, especially when injecting emulated lib.

- When using -dl_memfd and it fails then legacy dlopen will be called.

<h2> Compile: </h2>

- Make sure to have NDK, cmake and make installed and added to OS environment path.
- Set NDK_HOME to point to NDK folder
- You can check both [ndk-build.bat](AndKittyInjector/ndk-build.bat) and [cmake-build.bat](AndKittyInjector/cmake-build.bat)

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
