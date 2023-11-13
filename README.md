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

   -hide               Try to hide lib from /maps and linker solist.
   
   -watch              Monitor process launch then inject, useful if you want to inject as fast as possible.
   
   -delay              Set a delay in microseconds before injecting.
   ```

<h2>Notes: </h2>

- When using -hide do not use library constructor, instead define and export a function called hide_init

```cpp
extern "C" __attribute__((used)) void hide_init()
{
    // will be called after hide complete.
}
```

- When using -watch to inject as soon as the target app launches, you may need to use -delay as well, especially when injecting emulated lib.

- When using -dl_memfd and it fails then legacy dlopen will be called.

<h2>Credits: </h2>

[arminject](https://github.com/evilsocket/arminject)

[injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack)

[TinyInjector](https://github.com/shunix/TinyInjector)

[am_proc_start](https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp)
