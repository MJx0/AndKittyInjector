# AndKittyInjector

Shared library injector based on ptrace with help of [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx).

Requires C++11 or above.</br>
Inject from /data for Android

<h2> Support: </h2>

- [x] Tested on Android 5.0  ~ 13
- [x] ABI arm, arm64, x86, x86_64
- [x] Houdini support for emulators 32 & 64 bit
- [x] Inject emulated arm64 & arm32
- [x] Bypass android linker namespace restrictions
- [x] memfd dlopen support

<h2> How to use: </h2>
Make sure to chmod +x or 755

./path/to/AndKittyInjector [process name] [library path]

<h2>Credits: </h2>

[arminject](https://github.com/evilsocket/arminject)

[injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack)

[TinyInjector](https://github.com/shunix/TinyInjector)