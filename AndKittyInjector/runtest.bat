@ECHO OFF

SET "INJECTOR_ARCH=arm64"
SET "INJECTOR_NAME=AndKittyInjector"
SET "INJECTOR_PATH=/data/local/tmp/AndKittyInjector"

SET "APP=com.kiloo.subwaysurf"

:: test lib prints hello world to ( logcat -s "KittyMemoryEx" )
SET "LIB_ARCH=arm64"
SET "LIB_PATH=/data/local/tmp/injtest.so"

ECHO INJECTOR_PATH = %INJECTOR_PATH%
ECHO INJECTOR_ARCH = %INJECTOR_ARCH%
ECHO APP = %APP%
ECHO LIB_ARCH = %LIB_ARCH%
ECHO LIB_PATH = %LIB_PATH%

ECHO =========== PUSH ===========

IF "%INJECTOR_ARCH%"=="arm" adb push libs/armeabi-v7a/%INJECTOR_NAME% %INJECTOR_PATH%
IF "%INJECTOR_ARCH%"=="arm64" adb push libs/arm64-v8a/%INJECTOR_NAME% %INJECTOR_PATH%
IF "%INJECTOR_ARCH%"=="x86" adb push libs/x86/%INJECTOR_NAME% %INJECTOR_PATH%
IF "%INJECTOR_ARCH%"=="x86_64" adb push libs/x86_64/%INJECTOR_NAME% %INJECTOR_PATH%

IF "%LIB_ARCH%"=="arm" adb push injtest/armeabi-v7a/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="arm64" adb push injtest/arm64-v8a/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="x86" adb push injtest/x86/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="x86_64" adb push injtest/x86_64/libinjtest.so %LIB_PATH%

ECHO =========== INJECT ===========

adb shell "su -c 'kill $(pidof %INJECTOR_NAME%) > /dev/null 2>&1'"

:: exec perm
adb shell "su -c 'chmod 755 %INJECTOR_PATH%'"

:: using -dl_memfd -hide_maps -hide_solist -watch
:: native injection might not need -delay when using -watch
:: unless you try to inject emulated lib with NativeBridge then you will need some delay
SET NATIVE_CMD=adb shell "su -c './%INJECTOR_PATH% -pkg %APP% -lib %LIB_PATH% -dl_memfd -hide_maps -hide_solist -watch'"

:: using -dl_memfd -hide_maps -hide_solist -watch -delay 800000 (800ms) increase if needed
:: recommended for emulated injection with NatievBridge
:: -hide_solist here will be using memory scans to find solist, might not be perfect but it works most of time
SET EMULATED_CMD=adb shell "su -c './%INJECTOR_PATH% -pkg %APP% -lib %LIB_PATH% -dl_memfd -hide_maps -hide_solist -watch -delay 800000'"

IF "%INJECTOR_ARCH%"=="%LIB_ARCH%" (%NATIVE_CMD%) ELSE (%EMULATED_CMD%)

ECHO ========= CHECKING MAPS =========

adb shell "su -c 'cat /proc/$(pidof %APP%)/maps | grep %LIB_PATH%'"
adb shell "su -c 'cat /proc/$(pidof %APP%)/maps | grep memfd'"

PAUSE