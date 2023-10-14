@ECHO OFF

SET "INJECTOR_NAME=AndKittyInjector"
SET "INJECTOR_PATH=/data/local/tmp/AndKittyInjector"

SET "APP=com.kiloo.subwaysurf"

:: test lib prints hello world to ( logcat -s "KittyMemoryEx" )
SET "LIB_ARCH=arm64"
SET "LIB_PATH=/data/local/tmp/injtest.so"

ECHO INJECTOR_ARCH = %INJECTOR_ARCH%
ECHO APP = %APP%
ECHO LIB_ARCH = %LIB_ARCH%
ECHO LIB_PATH = %LIB_PATH%

IF "%LIB_ARCH%"=="arm" adb push injtest/armeabi-v7a/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="arm64" adb push injtest/arm64-v8a/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="x86" adb push injtest/x86/libinjtest.so %LIB_PATH%
IF "%LIB_ARCH%"=="x86_64" adb push injtest/x86_64/libinjtest.so %LIB_PATH%

ECHO =========== INJECTOR ===========

adb shell "su -c 'kill $(pidof %INJECTOR_PATH%) > /dev/null 2>&1'"

:: exec perm
adb shell "su -c 'chmod 755 %INJECTOR_PATH%'"

:: using -dl_memfd -watch and -delay 100000 microsecond, 100ms
adb shell "su -c './%INJECTOR_NAME% -pkg %APP% -lib %LIB_PATH% -dl_memfd -watch -delay 100000'"

ECHO ========= CHECKING MAPS =========

adb shell "su -c 'cat /proc/$(pgrep -n %APP%)/maps | grep %LIB_PATH%'"
adb shell "su -c 'cat /proc/$(pgrep -n %APP%)/maps | grep memfd'"

PAUSE