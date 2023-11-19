#include <thread>

#include <string>
#include <cstdint>
#include <vector>

#include <android/log.h>
#include <jni.h>

#include <dlfcn.h>
#include <link.h>

#define KITTY_LOG_TAG "KittyMemoryEx"

#define KITTY_LOGI(fmt, ...) ((void)__android_log_print(ANDROID_LOG_INFO, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#define KITTY_LOGE(fmt, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#define KITTY_LOGW(fmt, ...) ((void)__android_log_print(ANDROID_LOG_WARN, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))

// Don't start a thread in library constructor, do it in JNI_OnLoad instead.
__attribute__((constructor)) void init()
{
    KITTY_LOGI("hi ctor");
}

void print_solist_thread()
{
    KITTY_LOGI("===============================");
    KITTY_LOGI("Printing solist in 3 seconds...");

    std::this_thread::sleep_for(std::chrono::seconds(3));

    dl_iterate_phdr([] (struct dl_phdr_info *info, size_t, void *) -> int {
        KITTY_LOGI("%p -> %s", (void*)info->dlpi_addr, info->dlpi_name ? info->dlpi_name : "null");
        return 0;
    }, nullptr);
}

extern "C" jint JNIEXPORT JNI_OnLoad(JavaVM* vm, void *key)
{
    KITTY_LOGI("========================");
    KITTY_LOGI("JNI_OnLoad(%p, %p)", vm, key);

    // check if called by injector
    if (key != (void*)1337)
        return JNI_VERSION_1_6;

    KITTY_LOGI("JNI_OnLoad called by injector.");

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) == JNI_OK)
    {
        KITTY_LOGI("JavaEnv: %p.", env);
        // ...
    }
    
    std::thread(print_solist_thread).detach();
    
    return JNI_VERSION_1_6;
}