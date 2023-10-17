#include <thread>

#include <string>
#include <cstdint>
#include <vector>

#include <android/log.h>

#include <dlfcn.h>
#include <link.h>

#define KITTY_LOG_TAG "KittyMemoryEx"

#define KITTY_LOGI(fmt, ...) ((void)__android_log_print(ANDROID_LOG_INFO, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#define KITTY_LOGE(fmt, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#define KITTY_LOGW(fmt, ...) ((void)__android_log_print(ANDROID_LOG_WARN, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))

int hi = 0;

__attribute__((constructor)) void init()
{
    hi = 1;
    KITTY_LOGI("hi init %d", hi);
}

void hide_check_thread()
{
    KITTY_LOGI("===============================");
    KITTY_LOGI("Printing solist in 2 seconds...");

    std::this_thread::sleep_for(std::chrono::seconds(2));

    dl_iterate_phdr([] (struct dl_phdr_info *info, size_t, void *) -> int {
        KITTY_LOGI("%s", info->dlpi_name ? info->dlpi_name : "null");
        return 0;
    }, nullptr);
}

extern "C" __attribute__((used)) void hide_init()
{
    KITTY_LOGI("old hi %d", hi);

    hi = 2;
    KITTY_LOGI("hi hide_init %d", hi);

    std::thread(hide_check_thread).detach();
}