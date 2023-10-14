#include <thread>

#include <unistd.h>

#include <cstdint>
#include <string>

#include <sys/inotify.h>
#include <sys/types.h>

#include <chrono>
#define SLEEP_MICROS(x) { std::this_thread::sleep_for(std::chrono::microseconds(x)); }

#include <KittyUtils.hpp>

// parse cmd args
#include "KittyCmdln.hpp"

// injector
#include "Injector/KittyInjector.hpp"
KittyInjector kitInjector;

uintptr_t   inject_lib          (int pid, const std::string &lib, bool use_memfd);
std::string get_app_apk         (std::string pkgName);
void        list_files_callback (const std::string &path, std::function<void(const std::string &)> cb);
int         sync_watch_callback (const std::string &path, uint32_t mask, std::function<bool(int wd, struct inotify_event* event)> cb);

bool bHelp = false;

int main(int argc, char* args[])
{
    KittyCmdln cmdline(argc, args);

    cmdline.setUsage("Usage: ./path/to/AndKittyInjector [-h] [-pkg] [-pid] [-lib] [ options ]");

    cmdline.addCmd("-h", "--help", "show available arguments", false, [&cmdline]() { KITTY_LOGI("\n%s", cmdline.toString().c_str()); bHelp = true; });

    char appPkg[0xff] = { 0 }; // required
    cmdline.addScanf("-pkg", "", "Target app package.", true, "%s", appPkg);

    int appPID = 0; // optional
    cmdline.addScanf("-pid", "", "Target app pid.", false, "%d", &appPID);

    char libPath[0xff] = { 0 }; // required
    cmdline.addScanf("-lib", "", "Library path to inject.", true, "%s", libPath);

    bool use_dl_memfd = false; // optional
    cmdline.addFlag("-dl_memfd", "", "Use memfd_create & dlopen_ext to inject library, useful to bypass path restrictions.", false, &use_dl_memfd);

    bool use_watch_app = false; // optional
    cmdline.addFlag("-watch", "", "Monitor app launch by watching app's apk access then inject, useful if you want to inject as fast as possible.", false, &use_watch_app);

    unsigned int inj_delay = 0; // optional
    cmdline.addScanf("-delay", "", "Set a delay in microseconds before injecting.", false, "%d", &inj_delay);

    cmdline.parseArgs();

    if (bHelp)
        return 0;

    if (!cmdline.requiredCmdsCheck())
    {
        KITTY_LOGE("Required arguments missing. see -h.");
        exit(1);
    }

    if (appPID > 0)
        KITTY_LOGI("Process ID: %d", appPID);

    KITTY_LOGI("Process Name: %s", appPkg);
    KITTY_LOGI("Library Path: %s", libPath);

    KITTY_LOGI("Use memfd dlopen: %d", use_dl_memfd ? 1 : 0);
    KITTY_LOGI("Use app watch: %d", use_watch_app ? 1 : 0);
    KITTY_LOGI("Inject delay: %d", inj_delay);

    uintptr_t injectedLibBase = 0;

    // process already alive and set
    if (appPID > 0)
    {
        if (inj_delay > 0)
            SLEEP_MICROS(inj_delay);

        injectedLibBase = inject_lib(appPID, libPath, use_dl_memfd);
    }
    // PTRACE_O_TRACEFORK on zygote is overkill for me xD
    // instead watch for IN_OPEN event on app's base.apk then inject
    // if it can't find pid then you may need to use some -delay
    else if (use_watch_app)
    {
        if (KittyMemoryEx::getProcessID(appPkg) > 0)
        {
            KITTY_LOGE("-watch is used but the target process is already alive.");
            exit(1);
        }

        std::string appApk = get_app_apk(appPkg);

        KITTY_LOGI("Monitoring %s...", appApk.c_str());

        int watch = sync_watch_callback(appApk, IN_OPEN, [&](int wd, struct inotify_event* event) -> bool {
            // check watch descriptors
            if (wd != event->wd || !(event->mask & IN_OPEN))
                return false;

            if (inj_delay > 0)
                SLEEP_MICROS(inj_delay);

            int tries = 0, limit = 1000;
            do {
                errno = 0, tries++;
                appPID = KittyMemoryEx::getProcessID(appPkg);
                // 1ms each try
                if (appPID <= 0) { SLEEP_MICROS(1000); }
                if (tries >= limit) { break; }
            } while (appPID <= 0);

            if (appPID <= 0) {
                KITTY_LOGE("Couldn't find process id of %s, maybe add -delay.", appPkg);
                exit(1);
            }

            injectedLibBase = inject_lib(appPID, libPath, use_dl_memfd);

            return true;
        });

        if (watch == -1)
        {
            KITTY_LOGE("Failed to add watch on app's apk file.");
            exit(1);
        }
    }
    // find pid and inject
    else
    {
        if (inj_delay > 0)
            SLEEP_MICROS(inj_delay);

        appPID = KittyMemoryEx::getProcessID(appPkg);
        if (appPID <= 0) {
            KITTY_LOGE("Couldn't find process id of %s.", appPkg);
            exit(1);
        }

        injectedLibBase = inject_lib(appPID, libPath, use_dl_memfd);
    }

    if (!injectedLibBase)
    {
        KITTY_LOGE("Injection failed.");
        exit(1);
    }

    KITTY_LOGI("Injection successed.");
    return 0;
}

uintptr_t inject_lib(int pid, const std::string& lib, bool use_memfd)
{
    if (pid <= 0)
    {
        KITTY_LOGE("Invalid PID.");
        return 0;
    }

    // stop target app then take our sweet time to initialize injector
    bool stopped = kill(pid, SIGSTOP) != -1;
    bool init = kitInjector.init(pid, EK_MEM_OP_SYSCALL);
    if (stopped)
        kill(pid, SIGCONT);

    if (!init)
    {
        KITTY_LOGE("Couldn't initialize injector.");
        return 0;
    }

    kitInjector.attach();
    uintptr_t ret = kitInjector.injectLibrary(lib, RTLD_NOW, use_memfd);
    kitInjector.detach();

    return ret;
}

std::string get_app_apk(std::string pkgName)
{
    if (pkgName[0] != '/')
        pkgName = '/' + pkgName;

    std::string directory = "/data/app/", apk = "base.apk", ret;
    list_files_callback(directory, [&](const std::string& filePath) {
        if (KittyUtils::fileNameFromPath(filePath) == apk) {
            if (strstr(filePath.c_str(), pkgName.c_str())) {
                ret = filePath;
                return true;
            }
        }
        return false;
    });

    return ret;
}

void list_files_callback(const std::string &path, std::function<void(const std::string &)> cb)
{
    if (auto dir = opendir(path.c_str())) {
        while (auto f = readdir(dir)) {
            if (f->d_name[0] == '.') continue;
            
            if (f->d_type == DT_DIR) 
                list_files_callback(path + f->d_name + "/", cb);

            if (f->d_type == DT_REG)
                cb(path + f->d_name);
        }
        closedir(dir);
    }
}

int sync_watch_callback(
    const std::string &path, uint32_t mask, std::function<bool(int wd, struct inotify_event* event)> cb)
{
    thread_local static int inotifyFd = inotify_init1(IN_CLOEXEC);
    if (inotifyFd < 0)
        return -1;

    int wd = inotify_add_watch(inotifyFd, path.c_str(), mask);
    
    char buffer[1024] = { 0 };
    for (;;) {
        memset(buffer, 0, sizeof(buffer));
        auto bytes = KT_EINTR_RETRY(read(inotifyFd, buffer, 1024));
        if (bytes < 0)
            return -1;

        int offset = 0;
        while (offset < bytes) {
            auto event = reinterpret_cast<inotify_event*>(&buffer[offset]);

            if (cb(wd ,event))
                return 1;

            offset += offsetof(inotify_event, name) + event->len;
        }
    }

    return 0;
}