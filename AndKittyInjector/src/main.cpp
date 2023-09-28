#include <thread>

#include <string>
#include <cstdint>
#include <vector>

#include <dlfcn.h>

// include KittyMemory
#include <KittyMemoryEx/KittyMemoryMgr.hpp>

// injector
#include "Injector/KittyInjector.hpp"
KittyInjector kitInjector;

int main(int argc, char *args[])
{
    // ./exe [target process name] [library path]
    if (argc < 3)
    {
        KITTY_LOGE("Missing args.");
        return 1;
    }

    std::string processName = args[1];
    std::string libraryPath = args[2];

    // get process ID
    pid_t processID = KittyMemoryEx::getProcessID(processName);
    if (!processID)
    {
        KITTY_LOGI("Couldn't find process id of %s.", processName.c_str());
        return 1;
    }

    KITTY_LOGI("Process ID: %d", processID);
    KITTY_LOGI("Process Name: %s", processName.c_str());
    KITTY_LOGI("Library Path: %s", libraryPath.c_str());

    
    uintptr_t injectedLibBase = 0;

    //if (kitInjector.init(processID, EK_MEM_OP_SYSCALL))
    if (kitInjector.init(processID, EK_MEM_OP_IO))
    {
        injectedLibBase = kitInjector.injectLibrary(libraryPath, RTLD_NOW);
        KITTY_LOGI("Remote library: %p", (void *)injectedLibBase);
    }

    KITTY_LOGI("%s", injectedLibBase ? "Success." : "Failed.");

    return injectedLibBase ? 0 : 1;
}