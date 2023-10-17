LOCAL_PATH := $(call my-dir)

KITTYMEMORY_PATH = $(LOCAL_PATH)/../KittyMemoryEx/KittyMemoryEx
KITTYMEMORY_SRC  = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

XDL_PATH = $(LOCAL_PATH)/src/xdl
XDL_SRC  = $(wildcard $(XDL_PATH)/*.c)

## Example exec
include $(CLEAR_VARS)

LOCAL_MODULE := AndKittyInjector

# add -DkITTYMEMORY_DEBUG for debug outputs
# use logcat logging to get outputs in realtime
LOCAL_CPPFLAGS += -std=c++17 -DkNO_KEYSTONE #-DkUSE_LOGCAT -DkITTYMEMORY_DEBUG

LOCAL_C_INCLUDES += $(KITTYMEMORY_PATH) $(XDL_PATH)

PROJ_SRC = $(wildcard $(LOCAL_PATH)/src/*.cpp) $(wildcard $(LOCAL_PATH)/src/Injector/*.cpp)
LOCAL_SRC_FILES := $(PROJ_SRC) $(KITTYMEMORY_SRC) $(XDL_SRC)

include $(BUILD_EXECUTABLE)