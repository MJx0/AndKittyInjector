LOCAL_PATH := $(call my-dir)

KITTYMEMORY_PATH = $(LOCAL_PATH)/../KittyMemoryEx/KittyMemoryEx
KITTYMEMORY_SRC = $(wildcard $(KITTYMEMORY_PATH)/*.cpp)

## Example exec
include $(CLEAR_VARS)

LOCAL_MODULE := AndKittyInjector

# add -DkITTYMEMORY_DEBUG for debug outputs
LOCAL_CPPFLAGS += -std=c++17 -DkNO_KEYSTONE

LOCAL_SRC_FILES := src/main.cpp $(wildcard src/Injector/*.cpp) $(KITTYMEMORY_SRC)

LOCAL_C_INCLUDES += $(KITTYMEMORY_PATH)/../

include $(BUILD_EXECUTABLE)