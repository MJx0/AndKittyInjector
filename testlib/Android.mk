LOCAL_PATH := $(call my-dir)

## Example exec
include $(CLEAR_VARS)

LOCAL_MODULE := injtest

# add -DkITTYMEMORY_DEBUG for debug outputs
LOCAL_CPPFLAGS += -std=c++17

LOCAL_SRC_FILES := example.cpp

include $(BUILD_SHARED_LIBRARY)