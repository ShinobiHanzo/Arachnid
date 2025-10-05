LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := arachnid
LOCAL_SRC_FILES := arachnid.c
LOCAL_LDLIBS := -llog -landroid
include $(BUILD_EXECUTABLE)