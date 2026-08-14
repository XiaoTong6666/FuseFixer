// Copyright (C) 2026 XiaoTong6666
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "dlopen_monitor.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <thread>

#include "dex_loader.hpp"
#include "dobby.h"
#include "fusehide/elf/elf_utils.hpp"
#include "zygisk_log.hpp"

// module.cpp provides these process-local values.
extern JavaVM* gVm;
extern void* gFuseHideHandle;

namespace {

constexpr char kLogTag[] = "FuseHide";
constexpr char kFuseJniMarker[] = "libfuse_jni.so";
constexpr char kFuseHideMarker[] = "libfusehide.so";
constexpr char kDoDlopenSymbol[] = "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv";

using DoDlopen = void* (*)(const char*, int, const void*, const void*);
using JniOnLoad = jint (*)(JavaVM*, void*);
using NativeInit = void* (*)(void*);
using PostNativeInit = void (*)(const char*, void*);

DoDlopen gOriginalDoDlopen = nullptr;
std::atomic_bool gFuseHideInitStarted = false;

bool MapsContains(const char* needle) {
    FILE* maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        return false;
    }
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), maps) != nullptr) {
        if (strstr(line, needle) != nullptr) {
            found = true;
            break;
        }
    }
    fclose(maps);
    return found;
}

bool IsFuseJni(const char* name) {
    return name != nullptr && std::string_view(name).ends_with(kFuseJniMarker);
}

// Matches fusehide/core/state.hpp and the LSPosed native module API layout.
struct NativeApiEntries {
    uint32_t version;
    int (*hookFunc)(void*, void*, void**);
    void* unhookFunc;
};

int DobbyHookAdapter(void* target, void* replacement, void** backup) {
    return DobbyHook(target, replacement, backup);
}

bool GetJniEnv(JNIEnv** env, bool* attached) {
    if (gVm == nullptr || env == nullptr || attached == nullptr) {
        return false;
    }
    *attached = false;
    const jint result = gVm->GetEnv(reinterpret_cast<void**>(env), JNI_VERSION_1_6);
    if (result == JNI_OK) {
        return true;
    }
    if (result != JNI_EDETACHED || gVm->AttachCurrentThread(env, nullptr) != JNI_OK) {
        return false;
    }
    *attached = true;
    return true;
}

void StartInjectedJavaWhenApplicationReady(JNIEnv* env) {
    if (StartInjectedJava(env)) {
        return;
    }
    std::thread([]() {
        JNIEnv* workerEnv = nullptr;
        if (gVm == nullptr || gVm->AttachCurrentThread(&workerEnv, nullptr) != JNI_OK ||
            workerEnv == nullptr) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                                "failed to attach Java initialization worker");
            return;
        }
        constexpr int kMaxAttempts = 100;
        for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (StartInjectedJava(workerEnv)) {
                __android_log_print(ANDROID_LOG_INFO, kLogTag,
                                    "Application ready after %d Java initialization attempts",
                                    attempt);
                gVm->DetachCurrentThread();
                return;
            }
        }
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "timed out waiting for MediaProvider Application");
        gVm->DetachCurrentThread();
    }).detach();
}

void InitFuseHideOnFuseLoaded(const char* loadedLibrary, void* loadedHandle) {
    if (gFuseHideHandle == nullptr && MapsContains(kFuseHideMarker)) {
        __android_log_print(ANDROID_LOG_INFO, kLogTag,
                            "libfusehide.so already loaded; native framework owns initialization");
        return;
    }
    if (gFuseHideHandle == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "preloaded libfusehide.so is unavailable");
        return;
    }

    bool expected = false;
    if (!gFuseHideInitStarted.compare_exchange_strong(expected, true)) {
        return;
    }

    JNIEnv* env = nullptr;
    bool attached = false;
    if (!GetJniEnv(&env, &attached)) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed to obtain JNIEnv");
        return;
    }

    auto jniOnLoad = reinterpret_cast<JniOnLoad>(dlsym(gFuseHideHandle, "JNI_OnLoad"));
    if (jniOnLoad == nullptr || jniOnLoad(gVm, nullptr) < JNI_VERSION_1_6) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "JNI_OnLoad failed for libfusehide.so");
        if (attached) {
            gVm->DetachCurrentThread();
        }
        return;
    }

    auto nativeInit = reinterpret_cast<NativeInit>(dlsym(gFuseHideHandle, "native_init"));
    if (nativeInit == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "native_init not found in libfusehide.so");
        if (attached) {
            gVm->DetachCurrentThread();
        }
        return;
    }

    static const NativeApiEntries api = {2, DobbyHookAdapter, nullptr};
    auto postNativeInit =
        reinterpret_cast<PostNativeInit>(nativeInit(const_cast<NativeApiEntries*>(&api)));
    if (postNativeInit == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "native_init returned null");
        if (attached) {
            gVm->DetachCurrentThread();
        }
        return;
    }

    RegisterAllNativeMethods(env);
    postNativeInit(loadedLibrary, loadedHandle);
    StartInjectedJavaWhenApplicationReady(env);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "FuseHide initialized after %s", loadedLibrary);

    if (attached) {
        gVm->DetachCurrentThread();
    }
}

void* HookedDoDlopen(const char* name, int flags, const void* extinfo, const void* callerAddress) {
    void* handle = gOriginalDoDlopen(name, flags, extinfo, callerAddress);
    if (handle != nullptr && IsFuseJni(name)) {
        InitFuseHideOnFuseLoaded(name, handle);
    }
    return handle;
}

}  // namespace

void InstallDlopenMonitor() {
    if (gOriginalDoDlopen != nullptr) {
        return;
    }

    auto linker = fusehide::FindModuleFromMaps("/linker64");
    if (!linker.has_value()) {
        linker = fusehide::FindModuleFromMaps("/linker");
    }
    if (!linker.has_value()) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "dynamic linker mapping not found");
        return;
    }

    auto mapped = fusehide::MapReadOnlyFile(linker->path, linker->fileOffset);
    if (!mapped.has_value()) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed to map %s", linker->path.c_str());
        return;
    }
    auto offset = fusehide::FindSymbolOffset(*mapped, kDoDlopenSymbol);
    if (!offset.has_value()) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "linker symbol not found: %s",
                            kDoDlopenSymbol);
        return;
    }

    void* target = reinterpret_cast<void*>(linker->base + *offset);
    const int result = DobbyHook(target, reinterpret_cast<void*>(HookedDoDlopen),
                                 reinterpret_cast<void**>(&gOriginalDoDlopen));
    if (result != 0 || gOriginalDoDlopen == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed to hook do_dlopen: %d", result);
        gOriginalDoDlopen = nullptr;
        return;
    }

    __android_log_print(ANDROID_LOG_INFO, kLogTag, "hooked do_dlopen at %p from %s", target,
                        linker->path.c_str());
}
