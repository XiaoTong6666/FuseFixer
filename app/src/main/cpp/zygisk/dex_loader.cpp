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

#include "dex_loader.hpp"

#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "zygisk_log.hpp"

namespace {

constexpr char kLogTag[] = "FuseHide";

jobject gDexLoader = nullptr;

}  // namespace

// Held by module.cpp.
extern void* gFuseHideHandle;

namespace {

jclass FindInDex(JNIEnv* env, const char* name) {
    if (gDexLoader == nullptr) {
        return nullptr;
    }
    jclass loaderClass = env->FindClass("dalvik/system/BaseDexClassLoader");
    if (loaderClass == nullptr) {
        return nullptr;
    }
    jmethodID loadClass =
        env->GetMethodID(loaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    env->DeleteLocalRef(loaderClass);
    if (loadClass == nullptr) {
        return nullptr;
    }
    jstring className = env->NewStringUTF(name);
    jclass clazz =
        reinterpret_cast<jclass>(env->CallObjectMethod(gDexLoader, loadClass, className));
    env->DeleteLocalRef(className);
    if (clazz == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return nullptr;
    }
    return clazz;
}

// Matches HideConfigNativeBridge.java native methods.
struct NativeMethodEntry {
    const char* name;
    const char* signature;
    const char* jniSymbolSuffix;
};

constexpr NativeMethodEntry kNativeMethods[] = {
    {"getDefaultEnableHideAllRootEntries", "()Z", "getDefaultEnableHideAllRootEntries"},
    {"getDefaultHideAllRootEntriesExemptions", "()[Ljava/lang/String;",
     "getDefaultHideAllRootEntriesExemptions"},
    {"getDefaultHiddenRootEntryNames", "()[Ljava/lang/String;", "getDefaultHiddenRootEntryNames"},
    {"getDefaultHiddenRelativePaths", "()[Ljava/lang/String;", "getDefaultHiddenRelativePaths"},
    {"getDefaultHiddenPackages", "()[Ljava/lang/String;", "getDefaultHiddenPackages"},
    {"getCurrentEnableHideAllRootEntries", "()Z", "getCurrentEnableHideAllRootEntries"},
    {"getCurrentHideAllRootEntriesExemptions", "()[Ljava/lang/String;",
     "getCurrentHideAllRootEntriesExemptions"},
    {"getCurrentHiddenRootEntryNames", "()[Ljava/lang/String;", "getCurrentHiddenRootEntryNames"},
    {"getCurrentHiddenRelativePaths", "()[Ljava/lang/String;", "getCurrentHiddenRelativePaths"},
    {"getCurrentHiddenPackages", "()[Ljava/lang/String;", "getCurrentHiddenPackages"},
    {"getCurrentPackageRulePackages", "()[Ljava/lang/String;", "getCurrentPackageRulePackages"},
    {"getCurrentPackageRuleHiddenRootEntryNames", "()[Ljava/lang/String;",
     "getCurrentPackageRuleHiddenRootEntryNames"},
    {"getCurrentPackageRuleHiddenRelativePaths", "()[Ljava/lang/String;",
     "getCurrentPackageRuleHiddenRelativePaths"},
    {"applyHideConfig",
     "(Z[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;"
     "[Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V",
     "applyHideConfig"},
    {"notifyPackageSetChanged", "(Ljava/lang/String;)V", "notifyPackageSetChanged"},
};

constexpr char kJniSymbolPrefix[] =
    "Java_io_github_xiaotong6666_fusehide_config_HideConfigNativeBridge_";

}  // namespace

bool PreloadInjectedDex(JNIEnv* env, int frameworkDirFd) {
    std::vector<std::string> dexFiles;
    const int scanFd = dup(frameworkDirFd);
    DIR* dir = scanFd >= 0 ? fdopendir(scanFd) : nullptr;
    if (dir == nullptr) {
        if (scanFd >= 0) {
            close(scanFd);
        }
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "fdopendir failed: %s", strerror(errno));
        return false;
    }
    while (struct dirent* entry = readdir(dir)) {
        if (strncmp(entry->d_name, "injected", 8) == 0 &&
            strstr(entry->d_name, ".dex") != nullptr) {
            dexFiles.emplace_back(entry->d_name);
        }
    }
    closedir(dir);
    if (dexFiles.empty()) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "no injected dex in module directory");
        return false;
    }
    std::sort(dexFiles.begin(), dexFiles.end());

    const size_t count = dexFiles.size();
    std::vector<void*> data(count, nullptr);
    std::vector<size_t> sizes(count, 0);
    size_t loaded = 0;
    for (size_t i = 0; i < count; ++i) {
        const int fd = openat(frameworkDirFd, dexFiles[i].c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag, "open %s failed: %s",
                                dexFiles[i].c_str(), strerror(errno));
            continue;
        }
        struct stat st{};
        if (fstat(fd, &st) != 0 || st.st_size <= 0) {
            close(fd);
            continue;
        }
        void* mapped =
            mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapped == MAP_FAILED) {
            continue;
        }
        data[loaded] = mapped;
        sizes[loaded] = static_cast<size_t>(st.st_size);
        ++loaded;
    }
    if (loaded == 0) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed to mmap injected dex files");
        return false;
    }

    jclass loaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (loaderClass == nullptr) {
        return false;
    }
    jmethodID init =
        env->GetMethodID(loaderClass, "<init>", "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (init == nullptr) {
        env->DeleteLocalRef(loaderClass);
        return false;
    }
    jclass bufferClass = env->FindClass("java/nio/ByteBuffer");
    jobjectArray buffers = env->NewObjectArray(static_cast<jsize>(loaded), bufferClass, nullptr);
    env->DeleteLocalRef(bufferClass);
    for (size_t i = 0; i < loaded; ++i) {
        jobject buffer = env->NewDirectByteBuffer(data[i], static_cast<jlong>(sizes[i]));
        env->SetObjectArrayElement(buffers, static_cast<jsize>(i), buffer);
        env->DeleteLocalRef(buffer);
    }
    jobject loader = env->NewObject(loaderClass, init, buffers, nullptr);
    env->DeleteLocalRef(buffers);
    env->DeleteLocalRef(loaderClass);
    if (loader == nullptr) {
        if (env->ExceptionCheck()) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag, "InMemoryDexClassLoader failed");
            env->ExceptionClear();
        }
        return false;
    }
    gDexLoader = env->NewGlobalRef(loader);
    env->DeleteLocalRef(loader);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "loaded %zu injected dex files", loaded);
    return true;
}

void RegisterAllNativeMethods(JNIEnv* env) {
    if (gFuseHideHandle == nullptr || gDexLoader == nullptr) {
        return;
    }
    jclass bridge = FindInDex(env, "io.github.xiaotong6666.fusehide.config.HideConfigNativeBridge");
    if (bridge == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "HideConfigNativeBridge not found in injected dex");
        return;
    }

    JNINativeMethod methods[sizeof(kNativeMethods) / sizeof(kNativeMethods[0])];
    jsize count = 0;
    char symbol[256];
    for (const auto& entry : kNativeMethods) {
        snprintf(symbol, sizeof(symbol), "%s%s", kJniSymbolPrefix, entry.jniSymbolSuffix);
        void* fn = dlsym(gFuseHideHandle, symbol);
        if (fn == nullptr) {
            __android_log_print(ANDROID_LOG_WARN, kLogTag, "dlsym %s failed: %s", symbol,
                                dlerror());
            continue;
        }
        methods[count].name = entry.name;
        methods[count].signature = entry.signature;
        methods[count].fnPtr = fn;
        ++count;
    }
    if (count > 0) {
        env->RegisterNatives(bridge, methods, count);
        if (env->ExceptionCheck()) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag, "RegisterNatives failed");
            env->ExceptionClear();
        } else {
            __android_log_print(ANDROID_LOG_INFO, kLogTag, "registered %d native methods", count);
        }
    }
    env->DeleteLocalRef(bridge);
}

bool StartInjectedJava(JNIEnv* env) {
    if (gDexLoader == nullptr) {
        return false;
    }
    jclass entryClass = FindInDex(env, "io.github.xiaotong6666.fusehide.xposed.ZygiskEntry");
    if (entryClass == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "ZygiskEntry not found in injected dex");
        return false;
    }
    // MediaProvider has an Application by the time its FUSE JNI library is loaded.
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(entryClass);
        return false;
    }
    jmethodID currentApplication = env->GetStaticMethodID(activityThreadClass, "currentApplication",
                                                          "()Landroid/app/Application;");
    if (currentApplication == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(activityThreadClass);
        env->DeleteLocalRef(entryClass);
        return false;
    }
    jobject context = env->CallStaticObjectMethod(activityThreadClass, currentApplication);
    env->DeleteLocalRef(activityThreadClass);
    if (context == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(entryClass);
        return false;
    }
    jmethodID init = env->GetStaticMethodID(entryClass, "init", "(Landroid/content/Context;)V");
    if (init == nullptr) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(context);
        env->DeleteLocalRef(entryClass);
        return false;
    }
    env->CallStaticVoidMethod(entryClass, init, context);
    if (env->ExceptionCheck()) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "ZygiskEntry.init failed");
        env->ExceptionClear();
        env->DeleteLocalRef(context);
        env->DeleteLocalRef(entryClass);
        return false;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "ZygiskEntry.init invoked");
    env->DeleteLocalRef(context);
    env->DeleteLocalRef(entryClass);
    return true;
}
