#include "fusehide/state.hpp"

namespace fusehide {

UHasBinaryPropertyFn gUHasBinaryProperty = u_hasBinaryProperty;
HookInstaller gHookInstaller = nullptr;
JavaVM* gJavaVm = nullptr;
std::once_flag gXzCrcInitOnce;
IsAppAccessiblePathFn gOriginalIsAppAccessiblePath = nullptr;
IsPackageOwnedPathFn gOriginalIsPackageOwnedPath = nullptr;
IsBpfBackingPathFn gOriginalIsBpfBackingPath = nullptr;
void* gOriginalStrcasecmp = nullptr;
void* gOriginalEqualsIgnoreCase = nullptr;

std::atomic<int> gAppAccessibleLogCount{0};
std::atomic<int> gPackageOwnedLogCount{0};
std::atomic<int> gBpfBackingLogCount{0};
std::atomic<int> gStrcasecmpLogCount{0};
std::atomic<int> gEqualsIgnoreCaseLogCount{0};
std::atomic<int> gReplyErrFallbackLogCount{0};
std::atomic<int> gErrnoRemapLogCount{0};
std::atomic<int> gSuspiciousDirectLogCount{0};
std::mutex gUidHideCacheMutex;
std::unordered_map<uint32_t, bool> gUidHideCache;
std::shared_ptr<const HideConfig> gHideConfig = std::make_shared<HideConfig>(DefaultHideConfig());

namespace {}  // namespace

HideConfig DefaultHideConfig() {
    HideConfig config;
    config.enableHideAllRootEntries = kEnableHideAllRootEntries;
    for (const auto& value : kHideAllRootEntriesExemptions) {
        config.hideAllRootEntriesExemptions.emplace_back(value);
    }
    for (const auto& value : kHiddenRootEntryNames) {
        config.hiddenRootEntryNames.emplace_back(value);
    }
    for (const auto& value : kHiddenRelativePaths) {
        config.hiddenRelativePaths.emplace_back(value);
    }
    for (const auto& value : kHiddenPackages) {
        config.hiddenPackages.emplace_back(value);
    }
    return config;
}

std::shared_ptr<const HideConfig> CurrentHideConfig() {
    return std::atomic_load_explicit(&gHideConfig, std::memory_order_acquire);
}

void ApplyHideConfig(HideConfig config) {
    auto next = std::make_shared<const HideConfig>(std::move(config));
    std::atomic_store_explicit(&gHideConfig, std::move(next), std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideCache.clear();
    }
    DebugLogPrint(4, "applied hide config hide_all=%d exemptions=%zu roots=%zu packages=%zu",
                  CurrentHideConfig()->enableHideAllRootEntries ? 1 : 0,
                  CurrentHideConfig()->hideAllRootEntriesExemptions.size(),
                  CurrentHideConfig()->hiddenRootEntryNames.size(),
                  CurrentHideConfig()->hiddenPackages.size());
}

bool IsHiddenPackageName(std::string_view packageName) {
    const auto config = CurrentHideConfig();
    for (const auto& hiddenPackage : config->hiddenPackages) {
        if (packageName == hiddenPackage) {
            return true;
        }
    }
    return false;
}

namespace {

// Resolve uid -> packages inside the already-hooked MediaProvider process.
// We intentionally stay inside the current process and ask PackageManager instead of adding
// a separate framework hook in system_server. The injection entry point is Entry.java, which only
// loads this library into MediaProvider, so currentApplication() is available here.
// AOSP reference for the uid flowing into FUSE handlers: jni/FuseDaemon.cpp#1134 and #2121
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1134
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#2121
JNIEnv* GetJniEnv(bool* didAttach) {
    if (didAttach != nullptr) {
        *didAttach = false;
    }
    if (gJavaVm == nullptr) {
        return nullptr;
    }
    JNIEnv* env = nullptr;
    const jint status = gJavaVm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (status == JNI_OK) {
        return env;
    }
    if (status != JNI_EDETACHED) {
        return nullptr;
    }
    if (gJavaVm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        return nullptr;
    }
    if (didAttach != nullptr) {
        *didAttach = true;
    }
    return env;
}

}  // namespace

// Query PackageManager once per uid and cache the result for hot FUSE paths.
std::optional<bool> ResolveShouldHideUidWithPackageManager(uint32_t uid) {
    bool didAttach = false;
    JNIEnv* env = GetJniEnv(&didAttach);
    if (env == nullptr) {
        return std::nullopt;
    }

    auto finish = [&](std::optional<bool> value) {
        if (didAttach) {
            gJavaVm->DetachCurrentThread();
        }
        return value;
    };

    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return finish(std::nullopt);
    }
    jmethodID currentApplication = env->GetStaticMethodID(activityThreadClass, "currentApplication",
                                                          "()Landroid/app/Application;");
    if (currentApplication == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(activityThreadClass);
        return finish(std::nullopt);
    }
    jobject application = env->CallStaticObjectMethod(activityThreadClass, currentApplication);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(activityThreadClass);
        return finish(std::nullopt);
    }
    env->DeleteLocalRef(activityThreadClass);
    if (application == nullptr) {
        return finish(std::nullopt);
    }

    jclass applicationClass = env->GetObjectClass(application);
    jmethodID getPackageManager = env->GetMethodID(applicationClass, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    if (getPackageManager == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(applicationClass);
        env->DeleteLocalRef(application);
        return finish(std::nullopt);
    }
    jobject packageManager = env->CallObjectMethod(application, getPackageManager);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(applicationClass);
        env->DeleteLocalRef(application);
        return finish(std::nullopt);
    }
    env->DeleteLocalRef(applicationClass);
    env->DeleteLocalRef(application);
    if (packageManager == nullptr) {
        return finish(std::nullopt);
    }

    jclass packageManagerClass = env->FindClass("android/content/pm/PackageManager");
    jmethodID getPackagesForUid =
        env->GetMethodID(packageManagerClass, "getPackagesForUid", "(I)[Ljava/lang/String;");
    if (getPackagesForUid == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(packageManagerClass);
        env->DeleteLocalRef(packageManager);
        return finish(std::nullopt);
    }

    jobjectArray packages = static_cast<jobjectArray>(
        env->CallObjectMethod(packageManager, getPackagesForUid, (jint)uid));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(packageManagerClass);
        env->DeleteLocalRef(packageManager);
        return finish(std::nullopt);
    }
    env->DeleteLocalRef(packageManagerClass);
    env->DeleteLocalRef(packageManager);

    bool shouldHide = false;
    if (packages != nullptr) {
        const jsize count = env->GetArrayLength(packages);
        for (jsize i = 0; i < count; ++i) {
            jstring packageName = static_cast<jstring>(env->GetObjectArrayElement(packages, i));
            if (packageName == nullptr) {
                continue;
            }
            const char* packageNameChars = env->GetStringUTFChars(packageName, nullptr);
            if (packageNameChars != nullptr) {
                shouldHide = IsHiddenPackageName(packageNameChars);
                env->ReleaseStringUTFChars(packageName, packageNameChars);
            }
            env->DeleteLocalRef(packageName);
            if (shouldHide) {
                break;
            }
        }
        env->DeleteLocalRef(packages);
    }
    DebugLogPrint(4, "resolved uid=%u hide=%d", static_cast<unsigned>(uid), shouldHide ? 1 : 0);
    return finish(shouldHide);
}

}  // namespace fusehide
