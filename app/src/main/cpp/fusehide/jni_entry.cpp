#include "wrappers.hpp"

extern "C" void PostNativeInit(const char* loadedLibrary, void*) {
    if (loadedLibrary == nullptr ||
        std::strstr(loadedLibrary, fusehide::kTargetLibrary) == nullptr) {
        return;
    }
    fusehide::InstallFuseHooks();
}

std::vector<std::string> JStringArrayToVector(JNIEnv* env, jobjectArray values) {
    std::vector<std::string> out;
    if (env == nullptr || values == nullptr) {
        return out;
    }
    const jsize count = env->GetArrayLength(values);
    out.reserve(static_cast<size_t>(count));
    for (jsize i = 0; i < count; ++i) {
        jstring value = static_cast<jstring>(env->GetObjectArrayElement(values, i));
        if (value == nullptr) {
            continue;
        }
        const char* chars = env->GetStringUTFChars(value, nullptr);
        if (chars != nullptr) {
            out.emplace_back(chars);
            env->ReleaseStringUTFChars(value, chars);
        }
        env->DeleteLocalRef(value);
    }
    return out;
}

jobjectArray VectorToJavaStringArray(JNIEnv* env, const std::vector<std::string>& values) {
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray array =
        env->NewObjectArray(static_cast<jsize>(values.size()), stringClass, nullptr);
    for (jsize i = 0; i < static_cast<jsize>(values.size()); ++i) {
        jstring value = env->NewStringUTF(values[static_cast<size_t>(i)].c_str());
        env->SetObjectArrayElement(array, i, value);
        env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(stringClass);
    return array;
}

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    fusehide::gJavaVm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jboolean JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getDefaultEnableHideAllRootEntries(
    JNIEnv*, jclass) {
    return fusehide::DefaultHideConfig().enableHideAllRootEntries ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getDefaultHideAllRootEntriesExemptions(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env, fusehide::DefaultHideConfig().hideAllRootEntriesExemptions);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getDefaultHiddenRootEntryNames(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env, fusehide::DefaultHideConfig().hiddenRootEntryNames);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getDefaultHiddenRelativePaths(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env, fusehide::DefaultHideConfig().hiddenRelativePaths);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getDefaultHiddenPackages(JNIEnv* env,
                                                                                     jclass) {
    return VectorToJavaStringArray(env, fusehide::DefaultHideConfig().hiddenPackages);
}

JNIEXPORT jboolean JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getCurrentEnableHideAllRootEntries(
    JNIEnv*, jclass) {
    return fusehide::CurrentHideConfig()->enableHideAllRootEntries ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getCurrentHideAllRootEntriesExemptions(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env,
                                   fusehide::CurrentHideConfig()->hideAllRootEntriesExemptions);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getCurrentHiddenRootEntryNames(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env, fusehide::CurrentHideConfig()->hiddenRootEntryNames);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getCurrentHiddenRelativePaths(
    JNIEnv* env, jclass) {
    return VectorToJavaStringArray(env, fusehide::CurrentHideConfig()->hiddenRelativePaths);
}

JNIEXPORT jobjectArray JNICALL
Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_getCurrentHiddenPackages(JNIEnv* env,
                                                                                     jclass) {
    return VectorToJavaStringArray(env, fusehide::CurrentHideConfig()->hiddenPackages);
}

JNIEXPORT void JNICALL Java_io_github_xiaotong6666_fusehide_HideConfigNativeBridge_applyHideConfig(
    JNIEnv* env, jclass, jboolean enableHideAllRootEntries,
    jobjectArray hideAllRootEntriesExemptions, jobjectArray hiddenRootEntryNames,
    jobjectArray hiddenRelativePaths, jobjectArray hiddenPackages) {
    fusehide::HideConfig config;
    config.enableHideAllRootEntries = enableHideAllRootEntries == JNI_TRUE;
    config.hideAllRootEntriesExemptions = JStringArrayToVector(env, hideAllRootEntriesExemptions);
    config.hiddenRootEntryNames = JStringArrayToVector(env, hiddenRootEntryNames);
    config.hiddenRelativePaths = JStringArrayToVector(env, hiddenRelativePaths);
    config.hiddenPackages = JStringArrayToVector(env, hiddenPackages);
    fusehide::ApplyHideConfig(std::move(config));
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusehide_Utils_rmdir(JNIEnv* env, jclass clazz,
                                                                        jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = rmdir(c_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusehide_Utils_unlink(JNIEnv* env, jclass clazz,
                                                                         jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = unlink(c_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusehide_Utils_mkdir(JNIEnv* env, jclass clazz,
                                                                        jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = mkdir(c_path, 0777);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusehide_Utils_rename(JNIEnv* env, jclass clazz,
                                                                         jstring old_path,
                                                                         jstring new_path) {
    (void)clazz;
    const char* c_old_path = env->GetStringUTFChars(old_path, nullptr);
    const char* c_new_path = env->GetStringUTFChars(new_path, nullptr);

    jint ret = rename(c_old_path, c_new_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(old_path, c_old_path);
    env->ReleaseStringUTFChars(new_path, c_new_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusehide_Utils_create(JNIEnv* env, jclass clazz,
                                                                         jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    const int fd = open(c_path, O_CREAT | O_EXCL | O_CLOEXEC | O_RDWR, 0666);
    jint ret = 0;
    if (fd < 0) {
        ret = errno;
    } else {
        close(fd);
    }
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

}  // extern "C"

extern "C" __attribute__((visibility("default"))) void* native_init(void* api) {
    __android_log_print(4, fusehide::kLogTag, "Loaded");
    if (api != nullptr) {
        fusehide::gHookInstaller =
            reinterpret_cast<const fusehide::NativeApiEntries*>(api)->hookFunc;
    }
    return reinterpret_cast<void*>(+PostNativeInit);
}
