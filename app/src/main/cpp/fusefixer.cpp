#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "third_party/xz-embedded/linux_xz.h"
#ifdef __cplusplus
}
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <memory>
#include <mutex>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

// Minimal FUSE wire structs used by the reply hooks below.
struct fuse_session {};
struct fuse_req {
    struct fuse_session* se;
    uint64_t unique;
};
typedef struct fuse_req* fuse_req_t;

struct fuse_entry_param {
    uint64_t ino;
    uint64_t generation;
    struct stat attr;
    double attr_timeout;
    double entry_timeout;
    uint64_t backing_action;
    uint64_t backing_fd;
    uint64_t bpf_action;
    uint64_t bpf_fd;
};

struct fuse_entry_out;
struct fuse_entry_bpf_out;
struct fuse_dirent {
    uint64_t ino;
    uint64_t off;
    uint32_t namelen;
    uint32_t type;
    char name[];
};
struct fuse_read_out {
    uint64_t offset;
    uint32_t size;
    uint32_t padding;
};

namespace mediaprovider {
namespace fuse {

struct DirectoryEntry {
    DirectoryEntry(const std::string& name, int type) : d_name(name), d_type(type) {
    }
    const std::string d_name;
    const int d_type;
};

}  // namespace fuse
}  // namespace mediaprovider

namespace {

constexpr const char* kLogTag = "FuseFixer";
constexpr const char* kTargetLibrary = "libfuse_jni.so";
// Visible storage roots that resolve to the same subtree on the current device build.
constexpr std::string_view kVisibleStorageRoots[] = {"/storage/emulated/0"};
// Root-level directory names that should be hidden under each visible storage root.
constexpr std::string_view kHiddenRootEntryNames[] = {"xinhao"};
// Package-based policy is easier to maintain than hardcoded runtime UIDs.
constexpr std::string_view kHiddenPackages[] = {
    "com.eltavine.duckdetector",
    "io.github.xiaotong6666.fusefixer",
    "io.github.a13e300.fusefixer",
};

#if defined(NDEBUG)
constexpr bool kEnableDebugHooks = false;
#else
constexpr bool kEnableDebugHooks = true;
#endif

// Original binary directly imports u_hasBinaryProperty from libicu.so.
using UHasBinaryPropertyFn = int8_t (*)(uint32_t codePoint, int32_t which);
extern "C" int8_t u_hasBinaryProperty(uint32_t codePoint, int32_t which);
UHasBinaryPropertyFn gUHasBinaryProperty = u_hasBinaryProperty;

constexpr int32_t kUCHAR_DEFAULT_IGNORABLE_CODE_POINT = 5;

bool IsTestHiddenUid(uint32_t uid);
bool IsAnyHiddenSubtreePath(std::string_view path);
bool IsHiddenRootEntryName(std::string_view name);
bool ShouldHideTestPath(uint32_t uid, std::string_view path);
bool IsTrackedHiddenSubtreeInode(uint64_t ino);
bool RemoveTrackedHiddenSubtreeInode(uint64_t ino);

// Symbol spellings vary between libc++ and libstdc++ mangling, so keep both forms.

constexpr std::string_view kIsAppAccessiblePathSymbols[] = {
    "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt6__ndk112basic_stringIcNS3_11char_"
    "traitsIcEENS3_9allocatorIcEEEEj",
    "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt3__112basic_stringIcNS3_11char_"
    "traitsIcEENS3_9allocatorIcEEEEj",
};

constexpr std::string_view kIsPackageOwnedPathSymbols[] = {
    "_ZL21is_package_owned_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_"
    "9allocatorIcEEEES7_",
    "_ZL21is_package_owned_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_",
};

constexpr std::string_view kContainsMountSymbols[] = {
    "_ZN13mediaprovider4fuse13containsMountERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_"
    "9allocatorIcEEEE",
    "_ZN13mediaprovider4fuse13containsMountERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_"
    "9allocatorIcEEEE",
};

constexpr std::string_view kIsBpfBackingPathSymbols[] = {
    "_ZL19is_bpf_backing_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    "_ZL19is_bpf_backing_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
};

constexpr std::string_view kStrcasecmpSymbol = "strcasecmp";

constexpr std::string_view kEqualsIgnoreCaseSymbols[] = {
    "_ZN7android4base16EqualsIgnoreCaseENSt6__ndk117basic_string_viewIcNS1_11char_traitsIcEEEES5_",
    "_ZN7android4base16EqualsIgnoreCaseENSt3__117basic_string_viewIcNS1_11char_traitsIcEEEES5_",
};

using HookInstaller = int (*)(void* target, void* replacement, void** backup);
using IsAppAccessiblePathFn = bool (*)(void* fuse, const std::string& path, uint32_t uid);
using IsPackageOwnedPathFn = bool (*)(const std::string& lhs, const std::string& rhs);
using IsBpfBackingPathFn = bool (*)(const std::string& path);
using ShouldNotCacheFn = bool (*)(void* fuse, const std::string& path);
using FuseReplyErrFn = int (*)(fuse_req_t, int);
using DirectoryEntries = std::vector<std::shared_ptr<mediaprovider::fuse::DirectoryEntry>>;
using GetDirectoryEntriesFn = DirectoryEntries (*)(void* wrapper, uint32_t uid,
                                                   const std::string& path, DIR* dirp);

// These RVAs are device-specific addresses from the reverse-engineered libfuse_jni.so.
// InstallMinimalDebugHooks() and InstallAdvancedDebugHooks() use them only as a fallback when the
// safer imported-symbol path is missing or the device build routes execution through internal
// functions that are not exposed by name.
// Reverse-engineered record: is_app_accessible_path @ 0x0017bb5c.
constexpr uintptr_t kDeviceIsAppAccessiblePathOffset = 0x0017bb5c;
// Reverse-engineered record: pf_lookup @ 0x00175e48.
constexpr uintptr_t kDevicePfLookupOffset = 0x00175e48;
// Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
constexpr uintptr_t kDevicePfLookupPostfilterOffset = 0x00175f90;
// Reverse-engineered record: pf_getattr @ 0x001762bc.
constexpr uintptr_t kDevicePfGetattrOffset = 0x001762bc;
// Reverse-engineered record: ShouldNotCache @ 0x0017dc64.
constexpr uintptr_t kDeviceShouldNotCacheOffset = 0x0017dc64;
// Reverse-engineered record: MediaProviderWrapper::GetDirectoryEntries @ 0x0018a3ec.
constexpr uintptr_t kDeviceGetDirectoryEntriesOffset = 0x0018a3ec;
// Reverse-engineered record: pf_mkdir @ 0x00177050.
constexpr uintptr_t kDevicePfMkdirOffset = 0x00177050;
// Reverse-engineered record: pf_mknod @ 0x00176ba8.
constexpr uintptr_t kDevicePfMknodOffset = 0x00176ba8;
// Reverse-engineered record: pf_unlink @ 0x00177534.
constexpr uintptr_t kDevicePfUnlinkOffset = 0x00177534;
// Reverse-engineered record: pf_rmdir @ 0x00177920.
constexpr uintptr_t kDevicePfRmdirOffset = 0x00177920;
// Reverse-engineered record: pf_rename @ 0x00177ef4.
constexpr uintptr_t kDevicePfRenameOffset = 0x00177ef4;
// Reverse-engineered record: pf_create @ 0x0017a7c8.
constexpr uintptr_t kDevicePfCreateOffset = 0x0017a7c8;
// Reverse-engineered record: pf_readdir @ 0x00179c40.
constexpr uintptr_t kDevicePfReaddirOffset = 0x00179c40;
// Reverse-engineered record: pf_readdir_postfilter @ 0x00179cac.
constexpr uintptr_t kDevicePfReaddirPostfilterOffset = 0x00179cac;
// Reverse-engineered record: pf_readdirplus @ 0x0017b320.
constexpr uintptr_t kDevicePfReaddirplusOffset = 0x0017b320;
constexpr size_t kFuseEntryOutWireSize = 128;

#if defined(__LP64__)
using ElfHeader = Elf64_Ehdr;
using ElfSection = Elf64_Shdr;
using ElfSymbol = Elf64_Sym;
using ElfProgramHeader = Elf64_Phdr;
using ElfDynamic = Elf64_Dyn;
using ElfRelocationWithAddend = Elf64_Rela;
using ElfRelocationNoAddend = Elf64_Rel;
#else
using ElfHeader = Elf32_Ehdr;
using ElfSection = Elf32_Shdr;
using ElfSymbol = Elf32_Sym;
using ElfProgramHeader = Elf32_Phdr;
using ElfDynamic = Elf32_Dyn;
using ElfRelocationWithAddend = Elf32_Rel;
using ElfRelocationNoAddend = Elf32_Rel;
#endif

struct NativeApiEntries {
    uint32_t version;
    HookInstaller hookFunc;
    void* unhookFunc;
};

struct ModuleInfo {
    uintptr_t base = 0;
    std::string path;
    const ElfProgramHeader* phdrs = nullptr;
    uint16_t phnum = 0;
};

struct MappedFile {
    void* mapping = MAP_FAILED;
    size_t mappingSize = 0;
    const std::byte* data = nullptr;
    size_t size = 0;
    std::shared_ptr<std::vector<std::byte>> owned;

    MappedFile() = default;
    MappedFile(void* mapping_, size_t mappingSize_, const std::byte* data_, size_t size_)
        : mapping(mapping_), mappingSize(mappingSize_), data(data_), size(size_) {
    }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    MappedFile(MappedFile&& other) noexcept
        : mapping(other.mapping),
          mappingSize(other.mappingSize),
          data(other.data),
          size(other.size),
          owned(std::move(other.owned)) {
        other.mapping = MAP_FAILED;
        other.mappingSize = 0;
        other.data = nullptr;
        other.size = 0;
    }

    MappedFile& operator=(MappedFile&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        if (mapping != MAP_FAILED) {
            munmap(mapping, mappingSize);
        }
        mapping = other.mapping;
        mappingSize = other.mappingSize;
        data = other.data;
        size = other.size;
        owned = std::move(other.owned);
        other.mapping = MAP_FAILED;
        other.mappingSize = 0;
        other.data = nullptr;
        other.size = 0;
        return *this;
    }

    ~MappedFile() {
        if (mapping != MAP_FAILED) {
            munmap(mapping, mappingSize);
        }
    }

    const std::byte* bytes() const {
        return data;
    }
};

constexpr uint32_t kMaxGnuDebugdataOutputBytes = 16 * 1024 * 1024;
constexpr uint32_t kMaxGnuDebugdataDictBytes = 16 * 1024 * 1024;
std::once_flag gXzCrcInitOnce;

// Matches the original binary's internal ELF info structure layout.
// reads fields at offsets:
//   +0x00: hasGnuHash (byte/bool)
//   +0x01: hasDynsym (byte/bool)
//   +0x08: base (for VA→file offset delta)
//   +0x18: bias (load bias / min load VA)
//   +0x40: strtab pointer
//   +0x48: symtab pointer
//   +0x68: sysvHashNbucket
//   +0x70: sysvHashBuckets pointer
//   +0x78: sysvHashChains pointer
//   +0x80: gnuHashNbuckets
//   +0x84: gnuHashSymoffset
//   +0x88: gnuHashBloomSize
//   +0x8c: gnuHashBloomShift
//   +0x90: gnuHashBloom pointer
//   +0x98: gnuHashBuckets pointer
//   +0xa0: gnuHashChains pointer
//   +0xa8: usesRela (byte/bool)
//   +0xb0..0xdf: 3x(pointer, size, isRela) relocation table entries
struct DynamicInfo {
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t hash = 0;
    uintptr_t gnuHash = 0;
    uintptr_t jmprel = 0;
    size_t pltrelSize = 0;
    uintptr_t rela = 0;
    size_t relaSize = 0;
    uintptr_t rel = 0;
    size_t relSize = 0;
    size_t syment = sizeof(ElfSymbol);
    bool usesRela =
#if defined(__LP64__)
        true;
#else
        false;
#endif
};

struct RuntimeDynamicInfo {
    const ElfSymbol* symtab = nullptr;
    const char* strtab = nullptr;
    const uint32_t* hash = nullptr;
    const uint32_t* gnuHash = nullptr;
    uintptr_t jmprel = 0;
    size_t pltrelSize = 0;
    uintptr_t rela = 0;
    size_t relaSize = 0;
    uintptr_t rel = 0;
    size_t relSize = 0;
    size_t syment = sizeof(ElfSymbol);
    bool usesRela =
#if defined(__LP64__)
        true;
#else
        false;
#endif
};

uintptr_t RuntimePtr(uintptr_t base, uintptr_t value) {
    if (value == 0)
        return 0;
    return value < base ? base + value : value;
}

void FlushCodeRange(void* begin, void* end) {
    __builtin___clear_cache(reinterpret_cast<char*>(begin), reinterpret_cast<char*>(end));
}

HookInstaller gHookInstaller = nullptr;
JavaVM* gJavaVm = nullptr;
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
std::atomic<int> gSuspiciousDirectLogCount{0};
std::mutex gUidHideCacheMutex;
std::unordered_map<uint32_t, bool> gUidHideCache;
std::string EscapeForLog(const uint8_t* data, size_t length);

bool ShouldLogLimited(std::atomic<int>& counter, int limit = 8) {
    const int old = counter.fetch_add(1, std::memory_order_relaxed);
    return old < limit;
}

template <typename... Args>
inline void DebugLogPrint(int priority, const char* fmt, Args... args) {
    if constexpr (kEnableDebugHooks) {
        __android_log_print(priority, kLogTag, fmt, args...);
    }
}

bool IsHiddenPackageName(std::string_view packageName) {
    for (const auto& hiddenPackage : kHiddenPackages) {
        if (packageName == hiddenPackage) {
            return true;
        }
    }
    return false;
}

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

std::string DebugPreview(std::string_view value, size_t limit = 96) {
    const size_t n = value.size() < limit ? value.size() : limit;
    return EscapeForLog(reinterpret_cast<const uint8_t*>(value.data()), n);
}

bool ContainsInterestingIgnorableUtf8Bytes(std::string_view value) {
    return value.find("\xE2\x80\x8B") != std::string_view::npos ||  // U+200B
           value.find("\xE2\x80\x8C") != std::string_view::npos ||  // U+200C
           value.find("\xE2\x80\x8D") != std::string_view::npos ||  // U+200D
           value.find("\xE2\x81\xA0") != std::string_view::npos ||  // U+2060
           value.find("\xEF\xBB\xBF") != std::string_view::npos;    // U+FEFF
}

void LogSuspiciousDirectPath(const char* hookName, std::string_view path) {
    if (!ContainsInterestingIgnorableUtf8Bytes(path) ||
        !ShouldLogLimited(gSuspiciousDirectLogCount, 16)) {
        return;
    }
    __android_log_print(5, kLogTag,
                        "%s direct path still contains interesting zero-width bytes, "
                        "NeedsSanitization returned false path=%s icu=%p",
                        hookName, DebugPreview(path).c_str(),
                        reinterpret_cast<void*>(gUHasBinaryProperty));
}

// IsDefaultIgnorableCodePoint via ICU

bool IsDefaultIgnorableCodePoint(uint32_t cp) {
    return u_hasBinaryProperty(cp, kUCHAR_DEFAULT_IGNORABLE_CODE_POINT) != 0;
}

// Logging helpers match the original log format closely enough to compare traces.

// Escape for logging: printable ASCII as-is, else \xHH.
// Original builds a std::string internally for the escaped form.
std::string EscapeForLog(const uint8_t* data, size_t length) {
    std::string out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        const uint8_t ch = data[i];
        if (ch >= 0x20 && ch <= 0x7e) {
            out.push_back(static_cast<char>(ch));
        } else {
            char escaped[5] = {};
            std::snprintf(escaped, sizeof(escaped), "%02x", ch);
            out += "\\x";
            out += escaped;
        }
    }
    return out;
}

// Original logs at level 5 (WARN), with format "invalid char at %zu-%zu : %s"
// and escapes the ENTIRE input string, not just the invalid range.
void LogInvalidUtf8(const uint8_t* data, size_t dataLen, size_t begin, size_t end) {
    const std::string escaped = EscapeForLog(data, dataLen);
    __android_log_print(5, kLogTag, "invalid char at %zu-%zu : %s", begin, end, escaped.c_str());
}

// Inline UTF-8 decoder that mirrors the hand-rolled logic seen in the device binary.
// The reverse-engineered build validates 3-byte and 4-byte sequences through internal lookup
// tables; here we express the same rules with explicit range checks.

// Returns: true if a valid code point was decoded. Sets *cp and *width.
// On failure, returns false. Caller decides how to handle invalid bytes.
bool DecodeUtf8CodePoint(const uint8_t* data, size_t len, size_t index, uint32_t* cp,
                         size_t* width) {
    if (index >= len)
        return false;

    const uint8_t b0 = data[index];
    if (b0 < 0x80) {
        *cp = b0;
        *width = 1;
        return true;
    }

    if (index + 1 >= len)
        return false;

    if (b0 < 0xe0) {
        if (b0 <= 0xc1)
            return false;  // overlong
        const uint8_t b1 = data[index + 1];
        if ((b1 ^ 0x80) >= 0x40)
            return false;
        *cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
        *width = 2;
        return true;
    }

    if (b0 < 0xf0) {
        if (index + 2 >= len)
            return false;
        const uint8_t b1 = data[index + 1];
        // Replicate the original's lookup table validation:
        // Reject overlong (E0 80..9F) and surrogates (ED A0..BF)
        if (b0 == 0xe0 && b1 < 0xa0)
            return false;
        if (b0 == 0xed && b1 >= 0xa0)
            return false;
        if ((b1 ^ 0x80) >= 0x40)
            return false;
        const uint8_t b2 = data[index + 2];
        if ((b2 ^ 0x80) >= 0x40)
            return false;
        *cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
        *width = 3;
        return true;
    }

    if (b0 >= 0xf5)
        return false;  // > U+10FFFF

    if (index + 1 >= len)
        return false;
    const uint8_t b1 = data[index + 1];
    // Reject overlong (F0 80..8F) and too large (F4 90+)
    if (b0 == 0xf0 && b1 < 0x90)
        return false;
    if (b0 == 0xf4 && b1 >= 0x90)
        return false;
    if ((b1 ^ 0x80) >= 0x40)
        return false;

    if (index + 2 >= len)
        return false;
    const uint8_t b2 = data[index + 2];
    if ((b2 ^ 0x80) >= 0x40)
        return false;

    if (index + 3 >= len)
        return false;
    const uint8_t b3 = data[index + 3];
    if ((b3 ^ 0x80) >= 0x40)
        return false;

    *cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
    *width = 4;
    return true;
}

size_t InvalidUtf8SpanEnd(const uint8_t* data, size_t len, size_t index) {
    if (index >= len)
        return index;

    const uint8_t b0 = data[index];
    size_t next = index + 1;
    if (b0 < 0x80 || next >= len) {
        return next;
    }

    if (b0 < 0xe0) {
        if (b0 <= 0xc1)
            return next;
        const uint8_t b1 = data[next];
        return ((b1 ^ 0x80) < 0x40) ? next + 1 : next;
    }

    if (b0 < 0xf0) {
        const uint8_t b1 = data[next];
        if (b0 == 0xe0 && b1 < 0xa0)
            return next;
        if (b0 == 0xed && b1 >= 0xa0)
            return next;
        if ((b1 ^ 0x80) >= 0x40)
            return next;
        ++next;
        if (next >= len)
            return next;
        const uint8_t b2 = data[next];
        return ((b2 ^ 0x80) < 0x40) ? next + 1 : next;
    }

    if (b0 >= 0xf5)
        return next;
    const uint8_t b1 = data[next];
    if (b0 == 0xf0 && b1 < 0x90)
        return next;
    if (b0 == 0xf4 && b1 >= 0x90)
        return next;
    if ((b1 ^ 0x80) >= 0x40)
        return next;
    ++next;
    if (next >= len)
        return next;
    const uint8_t b2 = data[next];
    if ((b2 ^ 0x80) >= 0x40)
        return next;
    ++next;
    if (next >= len)
        return next;
    const uint8_t b3 = data[next];
    return ((b3 ^ 0x80) < 0x40) ? next + 1 : next;
}

// Checks whether the path contains any default-ignorable code point that the original
// binary strips before comparing package-owned and app-accessible paths.

bool NeedsSanitization(const std::string& input) {
    const auto* data = reinterpret_cast<const uint8_t*>(input.data());
    const size_t len = input.size();

    for (size_t i = 0; i < len;) {
        uint32_t cp = 0;
        size_t width = 0;

        if (data[i] < 0x80) {
            // ASCII code points are never default-ignorable.
            cp = data[i];
            width = 1;
        } else {
            if (!DecodeUtf8CodePoint(data, len, i, &cp, &width)) {
                // Invalid UTF-8 is treated as non-ignorable here, matching the device build.
                return false;
            }
        }

        if (IsDefaultIgnorableCodePoint(cp)) {
            return true;
        }
        i += width;
    }
    return false;
}

// Rewrites a string in place, stripping default-ignorable code points the same way the
// device binary does before delegating to MediaProvider policy helpers.

void RewriteString(std::string& input) {
    auto* data = reinterpret_cast<uint8_t*>(input.data());
    const size_t origLen = input.size();
    size_t readPos = 0;
    size_t writePos = 0;

    while (readPos < origLen) {
        uint32_t cp = 0;
        size_t width = 0;

        if (data[readPos] < 0x80) {
            cp = data[readPos];
            width = 1;
        } else {
            if (!DecodeUtf8CodePoint(data, origLen, readPos, &cp, &width)) {
                const size_t invalidEnd = InvalidUtf8SpanEnd(data, origLen, readPos);
                LogInvalidUtf8(reinterpret_cast<const uint8_t*>(input.data()), origLen, readPos,
                               invalidEnd);
                readPos = invalidEnd;
                continue;
            }
        }

        if (IsDefaultIgnorableCodePoint(cp)) {
            // Skip this code point (don't write it)
            readPos += width;
            continue;
        }

        // Copy bytes forward if writePos < readPos
        if (writePos != readPos) {
            std::memmove(data + writePos, data + readPos, width);
        }
        writePos += width;
        readPos += width;
    }

    // Truncate string to new length
    if (writePos < origLen) {
        input.resize(writePos);
    }
}

// ASCII case folding matches the lookup-table behavior seen in the analyzed device binary.

static char FoldAscii(uint8_t ch) {
    return static_cast<char>(std::tolower(ch));
}

// This is the core comparison routine used by the sanitizing wrappers below.
// The control flow mirrors the device binary's case-folding compare logic.
//
// Two indices (lhsIdx, rhsIdx) advance through (lhsData, lhsLen) and
// (rhsData, rhsLen) respectively.
//
// Main loop:
//   1. On lhs side: decode UTF-8 at lhsIdx. If it's a default-ignorable,
//      advance lhsIdx past it and repeat. If decode fails, log the ENTIRE
//      lhs string and use the current byte as-is for comparison.
//      When we hit a non-ignorable or invalid byte, we have our lhs char.
//
//   2. Same for rhs side.
//
//   3. Compare FoldAscii(lhs byte) vs FoldAscii(rhs byte).
//      If different, return the difference.
//      If same, advance both indices and continue.
//
//   4. If one side runs out, check if the other side's remaining bytes are
//      all default-ignorable. If so, equal. Otherwise, shorter side is less.
//
// The final return is the byte-wise difference after ASCII folding, which matches the original
// table-driven implementation.

int CompareCaseFoldIgnoringDefaultIgnorables(const uint8_t* lhsData, size_t lhsLen,
                                             const uint8_t* rhsData, size_t rhsLen) {
    size_t lhsIdx = 0;
    size_t rhsIdx = 0;
    // Tracks the "next index" for each side after skipping ignorables.
    // On invalid UTF-8, nextIdx == current idx (no skip).
    size_t lhsNextIdx = 0;
    size_t rhsNextIdx = 0;

    if (lhsLen == 0 || rhsLen == 0) {
        goto tail_check;
    }

    lhsNextIdx = 0;
    rhsNextIdx = 0;

    while (true) {
        // Advance lhs past ignorable code points.
        while (lhsIdx == lhsNextIdx) {
            if (lhsIdx >= lhsLen)
                goto tail_check;

            uint32_t cp = 0;
            size_t width = 0;
            if (lhsData[lhsIdx] < 0x80) {
                cp = lhsData[lhsIdx];
                width = 1;
            } else {
                if (!DecodeUtf8CodePoint(lhsData, lhsLen, lhsIdx, &cp, &width)) {
                    // Invalid: log entire lhs, treat byte as non-ignorable
                    LogInvalidUtf8(lhsData, lhsLen, lhsIdx, lhsIdx + 1);
                    // lhsNextIdx stays == lhsIdx, so we fall through
                    break;
                }
            }

            if (!IsDefaultIgnorableCodePoint(cp)) {
                lhsNextIdx = lhsIdx + width;
                break;
            }
            // Skip ignorable
            lhsIdx += width;
            lhsNextIdx = lhsIdx;
        }

        // Advance rhs past ignorable code points.
        while (rhsIdx == rhsNextIdx) {
            if (rhsIdx >= rhsLen)
                goto tail_check;

            uint32_t cp = 0;
            size_t width = 0;
            if (rhsData[rhsIdx] < 0x80) {
                cp = rhsData[rhsIdx];
                width = 1;
            } else {
                if (!DecodeUtf8CodePoint(rhsData, rhsLen, rhsIdx, &cp, &width)) {
                    LogInvalidUtf8(rhsData, rhsLen, rhsIdx, rhsIdx + 1);
                    break;
                }
            }

            if (!IsDefaultIgnorableCodePoint(cp)) {
                rhsNextIdx = rhsIdx + width;
                break;
            }
            rhsIdx += width;
            rhsNextIdx = rhsIdx;
        }

        // Compare the current bytes after ASCII folding.
        {
            const uint8_t lhsByte = static_cast<uint8_t>(FoldAscii(lhsData[lhsIdx]));
            const uint8_t rhsByte = static_cast<uint8_t>(FoldAscii(rhsData[rhsIdx]));
            if (lhsByte != rhsByte) {
                return static_cast<int>(lhsByte) - static_cast<int>(rhsByte);
            }
        }

        lhsIdx++;
        rhsIdx++;

        if (lhsIdx >= lhsLen || rhsIdx >= rhsLen) {
            break;
        }
    }

tail_check:
    // Check if remaining lhs bytes are all default-ignorable
    if (lhsIdx < lhsLen && lhsIdx == lhsNextIdx) {
        while (true) {
            if (lhsNextIdx >= lhsLen)
                break;

            uint32_t cp = 0;
            size_t width = 0;
            if (lhsData[lhsNextIdx] < 0x80) {
                cp = lhsData[lhsNextIdx];
                width = 1;
            } else {
                if (!DecodeUtf8CodePoint(lhsData, lhsLen, lhsNextIdx, &cp, &width)) {
                    LogInvalidUtf8(lhsData, lhsLen, lhsNextIdx, lhsNextIdx + 1);
                    goto final_compare;
                }
            }

            if (!IsDefaultIgnorableCodePoint(cp)) {
                goto final_compare;
            }
            lhsNextIdx += width;
        }
        lhsIdx = lhsLen;  // All remaining were ignorable
    }

    // Check if remaining rhs bytes are all default-ignorable
    if (rhsIdx < rhsLen && rhsIdx == rhsNextIdx) {
        while (true) {
            if (rhsNextIdx >= rhsLen)
                break;

            uint32_t cp = 0;
            size_t width = 0;
            if (rhsData[rhsNextIdx] < 0x80) {
                cp = rhsData[rhsNextIdx];
                width = 1;
            } else {
                if (!DecodeUtf8CodePoint(rhsData, rhsLen, rhsNextIdx, &cp, &width)) {
                    LogInvalidUtf8(rhsData, rhsLen, rhsNextIdx, rhsNextIdx + 1);
                    goto final_compare;
                }
            }

            if (!IsDefaultIgnorableCodePoint(cp)) {
                goto final_compare;
            }
            rhsNextIdx += width;
        }
        rhsIdx = rhsLen;  // All remaining were ignorable
    }

final_compare:
    // If both sides are exhausted, return equality. Otherwise return the folded byte difference.
    {
        const uint8_t lhsByte =
            (lhsIdx < lhsLen) ? static_cast<uint8_t>(FoldAscii(lhsData[lhsIdx])) : 0;
        const uint8_t rhsByte =
            (rhsIdx < rhsLen) ? static_cast<uint8_t>(FoldAscii(rhsData[rhsIdx])) : 0;
        return static_cast<int>(lhsByte) - static_cast<int>(rhsByte);
    }
}

// Hook state for libfuse_jni.so running inside the MediaProvider process.
void* gOriginalPfLookup = nullptr;
void* gOriginalPfLookupPostfilter = nullptr;
void* gOriginalPfAccess = nullptr;
void* gOriginalPfOpen = nullptr;
void* gOriginalPfOpendir = nullptr;
void* gOriginalPfMknod = nullptr;
void* gOriginalPfMkdir = nullptr;
void* gOriginalPfUnlink = nullptr;
void* gOriginalPfRmdir = nullptr;
void* gOriginalPfRename = nullptr;
void* gOriginalPfCreate = nullptr;
void* gOriginalPfReaddir = nullptr;
void* gOriginalPfReaddirPostfilter = nullptr;
void* gOriginalPfReaddirplus = nullptr;
void* gOriginalPfGetattr = nullptr;
void* gOriginalOpen = nullptr;
void* gOriginalOpen2 = nullptr;
void* gOriginalMkdir = nullptr;
void* gOriginalMknod = nullptr;
void* gOriginalLstat = nullptr;
void* gOriginalStat = nullptr;
void* gOriginalShouldNotCache = nullptr;
void* gOriginalNotifyInvalEntry = nullptr;
void* gOriginalNotifyInvalInode = nullptr;
void* gOriginalReplyAttr = nullptr;
void* gOriginalReplyEntry = nullptr;
void* gOriginalReplyBuf = nullptr;
void* gOriginalReplyErr = nullptr;
void* gOriginalGetDirectoryEntries = nullptr;
std::atomic<void*> gLastFuseSession{nullptr};
std::atomic<bool> gHiddenEntryInvalidationPending{false};
std::atomic<uint64_t> gHiddenRootParentInode{0};
thread_local bool gInPfLookup = false;
thread_local bool gInPfLookupPostfilter = false;
thread_local bool gInPfReaddir = false;
thread_local bool gInPfReaddirPostfilter = false;
thread_local bool gInPfReaddirplus = false;
thread_local bool gInPfGetattr = false;
thread_local uint32_t gPfGetattrUid = 0;
thread_local uint32_t gPfReaddirUid = 0;
thread_local uint64_t gPfGetattrIno = 0;
thread_local uint64_t gPfReaddirIno = 0;
thread_local uint64_t gCurrentLookupParentInode = 0;
thread_local bool gTrackRootHiddenLookup = false;
thread_local bool gTrackHiddenSubtreeLookup = false;
thread_local bool gZeroAttrCacheForCurrentGetattr = false;

void LogReplyErrFallbackFailure(const char* caller) {
    if (ShouldLogLimited(gReplyErrFallbackLogCount, 8)) {
        __android_log_print(6, kLogTag,
                            "%s could not resolve fuse_reply_err; delegating to the original path",
                            caller);
    }
}

FuseReplyErrFn ResolveReplyErrFunction() {
    auto replyErr = reinterpret_cast<FuseReplyErrFn>(gOriginalReplyErr);
    if (replyErr != nullptr) {
        return replyErr;
    }

    static std::atomic<void*> sResolvedReplyErr{nullptr};
    void* cached = sResolvedReplyErr.load(std::memory_order_acquire);
    if (cached != nullptr) {
        return reinterpret_cast<FuseReplyErrFn>(cached);
    }

    void* resolved = dlsym(RTLD_DEFAULT, "fuse_reply_err");
    if (resolved == nullptr) {
        return nullptr;
    }

    sResolvedReplyErr.store(resolved, std::memory_order_release);
    return reinterpret_cast<FuseReplyErrFn>(resolved);
}
std::mutex gHiddenSubtreeInodesMutex;
std::unordered_set<uint64_t> gHiddenSubtreeInodes;

uint32_t ReqUid(fuse_req_t req) {
    if (req == nullptr) {
        return 0;
    }
    // The reverse-engineered device build reads req->ctx.uid from fuse_req + 0x3c in pf_getattr()
    // and related handlers. AOSP accesses req->ctx.uid directly in C++, but our low-level hooks
    // only receive the opaque request pointer, so this mirrors the verified device layout. AOSP
    // reference: jni/FuseDaemon.cpp#2134 and #2145
    // https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#2134
    return *reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(req) + 0x3c);
}

void RememberFuseSession(fuse_req_t req) {
    if (req != nullptr && req->se != nullptr) {
        gLastFuseSession.store(req->se, std::memory_order_relaxed);
    }
}

// Shared dentry cache is not scoped per uid. Once another app resolves the hidden entry, the
// target uid can reuse that positive cache unless we actively invalidate the root dentry.
void ScheduleHiddenEntryInvalidation() {
    auto notifyEntry =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
    if (notifyEntry == nullptr || session == nullptr) {
        return;
    }
    if (gHiddenEntryInvalidationPending.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    const uint64_t parent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (parent == 0) {
        gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
        return;
    }
    std::thread([notifyEntry, session]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
        for (const auto& rootEntryName : kHiddenRootEntryNames) {
            const int ret =
                notifyEntry(session, rootParent, rootEntryName.data(), rootEntryName.size());
            DebugLogPrint(4, "scheduled hidden entry invalidation parent=0x%lx name=%s ret=%d",
                          (unsigned long)rootParent, DebugPreview(rootEntryName).c_str(), ret);
        }
        gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
    }).detach();
}

// Track subtree inodes so later getattr/readdir replies can also be forced uncached.
void ScheduleHiddenInodeInvalidation(uint64_t ino) {
    auto notifyInode =
        reinterpret_cast<int (*)(void*, uint64_t, off_t, off_t)>(gOriginalNotifyInvalInode);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
    if (notifyInode == nullptr || session == nullptr || ino == 0) {
        return;
    }
    std::thread([notifyInode, session, ino]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const int ret = notifyInode(session, ino, 0, 0);
        DebugLogPrint(4, "scheduled hidden inode invalidation ino=0x%lx ret=%d", (unsigned long)ino,
                      ret);
    }).detach();
}

std::string InodePath(uint64_t ino) {
    if (ino == 1)
        return "(ROOT)";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "(%p)", (void*)ino);
    // Keep inode values opaque in debug output.
    // On the analyzed device build, node::BuildPath() is a C++ member function with an
    // out-parameter return ABI and internal locking, so this logging helper must not assume
    // that an inode value can be converted into a valid node object or path string.
    return std::string(buf);
}

bool IsHiddenLookupTarget(uint32_t uid, uint64_t parent, uint32_t error_in, const char* name) {
    if (!IsTestHiddenUid(uid) || error_in != 0 || name == nullptr || !IsHiddenRootEntryName(name)) {
        return false;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    return rootParent == 0 || parent == rootParent;
}

enum class HiddenNamedTargetKind {
    None,
    Root,
    Descendant,
};

// Classify the current name-based operation as either the hidden root entry itself or a descendant
// below a previously learned hidden subtree inode.
HiddenNamedTargetKind ClassifyHiddenNamedTarget(uint32_t uid, uint64_t parent, const char* name) {
    if (!IsTestHiddenUid(uid) || name == nullptr) {
        return HiddenNamedTargetKind::None;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (parent != 0 && parent != rootParent && IsTrackedHiddenSubtreeInode(parent)) {
        return HiddenNamedTargetKind::Descendant;
    }
    if (!IsHiddenRootEntryName(name)) {
        return HiddenNamedTargetKind::None;
    }
    if (rootParent == 0 || parent == rootParent) {
        return HiddenNamedTargetKind::Root;
    }
    return HiddenNamedTargetKind::None;
}

bool ReplyHiddenNamedTargetError(fuse_req_t req, const char* opName, HiddenNamedTargetKind kind,
                                 int rootErr, int descendantErr) {
    if (kind == HiddenNamedTargetKind::None) {
        return false;
    }
    const int err = kind == HiddenNamedTargetKind::Root ? rootErr : descendantErr;
    DebugLogPrint(4, "%s hide named target err=%d root=%d", opName, err,
                  kind == HiddenNamedTargetKind::Root ? 1 : 0);
    auto replyErr = ResolveReplyErrFunction();
    if (replyErr != nullptr) {
        replyErr(req, err);
        return true;
    }
    LogReplyErrFallbackFailure(opName);
    return false;
}

// Device reverse engineering shows make_node_entry() and create_handle_for_node() both consult
// fuse->ShouldNotCache(path). Matching that behavior is what keeps positive dentries and file-cache
// state from being reused across UIDs.
// AOSP references: jni/FuseDaemon.cpp#347, #510, and #1428
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#347
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#510
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1428
extern "C" bool WrappedShouldNotCache(void* fuse, const std::string& path) {
    if (IsAnyHiddenSubtreePath(path)) {
        DebugLogPrint(4, "force uncached subtree path=%s", DebugPreview(path).c_str());
        return true;
    }
    auto fn = reinterpret_cast<ShouldNotCacheFn>(gOriginalShouldNotCache);
    return fn ? fn(fuse, path) : false;
}

bool IsTrackedHiddenSubtreeInode(uint64_t ino) {
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.find(ino) != gHiddenSubtreeInodes.end();
}

bool TrackHiddenSubtreeInode(uint64_t ino) {
    if (ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.insert(ino).second;
}

bool RemoveTrackedHiddenSubtreeInode(uint64_t ino) {
    if (ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.erase(ino) != 0;
}

bool IsHiddenRootEntryName(std::string_view name) {
    for (const auto& rootEntryName : kHiddenRootEntryNames) {
        if (name == rootEntryName) {
            return true;
        }
    }
    return false;
}

bool IsAnyHiddenSubtreePath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        for (const auto& rootEntryName : kHiddenRootEntryNames) {
            const size_t prefixLen = root.size() + 1 + rootEntryName.size();
            if (path.size() < prefixLen || path.compare(0, root.size(), root) != 0 ||
                path[root.size()] != '/' ||
                path.compare(root.size() + 1, rootEntryName.size(), rootEntryName) != 0) {
                continue;
            }
            if (path.size() == prefixLen || path[prefixLen] == '/') {
                return true;
            }
        }
    }
    return false;
}

bool IsExactHiddenTargetPath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        for (const auto& rootEntryName : kHiddenRootEntryNames) {
            const size_t prefixLen = root.size() + 1 + rootEntryName.size();
            if (path.size() != prefixLen || path.compare(0, root.size(), root) != 0 ||
                path[root.size()] != '/' ||
                path.compare(root.size() + 1, rootEntryName.size(), rootEntryName) != 0) {
                continue;
            }
            return true;
        }
    }
    return false;
}

bool IsHiddenRootDirectoryPath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return true;
        }
    }
    return false;
}

std::string JoinPathComponent(std::string_view parent, std::string_view child) {
    std::string joined(parent);
    if (joined.empty() || joined.back() != '/') {
        joined.push_back('/');
    }
    joined.append(child.data(), child.size());
    return joined;
}

size_t AlignDirentName(size_t nameLen) {
    return (nameLen + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1);
}

size_t FuseDirentRecordSize(const fuse_dirent* dirent) {
    return offsetof(fuse_dirent, name) + AlignDirentName(dirent->namelen);
}

size_t FuseDirentplusRecordSize(const fuse_dirent* dirent) {
    return kFuseEntryOutWireSize + offsetof(fuse_dirent, name) + AlignDirentName(dirent->namelen);
}

bool ShouldFilterHiddenRootDirent(uint32_t uid, uint64_t ino, std::string_view name,
                                  bool requireParentMatch) {
    if (!IsTestHiddenUid(uid) || !IsHiddenRootEntryName(name)) {
        return false;
    }
    if (!requireParentMatch) {
        return true;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    return rootParent == 0 || ino == rootParent;
}

bool BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                std::vector<char>* out, size_t* removedCount,
                                bool requireParentMatch = true) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent = reinterpret_cast<const fuse_dirent*>(data + offset);
        const size_t recordSize = FuseDirentRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
            removed++;
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

bool BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                    std::vector<char>* out, size_t* removedCount,
                                    bool requireParentMatch = true) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + kFuseEntryOutWireSize + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent =
            reinterpret_cast<const fuse_dirent*>(data + offset + kFuseEntryOutWireSize);
        const size_t recordSize = FuseDirentplusRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
            removed++;
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

// AOSP only decides dentry caching from the resolved path, not from uid policy.
// Once the daemon sees any path inside the hidden subtree, force cache invalidation globally for
// that subtree so positive dentries from other apps stop leaking into the target uid.
void NoteHiddenSubtreePathForCache(std::string_view path) {
    if (!IsAnyHiddenSubtreePath(path)) {
        return;
    }

    // AOSP get_entry_timeout()/pf_getattr cache decisions are path-based rather than uid-based.
    // Once this subtree is observed anywhere in the daemon, proactively invalidate the root dentry
    // so a positive lookup seeded by another uid does not stay shared in kernel/VFS cache.
    ScheduleHiddenEntryInvalidation();

    if (gInPfLookup && gCurrentLookupParentInode != 0) {
        const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
        if (IsExactHiddenTargetPath(path) && gCurrentLookupParentInode == rootParent) {
            RemoveTrackedHiddenSubtreeInode(gCurrentLookupParentInode);
            return;
        }
        gTrackHiddenSubtreeLookup = true;
        if (TrackHiddenSubtreeInode(gCurrentLookupParentInode)) {
            DebugLogPrint(4, "track hidden lookup parent=%s path=%s",
                          InodePath(gCurrentLookupParentInode).c_str(), DebugPreview(path).c_str());
            ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
        }
    }

    if (gInPfGetattr && gPfGetattrIno != 0) {
        gZeroAttrCacheForCurrentGetattr = true;
        if (TrackHiddenSubtreeInode(gPfGetattrIno)) {
            DebugLogPrint(4, "track hidden getattr ino=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(path).c_str());
            ScheduleHiddenInodeInvalidation(gPfGetattrIno);
        }
    }
}

// pf_lookup is the earliest reliable place to learn the real root parent inode on this device.
// AOSP reference: jni/FuseDaemon.cpp#851
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#851
extern "C" void WrappedPfLookup(fuse_req_t req, uint64_t parent, const char* name) {
    RememberFuseSession(req);
    if (name != nullptr && IsHiddenRootEntryName(name) && parent != 0) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, parent,
                                                           std::memory_order_relaxed)) {
            DebugLogPrint(4, "record hidden root parent=%s", InodePath(parent).c_str());
        }
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    gInPfLookup = true;
    gCurrentLookupParentInode = parent;
    gTrackRootHiddenLookup =
        name != nullptr && IsHiddenRootEntryName(name) && (rootParent == 0 || parent == rootParent);
    gTrackHiddenSubtreeLookup = IsTrackedHiddenSubtreeInode(parent);
    DebugLogPrint(3, "lookup: req=%lu parent=%s name=%s", (unsigned long)req->unique,
                  InodePath(parent).c_str(), name ? DebugPreview(name).c_str() : "null");

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfLookup);
    if (fn)
        fn(req, parent, name);
    gCurrentLookupParentInode = 0;
    gInPfLookup = false;
    gTrackHiddenSubtreeLookup = false;
    gTrackRootHiddenLookup = false;
}

// MediaProviderWrapper::GetDirectoryEntries() appends lower-fs directory names after the Java-side
// list is fetched, so root entry hiding must also filter the native vector here.
// AOSP references: jni/MediaProviderWrapper.cpp#373 and jni/FuseDaemon.cpp#1882
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/MediaProviderWrapper.cpp#373
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1882
DirectoryEntries FilterHiddenDirectoryEntries(uint32_t uid, std::string_view parentPath,
                                              DirectoryEntries entries) {
    if (!IsTestHiddenUid(uid) || entries.empty()) {
        return entries;
    }

    const size_t before = entries.size();
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const auto& entry) {
                                     if (!entry) {
                                         return false;
                                     }
                                     const std::string& name = entry->d_name;
                                     if (name.empty() || name[0] == '/') {
                                         return false;
                                     }
                                     return ShouldHideTestPath(uid,
                                                               JoinPathComponent(parentPath, name));
                                 }),
                  entries.end());

    if (entries.size() != before) {
        DebugLogPrint(4, "filter dir entries uid=%u parent=%s removed=%zu remaining=%zu",
                      static_cast<unsigned>(uid), DebugPreview(parentPath).c_str(),
                      before - entries.size(), entries.size());
    }
    return entries;
}

DirectoryEntries WrappedGetDirectoryEntries(void* wrapper, uint32_t uid, const std::string& path,
                                            DIR* dirp) {
    auto fn = reinterpret_cast<GetDirectoryEntriesFn>(gOriginalGetDirectoryEntries);
    DirectoryEntries entries = fn ? fn(wrapper, uid, path, dirp) : DirectoryEntries();
    return FilterHiddenDirectoryEntries(uid, path, std::move(entries));
}

// AOSP readdir postfilter stats each child path before copying the surviving dirents into a
// fuse_read_out buffer. This context flag lets WrappedReplyBuf preserve that wire layout when the
// device actually goes through pf_readdir_postfilter.
// AOSP reference: jni/FuseDaemon.cpp#1954
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1954
extern "C" void WrappedPfReaddirPostfilter(fuse_req_t req, uint64_t ino, uint32_t error_in,
                                           off_t off_in, off_t off_out, size_t size_out,
                                           const void* dirents_in, void* fi) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, off_t, off_t, size_t,
                                        const void*, void*)>(gOriginalPfReaddirPostfilter);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdir_postfilter uid=%u ino=%s err=%u off_in=%lld off_out=%lld size=%zu",
                  static_cast<unsigned>(uid), InodePath(ino).c_str(), error_in,
                  static_cast<long long>(off_in), static_cast<long long>(off_out), size_out);

    gInPfReaddirPostfilter = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    fn(req, ino, error_in, off_in, off_out, size_out, dirents_in, fi);
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddirPostfilter = false;
}

// pf_lookup_postfilter is the AOSP path-specific ENOENT gate that runs after lookup success but
// before the positive entry reaches the kernel.
// AOSP reference: jni/FuseDaemon.cpp#921
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#921
extern "C" void WrappedPfLookupPostfilter(fuse_req_t req, uint64_t parent, uint32_t error_in,
                                          const char* name, struct fuse_entry_out* feo,
                                          struct fuse_entry_bpf_out* febo) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    DebugLogPrint(3, "pf_lookup_postfilter req=%p uid=%u parent=%s name=%s err_in=%u", req,
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", error_in);
    if (IsHiddenLookupTarget(uid, parent, error_in, name)) {
        DebugLogPrint(4, "pf_lookup_postfilter hide uid=%u parent=%s name=%s",
                      static_cast<unsigned>(uid), InodePath(parent).c_str(), name);
        ScheduleHiddenEntryInvalidation();
        auto replyErr = ResolveReplyErrFunction();
        if (replyErr != nullptr) {
            replyErr(req, ENOENT);
            return;
        }
        LogReplyErrFallbackFailure("pf_lookup_postfilter");
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, const char*,
                                        struct fuse_entry_out*, struct fuse_entry_bpf_out*)>(
        gOriginalPfLookupPostfilter);
    if (fn) {
        gInPfLookupPostfilter = true;
        fn(req, parent, error_in, name, feo, febo);
        gInPfLookupPostfilter = false;
    }
}

extern "C" void WrappedPfAccess(fuse_req_t req, uint64_t ino, int mask) {
    RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, int)>(gOriginalPfAccess);
    if (fn) {
        fn(req, ino, mask);
    }
}

extern "C" void WrappedPfOpen(fuse_req_t req, uint64_t ino, void* fi) {
    RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpen);
    if (fn) {
        fn(req, ino, fi);
    }
}

extern "C" void WrappedPfOpendir(fuse_req_t req, uint64_t ino, void* fi) {
    RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpendir);
    if (fn) {
        fn(req, ino, fi);
    }
}

// AOSP pf_mkdir only checks parent_path accessibility before it calls mkdir(child_path), so a
// hidden leaf name would still leak existence semantics unless we stop it here.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1184
extern "C" void WrappedPfMkdir(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode) {
    RememberFuseSession(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(ReqUid(req), parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_mkdir", kind, EACCES, ENOENT)) {
        return;
    }
    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t)>(gOriginalPfMkdir);
    if (fn) {
        fn(req, parent, name, mode);
    }
}

// Some callers create regular files through the mknod op instead of create. AOSP still uses only
// parent_path policy here, so hidden leaf names must be blocked explicitly.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1134
extern "C" void WrappedPfMknod(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                               uint64_t rdev) {
    RememberFuseSession(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(ReqUid(req), parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_mknod", kind, EPERM, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, uint64_t)>(
        gOriginalPfMknod);
    if (fn) {
        fn(req, parent, name, mode, rdev);
    }
}

// AOSP pf_unlink only gates on parent_path before it deletes the final child path, so hidden leaf
// names must return ENOENT here instead of reaching the lower filesystem.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1218
extern "C" void WrappedPfUnlink(fuse_req_t req, uint64_t parent, const char* name) {
    RememberFuseSession(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(ReqUid(req), parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_unlink", kind, ENOENT, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfUnlink);
    if (fn) {
        fn(req, parent, name);
    }
}

// AOSP pf_rmdir follows the same parent-only validation pattern as pf_unlink, so hidden child
// names must be rejected before the real directory delete runs.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1248
extern "C" void WrappedPfRmdir(fuse_req_t req, uint64_t parent, const char* name) {
    RememberFuseSession(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(ReqUid(req), parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_rmdir", kind, ENOENT, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfRmdir);
    if (fn) {
        fn(req, parent, name);
    }
}

// AOSP do_rename only validates the old and new parent directories before it passes the final
// child paths into MediaProviderWrapper::Rename, so hidden names must be intercepted here as well.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1299
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1369
extern "C" void WrappedPfRename(fuse_req_t req, uint64_t parent, const char* name,
                                uint64_t new_parent, const char* new_name, uint32_t flags) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    const HiddenNamedTargetKind srcKind = ClassifyHiddenNamedTarget(uid, parent, name);
    const HiddenNamedTargetKind dstKind = ClassifyHiddenNamedTarget(uid, new_parent, new_name);
    if (srcKind != HiddenNamedTargetKind::None || dstKind != HiddenNamedTargetKind::None) {
        DebugLogPrint(4,
                      "pf_rename hide named target src_root=%d src_desc=%d dst_root=%d dst_desc=%d "
                      "flags=0x%x",
                      srcKind == HiddenNamedTargetKind::Root ? 1 : 0,
                      srcKind == HiddenNamedTargetKind::Descendant ? 1 : 0,
                      dstKind == HiddenNamedTargetKind::Root ? 1 : 0,
                      dstKind == HiddenNamedTargetKind::Descendant ? 1 : 0, flags);
        ScheduleHiddenEntryInvalidation();
        auto replyErr = ResolveReplyErrFunction();
        if (replyErr != nullptr) {
            replyErr(req, ENOENT);
            return;
        }
        LogReplyErrFallbackFailure("pf_rename");
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint64_t, const char*,
                                        uint32_t)>(gOriginalPfRename);
    if (fn) {
        fn(req, parent, name, new_parent, new_name, flags);
    }
}

// AOSP pf_create inserts into MediaProvider and then opens the lower-fs child path. Returning a
// positive entry here would let create leak EEXIST-like behavior for the hidden root entry.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#2121
extern "C" void WrappedPfCreate(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                                void* fi) {
    RememberFuseSession(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(ReqUid(req), parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_create", kind, EPERM, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, void*)>(
        gOriginalPfCreate);
    if (fn) {
        fn(req, parent, name, mode, fi);
    }
}

// Plain readdir delegates to do_readdir_common(..., plus=false). Most modern devices keep
// readdirplus enabled, but this hook is still useful as a fallback for alternative FUSE configs.
// AOSP reference: jni/FuseDaemon.cpp#1944
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1944
extern "C" void WrappedPfReaddir(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(gOriginalPfReaddir);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdir uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    gInPfReaddir = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    fn(req, ino, size, off, fi);
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddir = false;
}

// readdirplus is the common enumeration path on recent Android builds because do_readdir_common()
// emits fuse_direntplus records by first running do_lookup() for each directory entry.
// AOSP references: jni/FuseDaemon.cpp#1904 and #2000
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1904
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#2000
extern "C" void WrappedPfReaddirplus(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                     void* fi) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(
        gOriginalPfReaddirplus);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdirplus uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    gInPfReaddirplus = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    fn(req, ino, size, off, fi);
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddirplus = false;
}

extern "C" int WrappedNotifyInvalEntry(void* se, uint64_t parent, const char* name,
                                       size_t namelen) {
    auto fn =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    int ret = fn ? fn(se, parent, name, namelen) : -1;
    DebugLogPrint(3, "notify_inval_entry: ino=0x%lx name=%s ret=%d", (unsigned long)parent,
                  name ? DebugPreview(std::string_view(name, namelen)).c_str() : "null", ret);
    return ret;
}

extern "C" int WrappedNotifyInvalInode(void* se, uint64_t ino, off_t off, off_t len) {
    auto fn = reinterpret_cast<int (*)(void*, uint64_t, off_t, off_t)>(gOriginalNotifyInvalInode);
    int ret = fn ? fn(se, ino, off, len) : -1;
    // Device libfuse_jni routes a fallback invalidation path through notify_inval_inode().
    // The callback receives an inode handle, not a verified node object, so only log the rawvalue
    // here.
    DebugLogPrint(3, "notify_inval_inode: ino=0x%lx name=%s ret=%d", (unsigned long)ino,
                  ino == 1 ? "(ROOT)" : "", ret);
    return ret;
}

// This is the strongest uid-specific hiding point. Once a positive fuse_entry_param escapes here,
// later operations such as getattr, getxattr, or create can still observe existence through the
// resolved inode even if later path-based checks return false.
// AOSP references: jni/FuseDaemon.cpp#912, #1166, and #1211
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#912
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1166
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1211
extern "C" int WrappedReplyEntry(fuse_req_t req, const struct fuse_entry_param* e) {
    auto fn =
        reinterpret_cast<int (*)(fuse_req_t, const struct fuse_entry_param*)>(gOriginalReplyEntry);
    const bool hiddenLookupForUid =
        IsTestHiddenUid(ReqUid(req)) && (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup);
    if (hiddenLookupForUid) {
        auto replyErr = ResolveReplyErrFunction();
        const int ret = replyErr ? replyErr(req, ENOENT) : -1;
        if (replyErr != nullptr) {
            DebugLogPrint(4, "hide lookup entry uid=%u req=%lu ino=%s root=%d child=%d ret=%d",
                          static_cast<unsigned>(ReqUid(req)),
                          req ? (unsigned long)req->unique : 0UL,
                          e != nullptr ? InodePath(e->ino).c_str() : "(null)",
                          gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0, ret);
            ScheduleHiddenEntryInvalidation();
            return ret;
        }
        LogReplyErrFallbackFailure("fuse_reply_entry");
    }
    fuse_entry_param patchedEntry = {};
    const struct fuse_entry_param* replyEntry = e;
    if (e != nullptr && (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup)) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
        DebugLogPrint(4, "disable entry cache req=%lu ino=%s root=%d child=%d",
                      req ? (unsigned long)req->unique : 0UL, InodePath(e->ino).c_str(),
                      gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0);
        ScheduleHiddenEntryInvalidation();
        if (TrackHiddenSubtreeInode(e->ino)) {
            ScheduleHiddenInodeInvalidation(e->ino);
        }
    }
    int ret = fn ? fn(req, replyEntry) : -1;
    DebugLogPrint(3,
                  "fuse_reply_entry: req=%lu ino=%s timeout=%.2le attr_timeout=%.2le bpf_fd=%lu "
                  "bpf_action=%lu backing_action=%lu backing_fd=%lu ret=%d",
                  (unsigned long)req->unique, InodePath(replyEntry->ino).c_str(),
                  replyEntry->entry_timeout, replyEntry->attr_timeout,
                  (unsigned long)replyEntry->bpf_fd, (unsigned long)replyEntry->bpf_action,
                  (unsigned long)replyEntry->backing_action, (unsigned long)replyEntry->backing_fd,
                  ret);
    return ret;
}

// get_entry_timeout() only controls dentry caching; pf_getattr still replies with a separate
// attr timeout. Force both to zero when the request touches the hidden subtree.
// AOSP references: jni/FuseDaemon.cpp#510 and #1002
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#510
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1002
extern "C" int WrappedReplyAttr(fuse_req_t req, const struct stat* attr, double timeout) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const struct stat*, double)>(gOriginalReplyAttr);
    const double replyTimeout = gZeroAttrCacheForCurrentGetattr ? 0.0 : timeout;
    if (gZeroAttrCacheForCurrentGetattr) {
        DebugLogPrint(4, "disable attr cache req=%p timeout=%.2le", req, replyTimeout);
    }
    return fn ? fn(req, attr, replyTimeout) : -1;
}

// reply_buf is the last universal filtering point. AOSP emits directory data through plain readdir,
// readdir postfilter, readdirplus, and lookup_postfilter using different wire layouts, so auto-
// detecting dirent and direntplus records here is more reliable than betting on one upstream path.
// AOSP references: jni/FuseDaemon.cpp#946, #1941, and #1997
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#946
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1941
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1997
extern "C" int WrappedReplyBuf(fuse_req_t req, const char* buf, size_t size) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const char*, size_t)>(gOriginalReplyBuf);
    const char* replyBuf = buf;
    size_t replySize = size;
    std::vector<char> filteredStorage;
    size_t removedCount = 0;
    const uint32_t reqUid = ReqUid(req);
    const uint32_t filterUid = gPfReaddirUid != 0 ? gPfReaddirUid : reqUid;
    const uint64_t filterIno = gPfReaddirIno != 0 ? gPfReaddirIno : 0;
    const bool filterPlainReaddir = gInPfReaddir;
    const bool filterPostfilterReaddir = gInPfReaddirPostfilter;
    const bool filterReaddirplus = gInPfReaddirplus;
    const bool requireParentMatch = filterIno != 0;
    const char* filterMode = nullptr;

    if (IsTestHiddenUid(filterUid)) {
        if (filterPlainReaddir) {
            if (BuildFilteredDirentPayload(buf, size, filterUid, filterIno, &filteredStorage,
                                           &removedCount, requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdir";
            }
        } else if (filterReaddirplus) {
            if (BuildFilteredDirentplusPayload(buf, size, filterUid, filterIno, &filteredStorage,
                                               &removedCount, requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdirplus";
            }
        } else if (filterPostfilterReaddir && size >= sizeof(fuse_read_out)) {
            const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
            const size_t payloadSize =
                std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
            std::vector<char> filteredPayload;
            if (BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize, filterUid,
                                           filterIno, &filteredPayload, &removedCount,
                                           requireParentMatch)) {
                fuse_read_out patched = *readOut;
                patched.size = static_cast<uint32_t>(filteredPayload.size());
                filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                            filteredPayload.size());
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdir_postfilter";
            }
        }

        if (filterMode == nullptr) {
            if (BuildFilteredDirentplusPayload(buf, size, filterUid, 0, &filteredStorage,
                                               &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_direntplus";
            } else if (BuildFilteredDirentPayload(buf, size, filterUid, 0, &filteredStorage,
                                                  &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_dirent";
            } else if (size >= sizeof(fuse_read_out)) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize =
                    std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize, filterUid,
                                               0, &filteredPayload, &removedCount, false)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                                filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                    filterMode = "auto_read_out_dirent";
                }
            }
        }
    }

    int ret = fn ? fn(req, replyBuf, replySize) : -1;
    if (removedCount != 0) {
        DebugLogPrint(4, "filtered readdir reply mode=%s uid=%u ino=%s removed=%zu size=%zu->%zu",
                      filterMode ? filterMode : "unknown", static_cast<unsigned>(filterUid),
                      InodePath(filterIno).c_str(), removedCount, size, replySize);
    }
    if (gInPfLookupPostfilter) {
        DebugLogPrint(3, "pf_lookup_postfilter fuse_reply_buf req=%p", req);
    } else {
        DebugLogPrint(3, "fuse_reply_buf: req=%lu size=%zu ret=%d", (unsigned long)req->unique,
                      replySize, ret);
    }
    return ret;
}

extern "C" int WrappedReplyErr(fuse_req_t req, int err) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, int)>(gOriginalReplyErr);
    int ret = fn ? fn(req, err) : -1;
    if (gInPfLookupPostfilter) {
        DebugLogPrint(3, "pf_lookup_postfilter fuse_reply_err req=%p %d", req, err);
    } else {
        DebugLogPrint(3, "fuse_reply_err: req=%p err=%d ret=%d", req, err, ret);
    }
    return ret;
}

extern "C" void WrappedPfGetattr(fuse_req_t req, uint64_t ino, void* fi) {
    RememberFuseSession(req);
    const uint32_t uid = ReqUid(req);
    gZeroAttrCacheForCurrentGetattr = IsTrackedHiddenSubtreeInode(ino);
    if (IsTestHiddenUid(uid)) {
        DebugLogPrint(4, "pf_getattr test uid=%u ino=0x%lx", static_cast<unsigned>(uid),
                      (unsigned long)ino);
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfGetattr);
    if (fn) {
        gInPfGetattr = true;
        gPfGetattrUid = uid;
        gPfGetattrIno = ino;
        fn(req, ino, fi);
        gPfGetattrIno = 0;
        gPfGetattrUid = 0;
        gInPfGetattr = false;
        gZeroAttrCacheForCurrentGetattr = false;
    }
}

// lstat is the path-based source of truth used by pf_getattr and by some enumeration paths. This is
// where we convert a visible subtree path back into cache invalidation state.
// lstat is the path-based source of truth for pf_getattr and is also consulted by readdir
// postfilter. Recording the root parent inode here avoids assuming a fixed root inode value.
// AOSP references: jni/FuseDaemon.cpp#1002 and #1985
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1002
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1985
extern "C" int WrappedLstat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (gInPfGetattr && gPfGetattrIno != 0 && IsHiddenRootDirectoryPath(pathView)) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, gPfGetattrIno,
                                                           std::memory_order_relaxed)) {
            DebugLogPrint(4, "record hidden root parent from getattr=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(pathView).c_str());
        }
        RemoveTrackedHiddenSubtreeInode(gPfGetattrIno);
    }
    NoteHiddenSubtreePathForCache(pathView);
    if (gInPfGetattr && IsTestHiddenUid(gPfGetattrUid)) {
        DebugLogPrint(4, "pf_getattr lstat uid=%u path=%s", static_cast<unsigned>(gPfGetattrUid),
                      DebugPreview(pathView).c_str());
        if (ShouldHideTestPath(gPfGetattrUid, pathView)) {
            DebugLogPrint(4, "hide test lstat uid=%u path=%s", static_cast<unsigned>(gPfGetattrUid),
                          DebugPreview(pathView).c_str());
            errno = ENOENT;
            return -1;
        }
    }
    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalLstat);
    if (fn) {
        return fn(path, st);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedStat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (gInPfReaddirPostfilter && IsTestHiddenUid(gPfReaddirUid) &&
        IsAnyHiddenSubtreePath(pathView)) {
        DebugLogPrint(4, "hide readdir stat uid=%u path=%s", static_cast<unsigned>(gPfReaddirUid),
                      DebugPreview(pathView).c_str());
        errno = ENOENT;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalStat);
    if (fn) {
        return fn(path, st);
    }
    errno = ENOSYS;
    return -1;
}

// Even if the named FUSE wrappers are missed on a device-specific path, lower-fs mkdir/mknod/open
// calls still carry the final child path. These libc hooks are the last fallback for create/mkdir.
extern "C" int WrappedMkdirLibc(const char* path, mode_t mode) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (IsExactHiddenTargetPath(pathView)) {
        DebugLogPrint(4, "hide mkdir path=%s", DebugPreview(pathView).c_str());
        errno = EACCES;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, mode_t)>(gOriginalMkdir);
    if (fn) {
        return fn(path, mode);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedMknod(const char* path, mode_t mode, dev_t dev) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (IsExactHiddenTargetPath(pathView)) {
        DebugLogPrint(4, "hide mknod path=%s", DebugPreview(pathView).c_str());
        errno = EPERM;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, mode_t, dev_t)>(gOriginalMknod);
    if (fn) {
        return fn(path, mode, dev);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen(const char* path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if ((flags & O_CREAT) != 0 && IsExactHiddenTargetPath(pathView)) {
        DebugLogPrint(4, "hide open create path=%s flags=0x%x", DebugPreview(pathView).c_str(),
                      flags);
        errno = EPERM;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, int, ...)>(gOriginalOpen);
    if (fn) {
        if ((flags & O_CREAT) != 0) {
            return fn(path, flags, mode);
        }
        return fn(path, flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen2(const char* path, int flags) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if ((flags & O_CREAT) != 0 && IsExactHiddenTargetPath(pathView)) {
        DebugLogPrint(4, "hide __open_2 create path=%s flags=0x%x", DebugPreview(pathView).c_str(),
                      flags);
        errno = EPERM;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, int)>(gOriginalOpen2);
    if (fn) {
        return fn(path, flags);
    }
    errno = ENOSYS;
    return -1;
}

// Path hook wrappers

bool IsTestHiddenUid(uint32_t uid) {
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        const auto it = gUidHideCache.find(uid);
        if (it != gUidHideCache.end()) {
            return it->second;
        }
    }

    const std::optional<bool> resolved = ResolveShouldHideUidWithPackageManager(uid);
    if (!resolved.has_value()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideCache[uid] = *resolved;
    }
    return *resolved;
}

bool ShouldHideTestPath(uint32_t uid, std::string_view path) {
    return IsTestHiddenUid(uid) && IsAnyHiddenSubtreePath(path);
}

// Mirror the original app-accessible gate: sanitize only when needed, then delegate.
bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid) {
    if (gOriginalIsAppAccessiblePath == nullptr) {
        return false;
    }
    if (!NeedsSanitization(path)) {
        LogSuspiciousDirectPath("app_accessible", path);
        if (ShouldLogLimited(gAppAccessibleLogCount)) {
            DebugLogPrint(3, "app_accessible direct uid=%u path=%s", uid,
                          DebugPreview(path).c_str());
        }
        NoteHiddenSubtreePathForCache(path);
        if (ShouldHideTestPath(uid, path)) {
            DebugLogPrint(4, "hide test path uid=%u path=%s", static_cast<unsigned>(uid),
                          DebugPreview(path).c_str());
            return false;
        }
        return gOriginalIsAppAccessiblePath(fuse, path, uid);
    }
    std::string sanitized(path);
    RewriteString(sanitized);
    if (ShouldLogLimited(gAppAccessibleLogCount)) {
        DebugLogPrint(3, "app_accessible rewrite uid=%u old=%s new=%s", uid,
                      DebugPreview(path).c_str(), DebugPreview(sanitized).c_str());
    }
    NoteHiddenSubtreePathForCache(sanitized);
    if (ShouldHideTestPath(uid, sanitized)) {
        DebugLogPrint(4, "hide test path uid=%u path=%s src=%s", static_cast<unsigned>(uid),
                      DebugPreview(sanitized).c_str(), DebugPreview(path).c_str());
        return false;
    }
    return gOriginalIsAppAccessiblePath(fuse, sanitized, uid);
}

// The package-owned helper only sanitizes the first path argument on the device build.
bool WrappedIsPackageOwnedPath(const std::string& lhs, const std::string& rhs) {
    if (gOriginalIsPackageOwnedPath == nullptr) {
        return false;
    }
    if (!NeedsSanitization(lhs)) {
        LogSuspiciousDirectPath("package_owned", lhs);
        if (ShouldLogLimited(gPackageOwnedLogCount)) {
            DebugLogPrint(3, "package_owned direct lhs=%s rhs=%s", DebugPreview(lhs).c_str(),
                          DebugPreview(rhs).c_str());
        }
        return gOriginalIsPackageOwnedPath(lhs, rhs);
    }
    std::string sanitizedLhs(lhs);
    RewriteString(sanitizedLhs);
    if (ShouldLogLimited(gPackageOwnedLogCount)) {
        DebugLogPrint(3, "package_owned rewrite lhs=%s new=%s rhs=%s", DebugPreview(lhs).c_str(),
                      DebugPreview(sanitizedLhs).c_str(), DebugPreview(rhs).c_str());
    }
    return gOriginalIsPackageOwnedPath(sanitizedLhs, rhs);
}

// WrappedIsBpfBackingPath
bool WrappedIsBpfBackingPath(const std::string& path) {
    if (gOriginalIsBpfBackingPath == nullptr) {
        return false;
    }
    if (!NeedsSanitization(path)) {
        LogSuspiciousDirectPath("bpf_backing", path);
        if (ShouldLogLimited(gBpfBackingLogCount)) {
            DebugLogPrint(3, "bpf_backing direct path=%s", DebugPreview(path).c_str());
        }
        return gOriginalIsBpfBackingPath(path);
    }
    std::string sanitized(path);
    RewriteString(sanitized);
    if (ShouldLogLimited(gBpfBackingLogCount)) {
        DebugLogPrint(3, "bpf_backing rewrite old=%s new=%s", DebugPreview(path).c_str(),
                      DebugPreview(sanitized).c_str());
    }
    return gOriginalIsBpfBackingPath(sanitized);
}

// Keep libc strcasecmp behavior aligned with the original case-folding compare.
extern "C" int WrappedStrcasecmp(const char* lhs, const char* rhs) {
    const size_t lhsLen = (lhs != nullptr) ? std::strlen(lhs) : 0;
    const size_t rhsLen = (rhs != nullptr) ? std::strlen(rhs) : 0;
    const int result = CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhs ? lhs : ""), lhsLen,
        reinterpret_cast<const uint8_t*>(rhs ? rhs : ""), rhsLen);
    if (ShouldLogLimited(gStrcasecmpLogCount)) {
        DebugLogPrint(3, "strcasecmp lhs=%s rhs=%s result=%d",
                      DebugPreview(std::string_view(lhs ? lhs : "", lhsLen)).c_str(),
                      DebugPreview(std::string_view(rhs ? rhs : "", rhsLen)).c_str(), result);
    }
    return result;
}

// ABI adapter for android::base::EqualsIgnoreCase(string_view, string_view).
extern "C" bool WrappedEqualsIgnoreCaseAbi(const char* lhsData, size_t lhsSize, const char* rhsData,
                                           size_t rhsSize) {
    const int result = CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhsData ? lhsData : ""), lhsSize,
        reinterpret_cast<const uint8_t*>(rhsData ? rhsData : ""), rhsSize);
    if (ShouldLogLimited(gEqualsIgnoreCaseLogCount)) {
        DebugLogPrint(3, "equals_ignore_case lhs=%s rhs=%s result=%d",
                      DebugPreview(std::string_view(lhsData ? lhsData : "", lhsSize)).c_str(),
                      DebugPreview(std::string_view(rhsData ? rhsData : "", rhsSize)).c_str(),
                      result);
    }
    return result == 0;
}

// Module discovery

int DlIterateCallback(dl_phdr_info* info, size_t, void* data) {
    auto* module = reinterpret_cast<ModuleInfo*>(data);
    if (info == nullptr || info->dlpi_name == nullptr) {
        return 0;
    }
    const std::string_view name(info->dlpi_name);
    if (name.find(kTargetLibrary) == std::string_view::npos) {
        return 0;
    }
    module->base = static_cast<uintptr_t>(info->dlpi_addr);
    module->path = info->dlpi_name;
    module->phdrs = reinterpret_cast<const ElfProgramHeader*>(info->dlpi_phdr);
    module->phnum = info->dlpi_phnum;
    return 1;
}

std::optional<ModuleInfo> FindModuleFromMaps() {
    FILE* maps = std::fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        return std::nullopt;
    }

    char* line = nullptr;
    size_t lineCap = 0;
    uintptr_t lowestBase = 0;
    std::string path;
    while (getline(&line, &lineCap, maps) > 0) {
        const char* found = std::strstr(line, kTargetLibrary);
        if (found == nullptr) {
            continue;
        }
        unsigned long long start = 0;
        if (std::sscanf(line, "%llx-", &start) != 1) {
            continue;
        }
        if (lowestBase == 0 || static_cast<uintptr_t>(start) < lowestBase) {
            lowestBase = static_cast<uintptr_t>(start);
        }
        path = found;
        while (!path.empty() &&
               (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
            path.pop_back();
        }
    }

    if (line != nullptr) {
        std::free(line);
    }
    std::fclose(maps);

    if (lowestBase == 0 || path.empty()) {
        return std::nullopt;
    }
    return ModuleInfo{lowestBase, path};
}

std::optional<ModuleInfo> FindTargetModule() {
    ModuleInfo module;
    dl_iterate_phdr(DlIterateCallback, &module);
    if (module.base != 0 && !module.path.empty()) {
        return module;
    }
    return FindModuleFromMaps();
}

// ELF file mapping and parsing

std::optional<MappedFile> MapReadOnlyFile(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: open %s", errno,
                            strerror(errno), path.c_str());
        return std::nullopt;
    }

    struct stat st {};
    if (fstat(fd, &st) != 0) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: stat %s", errno,
                            strerror(errno), path.c_str());
        close(fd);
        return std::nullopt;
    }

    void* address = mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (address == MAP_FAILED) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: mmap %s", errno,
                            strerror(errno), path.c_str());
        return std::nullopt;
    }

    return MappedFile{address, static_cast<size_t>(st.st_size),
                      reinterpret_cast<const std::byte*>(address), static_cast<size_t>(st.st_size)};
}

std::optional<MappedFile> MakeOwnedFile(std::vector<std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }
    auto owned = std::make_shared<std::vector<std::byte>>(std::move(bytes));
    MappedFile file;
    file.owned = owned;
    file.data = owned->data();
    file.size = owned->size();
    return file;
}

uint16_t ReadLe16(const std::byte* ptr) {
    uint16_t value = 0;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

uint32_t ReadLe32(const std::byte* ptr) {
    uint32_t value = 0;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

std::optional<MappedFile> MapEmbeddedStoredElf(const std::string& modulePath) {
    const size_t bang = modulePath.find("!/");
    if (bang == std::string::npos) {
        return std::nullopt;
    }
    const std::string apkPath = modulePath.substr(0, bang);
    const std::string entryPath = modulePath.substr(bang + 2);

    auto apk = MapReadOnlyFile(apkPath);
    if (!apk.has_value()) {
        return std::nullopt;
    }

    const auto* bytes = apk->bytes();
    const size_t size = apk->size;
    if (size < 22) {
        return std::nullopt;
    }

    size_t eocdOffset = std::string::npos;
    const size_t searchStart = size > (0xFFFF + 22) ? size - (0xFFFF + 22) : 0;
    for (size_t off = size - 22 + 1; off-- > searchStart;) {
        if (ReadLe32(bytes + off) == 0x06054b50U) {
            eocdOffset = off;
            break;
        }
    }
    if (eocdOffset == std::string::npos) {
        __android_log_print(5, kLogTag, "embedded apk missing EOCD: %s", apkPath.c_str());
        return std::nullopt;
    }

    const uint32_t centralDirOffset = ReadLe32(bytes + eocdOffset + 16);
    const uint16_t totalEntries = ReadLe16(bytes + eocdOffset + 10);
    size_t cursor = centralDirOffset;
    for (uint16_t i = 0; i < totalEntries && cursor + 46 <= size; ++i) {
        if (ReadLe32(bytes + cursor) != 0x02014b50U) {
            break;
        }
        const uint16_t method = ReadLe16(bytes + cursor + 10);
        const uint32_t compressedSize = ReadLe32(bytes + cursor + 20);
        const uint32_t uncompressedSize = ReadLe32(bytes + cursor + 24);
        const uint16_t nameLen = ReadLe16(bytes + cursor + 28);
        const uint16_t extraLen = ReadLe16(bytes + cursor + 30);
        const uint16_t commentLen = ReadLe16(bytes + cursor + 32);
        const uint32_t localHeaderOffset = ReadLe32(bytes + cursor + 42);

        if (cursor + 46 + nameLen > size) {
            break;
        }
        const char* name = reinterpret_cast<const char*>(bytes + cursor + 46);
        if (entryPath == std::string_view(name, nameLen)) {
            if (method != 0) {
                __android_log_print(5, kLogTag, "embedded entry compressed method=%u path=%s",
                                    method, entryPath.c_str());
                return std::nullopt;
            }
            if (localHeaderOffset + 30 > size ||
                ReadLe32(bytes + localHeaderOffset) != 0x04034b50U) {
                __android_log_print(5, kLogTag, "embedded entry bad local header path=%s",
                                    entryPath.c_str());
                return std::nullopt;
            }
            const uint16_t localNameLen = ReadLe16(bytes + localHeaderOffset + 26);
            const uint16_t localExtraLen = ReadLe16(bytes + localHeaderOffset + 28);
            const size_t dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;
            if (dataOffset + uncompressedSize > size || compressedSize != uncompressedSize) {
                return std::nullopt;
            }

            MappedFile embedded = std::move(*apk);
            embedded.data = bytes + dataOffset;
            embedded.size = uncompressedSize;
            __android_log_print(4, kLogTag, "mapped embedded elf entry=%s size=%u",
                                entryPath.c_str(), uncompressedSize);
            return embedded;
        }

        cursor += 46 + nameLen + extraLen + commentLen;
    }

    __android_log_print(5, kLogTag, "embedded entry not found: %s", entryPath.c_str());
    return std::nullopt;
}

std::optional<std::pair<const std::byte*, size_t>> FindNamedSectionData(const MappedFile& file,
                                                                        std::string_view name) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    if (header == nullptr || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        return std::nullopt;
    }
    if (header->e_shoff == 0 || header->e_shnum == 0 || header->e_shentsize != sizeof(ElfSection) ||
        header->e_shstrndx >= header->e_shnum) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const ElfSection*>(file.bytes() + header->e_shoff);
    const auto& shstrtab = sections[header->e_shstrndx];
    if (shstrtab.sh_offset + shstrtab.sh_size > file.size) {
        return std::nullopt;
    }
    const char* sectionNames = reinterpret_cast<const char*>(file.bytes() + shstrtab.sh_offset);
    for (uint16_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        if (section.sh_name >= shstrtab.sh_size ||
            section.sh_offset + section.sh_size > file.size) {
            continue;
        }
        const char* currentName = sectionNames + section.sh_name;
        if (name == currentName) {
            return std::pair<const std::byte*, size_t>{file.bytes() + section.sh_offset,
                                                       static_cast<size_t>(section.sh_size)};
        }
    }
    return std::nullopt;
}

const char* XzRetName(enum xz_ret ret) {
    switch (ret) {
        case XZ_OK:
            return "XZ_OK";
        case XZ_STREAM_END:
            return "XZ_STREAM_END";
        case XZ_UNSUPPORTED_CHECK:
            return "XZ_UNSUPPORTED_CHECK";
        case XZ_MEM_ERROR:
            return "XZ_MEM_ERROR";
        case XZ_MEMLIMIT_ERROR:
            return "XZ_MEMLIMIT_ERROR";
        case XZ_FORMAT_ERROR:
            return "XZ_FORMAT_ERROR";
        case XZ_OPTIONS_ERROR:
            return "XZ_OPTIONS_ERROR";
        case XZ_DATA_ERROR:
            return "XZ_DATA_ERROR";
        case XZ_BUF_ERROR:
            return "XZ_BUF_ERROR";
        default:
            return "XZ_UNKNOWN";
    }
}

std::optional<MappedFile> DecompressGnuDebugdata(const std::byte* compressed, size_t size) {
    if (compressed == nullptr || size == 0) {
        return std::nullopt;
    }

    std::call_once(gXzCrcInitOnce, []() { xz_crc32_init(); });

    struct DecoderDeleter {
        void operator()(xz_dec* decoder) const {
            xz_dec_end(decoder);
        }
    };

    std::unique_ptr<xz_dec, DecoderDeleter> decoder(
        xz_dec_init(XZ_DYNALLOC, kMaxGnuDebugdataDictBytes));
    if (decoder == nullptr) {
        __android_log_print(5, kLogTag, "gnu_debugdata xz_dec_init failed");
        return std::nullopt;
    }

    std::vector<std::byte> output(64 * 1024);
    struct xz_buf buffer = {};
    buffer.in = reinterpret_cast<const uint8_t*>(compressed);
    buffer.in_size = size;
    buffer.out = reinterpret_cast<uint8_t*>(output.data());
    buffer.out_size = output.size();

    while (true) {
        const enum xz_ret ret = xz_dec_run(decoder.get(), &buffer);
        if (ret == XZ_STREAM_END) {
            output.resize(buffer.out_pos);
            __android_log_print(4, kLogTag, "decompressed .gnu_debugdata in=%zu out=%zu", size,
                                output.size());
            return MakeOwnedFile(std::move(output));
        }
        if (ret == XZ_UNSUPPORTED_CHECK) {
            continue;
        }
        if (ret == XZ_OK) {
            if (buffer.out_pos == buffer.out_size) {
                if (output.size() >= kMaxGnuDebugdataOutputBytes) {
                    __android_log_print(5, kLogTag, "gnu_debugdata output too large >= %u",
                                        kMaxGnuDebugdataOutputBytes);
                    return std::nullopt;
                }
                const size_t oldOutPos = buffer.out_pos;
                const size_t nextSize =
                    std::min<size_t>(output.size() * 2, kMaxGnuDebugdataOutputBytes);
                output.resize(nextSize);
                buffer.out = reinterpret_cast<uint8_t*>(output.data());
                buffer.out_pos = oldOutPos;
                buffer.out_size = output.size();
            }
            continue;
        }

        __android_log_print(
            5, kLogTag, "gnu_debugdata decompress failed ret=%s in_pos=%zu/%zu out_pos=%zu/%zu",
            XzRetName(ret), buffer.in_pos, buffer.in_size, buffer.out_pos, buffer.out_size);
        return std::nullopt;
    }
}

// Section-based symbol lookup (fallback path)
std::optional<uintptr_t> FindSymbolOffsetImpl(const MappedFile& file, std::string_view symbolName,
                                              int depth) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    if (header == nullptr || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_shoff == 0 || header->e_shnum == 0 || header->e_shentsize != sizeof(ElfSection)) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const ElfSection*>(file.bytes() + header->e_shoff);
    for (uint16_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM) {
            continue;
        }
        if (section.sh_link >= header->e_shnum || section.sh_entsize != sizeof(ElfSymbol) ||
            section.sh_size == 0) {
            continue;
        }
        const auto& strtab = sections[section.sh_link];
        if (strtab.sh_offset + strtab.sh_size > file.size ||
            section.sh_offset + section.sh_size > file.size) {
            continue;
        }
        const char* strings = reinterpret_cast<const char*>(file.bytes() + strtab.sh_offset);
        const auto* symbols = reinterpret_cast<const ElfSymbol*>(file.bytes() + section.sh_offset);
        const size_t symbolCount = section.sh_size / sizeof(ElfSymbol);
        for (size_t symbolIndex = 0; symbolIndex < symbolCount; ++symbolIndex) {
            const auto& symbol = symbols[symbolIndex];
            if (symbol.st_name == 0 || symbol.st_value == 0) {
                continue;
            }
            const char* currentName = strings + symbol.st_name;
            if (currentName != nullptr && symbolName == currentName) {
                return static_cast<uintptr_t>(symbol.st_value);
            }
        }
    }

    if (depth >= 2) {
        return std::nullopt;
    }

    auto debugdata = FindNamedSectionData(file, ".gnu_debugdata");
    if (!debugdata.has_value()) {
        return std::nullopt;
    }

    auto decompressed = DecompressGnuDebugdata(debugdata->first, debugdata->second);
    if (!decompressed.has_value()) {
        return std::nullopt;
    }

    const std::string symbolNameString(symbolName);
    __android_log_print(4, kLogTag, "searching .gnu_debugdata for %s", symbolNameString.c_str());
    auto offset = FindSymbolOffsetImpl(*decompressed, symbolName, depth + 1);
    if (offset.has_value()) {
        __android_log_print(4, kLogTag, "resolved from .gnu_debugdata %s value=%p",
                            symbolNameString.c_str(), reinterpret_cast<void*>(*offset));
    }
    return offset;
}

std::optional<uintptr_t> FindSymbolOffset(const MappedFile& file, std::string_view symbolName) {
    return FindSymbolOffsetImpl(file, symbolName, 0);
}

std::optional<size_t> VirtualAddressToFileOffset(const MappedFile& file, uintptr_t address) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    const auto* programHeaders =
        reinterpret_cast<const ElfProgramHeader*>(file.bytes() + header->e_phoff);
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        const auto& phdr = programHeaders[i];
        if (phdr.p_type != PT_LOAD && phdr.p_type != PT_DYNAMIC) {
            continue;
        }
        if (address < phdr.p_vaddr || address >= phdr.p_vaddr + phdr.p_memsz) {
            continue;
        }
        return static_cast<size_t>(phdr.p_offset + (address - phdr.p_vaddr));
    }
    return std::nullopt;
}

std::optional<DynamicInfo> ParseDynamicInfo(const MappedFile& file) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    const auto* programHeaders =
        reinterpret_cast<const ElfProgramHeader*>(file.bytes() + header->e_phoff);
    const ElfProgramHeader* dynamicPhdr = nullptr;
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (programHeaders[i].p_type == PT_DYNAMIC) {
            dynamicPhdr = &programHeaders[i];
            break;
        }
    }
    if (dynamicPhdr == nullptr) {
        return std::nullopt;
    }

    DynamicInfo info;
    const auto* dyn = reinterpret_cast<const ElfDynamic*>(file.bytes() + dynamicPhdr->p_offset);
    const size_t dynCount = dynamicPhdr->p_filesz / sizeof(ElfDynamic);
    for (size_t i = 0; i < dynCount; ++i) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:
                info.symtab = dyn[i].d_un.d_ptr;
                break;
            case DT_STRTAB:
                info.strtab = dyn[i].d_un.d_ptr;
                break;
            case DT_HASH:
                info.hash = dyn[i].d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                info.gnuHash = dyn[i].d_un.d_ptr;
                break;
            case DT_JMPREL:
                info.jmprel = dyn[i].d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                info.pltrelSize = dyn[i].d_un.d_val;
                break;
            case DT_RELA:
                info.rela = dyn[i].d_un.d_ptr;
                break;
            case DT_RELASZ:
                info.relaSize = dyn[i].d_un.d_val;
                break;
            case DT_REL:
                info.rel = dyn[i].d_un.d_ptr;
                break;
            case DT_RELSZ:
                info.relSize = dyn[i].d_un.d_val;
                break;
            case DT_SYMENT:
                info.syment = dyn[i].d_un.d_val;
                break;
            case DT_PLTREL:
                info.usesRela = dyn[i].d_un.d_val == DT_RELA;
                break;
            default:
                break;
        }
    }
    if (info.symtab == 0 || info.strtab == 0) {
        return std::nullopt;
    }
    return info;
}

std::optional<RuntimeDynamicInfo> ParseRuntimeDynamicInfo(const ModuleInfo& module) {
    if (module.base == 0 || module.phdrs == nullptr || module.phnum == 0) {
        return std::nullopt;
    }

    RuntimeDynamicInfo info;
    const ElfProgramHeader* dynamicPhdr = nullptr;
    for (uint16_t i = 0; i < module.phnum; ++i) {
        if (module.phdrs[i].p_type == PT_DYNAMIC) {
            dynamicPhdr = &module.phdrs[i];
            break;
        }
    }
    if (dynamicPhdr == nullptr) {
        return std::nullopt;
    }

    const auto* dyn = reinterpret_cast<const ElfDynamic*>(module.base + dynamicPhdr->p_vaddr);
    const size_t dynCount = dynamicPhdr->p_memsz / sizeof(ElfDynamic);
    for (size_t i = 0; i < dynCount; ++i) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:
                info.symtab =
                    reinterpret_cast<const ElfSymbol*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_STRTAB:
                info.strtab =
                    reinterpret_cast<const char*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_HASH:
                info.hash =
                    reinterpret_cast<const uint32_t*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_GNU_HASH:
                info.gnuHash =
                    reinterpret_cast<const uint32_t*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_JMPREL:
                info.jmprel = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                info.pltrelSize = dyn[i].d_un.d_val;
                break;
            case DT_RELA:
                info.rela = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_RELASZ:
                info.relaSize = dyn[i].d_un.d_val;
                break;
            case DT_REL:
                info.rel = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_RELSZ:
                info.relSize = dyn[i].d_un.d_val;
                break;
            case DT_SYMENT:
                info.syment = dyn[i].d_un.d_val;
                break;
            case DT_PLTREL:
                info.usesRela = dyn[i].d_un.d_val == DT_RELA;
                break;
            default:
                break;
        }
    }

    if (info.symtab == nullptr || info.strtab == nullptr) {
        return std::nullopt;
    }
    return info;
}

// Dynamic symbol table access

const ElfSymbol* DynamicSymbolTable(const MappedFile& file, const DynamicInfo& info) {
    const auto offset = VirtualAddressToFileOffset(file, info.symtab);
    if (!offset.has_value())
        return nullptr;
    return reinterpret_cast<const ElfSymbol*>(file.bytes() + *offset);
}

const char* DynamicStringTable(const MappedFile& file, const DynamicInfo& info) {
    const auto offset = VirtualAddressToFileOffset(file, info.strtab);
    if (!offset.has_value())
        return nullptr;
    return reinterpret_cast<const char*>(file.bytes() + *offset);
}

size_t SymbolCountFromSysvHash(const MappedFile& file, uintptr_t hashAddress) {
    const auto hashOffset = VirtualAddressToFileOffset(file, hashAddress);
    if (!hashOffset.has_value())
        return 0;
    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    return words[1];  // nchain
}

size_t SymbolCountFromGnuHash(const MappedFile& file, uintptr_t gnuHashAddress) {
    const auto hashOffset = VirtualAddressToFileOffset(file, gnuHashAddress);
    if (!hashOffset.has_value())
        return 0;
    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const auto* buckets = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset + 16 +
                                                            bloomSize * sizeof(uintptr_t));
    const auto* chains = buckets + nbuckets;

    uint32_t maxSymbol = symoffset;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        if (buckets[i] > maxSymbol) {
            maxSymbol = buckets[i];
        }
    }
    if (maxSymbol == symoffset)
        return symoffset;
    uint32_t chainIndex = maxSymbol - symoffset;
    while ((chains[chainIndex] & 1U) == 0U) {
        ++chainIndex;
    }
    return symoffset + chainIndex + 1;
}

size_t DynamicSymbolCount(const MappedFile& file, const DynamicInfo& info) {
    if (info.hash != 0) {
        const size_t count = SymbolCountFromSysvHash(file, info.hash);
        if (count != 0)
            return count;
    }
    if (info.gnuHash != 0) {
        const size_t count = SymbolCountFromGnuHash(file, info.gnuHash);
        if (count != 0)
            return count;
    }
    return 0;
}

// Hash-assisted symbol lookup

uint32_t ComputeGnuHash(const uint8_t* name, size_t len) {
    uint32_t hash = 0x1505U;
    for (size_t i = 0; i < len; ++i) {
        hash = hash * 33U + name[i];
    }
    return hash;
}

uint32_t ComputeElfHash(const uint8_t* name, size_t len) {
    uint32_t hash = 0;
    for (size_t i = 0; i < len; ++i) {
        hash = (hash << 4U) + name[i];
        const uint32_t high = hash & 0xF0000000U;
        if (high != 0) {
            hash ^= high >> 24U;
        }
        hash &= 0x0FFFFFFFU;
    }
    return hash;
}

// GNU hash-assisted symbol lookup
std::optional<uint32_t> FindDynamicSymbolIndexWithGnuHash(const MappedFile& file,
                                                          const DynamicInfo& info,
                                                          const uint8_t* name, size_t nameLen,
                                                          uint32_t gnuHash) {
    if (info.gnuHash == 0)
        return std::nullopt;
    const auto hashOffset = VirtualAddressToFileOffset(file, info.gnuHash);
    if (!hashOffset.has_value())
        return std::nullopt;

    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const uint32_t bloomShift = words[3];
    if (nbuckets == 0 || bloomSize == 0)
        return std::nullopt;

    const auto* bloom = reinterpret_cast<const uintptr_t*>(words + 4);
    const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
    const auto* chains = buckets + nbuckets;

    // Bloom filter check
    const uintptr_t bloomWord = bloom[(gnuHash / (sizeof(uintptr_t) * 8U)) % bloomSize];
    const uintptr_t mask = (uintptr_t{1} << (gnuHash % (sizeof(uintptr_t) * 8U))) |
                           (uintptr_t{1} << ((gnuHash >> bloomShift) % (sizeof(uintptr_t) * 8U)));
    if ((bloomWord & mask) != mask)
        return std::nullopt;

    uint32_t symbolIndex = buckets[gnuHash % nbuckets];
    if (symbolIndex < symoffset)
        return std::nullopt;

    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    if (symbols == nullptr || strings == nullptr)
        return std::nullopt;

    for (;; ++symbolIndex) {
        const uint32_t chainHash = chains[symbolIndex - symoffset];
        if ((chainHash ^ gnuHash) < 2) {
            const auto& symbol = symbols[symbolIndex];
            const char* currentName = strings + symbol.st_name;
            const size_t currentLen = std::strlen(currentName);
            if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
                return symbolIndex;
            }
        }
        if ((chainHash & 1U) != 0U)
            break;
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndexWithSysvHash(const MappedFile& file,
                                                           const DynamicInfo& info,
                                                           const uint8_t* name, size_t nameLen,
                                                           uint32_t elfHash) {
    if (info.hash == 0)
        return std::nullopt;
    const auto hashOffset = VirtualAddressToFileOffset(file, info.hash);
    if (!hashOffset.has_value())
        return std::nullopt;

    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbucket = words[0];
    const uint32_t nchain = words[1];
    if (nbucket == 0 || nchain == 0)
        return std::nullopt;

    const auto* buckets = words + 2;
    const auto* chains = buckets + nbucket;
    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    if (symbols == nullptr || strings == nullptr)
        return std::nullopt;

    uint32_t idx = buckets[elfHash % nbucket];
    while (idx != 0 && idx < nchain) {
        const auto& sym = symbols[idx];
        const char* currentName = strings + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return idx;
        }
        idx = chains[idx];
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndexLinear(const MappedFile& file,
                                                     const DynamicInfo& info, const uint8_t* name,
                                                     size_t nameLen) {
    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    const size_t symbolCount = DynamicSymbolCount(file, info);
    if (symbols == nullptr || strings == nullptr || symbolCount == 0)
        return std::nullopt;

    for (size_t i = 0; i < symbolCount; ++i) {
        const auto& sym = symbols[i];
        const char* currentName = strings + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return static_cast<uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndex(const MappedFile& file, const DynamicInfo& info,
                                               const uint8_t* name, size_t nameLen) {
    const uint32_t gnuHash = ComputeGnuHash(name, nameLen);
    if (auto index = FindDynamicSymbolIndexWithGnuHash(file, info, name, nameLen, gnuHash);
        index.has_value()) {
        return index;
    }

    const uint32_t elfHash = ComputeElfHash(name, nameLen);
    if (auto index = FindDynamicSymbolIndexWithSysvHash(file, info, name, nameLen, elfHash);
        index.has_value()) {
        return index;
    }

    return FindDynamicSymbolIndexLinear(file, info, name, nameLen);
}

std::optional<uint32_t> FindRuntimeSymbolIndexWithGnuHash(const RuntimeDynamicInfo& info,
                                                          const uint8_t* name, size_t nameLen,
                                                          uint32_t gnuHash) {
    if (info.gnuHash == nullptr)
        return std::nullopt;

    const auto* words = info.gnuHash;
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const uint32_t bloomShift = words[3];
    if (nbuckets == 0 || bloomSize == 0)
        return std::nullopt;

    const auto* bloom = reinterpret_cast<const uintptr_t*>(words + 4);
    const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
    const auto* chains = buckets + nbuckets;
    const uintptr_t bloomWord = bloom[(gnuHash / (sizeof(uintptr_t) * 8U)) % bloomSize];
    const uintptr_t mask = (uintptr_t{1} << (gnuHash % (sizeof(uintptr_t) * 8U))) |
                           (uintptr_t{1} << ((gnuHash >> bloomShift) % (sizeof(uintptr_t) * 8U)));
    if ((bloomWord & mask) != mask)
        return std::nullopt;

    uint32_t symbolIndex = buckets[gnuHash % nbuckets];
    if (symbolIndex < symoffset)
        return std::nullopt;

    for (;; ++symbolIndex) {
        const uint32_t chainHash = chains[symbolIndex - symoffset];
        if ((chainHash ^ gnuHash) < 2) {
            const auto& symbol = info.symtab[symbolIndex];
            const char* currentName = info.strtab + symbol.st_name;
            const size_t currentLen = std::strlen(currentName);
            if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
                return symbolIndex;
            }
        }
        if ((chainHash & 1U) != 0U)
            break;
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndexWithSysvHash(const RuntimeDynamicInfo& info,
                                                           const uint8_t* name, size_t nameLen,
                                                           uint32_t elfHash) {
    if (info.hash == nullptr)
        return std::nullopt;
    const uint32_t nbucket = info.hash[0];
    const uint32_t nchain = info.hash[1];
    if (nbucket == 0 || nchain == 0)
        return std::nullopt;

    const auto* buckets = info.hash + 2;
    const auto* chains = buckets + nbucket;
    uint32_t idx = buckets[elfHash % nbucket];
    while (idx != 0 && idx < nchain) {
        const auto& sym = info.symtab[idx];
        const char* currentName = info.strtab + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return idx;
        }
        idx = chains[idx];
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndexLinear(const RuntimeDynamicInfo& info,
                                                     const uint8_t* name, size_t nameLen) {
    size_t symbolCount = 0;
    if (info.hash != nullptr) {
        symbolCount = info.hash[1];
    } else if (info.gnuHash != nullptr) {
        const uint32_t nbuckets = info.gnuHash[0];
        const uint32_t symoffset = info.gnuHash[1];
        const uint32_t bloomSize = info.gnuHash[2];
        const auto* bloom = reinterpret_cast<const uintptr_t*>(info.gnuHash + 4);
        const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
        const auto* chains = buckets + nbuckets;
        uint32_t maxSymbol = symoffset;
        for (uint32_t i = 0; i < nbuckets; ++i) {
            if (buckets[i] > maxSymbol)
                maxSymbol = buckets[i];
        }
        if (maxSymbol == symoffset) {
            symbolCount = symoffset;
        } else {
            uint32_t chainIndex = maxSymbol - symoffset;
            while ((chains[chainIndex] & 1U) == 0U)
                ++chainIndex;
            symbolCount = symoffset + chainIndex + 1;
        }
    }
    if (symbolCount == 0)
        return std::nullopt;

    for (size_t i = 0; i < symbolCount; ++i) {
        const auto& sym = info.symtab[i];
        const char* currentName = info.strtab + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return static_cast<uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndex(const RuntimeDynamicInfo& info, const uint8_t* name,
                                               size_t nameLen) {
    const uint32_t gnuHash = ComputeGnuHash(name, nameLen);
    if (auto index = FindRuntimeSymbolIndexWithGnuHash(info, name, nameLen, gnuHash);
        index.has_value()) {
        return index;
    }

    const uint32_t elfHash = ComputeElfHash(name, nameLen);
    if (auto index = FindRuntimeSymbolIndexWithSysvHash(info, name, nameLen, elfHash);
        index.has_value()) {
        return index;
    }

    return FindRuntimeSymbolIndexLinear(info, name, nameLen);
}

// Relocation slot collector
// Finds all relocation slots matching a given symbol index.
// Original iterates 3 relocation table entries: (jmprel, rela, rel).
// Uses usesRela flag for jmprel, always rela for DT_RELA, always rel for DT_REL.
// Collects matching slot addresses into a vector.

#if defined(__LP64__)
static constexpr auto kRelocationTypeJumpSlot = static_cast<uint32_t>(R_AARCH64_JUMP_SLOT);
static constexpr auto kRelocationTypeGlobDat = static_cast<uint32_t>(R_AARCH64_GLOB_DAT);
static constexpr auto kRelocationTypeAbs = static_cast<uint32_t>(R_AARCH64_ABS64);
#else
static constexpr auto kRelocationTypeJumpSlot = static_cast<uint32_t>(R_ARM_JUMP_SLOT);
static constexpr auto kRelocationTypeGlobDat = static_cast<uint32_t>(R_ARM_GLOB_DAT);
static constexpr auto kRelocationTypeAbs = static_cast<uint32_t>(R_ARM_ABS32);
#endif

void CollectRelocationSlots(const MappedFile& file, uintptr_t relocAddress, size_t relocBytes,
                            bool rela, uint32_t targetSymIndex, uintptr_t loadBias,
                            std::vector<uintptr_t>& slots) {
    if (relocAddress == 0 || relocBytes == 0)
        return;
    const auto relocOffset = VirtualAddressToFileOffset(file, relocAddress);
    if (!relocOffset.has_value())
        return;

    const size_t entrySize = rela ? sizeof(ElfRelocationWithAddend) : sizeof(ElfRelocationNoAddend);
    const size_t count = relocBytes / entrySize;

    for (size_t i = 0; i < count; ++i) {
        uint64_t infoValue = 0;
        uintptr_t offsetValue = 0;
        if (rela) {
            const auto* r = reinterpret_cast<const ElfRelocationWithAddend*>(
                file.bytes() + *relocOffset + i * sizeof(ElfRelocationWithAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        } else {
            const auto* r = reinterpret_cast<const ElfRelocationNoAddend*>(
                file.bytes() + *relocOffset + i * sizeof(ElfRelocationNoAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        }

#if defined(__LP64__)
        const uint32_t relocationType = ELF64_R_TYPE(infoValue);
        const uint32_t symIndex = ELF64_R_SYM(infoValue);
#else
        const uint32_t relocationType = ELF32_R_TYPE(infoValue);
        const uint32_t symIndex = ELF32_R_SYM(infoValue);
#endif

        if (symIndex != targetSymIndex)
            continue;
        // Original accepts both JUMP_SLOT and GLOB_DAT for usesRela=true path,
        //   and JUMP_SLOT or ABS for usesRela=false.
        if (relocationType != kRelocationTypeJumpSlot && relocationType != kRelocationTypeGlobDat &&
            relocationType != kRelocationTypeAbs) {
            continue;
        }

        const uintptr_t slotAddr = offsetValue + loadBias;
        if (slotAddr <= loadBias)
            continue;  // sanity check matching original

        // Deduplicate
        bool found = false;
        for (const auto& existing : slots) {
            if (existing == slotAddr) {
                found = true;
                break;
            }
        }
        if (!found) {
            slots.push_back(slotAddr);
        }
    }
}

// Full relocation slot collection for a symbol index, across all 3 tables
std::vector<uintptr_t> FindRelocationSlotsForSymbol(const MappedFile& file, const DynamicInfo& info,
                                                    uint32_t symIndex, uintptr_t loadBias) {
    std::vector<uintptr_t> slots;

    // Table 1: JMPREL (uses DT_PLTREL to determine rela vs rel)
    CollectRelocationSlots(file, info.jmprel, info.pltrelSize, info.usesRela, symIndex, loadBias,
                           slots);
    // Table 2: DT_RELA
    CollectRelocationSlots(file, info.rela, info.relaSize, true, symIndex, loadBias, slots);
    // Table 3: DT_REL
    CollectRelocationSlots(file, info.rel, info.relSize, false, symIndex, loadBias, slots);
    return slots;
}

void CollectRuntimeRelocationSlots(uintptr_t relocAddress, size_t relocBytes, bool rela,
                                   uint32_t targetSymIndex, uintptr_t loadBias,
                                   std::vector<uintptr_t>& slots) {
    if (relocAddress == 0 || relocBytes == 0)
        return;

    const size_t entrySize = rela ? sizeof(ElfRelocationWithAddend) : sizeof(ElfRelocationNoAddend);
    const size_t count = relocBytes / entrySize;
    for (size_t i = 0; i < count; ++i) {
        uint64_t infoValue = 0;
        uintptr_t offsetValue = 0;
        if (rela) {
            const auto* r = reinterpret_cast<const ElfRelocationWithAddend*>(
                relocAddress + i * sizeof(ElfRelocationWithAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        } else {
            const auto* r = reinterpret_cast<const ElfRelocationNoAddend*>(
                relocAddress + i * sizeof(ElfRelocationNoAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        }

#if defined(__LP64__)
        const uint32_t relocationType = ELF64_R_TYPE(infoValue);
        const uint32_t symIndex = ELF64_R_SYM(infoValue);
#else
        const uint32_t relocationType = ELF32_R_TYPE(infoValue);
        const uint32_t symIndex = ELF32_R_SYM(infoValue);
#endif

        if (symIndex != targetSymIndex)
            continue;
        if (relocationType != kRelocationTypeJumpSlot && relocationType != kRelocationTypeGlobDat &&
            relocationType != kRelocationTypeAbs) {
            continue;
        }

        const uintptr_t slotAddr = offsetValue + loadBias;
        bool found = false;
        for (const auto existing : slots) {
            if (existing == slotAddr) {
                found = true;
                break;
            }
        }
        if (!found) {
            slots.push_back(slotAddr);
        }
    }
}

std::vector<uintptr_t> FindRuntimeRelocationSlotsForSymbol(const RuntimeDynamicInfo& info,
                                                           uint32_t symIndex, uintptr_t loadBias) {
    std::vector<uintptr_t> slots;
    CollectRuntimeRelocationSlots(info.jmprel, info.pltrelSize, info.usesRela, symIndex, loadBias,
                                  slots);
    CollectRuntimeRelocationSlots(info.rela, info.relaSize, true, symIndex, loadBias, slots);
    CollectRuntimeRelocationSlots(info.rel, info.relSize, false, symIndex, loadBias, slots);
    return slots;
}

// Compare hook installer
// Original signature (simplified):
//   void InstallCompareHook(ElfInfo* elfInfo, const char* symbolName,
//                           const char* altSymbolName, void* replacement,
//                           void** backup, const char* altMangledName)
//
// It calls function to find relocation slots for symbolName.
// If altSymbolName is provided and no slots found, tries altSymbolName.
// Then iterates slots, mprotect + patch + flush.
// Log format on no slots: "no %s found" with the label name.
// Log format on mprotect failure: "failed with %d %s: mprotect"
// Does NOT restore mprotect permissions after patching.

struct ElfInfo {
    uintptr_t loadBias = 0;  // used for slot address computation
    int pageSize = 0;        // ~pageSize mask for mprotect
    int pageSizeRaw = 0;     // pageSize value for mprotect length

    // These come from the parsed ELF, stored once by the init function
    const MappedFile* mapped = nullptr;
    const DynamicInfo* dynInfo = nullptr;
};

void InstallCompareHook(const ElfInfo& elfInfo, std::string_view symbolName,
                        std::string_view altSymbolName, void* replacement, void** backup,
                        const char* displayLabel) {
    // Find symbol index via GNU hash
    const auto* nameData = reinterpret_cast<const uint8_t*>(symbolName.data());
    const size_t nameLen = symbolName.size();

    auto symIdx = FindDynamicSymbolIndex(*elfInfo.mapped, *elfInfo.dynInfo, nameData, nameLen);

    std::vector<uintptr_t> slots;
    if (symIdx.has_value()) {
        slots = FindRelocationSlotsForSymbol(*elfInfo.mapped, *elfInfo.dynInfo, *symIdx,
                                             elfInfo.loadBias);
    }

    // Try alt symbol name if no slots found and alt is provided
    if (!altSymbolName.empty() && slots.empty()) {
        const auto* altData = reinterpret_cast<const uint8_t*>(altSymbolName.data());
        const size_t altLen = altSymbolName.size();

        symIdx = FindDynamicSymbolIndex(*elfInfo.mapped, *elfInfo.dynInfo, altData, altLen);
        if (symIdx.has_value()) {
            slots = FindRelocationSlotsForSymbol(*elfInfo.mapped, *elfInfo.dynInfo, *symIdx,
                                                 elfInfo.loadBias);
        }
    }

    if (slots.empty()) {
        __android_log_print(6, kLogTag, "no %s found", displayLabel);
        return;
    }

    __android_log_print(4, kLogTag, "compare hook %s slots=%zu primary=%s alt=%s", displayLabel,
                        slots.size(), std::string(symbolName).c_str(),
                        altSymbolName.empty() ? "" : std::string(altSymbolName).c_str());

    // Patch each slot
    for (const auto slotAddr : slots) {
        auto* slot = reinterpret_cast<void**>(slotAddr);
        const uintptr_t pageMask = ~static_cast<uintptr_t>(elfInfo.pageSize - 1);
        const auto* pageStart = reinterpret_cast<void*>(slotAddr & pageMask);

        if (mprotect(const_cast<void*>(pageStart), elfInfo.pageSizeRaw, PROT_READ | PROT_WRITE) <
            0) {
            const int err = errno;
            __android_log_print(6, kLogTag, "failed with %d %s: mprotect", err, strerror(err));
            continue;
        }

        // Store backup (first slot only, matching original)
        if (backup != nullptr) {
            *backup = *slot;
        }

        // Patch
        *slot = replacement;

        __android_log_print(3, kLogTag, "patched %s slot=%p old=%p new=%p", displayLabel,
                            reinterpret_cast<void*>(slotAddr),
                            backup != nullptr ? *backup : nullptr, replacement);

        // Flush instruction cache
        const auto flushEnd = reinterpret_cast<void*>((slotAddr + elfInfo.pageSizeRaw) & pageMask);
        FlushCodeRange(const_cast<void*>(pageStart), flushEnd);

        // Restore original memory permissions
        mprotect(const_cast<void*>(pageStart), elfInfo.pageSizeRaw, PROT_READ);
    }
}

// Unified symbol resolution (dynamic-first, section fallback)

std::optional<void*> ResolveTargetSymbol(const ModuleInfo& module, std::string_view symbolName) {
    auto mapped = MapReadOnlyFile(module.path);
    if (!mapped.has_value()) {
        return std::nullopt;
    }
    std::optional<uintptr_t> offset;
    if (auto dynamicInfo = ParseDynamicInfo(*mapped); dynamicInfo.has_value()) {
        // Try GNU hash first
        const auto* nameData = reinterpret_cast<const uint8_t*>(symbolName.data());
        const size_t nameLen = symbolName.size();
        const uint32_t gnuH = ComputeGnuHash(nameData, nameLen);

        auto symIdx =
            FindDynamicSymbolIndexWithGnuHash(*mapped, *dynamicInfo, nameData, nameLen, gnuH);
        if (symIdx.has_value()) {
            const ElfSymbol* symbols = DynamicSymbolTable(*mapped, *dynamicInfo);
            if (symbols != nullptr && symbols[*symIdx].st_value != 0) {
                offset = static_cast<uintptr_t>(symbols[*symIdx].st_value);
            }
        }

        // Fall back to SysV hash chain
        if (!offset.has_value() && dynamicInfo->hash != 0) {
            const auto hashOffset = VirtualAddressToFileOffset(*mapped, dynamicInfo->hash);
            if (hashOffset.has_value()) {
                const ElfSymbol* symbols = DynamicSymbolTable(*mapped, *dynamicInfo);
                const char* strings = DynamicStringTable(*mapped, *dynamicInfo);
                if (symbols && strings) {
                    const auto* words =
                        reinterpret_cast<const uint32_t*>(mapped->bytes() + *hashOffset);
                    const uint32_t nbucket = words[0];
                    const uint32_t nchain = words[1];
                    const auto* buckets = words + 2;
                    const auto* chains = buckets + nbucket;
                    const uint32_t elfH = ComputeElfHash(nameData, nameLen);

                    uint32_t idx = buckets[elfH % nbucket];
                    while (idx != 0 && idx < nchain) {
                        const auto& sym = symbols[idx];
                        const char* n = strings + sym.st_name;
                        const size_t nlen = std::strlen(n);
                        if (nameLen == nlen && std::memcmp(nameData, n, nameLen) == 0 &&
                            sym.st_value != 0) {
                            offset = static_cast<uintptr_t>(sym.st_value);
                            break;
                        }
                        idx = chains[idx];
                    }
                }
            }
        }

        // Fall back to linear scan
        if (!offset.has_value()) {
            const ElfSymbol* symbols = DynamicSymbolTable(*mapped, *dynamicInfo);
            const char* strings = DynamicStringTable(*mapped, *dynamicInfo);
            const size_t symbolCount = DynamicSymbolCount(*mapped, *dynamicInfo);
            if (symbols && strings && symbolCount > 0) {
                for (size_t i = 0; i < symbolCount; ++i) {
                    const auto& sym = symbols[i];
                    if (sym.st_name == 0 || sym.st_value == 0)
                        continue;
                    const char* n = strings + sym.st_name;
                    if (symbolName == n) {
                        offset = static_cast<uintptr_t>(sym.st_value);
                        break;
                    }
                }
            }
        }
    }

    // Section fallback
    if (!offset.has_value()) {
        offset = FindSymbolOffset(*mapped, symbolName);
    }

    if (!offset.has_value()) {
        return std::nullopt;
    }
    return reinterpret_cast<void*>(module.base + *offset);
}

std::optional<void*> ResolveTargetSymbolRuntime(const ModuleInfo& module,
                                                std::string_view symbolName) {
    auto dynInfo = ParseRuntimeDynamicInfo(module);
    if (dynInfo.has_value()) {
        const auto* nameData = reinterpret_cast<const uint8_t*>(symbolName.data());
        const size_t nameLen = symbolName.size();
        auto symIdx = FindRuntimeSymbolIndex(*dynInfo, nameData, nameLen);
        if (symIdx.has_value()) {
            const auto& sym = dynInfo->symtab[*symIdx];
            if (sym.st_value != 0) {
                return reinterpret_cast<void*>(module.base + sym.st_value);
            }
        }
    }

    std::optional<MappedFile> mapped;
    if (module.path.find("!/") != std::string::npos) {
        mapped = MapEmbeddedStoredElf(module.path);
    } else {
        mapped = MapReadOnlyFile(module.path);
    }

    if (!mapped.has_value()) {
        return std::nullopt;
    }

    auto offset = FindSymbolOffset(*mapped, symbolName);
    if (!offset.has_value()) {
        return std::nullopt;
    }

    return reinterpret_cast<void*>(module.base + *offset);
}

// Inline hook installer (for path functions)

struct CoreHookStatus {
    bool appAccessible = false;
    bool packageOwned = false;
    bool packageCoveredByComparePath = false;
    bool bpfBacking = false;
    bool strcasecmp = false;
    bool equalsIgnoreCase = false;
};

struct FileElfContext {
    MappedFile mapped;
    DynamicInfo dynInfo;
    ElfInfo elfInfo;
};

template <size_t N>
bool HasResolvableSymbol(const ModuleInfo& module, const std::string_view (&symbols)[N]) {
    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    for (const auto& symbol : symbols) {
        auto resolved = useRuntimeElf ? ResolveTargetSymbolRuntime(module, symbol)
                                      : ResolveTargetSymbol(module, symbol);
        if (resolved.has_value()) {
            return true;
        }
    }
    return false;
}

void RefreshCoreHookStatus(const ModuleInfo& module, CoreHookStatus* status) {
    if (status == nullptr) {
        return;
    }
    status->appAccessible = gOriginalIsAppAccessiblePath != nullptr;
    status->packageCoveredByComparePath =
        gOriginalIsPackageOwnedPath == nullptr && gOriginalEqualsIgnoreCase != nullptr &&
        gOriginalStrcasecmp != nullptr && HasResolvableSymbol(module, kContainsMountSymbols);
    status->packageOwned =
        gOriginalIsPackageOwnedPath != nullptr || status->packageCoveredByComparePath;
    status->bpfBacking = gOriginalIsBpfBackingPath != nullptr;
    status->strcasecmp = gOriginalStrcasecmp != nullptr;
    status->equalsIgnoreCase = gOriginalEqualsIgnoreCase != nullptr;
}

bool HasAllCoreHooks(const CoreHookStatus& status) {
    return status.appAccessible && status.packageOwned && status.bpfBacking && status.strcasecmp &&
           status.equalsIgnoreCase;
}

void LogCoreHookStatus(const char* stage, const CoreHookStatus& status) {
    __android_log_print(4, kLogTag,
                        "%s core hooks app=%d package=%d package_compare=%d bpf=%d strcasecmp=%d "
                        "equals=%d",
                        stage, status.appAccessible, status.packageOwned,
                        status.packageCoveredByComparePath, status.bpfBacking, status.strcasecmp,
                        status.equalsIgnoreCase);
}

std::optional<FileElfContext> BuildFileElfContext(const ModuleInfo& module) {
    auto mapped = MapReadOnlyFile(module.path);
    if (!mapped.has_value()) {
        return std::nullopt;
    }

    auto dynInfo = ParseDynamicInfo(*mapped);
    if (!dynInfo.has_value()) {
        return std::nullopt;
    }

    FileElfContext context;
    context.mapped = std::move(*mapped);
    context.dynInfo = std::move(*dynInfo);
    const int pageSize = getpagesize();
    context.elfInfo.loadBias = module.base;
    context.elfInfo.pageSize = pageSize;
    context.elfInfo.pageSizeRaw = pageSize;
    context.elfInfo.mapped = &context.mapped;
    context.elfInfo.dynInfo = &context.dynInfo;
    return context;
}

bool TryInstallInlineHookAt(void* target, void* replacement, void** backup,
                            const char* failureMessage) {
    if (backup != nullptr && *backup != nullptr) {
        return true;
    }
    if (gHookInstaller == nullptr) {
        __android_log_print(6, kLogTag, "hook installer is null for %s", failureMessage);
        return false;
    }
    const int status = gHookInstaller(target, replacement, backup);
    if (status != 0) {
        __android_log_print(6, kLogTag, "%s: %d", failureMessage, status);
        return false;
    }
    __android_log_print(4, kLogTag, "inline hook ok target=%p backup=%p", target,
                        backup != nullptr ? *backup : nullptr);
    return true;
}

bool TryInstallFileInlineHook(const ModuleInfo& module, std::string_view symbolName,
                              void* replacement, void** backup, const char* failureMessage) {
    auto target = ResolveTargetSymbol(module, symbolName);
    if (!target.has_value()) {
        __android_log_print(3, kLogTag, "resolve failed %s", std::string(symbolName).c_str());
        return false;
    }
    return TryInstallInlineHookAt(*target, replacement, backup, failureMessage);
}

bool TryInstallRuntimeInlineHook(const ModuleInfo& module, std::string_view symbolName,
                                 void* replacement, void** backup, const char* failureMessage) {
    auto target = ResolveTargetSymbolRuntime(module, symbolName);
    if (!target.has_value()) {
        __android_log_print(3, kLogTag, "runtime resolve failed %s",
                            std::string(symbolName).c_str());
        return false;
    }
    return TryInstallInlineHookAt(*target, replacement, backup, failureMessage);
}

bool InstallHookForSymbol(std::string_view symbolName, void* replacement, void** backup,
                          const char* failureMessage);

template <size_t N>
bool InstallFirstAvailableFileInlineHook(const ModuleInfo& module,
                                         const std::string_view (&symbols)[N], void* replacement,
                                         void** backup, const char* failureMessage) {
    for (const auto& sym : symbols) {
        if (TryInstallFileInlineHook(module, sym, replacement, backup, failureMessage)) {
            return true;
        }
    }
    return false;
}

template <size_t N>
bool InstallFirstAvailableInlineHook(const std::string_view (&symbols)[N], void* replacement,
                                     void** backup, const char* failureMessage) {
    for (const auto& sym : symbols) {
        if (InstallHookForSymbol(sym, replacement, backup, failureMessage)) {
            return true;
        }
    }
    return false;
}

void InstallFileCompareHookIfNeeded(const ElfInfo& elfInfo, std::string_view primary,
                                    std::string_view alt, void* replacement, void** backup,
                                    const char* label) {
    if (backup != nullptr && *backup != nullptr) {
        return;
    }
    InstallCompareHook(elfInfo, primary, alt, replacement, backup, label);
}

void PatchRuntimeRelocationSlots(const RuntimeDynamicInfo& runtimeDyn, uintptr_t moduleBase,
                                 int pageSize, std::string_view primary, std::string_view alt,
                                 void* replacement, void** backup, const char* label) {
    if (backup != nullptr && *backup != nullptr) {
        return;
    }

    auto idx = FindRuntimeSymbolIndex(runtimeDyn, reinterpret_cast<const uint8_t*>(primary.data()),
                                      primary.size());
    std::vector<uintptr_t> slots;
    if (idx.has_value()) {
        slots = FindRuntimeRelocationSlotsForSymbol(runtimeDyn, *idx, moduleBase);
    }
    if (slots.empty() && !alt.empty()) {
        idx = FindRuntimeSymbolIndex(runtimeDyn, reinterpret_cast<const uint8_t*>(alt.data()),
                                     alt.size());
        if (idx.has_value()) {
            slots = FindRuntimeRelocationSlotsForSymbol(runtimeDyn, *idx, moduleBase);
        }
    }
    if (slots.empty()) {
        __android_log_print(6, kLogTag, "no %s found", label);
        return;
    }

    __android_log_print(4, kLogTag, "compare hook %s slots=%zu", label, slots.size());
    for (const auto slotAddr : slots) {
        auto* slot = reinterpret_cast<void**>(slotAddr);
        const uintptr_t pageMask = ~static_cast<uintptr_t>(pageSize - 1);
        auto* pageStart = reinterpret_cast<void*>(slotAddr & pageMask);
        if (mprotect(pageStart, pageSize, PROT_READ | PROT_WRITE) < 0) {
            const int err = errno;
            __android_log_print(6, kLogTag, "failed with %d %s: mprotect", err, strerror(err));
            continue;
        }
        if (backup != nullptr) {
            *backup = *slot;
        }
        *slot = replacement;
        __android_log_print(3, kLogTag, "patched %s slot=%p old=%p new=%p", label,
                            reinterpret_cast<void*>(slotAddr),
                            backup != nullptr ? *backup : nullptr, replacement);
        FlushCodeRange(pageStart, reinterpret_cast<void*>((slotAddr + pageSize) & pageMask));
        mprotect(pageStart, pageSize, PROT_READ);
    }
}

bool InstallHookForSymbol(std::string_view symbolName, void* replacement, void** backup,
                          const char* failureMessage) {
    if (backup != nullptr && *backup != nullptr) {
        return true;
    }
    auto module = FindTargetModule();
    if (!module.has_value()) {
        __android_log_print(6, kLogTag, "no %s found", kTargetLibrary);
        return false;
    }
    const bool useRuntimeElf = module->path.find("!/") != std::string::npos;
    return useRuntimeElf
               ? TryInstallRuntimeInlineHook(*module, symbolName, replacement, backup,
                                             failureMessage)
               : TryInstallFileInlineHook(*module, symbolName, replacement, backup, failureMessage);
}

// File-backed hooks are preferred first because they let us resolve internal symbols by name even
// when the runtime ELF image is embedded inside an APK path.
void InstallMinimalCoreHooks(const ModuleInfo& module, const FileElfContext& fileContext,
                             CoreHookStatus* status) {
    InstallFirstAvailableFileInlineHook(module, kIsAppAccessiblePathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
                                        reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
                                        "hook is_app_accessible_path failed");
    InstallFirstAvailableFileInlineHook(module, kIsPackageOwnedPathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsPackageOwnedPath),
                                        reinterpret_cast<void**>(&gOriginalIsPackageOwnedPath),
                                        "hook is_package_owned_path failed");
    InstallFirstAvailableFileInlineHook(
        module, kIsBpfBackingPathSymbols, reinterpret_cast<void*>(+WrappedIsBpfBackingPath),
        reinterpret_cast<void**>(&gOriginalIsBpfBackingPath), "hook is_bpf_backing_path failed");

    InstallFileCompareHookIfNeeded(fileContext.elfInfo, kStrcasecmpSymbol, kStrcasecmpSymbol,
                                   reinterpret_cast<void*>(+WrappedStrcasecmp),
                                   &gOriginalStrcasecmp, "strcasecmp");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, kEqualsIgnoreCaseSymbols[0],
                                   kEqualsIgnoreCaseSymbols[1],
                                   reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                   &gOriginalEqualsIgnoreCase, "EqualsIgnoreCase");

    if (gOriginalIsAppAccessiblePath == nullptr) {
        // Reverse-engineered record: is_app_accessible_path @ 0x0017bb5c.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDeviceIsAppAccessiblePathOffset),
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (gOriginalShouldNotCache == nullptr) {
        // Reverse-engineered record: ShouldNotCache @ 0x0017dc64.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDeviceShouldNotCacheOffset),
                               (void*)WrappedShouldNotCache, &gOriginalShouldNotCache,
                               "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// These hooks are functionally required for hidden-path semantics. Only the verbose trace logging
// inside the wrappers stays gated by kEnableDebugHooks.
void InstallMinimalDebugHooks(const ModuleInfo& module, const FileElfContext& fileContext) {
    InstallFileCompareHookIfNeeded(
        fileContext.elfInfo, "fuse_lowlevel_notify_inval_entry", "fuse_lowlevel_notify_inval_entry",
        (void*)WrappedNotifyInvalEntry, &gOriginalNotifyInvalEntry, "notify_inval_entry");
    InstallFileCompareHookIfNeeded(
        fileContext.elfInfo, "fuse_lowlevel_notify_inval_inode", "fuse_lowlevel_notify_inval_inode",
        (void*)WrappedNotifyInvalInode, &gOriginalNotifyInvalInode, "notify_inval_inode");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_entry", "fuse_reply_entry",
                                   (void*)WrappedReplyEntry, &gOriginalReplyEntry, "reply_entry");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_attr", "fuse_reply_attr",
                                   (void*)WrappedReplyAttr, &gOriginalReplyAttr, "reply_attr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_buf", "fuse_reply_buf",
                                   (void*)WrappedReplyBuf, &gOriginalReplyBuf, "reply_buf");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_err", "fuse_reply_err",
                                   (void*)WrappedReplyErr, &gOriginalReplyErr, "reply_err");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "lstat", "lstat", (void*)WrappedLstat,
                                   &gOriginalLstat, "lstat");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "stat", "stat", (void*)WrappedStat,
                                   &gOriginalStat, "stat");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mkdir", "mkdir", (void*)WrappedMkdirLibc,
                                   &gOriginalMkdir, "mkdir");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mknod", "mknod", (void*)WrappedMknod,
                                   &gOriginalMknod, "mknod");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "open", "open", (void*)WrappedOpen,
                                   &gOriginalOpen, "open");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "__open_2", "__open_2", (void*)WrappedOpen2,
                                   &gOriginalOpen2, "__open_2");
    if (gOriginalGetDirectoryEntries == nullptr) {
        // Reverse-engineered record: MediaProviderWrapper::GetDirectoryEntries @ 0x0018a3ec.
        // This wrapper is a C++ member function and is not always reachable through imported symbol
        // tables on the device build, so keep the direct RVA fallback.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDeviceGetDirectoryEntriesOffset),
            (void*)WrappedGetDirectoryEntries, &gOriginalGetDirectoryEntries,
            "hook GetDirectoryEntries failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // mkdir policy lives in an internal static handler, so keep the device-specific offset as a
        // backup when symbol-based lookup is unavailable.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfMkdirOffset),
                               (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        // Some create paths go through pf_mknod instead of pf_create on device builds.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfMknodOffset),
                               (void*)WrappedPfMknod, &gOriginalPfMknod, "hook pf_mknod failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        // unlink/rmdir/create handlers are internal statics in libfuse_jni, so retain the verified
        // offset fallback for devices that do not expose stable symbols.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfUnlinkOffset),
                               (void*)WrappedPfUnlink, &gOriginalPfUnlink, "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfRmdirOffset),
                               (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        // rename follows the same parent-only access pattern as create/delete handlers, so keep an
        // explicit device RVA fallback for builds that do not expose the local symbol.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfRenameOffset),
                               (void*)WrappedPfRename, &gOriginalPfRename, "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfCreateOffset),
                               (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfReaddir == nullptr) {
        // Reverse-engineered record: pf_readdir @ 0x00179c40.
        // Directory enumeration behavior varies across device builds, so keep direct RVA hooks for
        // readdir, readdirplus, and readdir_postfilter in addition to the reply_buf fallback.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfReaddirOffset),
                               (void*)WrappedPfReaddir, &gOriginalPfReaddir,
                               "hook pf_readdir failed");
    }
    if (gOriginalPfReaddirplus == nullptr) {
        // Reverse-engineered record: pf_readdirplus @ 0x0017b320.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfReaddirplusOffset),
                               (void*)WrappedPfReaddirplus, &gOriginalPfReaddirplus,
                               "hook pf_readdirplus failed");
    }
    if (gOriginalPfReaddirPostfilter == nullptr) {
        // Reverse-engineered record: pf_readdir_postfilter @ 0x00179cac.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDevicePfReaddirPostfilterOffset),
            (void*)WrappedPfReaddirPostfilter, &gOriginalPfReaddirPostfilter,
            "hook pf_readdir_postfilter failed");
    }

    if (gOriginalPfLookup == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc",
                                 (void*)WrappedPfLookup, &gOriginalPfLookup,
                                 "hook pf_lookup failed");
    }
    if (gOriginalPfAccess == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_accessEP8fuse_reqmi",
                                 (void*)WrappedPfAccess, &gOriginalPfAccess,
                                 "hook pf_access failed");
    }
    if (gOriginalPfOpen == nullptr) {
        TryInstallFileInlineHook(module,
                                 "_ZN13mediaprovider4fuseL7pf_openEP8fuse_reqmP14fuse_file_info",
                                 (void*)WrappedPfOpen, &gOriginalPfOpen, "hook pf_open failed");
    }
    if (gOriginalPfOpendir == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL10pf_opendirEP8fuse_reqmP14fuse_file_info",
            (void*)WrappedPfOpendir, &gOriginalPfOpendir, "hook pf_opendir failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL8pf_mkdirEP8fuse_reqmPKcj",
                                 (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_unlinkEP8fuse_reqmPKc",
                                 (void*)WrappedPfUnlink, &gOriginalPfUnlink,
                                 "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL8pf_rmdirEP8fuse_reqmPKc",
                                 (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_renameEP8fuse_reqmPKcmS4_j",
                                 (void*)WrappedPfRename, &gOriginalPfRename,
                                 "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL9pf_createEP8fuse_reqmPKcjP14fuse_file_info",
            (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        TryInstallFileInlineHook(module,
                                 "_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_"
                                 "reqmjPKcP14fuse_entry_outP18fuse_"
                                 "entry_bpf_out",
                                 (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
                                 "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL10pf_getattrEP8fuse_reqmP14fuse_file_info",
            (void*)WrappedPfGetattr, &gOriginalPfGetattr, "hook pf_getattr failed");
    }
    if (gOriginalPfLookup == nullptr) {
        // Reverse-engineered record: pf_lookup @ 0x00175e48.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfLookupOffset),
                               (void*)WrappedPfLookup, &gOriginalPfLookup, "hook pf_lookup failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDevicePfLookupPostfilterOffset),
            (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfGetattrOffset),
                               (void*)WrappedPfGetattr, &gOriginalPfGetattr,
                               "hook pf_getattr failed");
    }
}

// When file-backed symbol lookup is unavailable, fall back to runtime relocation patching and
// verified device offsets recovered from the reverse-engineered libfuse_jni build.
void InstallAdvancedCoreHooks(const ModuleInfo& module, CoreHookStatus* status) {
    if (!status->appAccessible) {
        InstallFirstAvailableInlineHook(kIsAppAccessiblePathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
                                        reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
                                        "hook is_app_accessible_path failed");
    }

    if (!status->packageOwned) {
        InstallFirstAvailableInlineHook(kIsPackageOwnedPathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsPackageOwnedPath),
                                        reinterpret_cast<void**>(&gOriginalIsPackageOwnedPath),
                                        "hook is_package_owned_path failed");
    }

    if (!status->bpfBacking) {
        InstallFirstAvailableInlineHook(kIsBpfBackingPathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsBpfBackingPath),
                                        reinterpret_cast<void**>(&gOriginalIsBpfBackingPath),
                                        "hook is_bpf_backing_path failed");
    }

    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    const int ps = getpagesize();
    if (useRuntimeElf) {
        auto runtimeDyn = ParseRuntimeDynamicInfo(module);
        if (runtimeDyn.has_value()) {
            if (!status->strcasecmp) {
                PatchRuntimeRelocationSlots(*runtimeDyn, module.base, ps, kStrcasecmpSymbol,
                                            kStrcasecmpSymbol,
                                            reinterpret_cast<void*>(+WrappedStrcasecmp),
                                            &gOriginalStrcasecmp, "strcasecmp");
            }
            if (!status->equalsIgnoreCase) {
                PatchRuntimeRelocationSlots(*runtimeDyn, module.base, ps,
                                            kEqualsIgnoreCaseSymbols[0],
                                            kEqualsIgnoreCaseSymbols[1],
                                            reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                            &gOriginalEqualsIgnoreCase, "EqualsIgnoreCase");
            }
        }
    } else if (auto fileContext = BuildFileElfContext(module); fileContext.has_value()) {
        if (!status->strcasecmp) {
            InstallFileCompareHookIfNeeded(
                fileContext->elfInfo, kStrcasecmpSymbol, kStrcasecmpSymbol,
                reinterpret_cast<void*>(+WrappedStrcasecmp), &gOriginalStrcasecmp, "strcasecmp");
        }
        if (!status->equalsIgnoreCase) {
            InstallFileCompareHookIfNeeded(fileContext->elfInfo, kEqualsIgnoreCaseSymbols[0],
                                           kEqualsIgnoreCaseSymbols[1],
                                           reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                           &gOriginalEqualsIgnoreCase, "EqualsIgnoreCase");
        }
    }

    if (gOriginalIsAppAccessiblePath == nullptr) {
        // Reverse-engineered record: is_app_accessible_path @ 0x0017bb5c.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDeviceIsAppAccessiblePathOffset),
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (gOriginalShouldNotCache == nullptr) {
        // Reverse-engineered record: ShouldNotCache @ 0x0017dc64.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDeviceShouldNotCacheOffset),
                               (void*)WrappedShouldNotCache, &gOriginalShouldNotCache,
                               "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// Advanced debug hooks extend the functional set with device-specific inline hooks for lookup,
// create, rename, readdir, and invalidation code paths that are not reliably exposed through
// imported symbols.
void InstallAdvancedDebugHooks(const ModuleInfo& module) {
    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    if (useRuntimeElf) {
        auto runtimeDyn = ParseRuntimeDynamicInfo(module);
        if (runtimeDyn) {
            PatchRuntimeRelocationSlots(
                *runtimeDyn, module.base, getpagesize(), "fuse_lowlevel_notify_inval_entry",
                "fuse_lowlevel_notify_inval_entry", (void*)WrappedNotifyInvalEntry,
                &gOriginalNotifyInvalEntry, "notify_inval_entry");
            PatchRuntimeRelocationSlots(
                *runtimeDyn, module.base, getpagesize(), "fuse_lowlevel_notify_inval_inode",
                "fuse_lowlevel_notify_inval_inode", (void*)WrappedNotifyInvalInode,
                &gOriginalNotifyInvalInode, "notify_inval_inode");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_entry",
                                        "fuse_reply_entry", (void*)WrappedReplyEntry,
                                        &gOriginalReplyEntry, "reply_entry");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_attr",
                                        "fuse_reply_attr", (void*)WrappedReplyAttr,
                                        &gOriginalReplyAttr, "reply_attr");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_buf",
                                        "fuse_reply_buf", (void*)WrappedReplyBuf,
                                        &gOriginalReplyBuf, "reply_buf");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_err",
                                        "fuse_reply_err", (void*)WrappedReplyErr,
                                        &gOriginalReplyErr, "reply_err");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "lstat", "lstat",
                                        (void*)WrappedLstat, &gOriginalLstat, "lstat");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "stat", "stat",
                                        (void*)WrappedStat, &gOriginalStat, "stat");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "mkdir", "mkdir",
                                        (void*)WrappedMkdirLibc, &gOriginalMkdir, "mkdir");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "mknod", "mknod",
                                        (void*)WrappedMknod, &gOriginalMknod, "mknod");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "open", "open",
                                        (void*)WrappedOpen, &gOriginalOpen, "open");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "__open_2",
                                        "__open_2", (void*)WrappedOpen2, &gOriginalOpen2,
                                        "__open_2");
        }
    } else if (auto fileContext = BuildFileElfContext(module); fileContext.has_value()) {
        InstallMinimalDebugHooks(module, *fileContext);
    }

    if (gOriginalGetDirectoryEntries == nullptr) {
        // Reverse-engineered record: MediaProviderWrapper::GetDirectoryEntries @ 0x0018a3ec.
        // Keep the RVA fallback even after runtime relocation patching because this member function
        // is not guaranteed to participate in imported relocation slots.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDeviceGetDirectoryEntriesOffset),
            (void*)WrappedGetDirectoryEntries, &gOriginalGetDirectoryEntries,
            "hook GetDirectoryEntries failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // The advanced path still keeps explicit handler RVAs because these static functions may be
        // absent from runtime relocation metadata.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfMkdirOffset),
                               (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfMknodOffset),
                               (void*)WrappedPfMknod, &gOriginalPfMknod, "hook pf_mknod failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfUnlinkOffset),
                               (void*)WrappedPfUnlink, &gOriginalPfUnlink, "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfRmdirOffset),
                               (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfRenameOffset),
                               (void*)WrappedPfRename, &gOriginalPfRename, "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfCreateOffset),
                               (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfReaddir == nullptr) {
        // Reverse-engineered record: pf_readdir @ 0x00179c40.
        // These three offsets correspond to the internal enumeration handlers we validated in the
        // reverse-engineered device binary.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfReaddirOffset),
                               (void*)WrappedPfReaddir, &gOriginalPfReaddir,
                               "hook pf_readdir failed");
    }
    if (gOriginalPfReaddirplus == nullptr) {
        // Reverse-engineered record: pf_readdirplus @ 0x0017b320.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfReaddirplusOffset),
                               (void*)WrappedPfReaddirplus, &gOriginalPfReaddirplus,
                               "hook pf_readdirplus failed");
    }
    if (gOriginalPfReaddirPostfilter == nullptr) {
        // Reverse-engineered record: pf_readdir_postfilter @ 0x00179cac.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDevicePfReaddirPostfilterOffset),
            (void*)WrappedPfReaddirPostfilter, &gOriginalPfReaddirPostfilter,
            "hook pf_readdir_postfilter failed");
    }

    if (gOriginalPfLookup == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc",
                             (void*)WrappedPfLookup, &gOriginalPfLookup, "hook pf_lookup failed");
    }
    if (gOriginalPfAccess == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_accessEP8fuse_reqmi",
                             (void*)WrappedPfAccess, &gOriginalPfAccess, "hook pf_access failed");
    }
    if (gOriginalPfOpen == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL7pf_openEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfOpen, &gOriginalPfOpen, "hook pf_open failed");
    }
    if (gOriginalPfOpendir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL10pf_opendirEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfOpendir, &gOriginalPfOpendir,
                             "hook pf_opendir failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_mkdirEP8fuse_reqmPKcj",
                             (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfMknod == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_mknodEP8fuse_reqmPKcjm",
                             (void*)WrappedPfMknod, &gOriginalPfMknod, "hook pf_mknod failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_unlinkEP8fuse_reqmPKc",
                             (void*)WrappedPfUnlink, &gOriginalPfUnlink, "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_rmdirEP8fuse_reqmPKc",
                             (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_renameEP8fuse_reqmPKcmS4_j",
                             (void*)WrappedPfRename, &gOriginalPfRename, "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_createEP8fuse_reqmPKcjP14fuse_file_info",
                             (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        InstallHookForSymbol(
            "_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_reqmjPKcP14fuse_entry_"
            "outP18fuse_"
            "entry_bpf_out",
            (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL10pf_getattrEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfGetattr, &gOriginalPfGetattr,
                             "hook pf_getattr failed");
    }
    if (gOriginalPfLookup == nullptr) {
        // Reverse-engineered record: pf_lookup @ 0x00175e48.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfLookupOffset),
                               (void*)WrappedPfLookup, &gOriginalPfLookup, "hook pf_lookup failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + kDevicePfLookupPostfilterOffset),
            (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + kDevicePfGetattrOffset),
                               (void*)WrappedPfGetattr, &gOriginalPfGetattr,
                               "hook pf_getattr failed");
    }
}

// Install all hooks after LSPosed reports that libfuse_jni.so has been loaded into MediaProvider.

void InstallFuseHooks() {
    auto module = FindTargetModule();
    if (!module.has_value()) {
        __android_log_print(6, kLogTag, "no %s found", kTargetLibrary);
        return;
    }

    __android_log_print(4, kLogTag, "hooking libfuse_jni");
    __android_log_print(4, kLogTag, "target module base=%p path=%s",
                        reinterpret_cast<void*>(module->base), module->path.c_str());
    const bool useRuntimeElf = module->path.find("!/") != std::string::npos;
    if (useRuntimeElf) {
        __android_log_print(4, kLogTag, "using in-memory ELF parser for embedded library path");
    }

    CoreHookStatus coreStatus;
    RefreshCoreHookStatus(*module, &coreStatus);

    if (!useRuntimeElf) {
        if (auto fileContext = BuildFileElfContext(*module); fileContext.has_value()) {
            __android_log_print(4, kLogTag, "installing minimal file-backed hook path first");
            InstallMinimalCoreHooks(*module, *fileContext, &coreStatus);
            InstallMinimalDebugHooks(*module, *fileContext);
            LogCoreHookStatus("after minimal", coreStatus);
        } else {
            __android_log_print(5, kLogTag,
                                "minimal file-backed hook path unavailable, falling back");
        }
    }

    if (!HasAllCoreHooks(coreStatus) || useRuntimeElf) {
        __android_log_print(4, kLogTag, "installing advanced hook fallback");
        InstallAdvancedCoreHooks(*module, &coreStatus);
        LogCoreHookStatus("after fallback", coreStatus);
    }

    // Release builds still need these hooks for reply filtering, named target interception, and
    // cache invalidation. kEnableDebugHooks only suppresses the verbose trace logging inside the
    // wrappers themselves.
    InstallAdvancedDebugHooks(*module);

    __android_log_print(
        4, kLogTag,
        "hook summary app=%p package_ptr=%p package_compare=%d bpf=%p strcasecmp=%p equals=%p "
        "icu=%p",
        reinterpret_cast<void*>(gOriginalIsAppAccessiblePath),
        reinterpret_cast<void*>(gOriginalIsPackageOwnedPath),
        coreStatus.packageCoveredByComparePath, reinterpret_cast<void*>(gOriginalIsBpfBackingPath),
        gOriginalStrcasecmp, gOriginalEqualsIgnoreCase,
        reinterpret_cast<void*>(gUHasBinaryProperty));
}

// Native entry points exposed to JNI and the LSPosed native loader.

extern "C" void PostNativeInit(const char* loadedLibrary, void*) {
    if (loadedLibrary == nullptr || std::strstr(loadedLibrary, kTargetLibrary) == nullptr) {
        return;
    }
    InstallFuseHooks();
}

}  // end of namespace

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    gJavaVm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_rmdir(JNIEnv* env, jclass clazz,
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

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_unlink(JNIEnv* env, jclass clazz,
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

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_mkdir(JNIEnv* env, jclass clazz,
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

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_rename(JNIEnv* env, jclass clazz,
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

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_create(JNIEnv* env, jclass clazz,
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
    __android_log_print(4, kLogTag, "Loaded");
    if (api != nullptr) {
        gHookInstaller = reinterpret_cast<const NativeApiEntries*>(api)->hookFunc;
    }
    return reinterpret_cast<void*>(+PostNativeInit);
}
