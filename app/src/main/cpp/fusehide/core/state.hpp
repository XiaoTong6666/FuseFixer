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

#pragma once

#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "fusehide/hooks/hook_abi.hpp"

struct fuse_session {};
struct fuse_req {
    struct fuse_session* se;
    uint64_t unique;
};
typedef struct fuse_req* fuse_req_t;

struct fuse_ctx {
    uid_t uid;
    gid_t gid;
    pid_t pid;
    mode_t umask;
};

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

namespace fusehide {

inline constexpr const char* kLogTag = "FuseHide";
inline constexpr const char* kTargetLibrary = "libfuse_jni.so";
inline constexpr std::string_view kVisibleStorageRoots[] = {"/storage/emulated/0"};
// Optional stress mode: when enabled, treat every first-level entry under kVisibleStorageRoots
// as hidden for test UIDs. Keep disabled by default to avoid breaking normal app behavior.
inline constexpr bool kEnableHideAllRootEntries = false;
// Entries listed here remain visible even when kEnableHideAllRootEntries is enabled.
// Keeping Android visible avoids breaking /sdcard/Android/data and /sdcard/Android/obb.
inline constexpr std::string_view kHideAllRootEntriesExemptions[] = {
    "Android", "DCIM", "Document", "Download", "Movies", "Pictures",
};
inline constexpr std::string_view kHiddenRootEntryNames[] = {
    "su",
    "daemonsu",
};
inline constexpr std::string_view kHiddenRelativePaths[] = {};
inline constexpr std::string_view kHiddenPackages[] = {
    "com.eltavine.duckdetector",
    "io.github.xiaotong6666.fusehide",
    "io.github.a13e300.fusefixer",
};
inline constexpr std::string_view kFuseHidePackageRulePackages[] = {
    "io.github.xiaotong6666.fusehide",
    "com.eltavine.duckdetector",
};
inline constexpr std::string_view kFuseHidePackageRuleRootEntries0[] = {
    "xinhao",
};
inline constexpr std::string_view kFuseHidePackageRuleRootEntries1[] = {
    "MT2",
    "xinhao",
};

#if defined(NDEBUG)
inline constexpr bool kEnableDebugHooks = false;
#else
inline constexpr bool kEnableDebugHooks = true;
#endif

using UHasBinaryPropertyFn = int8_t (*)(uint32_t codePoint, int32_t which);
extern "C" int8_t u_hasBinaryProperty(uint32_t codePoint, int32_t which);

inline constexpr int32_t kUCHAR_DEFAULT_IGNORABLE_CODE_POINT = 5;

using HookInstaller = int (*)(void* target, void* replacement, void** backup);
// Platform libc++ may use std::__1 while the module is built against std::__ndk1. A const string
// reference is one object pointer on every supported ABI, so keep the boundary untyped and decode
// the stable libc++ object layout explicitly instead of invoking methods from the wrong namespace.
// Ghidra evidence from the supplied API 37 DEV arm64 sample: ShouldNotCache @ 0x00167ab0 and
// is_app_accessible_path @ 0x00166270 both receive the string object in x1. They read the tag from
// [x1], the long size from [x1 + 8], and the long data pointer from [x1 + 16], confirming the
// classic three-word libc++ layout decoded below for that exact binary.
using AbiStringParam = const void*;

using IsAppAccessiblePathFn = bool (*)(void* fuse, AbiStringParam path, uint32_t uid);
using IsPackageOwnedPathFn = bool (*)(AbiStringParam lhs, AbiStringParam rhs);
using IsBpfBackingPathFn = bool (*)(AbiStringParam path);
using ShouldNotCacheFn = bool (*)(void* fuse, AbiStringParam path);
using StrcasecmpFn = int (*)(const char* lhs, const char* rhs);
using EqualsIgnoreCaseAbiFn = bool (*)(const char* lhsData, size_t lhsSize, const char* rhsData,
                                       size_t rhsSize);
using FuseReplyErrFn = int (*)(fuse_req_t, int);
// Android 14 through the earlier analyzed Android 16/17 builds use the shared_ptr container. Keep
// this legacy alias and wrapper intact; it remains part of the supported MediaProvider ABI surface.
using DirectoryEntries = std::vector<std::shared_ptr<mediaprovider::fuse::DirectoryEntry>>;
// The supplied API 37 DEV sample changes the element representation to an inline DirectoryEntry.
using ValueDirectoryEntries = std::vector<mediaprovider::fuse::DirectoryEntry>;
struct CachedDirectorySnapshotEntry {
    std::string name;
    int type = 0;
};
using CachedValueDirectoryEntries = std::vector<CachedDirectorySnapshotEntry>;
inline constexpr size_t kExpectedDirectoryEntryAbiSize =
    (sizeof(std::string) + sizeof(int) + alignof(std::string) - 1) & ~(alignof(std::string) - 1);
static_assert(sizeof(std::shared_ptr<mediaprovider::fuse::DirectoryEntry>) == 2 * sizeof(void*));
static_assert(sizeof(mediaprovider::fuse::DirectoryEntry) == kExpectedDirectoryEntryAbiSize);
static_assert(sizeof(DirectoryEntries) == 3 * sizeof(void*));
static_assert(sizeof(ValueDirectoryEntries) == 3 * sizeof(void*));
static_assert(sizeof(CachedValueDirectoryEntries) == 3 * sizeof(void*));
using GetDirectoryEntriesFn = DirectoryEntries (*)(void* wrapper, uint32_t uid, AbiStringParam path,
                                                   DIR* dirp);
using GetValueDirectoryEntriesFn = ValueDirectoryEntries (*)(void* wrapper, uint32_t uid,
                                                             AbiStringParam path, DIR* dirp);
using LowerFsDirentFilterFn = bool (*)(const dirent& entry);
using AddDirectoryEntriesFromLowerFsFn = void (*)(DIR* dirp, LowerFsDirentFilterFn filter,
                                                  DirectoryEntries* entries);
using AddValueDirectoryEntriesFromLowerFsFn = void (*)(DIR* dirp, LowerFsDirentFilterFn filter,
                                                       ValueDirectoryEntries* entries);
using PfLookupFn = void (*)(fuse_req_t req, uint64_t parent, const char* name);
using PfLookupPostfilterFn = void (*)(fuse_req_t req, uint64_t parent, uint32_t errorIn,
                                      const char* name, fuse_entry_out* entryOut,
                                      fuse_entry_bpf_out* bpfOut);
using PfAccessFn = void (*)(fuse_req_t req, uint64_t ino, int mask);
using PfFileInfoFn = void (*)(fuse_req_t req, uint64_t ino, void* fileInfo);
using PfMkdirFn = void (*)(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode);
using PfMknodFn = void (*)(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                           uint64_t device);
using PfRemoveFn = void (*)(fuse_req_t req, uint64_t parent, const char* name);
using PfRenameFn = void (*)(fuse_req_t req, uint64_t parent, const char* name, uint64_t newParent,
                            const char* newName, uint32_t flags);
using PfCreateFn = void (*)(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                            void* fileInfo);
using PfReaddirFn = void (*)(fuse_req_t req, uint64_t ino, size_t size, off_t offset,
                             void* fileInfo);
using PfReaddirPostfilterFn = void (*)(fuse_req_t req, uint64_t ino, uint32_t errorIn,
                                       off_t offsetIn, off_t offsetOut, size_t sizeOut,
                                       const void* direntsIn, void* fileInfo);
using DoReaddirCommonFn = void (*)(fuse_req_t req, uint64_t ino, size_t size, off_t offset,
                                   void* fileInfo, bool plus);
using NotifyInvalEntryFn = int (*)(void* session, uint64_t parent, const char* name,
                                   size_t nameLen);
using NotifyInvalInodeFn = int (*)(void* session, uint64_t ino, off_t offset, off_t length);
using FuseReplyEntryFn = int (*)(fuse_req_t req, const fuse_entry_param* entry);
using FuseReplyAttrFn = int (*)(fuse_req_t req, const struct stat* attr, double timeout);
using FuseReplyBufFn = int (*)(fuse_req_t req, const char* buffer, size_t size);
using LibcStatFn = int (*)(const char* path, struct stat* statBuffer);
using LibcXattrFn = ssize_t (*)(const char* path, const char* name, void* value, size_t size);
using LibcMkdirFn = int (*)(const char* path, mode_t mode);
using LibcMknodFn = int (*)(const char* path, mode_t mode, dev_t device);
using LibcOpenFn = int (*)(const char* path, int flags, ...);
using LibcOpen2Fn = int (*)(const char* path, int flags);
using FuseReqCtxFn = const fuse_ctx* (*)(fuse_req_t req);

inline std::string_view AbiStringView(AbiStringParam raw) {
    if (raw == nullptr) {
        return {};
    }
    const auto* bytes = reinterpret_cast<const uint8_t*>(raw);
    constexpr size_t kWordSize = sizeof(uintptr_t);
    const bool isLong = (bytes[0] & 0x1U) != 0U;
    if (!isLong) {
        const size_t shortSize = static_cast<size_t>(bytes[0] >> 1);
        return {reinterpret_cast<const char*>(bytes + 1), shortSize};
    }
    size_t longSize = 0;
    const char* longData = nullptr;
    std::memcpy(&longSize, bytes + kWordSize, sizeof(longSize));
    std::memcpy(&longData, bytes + 2 * kWordSize, sizeof(longData));
    if (longData == nullptr) {
        return {};
    }
    return {longData, longSize};
}

class ScopedAbiStringParam final {
   public:
    explicit ScopedAbiStringParam(std::string_view value) {
        constexpr size_t kWordSize = sizeof(uintptr_t);
        constexpr size_t kObjectBytes = kWordSize * 3;
        constexpr size_t kShortCapacity = kObjectBytes - 2;
        object_.fill(std::byte{0});
        if (value.size() <= kShortCapacity) {
            object_[0] = std::byte{static_cast<uint8_t>(value.size() << 1)};
            if (!value.empty()) {
                std::memcpy(object_.data() + 1, value.data(), value.size());
            }
            object_[1 + value.size()] = std::byte{0};
            return;
        }

        storage_.assign(value.data(), value.size());
        const uintptr_t encodedCap = static_cast<uintptr_t>(storage_.capacity() + 1) | 1U;
        const uintptr_t sizeValue = static_cast<uintptr_t>(storage_.size());
        const char* data = storage_.c_str();
        std::memcpy(object_.data(), &encodedCap, sizeof(encodedCap));
        std::memcpy(object_.data() + kWordSize, &sizeValue, sizeof(sizeValue));
        std::memcpy(object_.data() + 2 * kWordSize, &data, sizeof(data));
    }

    AbiStringParam get() const {
        return object_.data();
    }

   private:
    alignas(uintptr_t) std::array<std::byte, sizeof(uintptr_t) * 3> object_{};
    std::string storage_;
};

enum class DirectoryEntriesAbi : uint8_t {
    kUnknown,
    kSharedPtr,
    kValue,
};

enum class AbiStringLayout : uint8_t {
    // AbiStringView implements libc++'s classic (__long: cap,size,data) layout. libc++ also has an
    // incompatible alternate layout, so hook installation must require an explicit profile value:
    // https://android.googlesource.com/platform/external/libcxx/+/4f4a65c06cecf421b56b9fea867d3aa7200f7f1a/include/string#704
    // https://android.googlesource.com/platform/external/libcxx/+/4f4a65c06cecf421b56b9fea867d3aa7200f7f1a/include/string#734
    kUnknown,
    kClassic,
};

struct PackageHideRule {
    std::string packageName;
    std::vector<std::string> hiddenRootEntryNames;
    std::vector<std::string> hiddenRelativePaths;
};

struct HideConfig {
    bool enableHideAllRootEntries = false;
    std::vector<std::string> hideAllRootEntriesExemptions;
    std::vector<std::string> hiddenRootEntryNames;
    std::vector<std::string> hiddenRelativePaths;
    std::vector<std::string> hiddenPackages;
    std::vector<PackageHideRule> packageRules;
};

// Precompute the rule into lookup-friendly shapes once so hot FUSE path checks stay on set/prefix
// lookups. fingerprint identifies FuseHide policy semantics only; callers still need uid/path when
// they cache MediaProvider-visible results.
struct CompiledHideRule {
    uint64_t fingerprint = 0;
    bool enableHideAllRootEntries = false;
    std::vector<std::string> hideAllRootEntriesExemptions;
    std::vector<std::string> hiddenRootEntryNames;
    std::vector<std::string> hiddenRelativePaths;
    std::unordered_set<std::string> hideAllRootEntriesExemptionSet;
    std::unordered_set<std::string> hiddenRootEntryNameSet;
    std::unordered_set<std::string> normalizedHiddenRelativePathExactSet;
    std::vector<std::string> normalizedHiddenRelativePathPrefixes;
    std::unordered_set<std::string> hiddenRelativePathFirstComponentSet;
    std::unordered_set<std::string> exactHiddenTargetParentRelativePathSet;
};

// Keep global, any-package, and per-package fragments separate so uid resolution only merges the
// fragments returned by PackageManager instead of rescanning the raw config each time.
struct CompiledHideConfig {
    std::shared_ptr<const CompiledHideRule> globalRuleFragment;
    std::shared_ptr<const CompiledHideRule> anyPackageRule;
    std::unordered_set<std::string> hiddenPackageSet;
    std::unordered_map<std::string, std::shared_ptr<const CompiledHideRule>> packageRuleFragments;
};

// The effective rule for one uid can change on either config reload or package add/remove, so both
// generations participate in uid cache validity.
struct UidHideRuleCacheEntry {
    uint64_t configGeneration = 0;
    uint64_t packageSetGeneration = 0;
    std::shared_ptr<const CompiledHideRule> rule;
};

// These RVAs are device-specific addresses from reverse-engineered libfuse_jni.so builds.
// The production device library we analyzed is stripped, so internal helpers such as
// is_app_accessible_path and several pf_* handlers are not always recoverable by name from the
// shipped ELF. Keep these offsets only as a last resort after symbol-based lookup fails, and
// select among known profiles at runtime instead of baking one device's layout globally.
struct DeviceHookProfile {
    const char* name;
    AbiStringLayout stringLayout;
    uintptr_t isAppAccessiblePathOffset;
    uintptr_t pfLookupOffset;
    uintptr_t pfLookupPostfilterOffset;
    uintptr_t pfGetattrOffset;
    uintptr_t shouldNotCacheOffset;
    uintptr_t doReaddirCommonOffset;
    uintptr_t getDirectoryEntriesOffset;
    uintptr_t addDirectoryEntriesFromLowerFsOffset;
    uintptr_t addDirectoryEntriesFromLowerFsThunkOffset;
    uintptr_t pfMkdirOffset;
    uintptr_t pfMknodOffset;
    uintptr_t pfUnlinkOffset;
    uintptr_t pfRmdirOffset;
    uintptr_t pfRenameOffset;
    uintptr_t pfCreateOffset;
    uintptr_t pfReaddirOffset;
    uintptr_t pfReaddirPostfilterOffset;
    uintptr_t pfReaddirplusOffset;
};

// Reverse-engineered record: ShouldNotCache @ 0x0017dc64, do_readdir_common @ 0x0018036c,
// GetDirectoryEntries @ 0x0018a3ec, addDirectoryEntriesFromLowerFs @ 0x0018be00,
// thunk @ 0x001fdcf8 in Ghidra with image base 0x00100000.
inline constexpr DeviceHookProfile kDeviceHookProfileLegacy = {
    .name = "legacy_device",
    .stringLayout = AbiStringLayout::kClassic,
    .isAppAccessiblePathOffset = 0x0007bb5c,
    .pfLookupOffset = 0x00075e48,
    .pfLookupPostfilterOffset = 0x00075f90,
    .pfGetattrOffset = 0x000762bc,
    .shouldNotCacheOffset = 0x0007dc64,
    .doReaddirCommonOffset = 0x0008036c,
    .getDirectoryEntriesOffset = 0x0008a3ec,
    .addDirectoryEntriesFromLowerFsOffset = 0x0008be00,
    .addDirectoryEntriesFromLowerFsThunkOffset = 0x000fdcf8,
    .pfMkdirOffset = 0x00077050,
    .pfMknodOffset = 0x00076ba8,
    .pfUnlinkOffset = 0x00077534,
    .pfRmdirOffset = 0x00077920,
    .pfRenameOffset = 0x00077ef4,
    .pfCreateOffset = 0x0007a7c8,
    .pfReaddirOffset = 0x00079c40,
    .pfReaddirPostfilterOffset = 0x00079cac,
    .pfReaddirplusOffset = 0x0007b320,
};

// Reverse-engineered record: ShouldNotCache @ 0x001eb658, do_readdir_common @ 0x001ee694,
// GetDirectoryEntries @ 0x001f8838, addDirectoryEntriesFromLowerFs @ 0x001fa180,
// thunk @ 0x002073d0 in Ghidra with image base 0x00100000.
inline constexpr DeviceHookProfile kDeviceHookProfileBp2a = {
    .name = "bp2a_device",
    .stringLayout = AbiStringLayout::kClassic,
    .isAppAccessiblePathOffset = 0x000e9b94,
    .pfLookupOffset = 0x000e3f94,
    .pfLookupPostfilterOffset = 0x000e40e4,
    .pfGetattrOffset = 0x000e4418,
    .shouldNotCacheOffset = 0x000eb658,
    .doReaddirCommonOffset = 0x000ee694,
    .getDirectoryEntriesOffset = 0x000f8838,
    .addDirectoryEntriesFromLowerFsOffset = 0x000fa180,
    .addDirectoryEntriesFromLowerFsThunkOffset = 0x001073d0,
    .pfMkdirOffset = 0x000e5250,
    .pfMknodOffset = 0x000e4d80,
    .pfUnlinkOffset = 0x000e573c,
    .pfRmdirOffset = 0x000e5b64,
    .pfRenameOffset = 0x000e60b0,
    .pfCreateOffset = 0x000e8890,
    .pfReaddirOffset = 0x000e7aa0,
    .pfReaddirPostfilterOffset = 0x000e7b0c,
    .pfReaddirplusOffset = 0x000e93c4,
};

inline constexpr DeviceHookProfile kDeviceHookProfileV3 = {
    .name = "v3_device",
    .stringLayout = AbiStringLayout::kClassic,
    .isAppAccessiblePathOffset = 0x000e9df8,
    .pfLookupOffset = 0x000e3f18,
    .pfLookupPostfilterOffset = 0x000e4068,
    .pfGetattrOffset = 0x000e43a8,
    .shouldNotCacheOffset = 0x000eb96c,
    .doReaddirCommonOffset = 0x000ee9fc,
    .getDirectoryEntriesOffset = 0x000f8cac,
    .addDirectoryEntriesFromLowerFsOffset = 0x000fa5f4,
    .addDirectoryEntriesFromLowerFsThunkOffset = 0x001077e0,
    .pfMkdirOffset = 0x000e521c,
    .pfMknodOffset = 0x000e4d40,
    .pfUnlinkOffset = 0x000e5714,
    .pfRmdirOffset = 0x000e5b4c,
    .pfRenameOffset = 0x000e60cc,
    .pfCreateOffset = 0x000e8acc,
    .pfReaddirOffset = 0x000e7cb8,
    .pfReaddirPostfilterOffset = 0x000e7d24,
    .pfReaddirplusOffset = 0x000e961c,
};

inline constexpr DeviceHookProfile kDeviceHookProfileV6 = {
    .name = "v6_device",
    .stringLayout = AbiStringLayout::kClassic,
    .isAppAccessiblePathOffset = 0x000e7620,
    .pfLookupOffset = 0x000e1aec,
    .pfLookupPostfilterOffset = 0x000e1c3c,
    .pfGetattrOffset = 0x000e1f70,
    .shouldNotCacheOffset = 0x000ec724,
    .doReaddirCommonOffset = 0x000ef6f4,
    .getDirectoryEntriesOffset = 0x000f9b98,
    .addDirectoryEntriesFromLowerFsOffset = 0x000fb488,
    .addDirectoryEntriesFromLowerFsThunkOffset = 0x001086f8,
    .pfMkdirOffset = 0x000e2d7c,
    .pfMknodOffset = 0x000e28d8,
    .pfUnlinkOffset = 0x000e323c,
    .pfRmdirOffset = 0x000e3640,
    .pfRenameOffset = 0x000e3b8c,
    .pfCreateOffset = 0x000e635c,
    .pfReaddirOffset = 0x000e557c,
    .pfReaddirPostfilterOffset = 0x000e55e8,
    .pfReaddirplusOffset = 0x000e6e84,
};

// Supplied Google MediaProvider API 37 DEV sample, arm64 Build ID
// be026ea7a89bbd3d48422fa9a1289e2d. Its manifest reports versionName=DEV/versionCode=37 and does
// not independently identify a QPR release train. Ghidra image base is 0x00100000:
//   do_readdir_common                       @ 0x0016a9d0
//   MediaProviderWrapper::GetDirectoryEntries @ 0x001749e0
//   addDirectoryEntriesFromLowerFs          @ 0x00176620 (PLT thunk 0x00184028)
// The decompiler shows do_readdir_common indexing the returned vector with a 0x20-byte stride;
// d_name starts at +0x00 and d_type is read at +0x18. Earlier profiles index 0x10-byte shared_ptr
// elements instead, which is why the container ABIs must never share one wrapper.
inline constexpr DeviceHookProfile kDeviceHookProfileApi37ValueEntries = {
    .name = "api37_google_value_entries",
    .stringLayout = AbiStringLayout::kClassic,
    .isAppAccessiblePathOffset = 0x00066270,
    .pfLookupOffset = 0x0005ffc0,
    .pfLookupPostfilterOffset = 0x00060110,
    .pfGetattrOffset = 0x00060450,
    .shouldNotCacheOffset = 0x00067ab0,
    .doReaddirCommonOffset = 0x0006a9d0,
    .getDirectoryEntriesOffset = 0x000749e0,
    .addDirectoryEntriesFromLowerFsOffset = 0x00076620,
    .addDirectoryEntriesFromLowerFsThunkOffset = 0x00084028,
    .pfMkdirOffset = 0x00061370,
    .pfMknodOffset = 0x00060ed0,
    .pfUnlinkOffset = 0x00061890,
    .pfRmdirOffset = 0x00061cf0,
    .pfRenameOffset = 0x000622a0,
    .pfCreateOffset = 0x00064e90,
    .pfReaddirOffset = 0x00063ea0,
    .pfReaddirPostfilterOffset = 0x00063fd0,
    .pfReaddirplusOffset = 0x00065a60,
};

inline constexpr DeviceHookProfile kKnownDeviceHookProfiles[] = {
    kDeviceHookProfileLegacy,
    kDeviceHookProfileBp2a,
    kDeviceHookProfileV3,
    kDeviceHookProfileV6,
    kDeviceHookProfileApi37ValueEntries,
};
inline constexpr size_t kFuseEntryOutWireSize = 128;

struct NativeApiEntries {
    uint32_t version;
    HookInstaller hookFunc;
    void* unhookFunc;
};

extern HookInstaller gHookInstaller;
extern JavaVM* gJavaVm;
extern UHasBinaryPropertyFn gUHasBinaryProperty;
extern HookOriginal<IsAppAccessiblePathFn> gOriginalIsAppAccessiblePath;
extern HookOriginal<IsPackageOwnedPathFn> gOriginalIsPackageOwnedPath;
extern HookOriginal<IsBpfBackingPathFn> gOriginalIsBpfBackingPath;
extern HookOriginal<StrcasecmpFn> gOriginalStrcasecmp;
extern HookOriginal<EqualsIgnoreCaseAbiFn> gOriginalEqualsIgnoreCase;

extern std::atomic<int> gAppAccessibleLogCount;
extern std::atomic<int> gPackageOwnedLogCount;
extern std::atomic<int> gBpfBackingLogCount;
extern std::atomic<int> gStrcasecmpLogCount;
extern std::atomic<int> gEqualsIgnoreCaseLogCount;
extern std::atomic<int> gReplyErrFallbackLogCount;
extern std::atomic<int> gErrnoRemapLogCount;
extern std::atomic<int> gSuspiciousDirectLogCount;
extern std::atomic<uint64_t> gHideConfigGeneration;
extern std::atomic<uint64_t> gUidPackageSetGeneration;
extern std::mutex gUidHideCacheMutex;
extern std::unordered_map<uint32_t, UidHideRuleCacheEntry> gUidHideRuleCache;
extern std::shared_ptr<const HideConfig> gHideConfig;
extern std::shared_ptr<const CompiledHideConfig> gCompiledHideConfig;

inline bool ShouldLogLimited(std::atomic<int>& counter, int limit = 8) {
    const int old = counter.fetch_add(1, std::memory_order_relaxed);
    return old < limit;
}

template <typename... Args>
inline void DebugLogPrint(int priority, const char* fmt, Args... args) {
    if constexpr (kEnableDebugHooks) {
        __android_log_print(priority, kLogTag, fmt, args...);
    }
}

std::shared_ptr<const CompiledHideRule> ResolveHideRuleForUid(uint32_t uid);
std::optional<std::shared_ptr<const CompiledHideRule>> ResolveHideRuleForUidWithPackageManager(
    uint32_t uid);
HideConfig DefaultHideConfig();
std::shared_ptr<const HideConfig> CurrentHideConfig();
std::shared_ptr<const CompiledHideConfig> CurrentCompiledHideConfig();
void ApplyHideConfig(HideConfig config);
void ClearRootSnapshotCache();
void ClearHiddenPathClassificationCache();
void NotifyUidRulePackageSetChanged(std::string_view reason);
std::shared_ptr<const CompiledHideRule> RuleForAnyPackage();
uint64_t EffectiveHideRuleFingerprint(const std::shared_ptr<const CompiledHideRule>& rule);
bool CompiledHideRulesSemanticallyEqual(const std::shared_ptr<const CompiledHideRule>& lhs,
                                        const std::shared_ptr<const CompiledHideRule>& rhs);

class UnicodePolicy final {
   public:
    static std::string EscapeForLog(const uint8_t* data, size_t length);
    static std::string DebugPreview(std::string_view value, size_t limit = 96);
    static void LogInvalidUtf8(const uint8_t* data, size_t dataLen, size_t begin, size_t end);
    static void LogSuspiciousDirectPath(const char* hookName, std::string_view path);
    static bool DecodeUtf8CodePoint(const uint8_t* data, size_t len, size_t index, uint32_t* cp,
                                    size_t* width);
    static size_t InvalidUtf8SpanEnd(const uint8_t* data, size_t len, size_t index);
    static bool NeedsSanitization(const std::string& input);
    static void RewriteString(std::string& input);
    static int CompareCaseFoldIgnoringDefaultIgnorables(const uint8_t* lhsData, size_t lhsLen,
                                                        const uint8_t* rhsData, size_t rhsLen);
};

class RuntimeState final {
   public:
    static uint32_t ReqUid(fuse_req_t req);
    static void RememberFuseSession(fuse_req_t req);
    static void ScheduleHiddenEntryInvalidation();
    static void ScheduleSpecificEntryInvalidation(uint64_t parent, std::string_view name);
    static void ScheduleHiddenInodeInvalidation(uint64_t ino);
};

bool IsTestHiddenUid(uint32_t uid);
bool ShouldHideTestPath(uint32_t uid, std::string_view path);
std::string EscapeForLog(const uint8_t* data, size_t length);
std::string DebugPreview(std::string_view value, size_t limit = 96);
void LogInvalidUtf8(const uint8_t* data, size_t dataLen, size_t begin, size_t end);
void LogSuspiciousDirectPath(const char* hookName, std::string_view path);
bool DecodeUtf8CodePoint(const uint8_t* data, size_t len, size_t index, uint32_t* cp,
                         size_t* width);
size_t InvalidUtf8SpanEnd(const uint8_t* data, size_t len, size_t index);
bool NeedsSanitization(const std::string& input);
void RewriteString(std::string& input);
int CompareCaseFoldIgnoringDefaultIgnorables(const uint8_t* lhsData, size_t lhsLen,
                                             const uint8_t* rhsData, size_t rhsLen);

extern HookOriginal<PfLookupFn> gOriginalPfLookup;
extern HookOriginal<PfLookupPostfilterFn> gOriginalPfLookupPostfilter;
extern HookOriginal<PfAccessFn> gOriginalPfAccess;
extern HookOriginal<PfFileInfoFn> gOriginalPfOpen;
extern HookOriginal<PfFileInfoFn> gOriginalPfOpendir;
extern HookOriginal<PfMknodFn> gOriginalPfMknod;
extern HookOriginal<PfMkdirFn> gOriginalPfMkdir;
extern HookOriginal<PfRemoveFn> gOriginalPfUnlink;
extern HookOriginal<PfRemoveFn> gOriginalPfRmdir;
extern HookOriginal<PfRenameFn> gOriginalPfRename;
extern HookOriginal<PfCreateFn> gOriginalPfCreate;
extern HookOriginal<PfReaddirFn> gOriginalPfReaddir;
extern HookOriginal<PfReaddirPostfilterFn> gOriginalPfReaddirPostfilter;
extern HookOriginal<PfReaddirFn> gOriginalPfReaddirplus;
extern HookOriginal<DoReaddirCommonFn> gOriginalDoReaddirCommon;
extern HookOriginal<PfFileInfoFn> gOriginalPfGetattr;
extern HookOriginal<LibcOpenFn> gOriginalOpen;
extern HookOriginal<LibcOpen2Fn> gOriginalOpen2;
extern HookOriginal<FuseReqCtxFn> gFuseReqCtx;
extern HookOriginal<LibcMkdirFn> gOriginalMkdir;
extern HookOriginal<LibcMknodFn> gOriginalMknod;
extern HookOriginal<LibcStatFn> gOriginalLstat;
extern HookOriginal<LibcStatFn> gOriginalStat;
extern HookOriginal<LibcXattrFn> gOriginalGetxattr;
extern HookOriginal<LibcXattrFn> gOriginalLgetxattr;
extern HookOriginal<ShouldNotCacheFn> gOriginalShouldNotCache;
extern HookOriginal<NotifyInvalEntryFn> gOriginalNotifyInvalEntry;
extern HookOriginal<NotifyInvalInodeFn> gOriginalNotifyInvalInode;
extern HookOriginal<FuseReplyAttrFn> gOriginalReplyAttr;
extern HookOriginal<FuseReplyEntryFn> gOriginalReplyEntry;
extern HookOriginal<FuseReplyBufFn> gOriginalReplyBuf;
extern HookOriginal<FuseReplyErrFn> gOriginalReplyErr;
extern HookOriginal<GetDirectoryEntriesFn> gOriginalGetDirectoryEntries;
extern HookOriginal<AddDirectoryEntriesFromLowerFsFn> gOriginalAddDirectoryEntriesFromLowerFs;
extern std::atomic<DirectoryEntriesAbi> gDirectoryEntriesAbi;
extern std::atomic<void*> gLastFuseSession;
extern std::atomic<bool> gHiddenEntryInvalidationPending;
extern std::atomic<uint64_t> gHiddenRootParentInode;
extern thread_local bool gInPfLookup;
extern thread_local bool gInPfLookupPostfilter;
extern thread_local bool gInPfReaddir;
extern thread_local bool gInPfReaddirPostfilter;
extern thread_local bool gInPfReaddirplus;
extern thread_local bool gInPfGetattr;
extern thread_local uint32_t gPfGetattrUid;
extern thread_local uint32_t gPfReaddirUid;
extern thread_local uint32_t gCurrentLookupUid;
extern thread_local uint64_t gPfGetattrIno;
extern thread_local uint64_t gPfReaddirIno;
extern thread_local uint64_t gCurrentLookupParentInode;
extern thread_local std::string gCurrentLookupName;
extern thread_local bool gTrackRootHiddenLookup;
extern thread_local bool gTrackHiddenSubtreeLookup;
extern thread_local bool gZeroAttrCacheForCurrentGetattr;
extern thread_local fuse_req_t gPendingHiddenErrReq;
extern thread_local uint64_t gPendingHiddenErrReqUnique;
extern thread_local int gPendingHiddenErrno;
extern std::mutex gHiddenSubtreeInodesMutex;
extern std::unordered_map<uint64_t, std::vector<std::shared_ptr<const CompiledHideRule>>>
    gHiddenSubtreeInodeRules;
extern std::mutex gInodePathCacheMutex;
extern std::unordered_map<uint64_t, std::string> gInodePathCache;
struct PendingReaddirContext {
    uint32_t uid = 0;
    uint64_t ino = 0;
    std::string path;
};
extern std::mutex gPendingReaddirContextsMutex;
extern std::unordered_map<uint64_t, PendingReaddirContext> gPendingReaddirContexts;
extern thread_local uint64_t gCurrentReaddirReqUnique;
extern std::mutex gRecentHiddenParentPathsMutex;
extern std::unordered_map<uint32_t, std::string> gRecentHiddenParentPaths;
extern std::unordered_map<uint32_t, uint32_t> gRecentHiddenParentPathUids;
extern std::string gRecentHiddenParentPathAnyUid;
extern uint32_t gRecentHiddenParentPathAnyUidOwner;

namespace ReplyErrorBridge {
// Use Original() only when preserving strict "hook backup only" semantics for a wrapper that
// directly proxies fuse_reply_err itself.
// Use Reply() for policy/error short-circuit paths; it resolves via Original() first, then dlsym
// cache, and emits fallback diagnostics when fuse_reply_err cannot be resolved.
FuseReplyErrFn Original();
FuseReplyErrFn Resolve();
std::optional<int> Reply(fuse_req_t req, int err, const char* caller);
}  // namespace ReplyErrorBridge

uint32_t ReqUid(fuse_req_t req);
void RememberFuseSession(fuse_req_t req);
void ClearActiveFuseRequestSession();
void ScheduleHiddenEntryInvalidation();
void ScheduleHiddenInodeInvalidation(uint64_t ino);
std::string InodePath(uint64_t ino);
bool IsHiddenLookupTarget(uint32_t uid, uint64_t parent, uint32_t error_in, const char* name);
bool IsHiddenLookupCacheTarget(uint32_t uid, uint64_t parent, const char* name);

enum class HiddenNamedTargetKind {
    None,
    Root,
    Descendant,
};

HiddenNamedTargetKind ClassifyHiddenNamedTarget(uint32_t uid, uint64_t parent, const char* name);
bool ReplyHiddenNamedTargetError(fuse_req_t req, const char* opName, HiddenNamedTargetKind kind,
                                 int rootErr, int descendantErr);
void ArmHiddenErrorRemap(fuse_req_t req, int err, const char* opName);
int MaybeRewriteHiddenLeakErrno(fuse_req_t req, int err, const char* caller);
void ArmHiddenCreateLeakRemap(fuse_req_t req, const char* opName);
void ClearPendingRootSnapshotMutations();

bool IsTrackedHiddenSubtreeInode(uint32_t uid, uint64_t ino);
bool TrackHiddenSubtreeInode(uint32_t uid, uint64_t ino);
bool RemoveTrackedHiddenSubtreeInode(uint32_t uid, uint64_t ino);
std::optional<std::string> LookupTrackedPathForInode(uint64_t ino);
std::optional<uint64_t> LookupTrackedInodeForPath(std::string_view path);
void RememberTrackedPathForInode(uint64_t ino, std::string_view path);
void NoteHiddenSubtreePathForCache(uint32_t uid, std::string_view path);
void RememberRecentHiddenParentPath(uint32_t uid, std::string_view path);
std::optional<std::string> LookupRecentHiddenParentPath(uint32_t uid,
                                                        uint32_t* matchedHiddenUid = nullptr);
void ClearRecentHiddenParentPath(uint32_t uid);
}  // namespace fusehide
