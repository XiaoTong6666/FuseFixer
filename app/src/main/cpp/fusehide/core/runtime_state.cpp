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

#include "fusehide/policy/path_policy.hpp"

namespace fusehide {

// Hook state for libfuse_jni.so running inside the MediaProvider process.
HookOriginal<PfLookupFn> gOriginalPfLookup;
HookOriginal<PfLookupPostfilterFn> gOriginalPfLookupPostfilter;
HookOriginal<PfAccessFn> gOriginalPfAccess;
HookOriginal<PfFileInfoFn> gOriginalPfOpen;
HookOriginal<PfFileInfoFn> gOriginalPfOpendir;
HookOriginal<PfMknodFn> gOriginalPfMknod;
HookOriginal<PfMkdirFn> gOriginalPfMkdir;
HookOriginal<PfRemoveFn> gOriginalPfUnlink;
HookOriginal<PfRemoveFn> gOriginalPfRmdir;
HookOriginal<PfRenameFn> gOriginalPfRename;
HookOriginal<PfCreateFn> gOriginalPfCreate;
HookOriginal<PfReaddirFn> gOriginalPfReaddir;
HookOriginal<PfReaddirPostfilterFn> gOriginalPfReaddirPostfilter;
HookOriginal<PfReaddirFn> gOriginalPfReaddirplus;
HookOriginal<DoReaddirCommonFn> gOriginalDoReaddirCommon;
HookOriginal<PfFileInfoFn> gOriginalPfGetattr;
HookOriginal<LibcOpenFn> gOriginalOpen;
HookOriginal<LibcOpen2Fn> gOriginalOpen2;
HookOriginal<LibcMkdirFn> gOriginalMkdir;
HookOriginal<LibcMknodFn> gOriginalMknod;
HookOriginal<LibcStatFn> gOriginalLstat;
HookOriginal<LibcStatFn> gOriginalStat;
HookOriginal<LibcXattrFn> gOriginalGetxattr;
HookOriginal<LibcXattrFn> gOriginalLgetxattr;
HookOriginal<ShouldNotCacheFn> gOriginalShouldNotCache;
HookOriginal<NotifyInvalEntryFn> gOriginalNotifyInvalEntry;
HookOriginal<NotifyInvalInodeFn> gOriginalNotifyInvalInode;
HookOriginal<FuseReplyAttrFn> gOriginalReplyAttr;
HookOriginal<FuseReplyEntryFn> gOriginalReplyEntry;
HookOriginal<FuseReplyBufFn> gOriginalReplyBuf;
HookOriginal<FuseReplyErrFn> gOriginalReplyErr;
HookOriginal<GetDirectoryEntriesFn> gOriginalGetDirectoryEntries;
HookOriginal<AddDirectoryEntriesFromLowerFsFn> gOriginalAddDirectoryEntriesFromLowerFs;
std::atomic<DirectoryEntriesAbi> gDirectoryEntriesAbi{DirectoryEntriesAbi::kUnknown};
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
thread_local uint32_t gCurrentLookupUid = 0;
thread_local uint64_t gPfGetattrIno = 0;
thread_local uint64_t gPfReaddirIno = 0;
thread_local uint64_t gCurrentLookupParentInode = 0;
thread_local std::string gCurrentLookupName;
thread_local bool gTrackRootHiddenLookup = false;
thread_local bool gTrackHiddenSubtreeLookup = false;
thread_local bool gZeroAttrCacheForCurrentGetattr = false;
thread_local fuse_req_t gPendingHiddenErrReq = nullptr;
thread_local uint64_t gPendingHiddenErrReqUnique = 0;
thread_local int gPendingHiddenErrno = 0;
thread_local uint64_t gCurrentReaddirReqUnique = 0;

namespace ReplyErrorBridge {

namespace {

void LogFallbackFailure(const char* caller) {
    if (ShouldLogLimited(gReplyErrFallbackLogCount, 8)) {
        __android_log_print(6, kLogTag,
                            "%s could not resolve fuse_reply_err; delegating to the original path",
                            caller);
    }
}

}  // namespace

FuseReplyErrFn Original() {
    return gOriginalReplyErr.get();
}

FuseReplyErrFn Resolve() {
    if (auto replyErr = Original(); replyErr != nullptr) {
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

std::optional<int> Reply(fuse_req_t req, int err, const char* caller) {
    auto replyErr = Resolve();
    if (replyErr == nullptr) {
        LogFallbackFailure(caller);
        return std::nullopt;
    }
    return replyErr(req, err);
}

}  // namespace ReplyErrorBridge

std::mutex gHiddenSubtreeInodesMutex;
std::unordered_map<uint64_t, std::vector<std::shared_ptr<const CompiledHideRule>>>
    gHiddenSubtreeInodeRules;
std::mutex gInodePathCacheMutex;
std::unordered_map<uint64_t, std::string> gInodePathCache;
std::unordered_map<uint64_t, uint64_t> gInodePathCacheAccessOrder;
uint64_t gInodePathCacheAccessGeneration = 0;
std::mutex gPendingReaddirContextsMutex;
std::unordered_map<uint64_t, PendingReaddirContext> gPendingReaddirContexts;
std::mutex gRecentHiddenParentPathsMutex;
std::unordered_map<uint32_t, std::string> gRecentHiddenParentPaths;
std::unordered_map<uint32_t, uint32_t> gRecentHiddenParentPathUids;
std::string gRecentHiddenParentPathAnyUid;
uint32_t gRecentHiddenParentPathAnyUidOwner = 0;
std::mutex gUidErrRemapMutex;

struct UidErrRemapState {
    int baselineErr = 0;
    std::chrono::steady_clock::time_point expiresAt{};
    uint32_t pendingCount = 0;
};

std::unordered_map<uint32_t, UidErrRemapState> gUidErrRemapStates;

namespace {

constexpr size_t kMaxTrackedPathEntries = 16384;

std::mutex gFuseSessionStateMutex;
thread_local void* gActiveFuseRequestSession = nullptr;

void ClearSessionScopedTracking() {
    gHiddenRootParentInode.store(0, std::memory_order_release);
    gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
        gHiddenSubtreeInodeRules.clear();
    }
    {
        std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
        gInodePathCache.clear();
        gInodePathCacheAccessOrder.clear();
        gInodePathCacheAccessGeneration = 0;
    }
    {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.clear();
    }
    ClearPendingRootSnapshotMutations();
    {
        std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
        gRecentHiddenParentPaths.clear();
        gRecentHiddenParentPathUids.clear();
        gRecentHiddenParentPathAnyUid.clear();
        gRecentHiddenParentPathAnyUidOwner = 0;
    }
    {
        std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
        gUidErrRemapStates.clear();
    }
}

void* CurrentSchedulingFuseSession() {
    if (gActiveFuseRequestSession != nullptr) {
        return gActiveFuseRequestSession;
    }
    return gLastFuseSession.load(std::memory_order_acquire);
}

bool PathEqualsForFuseLookup(std::string_view lhs, std::string_view rhs) {
    return UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
               reinterpret_cast<const uint8_t*>(lhs.data()), lhs.size(),
               reinterpret_cast<const uint8_t*>(rhs.data()), rhs.size()) == 0;
}

bool IsVisibleRootChildLookupPath(std::string_view path, std::string_view name) {
    if (path.empty() || name.empty()) {
        return false;
    }
    for (const auto& root : kVisibleStorageRoots) {
        if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0 ||
            path[root.size()] != '/') {
            continue;
        }
        const std::string_view childName = path.substr(root.size() + 1);
        if (childName.find('/') == std::string_view::npos &&
            PathEqualsForFuseLookup(childName, name)) {
            return true;
        }
    }
    return false;
}

void NoteTrackedPathAccessLocked(uint64_t ino) {
    gInodePathCacheAccessOrder[ino] = ++gInodePathCacheAccessGeneration;
}

bool IsProtectedTrackedPath(std::string_view path) {
    if (HiddenPathPolicy::IsAnyHiddenSubtreePath(path) || IsParentOfExactHiddenTargetPath(path)) {
        return true;
    }

    const auto rule = RuleForAnyPackage();
    if (rule == nullptr) {
        return false;
    }

    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return !rule->hiddenRootEntryNames.empty() || rule->enableHideAllRootEntries ||
                   !rule->normalizedHiddenRelativePathExactSet.empty();
        }
    }

    const auto relativePath = RelativePathForVisibleRoot(path);
    if (!relativePath.has_value() || relativePath->empty()) {
        return false;
    }
    const std::string canonicalRelativePath = CanonicalizeRelativeHiddenPathForMatch(*relativePath);
    if (canonicalRelativePath.empty()) {
        return false;
    }
    for (const auto& hiddenPath : rule->normalizedHiddenRelativePathExactSet) {
        if (hiddenPath.size() > canonicalRelativePath.size() &&
            hiddenPath.compare(0, canonicalRelativePath.size(), canonicalRelativePath) == 0 &&
            hiddenPath[canonicalRelativePath.size()] == '/') {
            return true;
        }
    }
    return false;
}

bool EvictOldestTrackedPathLocked() {
    if (gInodePathCacheAccessOrder.empty()) {
        return false;
    }
    uint64_t victimIno = 0;
    uint64_t victimAccess = 0;
    bool foundVictim = false;
    for (const auto& [ino, access] : gInodePathCacheAccessOrder) {
        const auto pathIt = gInodePathCache.find(ino);
        if (pathIt == gInodePathCache.end() || IsProtectedTrackedPath(pathIt->second)) {
            continue;
        }
        if (!foundVictim || access < victimAccess) {
            victimIno = ino;
            victimAccess = access;
            foundVictim = true;
        }
    }
    if (!foundVictim) {
        return false;
    }
    gInodePathCache.erase(victimIno);
    gInodePathCacheAccessOrder.erase(victimIno);
    return true;
}

}  // namespace

uint32_t RuntimeState::ReqUid(fuse_req_t req) {
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

void RuntimeState::RememberFuseSession(fuse_req_t req) {
    if (req == nullptr || req->se == nullptr) {
        gActiveFuseRequestSession = nullptr;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(gFuseSessionStateMutex);
        void* previous = gLastFuseSession.load(std::memory_order_relaxed);
        if (previous != req->se) {
            ClearSessionScopedTracking();
            gLastFuseSession.store(req->se, std::memory_order_release);
        }
    }
    gActiveFuseRequestSession = req->se;
}

// Shared dentry cache is not scoped per uid. Once another app resolves the hidden entry, the
// target uid can reuse that positive cache unless we actively invalidate the root dentry.
void RuntimeState::ScheduleHiddenEntryInvalidation() {
    const auto notifyEntry = gOriginalNotifyInvalEntry.get();
    void* session = CurrentSchedulingFuseSession();
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
        const auto rule = RuleForAnyPackage();
        std::unordered_set<std::string> namesToInvalidate;
        if (rule != nullptr) {
            for (const auto& rootEntryName : rule->hiddenRootEntryNames) {
                namesToInvalidate.emplace(rootEntryName);
            }
        }

        if (rule != nullptr && rule->enableHideAllRootEntries) {
            for (const auto& rootPath : kVisibleStorageRoots) {
                DIR* dir = opendir(std::string(rootPath).c_str());
                if (dir == nullptr) {
                    continue;
                }
                while (dirent* entry = readdir(dir)) {
                    const std::string_view name(entry->d_name);
                    if (IsWildcardRootEntryCandidate(name)) {
                        namesToInvalidate.emplace(name);
                    }
                }
                closedir(dir);
            }
        }

        for (const auto& name : namesToInvalidate) {
            const int ret = notifyEntry(session, rootParent, name.c_str(), name.size());
            DebugLogPrint(4, "scheduled hidden entry invalidation parent=0x%lx name=%s ret=%d",
                          (unsigned long)rootParent, DebugPreview(name).c_str(), ret);
        }
        gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
    }).detach();
}

void RuntimeState::ScheduleSpecificEntryInvalidation(uint64_t parent, std::string_view name) {
    const auto notifyEntry = gOriginalNotifyInvalEntry.get();
    void* session = CurrentSchedulingFuseSession();
    if (notifyEntry == nullptr || session == nullptr || parent == 0 || name.empty()) {
        return;
    }
    const std::string ownedName(name);
    std::thread([notifyEntry, session, parent, ownedName]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        const int ret = notifyEntry(session, parent, ownedName.c_str(), ownedName.size());
        DebugLogPrint(4, "scheduled specific entry invalidation parent=%s name=%s ret=%d",
                      InodePath(parent).c_str(), DebugPreview(ownedName).c_str(), ret);
    }).detach();
}

// Track subtree inodes so later getattr/readdir replies can also be forced uncached.
void RuntimeState::ScheduleHiddenInodeInvalidation(uint64_t ino) {
    const auto notifyInode = gOriginalNotifyInvalInode.get();
    void* session = CurrentSchedulingFuseSession();
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
    (void)error_in;
    if (!IsTestHiddenUid(uid) || name == nullptr) {
        return false;
    }
    if (IsHiddenLookupCacheTarget(uid, parent, name)) {
        return true;
    }
    const auto kind = ClassifyHiddenNamedTarget(uid, parent, name);
    return kind == HiddenNamedTargetKind::Root || kind == HiddenNamedTargetKind::Descendant;
}

bool IsHiddenLookupCacheTarget(uint32_t uid, uint64_t parent, const char* name) {
    if (name == nullptr) {
        return false;
    }
    if (!IsTestHiddenUid(uid)) {
        return false;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    return rootParent != 0 && parent == rootParent &&
           HiddenPathPolicy::IsHiddenRootEntryName(uid, name);
}

std::optional<HiddenNamedTargetKind> ClassifyHiddenNamedTargetByTrackedPath(uint32_t uid,
                                                                            uint64_t parent,
                                                                            const char* name) {
    if (name == nullptr) {
        return std::nullopt;
    }
    const auto parentPath = LookupTrackedPathForInode(parent);
    if (!parentPath.has_value()) {
        return std::nullopt;
    }
    const std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name);
    if (HiddenPathPolicy::IsExactHiddenTargetPath(uid, childPath)) {
        return HiddenNamedTargetKind::Root;
    }
    if (HiddenPathPolicy::IsAnyHiddenSubtreePath(uid, childPath)) {
        return HiddenNamedTargetKind::Descendant;
    }
    return std::nullopt;
}

// Classify the current name-based operation as either the hidden root entry itself or a descendant
// below a previously learned hidden subtree inode.
HiddenNamedTargetKind ClassifyHiddenNamedTarget(uint32_t uid, uint64_t parent, const char* name) {
    if (!IsTestHiddenUid(uid) || name == nullptr) {
        return HiddenNamedTargetKind::None;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (parent != 0 && parent != rootParent && IsTrackedHiddenSubtreeInode(uid, parent)) {
        return HiddenNamedTargetKind::Descendant;
    }
    const auto rule = ResolveHideRuleForUid(uid);
    if (rule == nullptr) {
        return HiddenNamedTargetKind::None;
    }
    if (rootParent != 0 && parent == rootParent &&
        HiddenPathPolicy::IsHiddenRootEntryName(uid, name)) {
        return HiddenNamedTargetKind::Root;
    }
    if (const auto trackedPathKind = ClassifyHiddenNamedTargetByTrackedPath(uid, parent, name);
        trackedPathKind.has_value()) {
        return *trackedPathKind;
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
    if (ReplyErrorBridge::Reply(req, err, opName).has_value()) {
        return true;
    }
    ArmHiddenErrorRemap(req, err, opName);
    return false;
}

namespace {

bool IsExistenceLeakErrno(int err) {
    switch (err) {
        case EEXIST:
        case EISDIR:
        case ENOTEMPTY:
        case ENOTDIR:
            return true;
        default:
            return false;
    }
}

void LogErrnoRemapEvent(const char* source, fuse_req_t req, uint32_t uid, int fromErr, int toErr) {
    if (!ShouldLogLimited(gErrnoRemapLogCount, 24)) {
        return;
    }
    __android_log_print(4, kLogTag, "errno remap source=%s req=%p unique=%lu uid=%u from=%d to=%d",
                        source, req, req ? (unsigned long)req->unique : 0UL,
                        static_cast<unsigned>(uid), fromErr, toErr);
}

}  // namespace

void ArmHiddenErrorRemap(fuse_req_t req, int err, const char* opName) {
    if (req == nullptr || err <= 0) {
        return;
    }
    gPendingHiddenErrReq = req;
    gPendingHiddenErrReqUnique = req->unique;
    gPendingHiddenErrno = err;
    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid != 0) {
        std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
        UidErrRemapState& state = gUidErrRemapStates[uid];
        state.baselineErr = err;
        state.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        state.pendingCount = std::min<uint32_t>(state.pendingCount + 1, 8);
    }
    DebugLogPrint(4, "%s arm hidden errno remap req=%p unique=%lu baseline=%d", opName, req,
                  req ? (unsigned long)req->unique : 0UL, err);
}

void ArmHiddenCreateLeakRemap(fuse_req_t req, const char* opName) {
    if (req == nullptr) {
        return;
    }
    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid == 0 || !HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return;
    }
    std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
    UidErrRemapState& state = gUidErrRemapStates[uid];
    state.baselineErr = EPERM;
    state.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    state.pendingCount = std::min<uint32_t>(state.pendingCount + 1, 8);
    DebugLogPrint(4, "%s arm create leak remap uid=%u baseline=%d", opName,
                  static_cast<unsigned>(uid), EPERM);
}

int MaybeRewriteHiddenLeakErrno(fuse_req_t req, int err, const char* caller) {
    if (req != nullptr && gPendingHiddenErrReq == req &&
        gPendingHiddenErrReqUnique == req->unique && gPendingHiddenErrno > 0 && err > 0 &&
        IsExistenceLeakErrno(err)) {
        const int baselineErr = gPendingHiddenErrno;
        gPendingHiddenErrReq = nullptr;
        gPendingHiddenErrReqUnique = 0;
        gPendingHiddenErrno = 0;

        if (err != baselineErr) {
            DebugLogPrint(4, "%s remap leaked errno req=%p unique=%lu from=%d to=%d", caller, req,
                          (unsigned long)req->unique, err, baselineErr);
            LogErrnoRemapEvent("req", req, RuntimeState::ReqUid(req), err, baselineErr);
            return baselineErr;
        }
        return err;
    }

    if (req == nullptr || err <= 0 || !IsExistenceLeakErrno(err)) {
        return err;
    }

    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid == 0) {
        return err;
    }

    int uidBaselineErr = 0;
    {
        std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
        const auto it = gUidErrRemapStates.find(uid);
        if (it != gUidErrRemapStates.end()) {
            if (it->second.expiresAt >= std::chrono::steady_clock::now() &&
                it->second.baselineErr > 0 && it->second.pendingCount > 0) {
                uidBaselineErr = it->second.baselineErr;
                it->second.pendingCount--;
            }
            if (it->second.pendingCount == 0 ||
                it->second.expiresAt < std::chrono::steady_clock::now()) {
                gUidErrRemapStates.erase(it);
            }
        }
    }

    if (uidBaselineErr > 0 && uidBaselineErr != err) {
        DebugLogPrint(4, "%s remap leaked errno by uid=%u from=%d to=%d", caller,
                      static_cast<unsigned>(uid), err, uidBaselineErr);
        LogErrnoRemapEvent("uid", req, uid, err, uidBaselineErr);
        return uidBaselineErr;
    }
    return err;
}

// Device reverse engineering shows make_node_entry() and create_handle_for_node() both consult
// fuse->ShouldNotCache(path). Matching that behavior is what keeps positive dentries and file-cache
// state from being reused across UIDs.
// AOSP references: jni/FuseDaemon.cpp#347, #510, and #1428
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#347
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#510
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1428
extern "C" bool WrappedShouldNotCache(void* fuse, AbiStringParam pathArg) {
    const std::string_view path = AbiStringView(pathArg);
    if (gInPfLookup && gCurrentLookupUid != 0 && gCurrentLookupParentInode != 0 &&
        !gCurrentLookupName.empty() && IsVisibleRootChildLookupPath(path, gCurrentLookupName) &&
        HiddenPathPolicy::IsExactHiddenTargetPath(gCurrentLookupUid, path)) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, gCurrentLookupParentInode,
                                                           std::memory_order_relaxed)) {
            DebugLogPrint(4, "recover hidden root parent from should_not_cache ino=%s path=%s",
                          InodePath(gCurrentLookupParentInode).c_str(), DebugPreview(path).c_str());
        }
        gTrackRootHiddenLookup = true;
    }
    if (HiddenPathPolicy::IsAnyHiddenSubtreePath(path)) {
        DebugLogPrint(4, "force uncached subtree path=%s", DebugPreview(path).c_str());
        return true;
    }
    const auto fn = gOriginalShouldNotCache.get();
    return fn ? fn(fuse, pathArg) : false;
}

bool IsTrackedHiddenSubtreeInode(uint32_t uid, uint64_t ino) {
    const auto rule = ResolveHideRuleForUid(uid);
    if (rule == nullptr || ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    const auto it = gHiddenSubtreeInodeRules.find(ino);
    if (it == gHiddenSubtreeInodeRules.end()) {
        return false;
    }
    return std::any_of(it->second.begin(), it->second.end(), [&](const auto& trackedRule) {
        return CompiledHideRulesSemanticallyEqual(rule, trackedRule);
    });
}

bool TrackHiddenSubtreeInode(uint32_t uid, uint64_t ino) {
    const auto rule = ResolveHideRuleForUid(uid);
    if (rule == nullptr || ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    auto& rules = gHiddenSubtreeInodeRules[ino];
    const bool alreadyTracked =
        std::any_of(rules.begin(), rules.end(), [&](const auto& trackedRule) {
            return CompiledHideRulesSemanticallyEqual(rule, trackedRule);
        });
    if (alreadyTracked) {
        return false;
    }
    rules.push_back(rule);
    return true;
}

bool RemoveTrackedHiddenSubtreeInode(uint32_t uid, uint64_t ino) {
    const auto rule = ResolveHideRuleForUid(uid);
    if (rule == nullptr || ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    const auto it = gHiddenSubtreeInodeRules.find(ino);
    if (it == gHiddenSubtreeInodeRules.end()) {
        return false;
    }
    auto& rules = it->second;
    const size_t oldSize = rules.size();
    rules.erase(std::remove_if(rules.begin(), rules.end(),
                               [&](const auto& trackedRule) {
                                   return CompiledHideRulesSemanticallyEqual(rule, trackedRule);
                               }),
                rules.end());
    const bool changed = rules.size() != oldSize;
    if (rules.empty()) {
        gHiddenSubtreeInodeRules.erase(it);
    }
    return changed;
}

std::optional<std::string> LookupTrackedPathForInode(uint64_t ino) {
    if (ino == 0) {
        return std::nullopt;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (rootParent != 0 && ino == rootParent) {
        return std::string(kVisibleStorageRoots[0]);
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    const auto it = gInodePathCache.find(ino);
    if (it == gInodePathCache.end()) {
        return std::nullopt;
    }
    NoteTrackedPathAccessLocked(ino);
    return it->second;
}

std::optional<uint64_t> LookupTrackedInodeForPath(std::string_view path) {
    if (path.empty()) {
        return std::nullopt;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (rootParent != 0 && path == kVisibleStorageRoots[0]) {
        return rootParent;
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    for (const auto& [ino, trackedPath] : gInodePathCache) {
        if (trackedPath == path) {
            NoteTrackedPathAccessLocked(ino);
            return ino;
        }
    }
    return std::nullopt;
}

void RememberTrackedPathForInode(uint64_t ino, std::string_view path) {
    if (ino == 0 || path.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    const bool newEntry = gInodePathCache.find(ino) == gInodePathCache.end();
    if (newEntry) {
        while (gInodePathCache.size() >= kMaxTrackedPathEntries && EvictOldestTrackedPathLocked()) {
        }
        if (gInodePathCache.size() >= kMaxTrackedPathEntries && !IsProtectedTrackedPath(path)) {
            return;
        }
    }
    gInodePathCache[ino] = std::string(path);
    NoteTrackedPathAccessLocked(ino);
}

void RememberRecentHiddenParentPath(uint32_t uid, std::string_view path) {
    if (path.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    gRecentHiddenParentPathAnyUid = std::string(path);
    gRecentHiddenParentPathAnyUidOwner = uid;
    if (uid != 0) {
        gRecentHiddenParentPaths[uid] = gRecentHiddenParentPathAnyUid;
        gRecentHiddenParentPathUids[uid] = uid;
    }
}

std::optional<std::string> LookupRecentHiddenParentPath(uint32_t uid, uint32_t* matchedHiddenUid) {
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    if (uid != 0) {
        const auto it = gRecentHiddenParentPaths.find(uid);
        if (it != gRecentHiddenParentPaths.end()) {
            if (matchedHiddenUid != nullptr) {
                const auto uidIt = gRecentHiddenParentPathUids.find(uid);
                *matchedHiddenUid =
                    uidIt != gRecentHiddenParentPathUids.end() ? uidIt->second : uid;
            }
            return it->second;
        }
        return std::nullopt;
    }
    if (gRecentHiddenParentPathAnyUid.empty()) {
        return std::nullopt;
    }
    if (matchedHiddenUid != nullptr) {
        *matchedHiddenUid = gRecentHiddenParentPathAnyUidOwner;
    }
    return gRecentHiddenParentPathAnyUid;
}

void ClearRecentHiddenParentPath(uint32_t uid) {
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    if (uid != 0) {
        gRecentHiddenParentPaths.erase(uid);
        gRecentHiddenParentPathUids.erase(uid);
    }
    if (uid == 0 || uid == gRecentHiddenParentPathAnyUidOwner) {
        gRecentHiddenParentPathAnyUid.clear();
        gRecentHiddenParentPathAnyUidOwner = 0;
    }
}

// AOSP only decides dentry caching from the resolved path, not from uid policy.
// Once the daemon sees any path inside the hidden subtree, force cache invalidation globally for
// that subtree so positive dentries from other apps stop leaking into the target uid.
void NoteHiddenSubtreePathForCache(uint32_t uid, std::string_view path) {
    if (!HiddenPathPolicy::IsAnyHiddenSubtreePath(uid, path)) {
        return;
    }

    // AOSP get_entry_timeout()/pf_getattr cache decisions are path-based rather than uid-based.
    // Once this subtree is observed anywhere in the daemon, proactively invalidate the root dentry
    // so a positive lookup seeded by another uid does not stay shared in kernel/VFS cache.
    RuntimeState::ScheduleHiddenEntryInvalidation();

    if (gInPfLookup && gCurrentLookupParentInode != 0) {
        const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
        if (HiddenPathPolicy::IsExactHiddenTargetPath(uid, path) &&
            gCurrentLookupParentInode == rootParent) {
            RemoveTrackedHiddenSubtreeInode(uid, gCurrentLookupParentInode);
            return;
        }
        gTrackHiddenSubtreeLookup = true;
        if (TrackHiddenSubtreeInode(uid, gCurrentLookupParentInode)) {
            DebugLogPrint(4, "track hidden lookup parent=%s path=%s",
                          InodePath(gCurrentLookupParentInode).c_str(), DebugPreview(path).c_str());
            RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
        }
    }

    if (gInPfGetattr && gPfGetattrIno != 0) {
        gZeroAttrCacheForCurrentGetattr = true;
        if (TrackHiddenSubtreeInode(uid, gPfGetattrIno)) {
            DebugLogPrint(4, "track hidden getattr ino=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(path).c_str());
            RuntimeState::ScheduleHiddenInodeInvalidation(gPfGetattrIno);
        }
    }
}

uint32_t ReqUid(fuse_req_t req) {
    return RuntimeState::ReqUid(req);
}

void RememberFuseSession(fuse_req_t req) {
    RuntimeState::RememberFuseSession(req);
}

void ClearActiveFuseRequestSession() {
    gActiveFuseRequestSession = nullptr;
}

void ScheduleHiddenEntryInvalidation() {
    RuntimeState::ScheduleHiddenEntryInvalidation();
}

void ScheduleHiddenInodeInvalidation(uint64_t ino) {
    RuntimeState::ScheduleHiddenInodeInvalidation(ino);
}

}  // namespace fusehide
