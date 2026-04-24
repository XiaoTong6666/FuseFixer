#include "state.hpp"

namespace fusehide {

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
void* gOriginalDoReaddirCommon = nullptr;
void* gOriginalPfGetattr = nullptr;
void* gOriginalOpen = nullptr;
void* gOriginalOpen2 = nullptr;
void* gOriginalMkdir = nullptr;
void* gOriginalMknod = nullptr;
void* gOriginalLstat = nullptr;
void* gOriginalStat = nullptr;
void* gOriginalGetxattr = nullptr;
void* gOriginalLgetxattr = nullptr;
void* gOriginalShouldNotCache = nullptr;
void* gOriginalNotifyInvalEntry = nullptr;
void* gOriginalNotifyInvalInode = nullptr;
void* gOriginalReplyAttr = nullptr;
void* gOriginalReplyEntry = nullptr;
void* gOriginalReplyBuf = nullptr;
void* gOriginalReplyErr = nullptr;
void* gOriginalGetDirectoryEntries = nullptr;
void* gOriginalAddDirectoryEntriesFromLowerFs = nullptr;
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
    return reinterpret_cast<FuseReplyErrFn>(gOriginalReplyErr);
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
std::unordered_set<uint64_t> gHiddenSubtreeInodes;
std::mutex gInodePathCacheMutex;
std::unordered_map<uint64_t, std::string> gInodePathCache;
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

bool HasNonAsciiByte(std::string_view value) {
    for (unsigned char ch : value) {
        if ((ch & 0x80u) != 0) {
            return true;
        }
    }
    return false;
}

std::string NormalizeRelativeHiddenPath(std::string_view path) {
    size_t begin = 0;
    size_t end = path.size();
    while (begin < end && path[begin] == '/') {
        begin++;
    }
    while (end > begin && path[end - 1] == '/') {
        end--;
    }
    std::string normalized;
    normalized.reserve(end - begin);
    bool previousSlash = false;
    for (size_t i = begin; i < end; ++i) {
        const char ch = path[i];
        if (ch == '/') {
            if (previousSlash) {
                continue;
            }
            previousSlash = true;
        } else {
            previousSlash = false;
        }
        normalized.push_back(ch);
    }
    return normalized;
}

std::optional<std::string> RelativePathForVisibleRoot(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return std::string();
        }
        if (path.size() > root.size() && path.compare(0, root.size(), root) == 0 &&
            path[root.size()] == '/') {
            return NormalizeRelativeHiddenPath(path.substr(root.size() + 1));
        }
    }
    return std::nullopt;
}

bool MatchesRelativeHiddenPathList(std::string_view relativePath, bool exactOnly) {
    const std::string normalized = NormalizeRelativeHiddenPath(relativePath);
    if (normalized.empty()) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& configuredPath : config->hiddenRelativePaths) {
        const std::string candidate = NormalizeRelativeHiddenPath(configuredPath);
        if (candidate.empty()) {
            continue;
        }
        if (normalized == candidate) {
            return true;
        }
        if (!exactOnly && normalized.size() > candidate.size() &&
            normalized.compare(0, candidate.size(), candidate) == 0 &&
            normalized[candidate.size()] == '/') {
            return true;
        }
    }
    return false;
}

bool IsWildcardRootEntryCandidate(std::string_view name) {
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    if (name.find('/') != std::string_view::npos) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& exemptEntry : config->hideAllRootEntriesExemptions) {
        if (name == exemptEntry) {
            return false;
        }
    }
    return true;
}

bool ShouldHideWildcardRootEntryByParent(uint64_t parent, uint64_t rootParent,
                                         std::string_view name) {
    return CurrentHideConfig()->enableHideAllRootEntries && rootParent != 0 &&
           parent == rootParent && IsWildcardRootEntryCandidate(name);
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
    if (req != nullptr && req->se != nullptr) {
        gLastFuseSession.store(req->se, std::memory_order_relaxed);
    }
}

// Shared dentry cache is not scoped per uid. Once another app resolves the hidden entry, the
// target uid can reuse that positive cache unless we actively invalidate the root dentry.
void RuntimeState::ScheduleHiddenEntryInvalidation() {
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
        const auto config = CurrentHideConfig();
        std::unordered_set<std::string> namesToInvalidate;
        for (const auto& rootEntryName : config->hiddenRootEntryNames) {
            namesToInvalidate.emplace(rootEntryName);
        }

        if (config->enableHideAllRootEntries) {
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
    auto notifyEntry =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
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
    if (!IsTestHiddenUid(uid) || error_in != 0 || name == nullptr) {
        return false;
    }
    if (IsHiddenLookupCacheTarget(parent, name)) {
        return true;
    }
    const auto kind = ClassifyHiddenNamedTarget(uid, parent, name);
    return kind == HiddenNamedTargetKind::Root || kind == HiddenNamedTargetKind::Descendant;
}

bool IsHiddenLookupCacheTarget(uint64_t parent, const char* name) {
    if (name == nullptr) {
        return false;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (ShouldHideWildcardRootEntryByParent(parent, rootParent, name)) {
        return true;
    }
    return IsConfiguredHiddenRootEntryName(name) && (rootParent == 0 || parent == rootParent);
}

std::optional<HiddenNamedTargetKind> ClassifyHiddenNamedTargetByTrackedPath(uint64_t parent,
                                                                            const char* name) {
    if (name == nullptr) {
        return std::nullopt;
    }
    const auto parentPath = LookupTrackedPathForInode(parent);
    if (!parentPath.has_value()) {
        return std::nullopt;
    }
    const std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name);
    if (HiddenPathPolicy::IsExactHiddenTargetPath(childPath)) {
        return HiddenNamedTargetKind::Root;
    }
    if (HiddenPathPolicy::IsAnyHiddenSubtreePath(childPath)) {
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
    if (parent != 0 && parent != rootParent && IsTrackedHiddenSubtreeInode(parent)) {
        return HiddenNamedTargetKind::Descendant;
    }
    if (ShouldHideWildcardRootEntryByParent(parent, rootParent, name)) {
        return HiddenNamedTargetKind::Root;
    }
    if (IsConfiguredHiddenRootEntryName(name) && (rootParent == 0 || parent == rootParent)) {
        return HiddenNamedTargetKind::Root;
    }
    if (const auto trackedPathKind = ClassifyHiddenNamedTargetByTrackedPath(parent, name);
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
    gInodePathCache[ino] = std::string(path);
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

bool HiddenPathPolicy::IsConfiguredHiddenRootEntryName(std::string_view name) {
    const auto config = CurrentHideConfig();
    for (const auto& rootEntryName : config->hiddenRootEntryNames) {
        if (name == rootEntryName) {
            return true;
        }
    }

    if (!HasNonAsciiByte(name)) {
        return false;
    }

    std::string sanitized(name);
    if (!UnicodePolicy::NeedsSanitization(sanitized)) {
        return false;
    }
    UnicodePolicy::RewriteString(sanitized);

    for (const auto& rootEntryName : config->hiddenRootEntryNames) {
        if (sanitized == rootEntryName) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsHiddenRootEntryName(std::string_view name) {
    return IsConfiguredHiddenRootEntryName(name) ||
           (CurrentHideConfig()->enableHideAllRootEntries && IsWildcardRootEntryCandidate(name));
}

bool HiddenPathPolicy::IsAnyHiddenSubtreePath(std::string_view path) {
    if (const auto relativePath = RelativePathForVisibleRoot(path);
        relativePath.has_value() && MatchesRelativeHiddenPathList(*relativePath, false)) {
        return true;
    }
    for (const auto& root : kVisibleStorageRoots) {
        if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0 ||
            path[root.size()] != '/') {
            continue;
        }

        const size_t componentStart = root.size() + 1;
        const size_t slashPos = path.find('/', componentStart);
        const size_t componentEnd = slashPos == std::string_view::npos ? path.size() : slashPos;
        if (componentEnd <= componentStart) {
            continue;
        }

        const std::string_view rootEntry =
            path.substr(componentStart, componentEnd - componentStart);
        if (IsHiddenRootEntryName(rootEntry)) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsExactHiddenTargetPath(std::string_view path) {
    if (const auto relativePath = RelativePathForVisibleRoot(path);
        relativePath.has_value() && MatchesRelativeHiddenPathList(*relativePath, true)) {
        return true;
    }
    for (const auto& root : kVisibleStorageRoots) {
        if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0 ||
            path[root.size()] != '/') {
            continue;
        }

        const size_t componentStart = root.size() + 1;
        const size_t slashPos = path.find('/', componentStart);
        if (slashPos != std::string_view::npos) {
            continue;
        }

        const std::string_view rootEntry = path.substr(componentStart);
        if (IsHiddenRootEntryName(rootEntry)) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsHiddenRootDirectoryPath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return true;
        }
    }
    return false;
}

bool IsParentOfExactHiddenTargetPath(std::string_view path) {
    // Root targets and nested relative targets need different list filtering keys. Root-level
    // targets can be recognized by child name alone under /storage/emulated/0, but nested targets
    // need the exact visible parent path so reply_buf can rebuild parentPath + childName.
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            const auto config = CurrentHideConfig();
            return !config->hiddenRootEntryNames.empty() || config->enableHideAllRootEntries;
        }
    }

    const auto relativePath = RelativePathForVisibleRoot(path);
    if (!relativePath.has_value()) {
        return false;
    }

    const auto config = CurrentHideConfig();
    for (const auto& hiddenRelativePath : config->hiddenRelativePaths) {
        const std::string normalized = NormalizeRelativeHiddenPath(hiddenRelativePath);
        if (normalized.empty()) {
            continue;
        }
        const size_t slash = normalized.rfind('/');
        if (slash == std::string::npos) {
            continue;
        }
        if (*relativePath == normalized.substr(0, slash)) {
            return true;
        }
    }
    return false;
}

std::string HiddenPathPolicy::JoinPathComponent(std::string_view parent, std::string_view child) {
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

bool HiddenPathPolicy::ShouldFilterHiddenRootDirent(uint32_t uid, uint64_t ino,
                                                    std::string_view name,
                                                    bool requireParentMatch) {
    if (!IsTestHiddenUid(uid)) {
        return false;
    }

    if (const auto parentPath = LookupTrackedPathForInode(ino); parentPath.has_value()) {
        const std::string childPath = JoinPathComponent(*parentPath, name);
        if (IsExactHiddenTargetPath(childPath)) {
            return true;
        }
    }

    if (!IsHiddenRootEntryName(name)) {
        return false;
    }
    if (!requireParentMatch) {
        return true;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    return rootParent == 0 || ino == rootParent;
}

bool ShouldFilterTrackedHiddenDirentInode(uint32_t uid, uint64_t childIno, std::string_view name) {
    if (!HiddenPathPolicy::IsTestHiddenUid(uid) || childIno == 0) {
        return false;
    }
    if (!IsTrackedHiddenSubtreeInode(childIno)) {
        return false;
    }
    DebugLogPrint(4, "filter dirent by tracked inode uid=%u child=%s name=%s",
                  static_cast<unsigned>(uid), InodePath(childIno).c_str(),
                  DebugPreview(name).c_str());
    return true;
}

bool ShouldFilterDirentForParentPath(uint32_t uid, std::string_view parentPath, uint64_t childIno,
                                     std::string_view name) {
    if (!HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return false;
    }
    // Prefer exact inode matches when a hidden child inode is already known, then fall back to
    // exact path matching for the recovered visible parent directory.
    if (ShouldFilterTrackedHiddenDirentInode(uid, childIno, name)) {
        return true;
    }
    const std::string childPath = HiddenPathPolicy::JoinPathComponent(parentPath, name);
    return HiddenPathPolicy::IsExactHiddenTargetPath(childPath);
}

bool DirentFilter::BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid,
                                              uint64_t ino, std::vector<char>* out,
                                              size_t* removedCount, bool requireParentMatch) {
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
        if (ShouldFilterTrackedHiddenDirentInode(uid, dirent->ino, name) ||
            ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
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

bool BuildFilteredDirentPayloadForParentPath(const char* data, size_t size, uint32_t uid,
                                             std::string_view parentPath, std::vector<char>* out,
                                             size_t* removedCount,
                                             std::vector<FilteredDirentMatch>* removedEntries) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr ||
        parentPath.empty()) {
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
        if (ShouldFilterDirentForParentPath(uid, parentPath, dirent->ino, name)) {
            removed++;
            if (removedEntries != nullptr) {
                removedEntries->push_back(FilteredDirentMatch{std::string(name), dirent->ino});
            }
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

bool DirentFilter::BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid,
                                                  uint64_t ino, std::vector<char>* out,
                                                  size_t* removedCount, bool requireParentMatch) {
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
        if (ShouldFilterTrackedHiddenDirentInode(uid, dirent->ino, name) ||
            ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
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

bool BuildFilteredDirentplusPayloadForParentPath(const char* data, size_t size, uint32_t uid,
                                                 std::string_view parentPath,
                                                 std::vector<char>* out, size_t* removedCount,
                                                 std::vector<FilteredDirentMatch>* removedEntries) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr ||
        parentPath.empty()) {
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
        if (ShouldFilterDirentForParentPath(uid, parentPath, dirent->ino, name)) {
            removed++;
            if (removedEntries != nullptr) {
                removedEntries->push_back(FilteredDirentMatch{std::string(name), dirent->ino});
            }
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
    RuntimeState::ScheduleHiddenEntryInvalidation();

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
            RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
        }
    }

    if (gInPfGetattr && gPfGetattrIno != 0) {
        gZeroAttrCacheForCurrentGetattr = true;
        if (TrackHiddenSubtreeInode(gPfGetattrIno)) {
            DebugLogPrint(4, "track hidden getattr ino=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(path).c_str());
            RuntimeState::ScheduleHiddenInodeInvalidation(gPfGetattrIno);
        }
    }
}

bool IsConfiguredHiddenRootEntryName(std::string_view name) {
    return HiddenPathPolicy::IsConfiguredHiddenRootEntryName(name);
}

bool IsHiddenRootEntryName(std::string_view name) {
    return HiddenPathPolicy::IsHiddenRootEntryName(name);
}

bool IsAnyHiddenSubtreePath(std::string_view path) {
    return HiddenPathPolicy::IsAnyHiddenSubtreePath(path);
}

bool IsExactHiddenTargetPath(std::string_view path) {
    return HiddenPathPolicy::IsExactHiddenTargetPath(path);
}

bool IsHiddenRootDirectoryPath(std::string_view path) {
    return HiddenPathPolicy::IsHiddenRootDirectoryPath(path);
}

std::string JoinPathComponent(std::string_view parent, std::string_view child) {
    return HiddenPathPolicy::JoinPathComponent(parent, child);
}

bool ShouldFilterHiddenRootDirent(uint32_t uid, uint64_t ino, std::string_view name,
                                  bool requireParentMatch) {
    return HiddenPathPolicy::ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch);
}

bool BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                std::vector<char>* out, size_t* removedCount,
                                bool requireParentMatch) {
    return DirentFilter::BuildFilteredDirentPayload(data, size, uid, ino, out, removedCount,
                                                    requireParentMatch);
}

bool BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                    std::vector<char>* out, size_t* removedCount,
                                    bool requireParentMatch) {
    return DirentFilter::BuildFilteredDirentplusPayload(data, size, uid, ino, out, removedCount,
                                                        requireParentMatch);
}

uint32_t ReqUid(fuse_req_t req) {
    return RuntimeState::ReqUid(req);
}

void RememberFuseSession(fuse_req_t req) {
    RuntimeState::RememberFuseSession(req);
}

void ScheduleHiddenEntryInvalidation() {
    RuntimeState::ScheduleHiddenEntryInvalidation();
}

void ScheduleHiddenInodeInvalidation(uint64_t ino) {
    RuntimeState::ScheduleHiddenInodeInvalidation(ino);
}

}  // namespace fusehide
