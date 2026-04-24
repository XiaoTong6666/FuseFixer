#include "wrappers.hpp"

namespace fusehide {

namespace {

thread_local uint32_t gActiveCreateUid = 0;
thread_local uint32_t gLastPathPolicyUid = 0;
thread_local std::string gLastPathPolicyPath;

class ScopedCreateUid final {
   public:
    explicit ScopedCreateUid(uint32_t uid) : previous_(gActiveCreateUid) {
        gActiveCreateUid = uid;
    }

    ~ScopedCreateUid() {
        gActiveCreateUid = previous_;
    }

   private:
    uint32_t previous_;
};

bool ShouldHideLowerFsCreatePath(std::string_view pathView) {
    const uint32_t uid = gActiveCreateUid != 0 ? gActiveCreateUid : gLastPathPolicyUid;
    return uid != 0 && HiddenPathPolicy::IsTestHiddenUid(uid) &&
           HiddenPathPolicy::IsExactHiddenTargetPath(pathView);
}

bool ShouldHideLowerFsPath(std::string_view pathView) {
    const uint32_t uid = gActiveCreateUid != 0 ? gActiveCreateUid : gLastPathPolicyUid;
    return uid != 0 && HiddenPathPolicy::ShouldHideTestPath(uid, pathView);
}

std::string ReadDirectoryPathFromDir(DIR* dirp) {
    if (dirp == nullptr) {
        return {};
    }
    const int fd = dirfd(dirp);
    if (fd < 0) {
        return {};
    }
    char procPath[64];
    std::snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fd);
    char resolved[PATH_MAX];
    const ssize_t len = readlink(procPath, resolved, sizeof(resolved) - 1);
    if (len <= 0) {
        return {};
    }
    resolved[len] = '\0';
    return std::string(resolved, static_cast<size_t>(len));
}

bool IsFirstComponentOfHiddenRelativePath(std::string_view name) {
    if (name.empty() || name.find('/') != std::string_view::npos) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& hiddenRelativePath : config->hiddenRelativePaths) {
        std::string normalized = hiddenRelativePath;
        while (!normalized.empty() && normalized.front() == '/') {
            normalized.erase(normalized.begin());
        }
        while (!normalized.empty() && normalized.back() == '/') {
            normalized.pop_back();
        }
        if (normalized.empty()) {
            continue;
        }
        const size_t slash = normalized.find('/');
        const std::string_view first = slash == std::string::npos
                                           ? std::string_view(normalized)
                                           : std::string_view(normalized).substr(0, slash);
        if (first == name) {
            return true;
        }
    }
    return false;
}

void InvalidateFilteredParentChildren(std::string_view parentPath,
                                      const std::vector<FilteredDirentMatch>& removedEntries) {
    if (parentPath.empty() || removedEntries.empty()) {
        return;
    }
    const auto parentIno = LookupTrackedInodeForPath(parentPath);
    if (!parentIno.has_value()) {
        DebugLogPrint(4,
                      "skip filtered child invalidation parent=%s names=%zu reason=no_parent_ino",
                      DebugPreview(parentPath).c_str(), removedEntries.size());
        return;
    }
    for (const auto& entry : removedEntries) {
        RuntimeState::ScheduleSpecificEntryInvalidation(*parentIno, entry.name);
        if (entry.ino != 0) {
            const std::string childPath =
                HiddenPathPolicy::JoinPathComponent(parentPath, entry.name);
            RememberTrackedPathForInode(entry.ino, childPath);
            if (TrackHiddenSubtreeInode(entry.ino)) {
                DebugLogPrint(4, "track filtered child inode parent=%s child=%s ino=%s",
                              DebugPreview(parentPath).c_str(), DebugPreview(entry.name).c_str(),
                              InodePath(entry.ino).c_str());
            }
            RuntimeState::ScheduleHiddenInodeInvalidation(entry.ino);
        }
    }
    DebugLogPrint(4, "invalidate filtered children parent=%s ino=%s names=%zu",
                  DebugPreview(parentPath).c_str(), InodePath(*parentIno).c_str(),
                  removedEntries.size());
}

}  // namespace

// pf_lookup is the earliest reliable place to learn the real root parent inode on this device.
// AOSP reference: jni/FuseDaemon.cpp#851
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#851
extern "C" void WrappedPfLookup(fuse_req_t req, uint64_t parent, const char* name) {
    RuntimeState::RememberFuseSession(req);
    if (name != nullptr && IsConfiguredHiddenRootEntryName(name) && parent != 0) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, parent,
                                                           std::memory_order_relaxed)) {
            DebugLogPrint(4, "record hidden root parent=%s", InodePath(parent).c_str());
        }
    }
    gInPfLookup = true;
    gCurrentLookupParentInode = parent;
    gCurrentLookupName = name != nullptr ? std::string(name) : std::string();
    gTrackRootHiddenLookup = IsHiddenLookupCacheTarget(parent, name);
    gTrackHiddenSubtreeLookup = IsTrackedHiddenSubtreeInode(parent);
    DebugLogPrint(3, "lookup: req=%lu parent=%s name=%s", (unsigned long)req->unique,
                  InodePath(parent).c_str(), name ? DebugPreview(name).c_str() : "null");

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfLookup);
    if (fn)
        fn(req, parent, name);
    gCurrentLookupParentInode = 0;
    gCurrentLookupName.clear();
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
    if (!HiddenPathPolicy::IsTestHiddenUid(uid) || entries.empty()) {
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
                                     return HiddenPathPolicy::ShouldHideTestPath(
                                         uid,
                                         HiddenPathPolicy::JoinPathComponent(parentPath, name));
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
    if (gCurrentReaddirReqUnique != 0) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        auto it = gPendingReaddirContexts.find(gCurrentReaddirReqUnique);
        if (it != gPendingReaddirContexts.end()) {
            it->second.path = path;
            DebugLogPrint(4, "record readdir path req=%lu ino=%s path=%s",
                          (unsigned long)gCurrentReaddirReqUnique,
                          InodePath(it->second.ino).c_str(), DebugPreview(path).c_str());
        }
    }
    return FilterHiddenDirectoryEntries(uid, path, std::move(entries));
}

void WrappedAddDirectoryEntriesFromLowerFs(DIR* dirp, LowerFsDirentFilterFn filter,
                                           DirectoryEntries* entries) {
    auto fn =
        reinterpret_cast<AddDirectoryEntriesFromLowerFsFn>(gOriginalAddDirectoryEntriesFromLowerFs);
    if (fn == nullptr) {
        return;
    }
    fn(dirp, filter, entries);
    if (entries == nullptr || entries->empty()) {
        return;
    }

    const uint32_t uid = gLastPathPolicyUid;
    if (!HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return;
    }

    std::string parentPath = ReadDirectoryPathFromDir(dirp);
    if (parentPath.empty()) {
        parentPath = gLastPathPolicyPath;
    }
    if (parentPath.empty()) {
        return;
    }

    const size_t before = entries->size();
    *entries = FilterHiddenDirectoryEntries(uid, parentPath, std::move(*entries));
    if (entries->size() != before) {
        DebugLogPrint(4, "filter lower-fs dir entries uid=%u parent=%s removed=%zu remaining=%zu",
                      static_cast<unsigned>(uid), DebugPreview(parentPath).c_str(),
                      before - entries->size(), entries->size());
    }
}

// AOSP readdir postfilter stats each child path before copying the surviving dirents into a
// fuse_read_out buffer. This context flag lets WrappedReplyBuf preserve that wire layout when the
// device actually goes through pf_readdir_postfilter.
// AOSP reference: jni/FuseDaemon.cpp#1954
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1954
extern "C" void WrappedPfReaddirPostfilter(fuse_req_t req, uint64_t ino, uint32_t error_in,
                                           off_t off_in, off_t off_out, size_t size_out,
                                           const void* dirents_in, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
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
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, error_in, off_in, off_out, size_out, dirents_in, fi);
    gCurrentReaddirReqUnique = 0;
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
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    DebugLogPrint(3, "pf_lookup_postfilter req=%p uid=%u parent=%s name=%s err_in=%u", req,
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", error_in);
    if (IsHiddenLookupTarget(uid, parent, error_in, name)) {
        DebugLogPrint(4, "pf_lookup_postfilter hide uid=%u parent=%s name=%s",
                      static_cast<unsigned>(uid), InodePath(parent).c_str(), name);
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_lookup_postfilter").has_value()) {
            return;
        }
        ArmHiddenErrorRemap(req, ENOENT, "pf_lookup_postfilter");
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
    RuntimeState::RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, int)>(gOriginalPfAccess);
    if (fn) {
        fn(req, ino, mask);
    }
}

extern "C" void WrappedPfOpen(fuse_req_t req, uint64_t ino, void* fi) {
    RuntimeState::RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpen);
    if (fn) {
        fn(req, ino, fi);
    }
}

extern "C" void WrappedPfOpendir(fuse_req_t req, uint64_t ino, void* fi) {
    RuntimeState::RememberFuseSession(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpendir);
    if (fn) {
        fn(req, ino, fi);
    }
}

// AOSP pf_mkdir only checks parent_path accessibility before it calls mkdir(child_path), so a
// hidden leaf name would still leak existence semantics unless we stop it here.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1184
extern "C" void WrappedPfMkdir(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_mkdir uid=%u parent=%s name=%s mode=%o hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode,
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_mkdir", kind, EACCES, ENOENT)) {
        return;
    }
    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t)>(gOriginalPfMkdir);
    if (fn) {
        ScopedCreateUid scopedUid(uid);
        fn(req, parent, name, mode);
    }
}

// Some callers create regular files through the mknod op instead of create. AOSP still uses only
// parent_path policy here, so hidden leaf names must be blocked explicitly.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1134
extern "C" void WrappedPfMknod(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                               uint64_t rdev) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_mknod uid=%u parent=%s name=%s mode=%o rdev=%llu hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode,
                  static_cast<unsigned long long>(rdev),
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_mknod", kind, EPERM, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, uint64_t)>(
        gOriginalPfMknod);
    if (fn) {
        ScopedCreateUid scopedUid(uid);
        fn(req, parent, name, mode, rdev);
    }
}

// AOSP pf_unlink only gates on parent_path before it deletes the final child path, so hidden leaf
// names must return ENOENT here instead of reaching the lower filesystem.
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1218
extern "C" void WrappedPfUnlink(fuse_req_t req, uint64_t parent, const char* name) {
    RuntimeState::RememberFuseSession(req);
    const HiddenNamedTargetKind kind =
        ClassifyHiddenNamedTarget(RuntimeState::ReqUid(req), parent, name);
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
    RuntimeState::RememberFuseSession(req);
    const HiddenNamedTargetKind kind =
        ClassifyHiddenNamedTarget(RuntimeState::ReqUid(req), parent, name);
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
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
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
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_rename").has_value()) {
            return;
        }
        ArmHiddenErrorRemap(req, ENOENT, "pf_rename");
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
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_create uid=%u parent=%s name=%s mode=%o fi=%p hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode, fi,
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_create", kind, EPERM, ENOENT)) {
        return;
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, void*)>(
        gOriginalPfCreate);
    if (fn) {
        ScopedCreateUid scopedUid(uid);
        fn(req, parent, name, mode, fi);
    }
}

// Plain readdir delegates to do_readdir_common(..., plus=false). Most modern devices keep
// readdirplus enabled, but this hook is still useful as a fallback for alternative FUSE configs.
// AOSP reference: jni/FuseDaemon.cpp#1944
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1944
extern "C" void WrappedPfReaddir(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(gOriginalPfReaddir);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdir uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddir = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi);
    gCurrentReaddirReqUnique = 0;
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddir = false;
}

extern "C" void WrappedDoReaddirCommon(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                       void* fi, bool plus) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*, bool)>(
        gOriginalDoReaddirCommon);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "do_readdir_common uid=%u ino=%s size=%zu off=%lld plus=%d",
                  static_cast<unsigned>(uid), InodePath(ino).c_str(), size,
                  static_cast<long long>(off), plus ? 1 : 0);
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi, plus);
    gCurrentReaddirReqUnique = 0;
}

// readdirplus is the common enumeration path on recent Android builds because do_readdir_common()
// emits fuse_direntplus records by first running do_lookup() for each directory entry.
// AOSP references: jni/FuseDaemon.cpp#1904 and #2000
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1904
// https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#2000
extern "C" void WrappedPfReaddirplus(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                     void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(
        gOriginalPfReaddirplus);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdirplus uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddirplus = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi);
    gCurrentReaddirReqUnique = 0;
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
    const bool hiddenLookupForUid = HiddenPathPolicy::IsTestHiddenUid(RuntimeState::ReqUid(req)) &&
                                    (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup);
    if (hiddenLookupForUid) {
        if (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup) {
            ArmHiddenCreateLeakRemap(req, "fuse_reply_entry");
        }
        if (gTrackHiddenSubtreeLookup) {
            if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode);
                parentPath.has_value()) {
                RememberTrackedPathForInode(gCurrentLookupParentInode, *parentPath);
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *parentPath);
                DebugLogPrint(4, "refresh recent hidden parent from hidden lookup uid=%u path=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*parentPath).c_str());
                RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
            }
        }
        if (auto ret = ReplyErrorBridge::Reply(req, ENOENT, "fuse_reply_entry"); ret.has_value()) {
            DebugLogPrint(4, "hide lookup entry uid=%u req=%lu ino=%s root=%d child=%d ret=%d",
                          static_cast<unsigned>(RuntimeState::ReqUid(req)),
                          req ? (unsigned long)req->unique : 0UL,
                          e != nullptr ? InodePath(e->ino).c_str() : "(null)",
                          gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0, *ret);
            RuntimeState::ScheduleHiddenEntryInvalidation();
            if (gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode,
                                                                gCurrentLookupName);
            }
            if (e != nullptr && e->ino != 0) {
                RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
            }
            return *ret;
        }
    }
    fuse_entry_param patchedEntry = {};
    const struct fuse_entry_param* replyEntry = e;
    bool forceUncachedReplyEntry = gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup;
    bool exactHiddenTargetReplyEntry = false;
    if (e != nullptr && (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup)) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
        DebugLogPrint(4, "disable entry cache req=%lu ino=%s root=%d child=%d",
                      req ? (unsigned long)req->unique : 0UL, InodePath(e->ino).c_str(),
                      gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0);
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (TrackHiddenSubtreeInode(e->ino)) {
            RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
        }
    }
    // The device build sometimes delivers directory data through reply_buf without ever hitting our
    // readdir-family wrappers, but lookup success for the visible parent still flows through
    // fuse_reply_entry. Record the parent path here so reply_buf can later reconstruct an exact
    // parentPath + childName match for nested hidden targets.
    // AOSP references: jni/FuseDaemon.cpp#889, #912, and #1909
    // https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#889
    // https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#912
    // https://android.googlesource.com/platform/packages/providers/MediaProvider/+/refs/heads/android14-release/jni/FuseDaemon.cpp#1909
    if (e != nullptr && gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
        std::optional<std::string> childPath;
        if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode);
            parentPath.has_value()) {
            childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, gCurrentLookupName);
        } else if (IsFirstComponentOfHiddenRelativePath(gCurrentLookupName)) {
            childPath =
                HiddenPathPolicy::JoinPathComponent(kVisibleStorageRoots[0], gCurrentLookupName);
            DebugLogPrint(4, "infer root child path ino=%s name=%s path=%s",
                          InodePath(gCurrentLookupParentInode).c_str(),
                          DebugPreview(gCurrentLookupName).c_str(),
                          DebugPreview(*childPath).c_str());
        }
        if (childPath.has_value()) {
            RememberTrackedPathForInode(e->ino, *childPath);
            const bool hiddenSubtreePath = HiddenPathPolicy::IsAnyHiddenSubtreePath(*childPath);
            exactHiddenTargetReplyEntry = HiddenPathPolicy::IsExactHiddenTargetPath(*childPath);
            if (hiddenSubtreePath) {
                TrackHiddenSubtreeInode(e->ino);
                forceUncachedReplyEntry = true;
            }
            if (exactHiddenTargetReplyEntry) {
                forceUncachedReplyEntry = true;
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode,
                                                                gCurrentLookupName);
                RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
                DebugLogPrint(4, "force uncached exact hidden target uid=%u path=%s ino=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*childPath).c_str(), InodePath(e->ino).c_str());
            }
            if (IsParentOfExactHiddenTargetPath(*childPath)) {
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *childPath);
                DebugLogPrint(4, "remember recent hidden parent uid=%u path=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*childPath).c_str());
            }
        }
    }
    if (e != nullptr && forceUncachedReplyEntry && replyEntry == e) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
        DebugLogPrint(4, "disable entry cache req=%lu ino=%s root=%d child=%d exact=%d",
                      req ? (unsigned long)req->unique : 0UL, InodePath(e->ino).c_str(),
                      gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0,
                      exactHiddenTargetReplyEntry ? 1 : 0);
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
    std::vector<FilteredDirentMatch> removedEntries;
    PendingReaddirContext pendingContext{};
    bool hasPendingContext = false;
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        const auto it = gPendingReaddirContexts.find(req->unique);
        if (it != gPendingReaddirContexts.end()) {
            pendingContext = it->second;
            hasPendingContext = true;
        }
    }
    const uint32_t reqUid = RuntimeState::ReqUid(req);
    const uint32_t requestFilterUid =
        gPfReaddirUid != 0
            ? gPfReaddirUid
            : (hasPendingContext && pendingContext.uid != 0 ? pendingContext.uid : reqUid);
    const uint64_t filterIno =
        gPfReaddirIno != 0 ? gPfReaddirIno : (hasPendingContext ? pendingContext.ino : 0);
    const bool filterPlainReaddir = gInPfReaddir;
    const bool filterPostfilterReaddir = gInPfReaddirPostfilter;
    const bool filterReaddirplus = gInPfReaddirplus;
    const bool requireParentMatch = filterIno != 0;
    const char* filterMode = nullptr;
    uint32_t fallbackHiddenUid = 0;
    const std::optional<std::string> fallbackParentPath =
        filterIno == 0 ? LookupRecentHiddenParentPath(requestFilterUid, &fallbackHiddenUid)
                       : std::nullopt;
    // Some device reply_buf paths lose the caller uid entirely, but we must not reuse the last
    // hidden uid for an explicit non-hidden app. Only borrow fallback uid when the request uid is
    // absent (0); otherwise recent parent state would bleed into unrelated apps.
    const bool canBorrowFallbackUid =
        requestFilterUid == 0 && HiddenPathPolicy::IsTestHiddenUid(fallbackHiddenUid);
    const uint32_t filterUid = HiddenPathPolicy::IsTestHiddenUid(requestFilterUid)
                                   ? requestFilterUid
                                   : (canBorrowFallbackUid ? fallbackHiddenUid : 0);

    if (filterIno != 0 && !pendingContext.path.empty()) {
        RememberTrackedPathForInode(filterIno, pendingContext.path);
    }

    if (HiddenPathPolicy::IsTestHiddenUid(filterUid)) {
        DebugLogPrint(
            4,
            "reply_buf filter ctx req=%lu req_uid=%u uid=%u ino=%s pending=%d pending_path=%s "
            "fallback_parent=%s fallback_uid=%u mode_flags=%d/%d/%d",
            req ? (unsigned long)req->unique : 0UL, static_cast<unsigned>(requestFilterUid),
            static_cast<unsigned>(filterUid), InodePath(filterIno).c_str(),
            hasPendingContext ? 1 : 0,
            pendingContext.path.empty() ? "" : DebugPreview(pendingContext.path).c_str(),
            fallbackParentPath.has_value() ? DebugPreview(*fallbackParentPath).c_str() : "",
            static_cast<unsigned>(fallbackHiddenUid), filterPlainReaddir ? 1 : 0,
            filterReaddirplus ? 1 : 0, filterPostfilterReaddir ? 1 : 0);
    }

    if (HiddenPathPolicy::IsTestHiddenUid(filterUid)) {
        if (filterPlainReaddir) {
            if (DirentFilter::BuildFilteredDirentPayload(buf, size, filterUid, filterIno,
                                                         &filteredStorage, &removedCount,
                                                         requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdir";
            }
        } else if (filterReaddirplus) {
            if (DirentFilter::BuildFilteredDirentplusPayload(buf, size, filterUid, filterIno,
                                                             &filteredStorage, &removedCount,
                                                             requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdirplus";
            }
        } else if (filterPostfilterReaddir && size >= sizeof(fuse_read_out)) {
            const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
            const size_t payloadSize =
                std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
            std::vector<char> filteredPayload;
            if (DirentFilter::BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize,
                                                         filterUid, filterIno, &filteredPayload,
                                                         &removedCount, requireParentMatch)) {
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

        // When the active device path bypasses our readdir wrappers, reply_buf still sees the final
        // dirent payload but loses the parent inode/path context. Fall back to the last visible
        // parent path learned from fuse_reply_entry so nested targets like Download/Download can be
        // filtered by exact path instead of by name alone.
        if (filterMode == nullptr) {
            if (fallbackParentPath.has_value() &&
                BuildFilteredDirentplusPayloadForParentPath(buf, size, filterUid,
                                                            *fallbackParentPath, &filteredStorage,
                                                            &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "fallback_parent_direntplus";
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (fallbackParentPath.has_value() &&
                       BuildFilteredDirentPayloadForParentPath(
                           buf, size, filterUid, *fallbackParentPath, &filteredStorage,
                           &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "fallback_parent_dirent";
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (size >= sizeof(fuse_read_out) && fallbackParentPath.has_value()) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize =
                    std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (BuildFilteredDirentPayloadForParentPath(
                        buf + sizeof(fuse_read_out), payloadSize, filterUid, *fallbackParentPath,
                        &filteredPayload, &removedCount, &removedEntries)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                                filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                    filterMode = "fallback_parent_read_out_dirent";
                    InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                    ClearRecentHiddenParentPath(filterUid);
                }
            }
        }

        if (filterMode == nullptr) {
            if (DirentFilter::BuildFilteredDirentplusPayload(
                    buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_direntplus";
            } else if (DirentFilter::BuildFilteredDirentPayload(
                           buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_dirent";
            } else if (size >= sizeof(fuse_read_out)) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize =
                    std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (DirentFilter::BuildFilteredDirentPayload(
                        buf + sizeof(fuse_read_out), payloadSize, filterUid, 0, &filteredPayload,
                        &removedCount, false)) {
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
    if (hasPendingContext && req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.erase(req->unique);
    }
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
    auto fn = ReplyErrorBridge::Original();
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.erase(req->unique);
    }
    err = MaybeRewriteHiddenLeakErrno(req, err, "fuse_reply_err");
    int ret = fn ? fn(req, err) : -1;
    if (gInPfLookupPostfilter) {
        DebugLogPrint(3, "pf_lookup_postfilter fuse_reply_err req=%p %d", req, err);
    } else {
        DebugLogPrint(3, "fuse_reply_err: req=%p err=%d ret=%d", req, err, ret);
    }
    return ret;
}

extern "C" void WrappedPfGetattr(fuse_req_t req, uint64_t ino, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    gZeroAttrCacheForCurrentGetattr = IsTrackedHiddenSubtreeInode(ino);
    if (HiddenPathPolicy::IsTestHiddenUid(uid)) {
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
    if (gInPfGetattr && gPfGetattrIno != 0 &&
        HiddenPathPolicy::IsHiddenRootDirectoryPath(pathView)) {
        uint64_t expected = 0;
        const bool recorded = gHiddenRootParentInode.compare_exchange_strong(
            expected, gPfGetattrIno, std::memory_order_relaxed);
        if (recorded) {
            DebugLogPrint(4, "record hidden root parent from getattr=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(pathView).c_str());
        }
        RemoveTrackedHiddenSubtreeInode(gPfGetattrIno);
        if (recorded && CurrentHideConfig()->enableHideAllRootEntries) {
            RuntimeState::ScheduleHiddenEntryInvalidation();
        }
    }
    NoteHiddenSubtreePathForCache(pathView);
    if (gInPfGetattr && HiddenPathPolicy::IsTestHiddenUid(gPfGetattrUid)) {
        DebugLogPrint(4, "pf_getattr lstat uid=%u path=%s", static_cast<unsigned>(gPfGetattrUid),
                      DebugPreview(pathView).c_str());
        if (HiddenPathPolicy::ShouldHideTestPath(gPfGetattrUid, pathView)) {
            DebugLogPrint(4, "hide test lstat uid=%u path=%s", static_cast<unsigned>(gPfGetattrUid),
                          DebugPreview(pathView).c_str());
            errno = ENOENT;
            return -1;
        }
    }
    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalLstat);
    if (fn) {
        const int ret = fn(path, st);
        if (ret == 0 && gInPfGetattr && gPfGetattrIno != 0) {
            RememberTrackedPathForInode(gPfGetattrIno, pathView);
            if (HiddenPathPolicy::IsTestHiddenUid(gPfGetattrUid) &&
                IsParentOfExactHiddenTargetPath(pathView)) {
                // Some device builds enumerate the parent directory after only touching it through
                // pf_getattr/lstat, without a visible parent lookup that would reach reply_entry.
                // Seed the fallback parent path here so reply_buf can still filter nested children.
                RememberRecentHiddenParentPath(gPfGetattrUid, pathView);
                DebugLogPrint(4, "remember recent hidden parent from getattr uid=%u path=%s",
                              static_cast<unsigned>(gPfGetattrUid), DebugPreview(pathView).c_str());
            }
            if (HiddenPathPolicy::IsAnyHiddenSubtreePath(pathView)) {
                TrackHiddenSubtreeInode(gPfGetattrIno);
            }
        }
        return ret;
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedStat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (gInPfReaddirPostfilter && HiddenPathPolicy::IsTestHiddenUid(gPfReaddirUid) &&
        HiddenPathPolicy::IsAnyHiddenSubtreePath(pathView)) {
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

extern "C" ssize_t WrappedGetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsPath(pathView)) {
        DebugLogPrint(4, "hide getxattr path=%s name=%s", DebugPreview(pathView).c_str(),
                      name != nullptr ? DebugPreview(name).c_str() : "null");
        errno = ENOENT;
        return -1;
    }
    auto fn =
        reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalGetxattr);
    if (fn) {
        return fn(path, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" ssize_t WrappedLgetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsPath(pathView)) {
        DebugLogPrint(4, "hide lgetxattr path=%s name=%s", DebugPreview(pathView).c_str(),
                      name != nullptr ? DebugPreview(name).c_str() : "null");
        errno = ENOENT;
        return -1;
    }
    auto fn =
        reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalLgetxattr);
    if (fn) {
        return fn(path, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

// Even if the named FUSE wrappers are missed on a device-specific path, lower-fs mkdir/mknod/open
// calls still carry the final child path. These libc hooks are the last fallback for create/mkdir.
extern "C" int WrappedMkdirLibc(const char* path, mode_t mode) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    const uint32_t uid = gActiveCreateUid;
    const bool hidden = ShouldHideLowerFsCreatePath(pathView);
    DebugLogPrint(4, "create-trace lower_mkdir uid=%u path=%s mode=%o hidden=%d",
                  static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), mode, hidden ? 1 : 0);
    if (hidden) {
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
    const uint32_t uid = gActiveCreateUid;
    const bool hidden = ShouldHideLowerFsCreatePath(pathView);
    DebugLogPrint(4, "create-trace lower_mknod uid=%u path=%s mode=%o dev=%llu hidden=%d",
                  static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), mode,
                  static_cast<unsigned long long>(dev), hidden ? 1 : 0);
    if (hidden) {
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
    const uint32_t uid = gActiveCreateUid;
    const bool hidden = (flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView);
    if ((flags & O_CREAT) != 0) {
        DebugLogPrint(4, "create-trace lower_open uid=%u path=%s flags=0x%x mode=%o hidden=%d",
                      static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), flags, mode,
                      hidden ? 1 : 0);
    }
    if (hidden) {
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
    const uint32_t uid = gActiveCreateUid;
    const bool hidden = (flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView);
    if ((flags & O_CREAT) != 0) {
        DebugLogPrint(4, "create-trace lower_open2 uid=%u path=%s flags=0x%x hidden=%d",
                      static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), flags,
                      hidden ? 1 : 0);
    }
    if (hidden) {
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

bool HiddenPathPolicy::IsTestHiddenUid(uint32_t uid) {
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

bool HiddenPathPolicy::ShouldHideTestPath(uint32_t uid, std::string_view path) {
    if (!IsTestHiddenUid(uid)) {
        return false;
    }
    if (IsHiddenRootDirectoryPath(path)) {
        return false;
    }
    return IsAnyHiddenSubtreePath(path);
}

// Mirror the original app-accessible gate: sanitize only when needed, then delegate.
bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid) {
    if (gOriginalIsAppAccessiblePath == nullptr) {
        return false;
    }
    gLastPathPolicyUid = uid;
    gLastPathPolicyPath = path;
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("app_accessible", path);
        if (ShouldLogLimited(gAppAccessibleLogCount)) {
            DebugLogPrint(3, "app_accessible direct uid=%u path=%s", uid,
                          DebugPreview(path).c_str());
        }
        NoteHiddenSubtreePathForCache(path);
        if (HiddenPathPolicy::ShouldHideTestPath(uid, path)) {
            DebugLogPrint(4, "hide test path uid=%u path=%s", static_cast<unsigned>(uid),
                          DebugPreview(path).c_str());
            return false;
        }
        return gOriginalIsAppAccessiblePath(fuse, path, uid);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
    gLastPathPolicyPath = sanitized;
    if (ShouldLogLimited(gAppAccessibleLogCount)) {
        DebugLogPrint(3, "app_accessible rewrite uid=%u old=%s new=%s", uid,
                      DebugPreview(path).c_str(), DebugPreview(sanitized).c_str());
    }
    NoteHiddenSubtreePathForCache(sanitized);
    if (HiddenPathPolicy::ShouldHideTestPath(uid, sanitized)) {
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
    if (!UnicodePolicy::NeedsSanitization(lhs)) {
        UnicodePolicy::LogSuspiciousDirectPath("package_owned", lhs);
        if (ShouldLogLimited(gPackageOwnedLogCount)) {
            DebugLogPrint(3, "package_owned direct lhs=%s rhs=%s", DebugPreview(lhs).c_str(),
                          DebugPreview(rhs).c_str());
        }
        return gOriginalIsPackageOwnedPath(lhs, rhs);
    }
    std::string sanitizedLhs(lhs);
    UnicodePolicy::RewriteString(sanitizedLhs);
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
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("bpf_backing", path);
        if (ShouldLogLimited(gBpfBackingLogCount)) {
            DebugLogPrint(3, "bpf_backing direct path=%s", DebugPreview(path).c_str());
        }
        return gOriginalIsBpfBackingPath(path);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
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
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
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
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
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

bool IsTestHiddenUid(uint32_t uid) {
    return HiddenPathPolicy::IsTestHiddenUid(uid);
}

bool ShouldHideTestPath(uint32_t uid, std::string_view path) {
    return HiddenPathPolicy::ShouldHideTestPath(uid, path);
}

}  // namespace fusehide
