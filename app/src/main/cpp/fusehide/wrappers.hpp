#pragma once

#include "state.hpp"

namespace fusehide {

extern "C" bool WrappedShouldNotCache(void* fuse, const std::string& path);
void WrappedAddDirectoryEntriesFromLowerFs(DIR* dirp, LowerFsDirentFilterFn filter,
                                           DirectoryEntries* entries);
extern "C" void WrappedPfLookup(fuse_req_t req, uint64_t parent, const char* name);
extern "C" void WrappedPfReaddirPostfilter(fuse_req_t req, uint64_t ino, uint32_t error_in,
                                           off_t off_in, off_t off_out, size_t size_out,
                                           const void* dirents_in, void* fi);
extern "C" void WrappedPfLookupPostfilter(fuse_req_t req, uint64_t parent, uint32_t error_in,
                                          const char* name, struct fuse_entry_out* feo,
                                          struct fuse_entry_bpf_out* febo);
extern "C" void WrappedPfAccess(fuse_req_t req, uint64_t ino, int mask);
extern "C" void WrappedPfOpen(fuse_req_t req, uint64_t ino, void* fi);
extern "C" void WrappedPfOpendir(fuse_req_t req, uint64_t ino, void* fi);
extern "C" void WrappedPfMkdir(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode);
extern "C" void WrappedPfMknod(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                               uint64_t rdev);
extern "C" void WrappedPfUnlink(fuse_req_t req, uint64_t parent, const char* name);
extern "C" void WrappedPfRmdir(fuse_req_t req, uint64_t parent, const char* name);
extern "C" void WrappedPfRename(fuse_req_t req, uint64_t parent, const char* name,
                                uint64_t new_parent, const char* new_name, uint32_t flags);
extern "C" void WrappedPfCreate(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                                void* fi);
extern "C" void WrappedPfReaddir(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi);
extern "C" void WrappedPfReaddirplus(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                     void* fi);
extern "C" void WrappedDoReaddirCommon(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                       void* fi, bool plus);
extern "C" int WrappedNotifyInvalEntry(void* se, uint64_t parent, const char* name, size_t namelen);
extern "C" int WrappedNotifyInvalInode(void* se, uint64_t ino, off_t off, off_t len);
extern "C" int WrappedReplyEntry(fuse_req_t req, const struct fuse_entry_param* e);
extern "C" int WrappedReplyAttr(fuse_req_t req, const struct stat* attr, double timeout);
extern "C" int WrappedReplyBuf(fuse_req_t req, const char* buf, size_t size);
extern "C" int WrappedReplyErr(fuse_req_t req, int err);
extern "C" void WrappedPfGetattr(fuse_req_t req, uint64_t ino, void* fi);
extern "C" int WrappedLstat(const char* path, struct stat* st);
extern "C" int WrappedStat(const char* path, struct stat* st);
extern "C" ssize_t WrappedGetxattr(const char* path, const char* name, void* value, size_t size);
extern "C" ssize_t WrappedLgetxattr(const char* path, const char* name, void* value, size_t size);
extern "C" int WrappedMkdirLibc(const char* path, mode_t mode);
extern "C" int WrappedMknod(const char* path, mode_t mode, dev_t dev);
extern "C" int WrappedOpen(const char* path, int flags, ...);
extern "C" int WrappedOpen2(const char* path, int flags);
bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid);
bool WrappedIsPackageOwnedPath(const std::string& lhs, const std::string& rhs);
bool WrappedIsBpfBackingPath(const std::string& path);
extern "C" int WrappedStrcasecmp(const char* lhs, const char* rhs);
extern "C" bool WrappedEqualsIgnoreCaseAbi(const char* lhsData, size_t lhsSize, const char* rhsData,
                                           size_t rhsSize);

void InstallFuseHooks();

}  // namespace fusehide
