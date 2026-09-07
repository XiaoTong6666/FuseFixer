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

#include "fusehide/policy/path_policy.hpp"

namespace fusehide {

struct FilteredDirentMatch {
    std::string name;
    uint64_t ino = 0;
};

class DirentFilter final {
   public:
    static bool BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid,
                                           uint64_t ino, std::vector<char>* out,
                                           size_t* removedCount, bool requireParentMatch = true);
    static bool BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid,
                                               uint64_t ino, std::vector<char>* out,
                                               size_t* removedCount,
                                               bool requireParentMatch = true);
};

bool AlignDirentName(size_t nameLen, size_t* alignedSize);
bool FuseDirentRecordSize(const fuse_dirent* dirent, size_t available, size_t* recordSize);
bool FuseDirentplusRecordSize(const fuse_dirent* dirent, size_t available, size_t* recordSize);

bool ShouldFilterTrackedHiddenDirentInode(uint32_t uid, uint64_t childIno, std::string_view name);
bool ShouldFilterDirentForParentPath(uint32_t uid, std::string_view parentPath, uint64_t childIno,
                                     std::string_view name);
bool BuildFilteredDirentPayloadForParentPath(
    const char* data, size_t size, uint32_t uid, std::string_view parentPath,
    std::vector<char>* out, size_t* removedCount,
    std::vector<FilteredDirentMatch>* removedEntries = nullptr);
bool BuildFilteredDirentplusPayloadForParentPath(
    const char* data, size_t size, uint32_t uid, std::string_view parentPath,
    std::vector<char>* out, size_t* removedCount,
    std::vector<FilteredDirentMatch>* removedEntries = nullptr);

}  // namespace fusehide
