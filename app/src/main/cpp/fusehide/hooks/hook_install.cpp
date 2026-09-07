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

#include "fusehide/elf/elf_utils.hpp"
#include "fusehide/hooks/wrappers.hpp"

namespace fusehide {

static_assert(std::is_same_v<decltype(&WrappedShouldNotCache), ShouldNotCacheFn>);
static_assert(std::is_same_v<decltype(&WrappedGetDirectoryEntriesShared), GetDirectoryEntriesFn>);
static_assert(
    std::is_same_v<decltype(&WrappedGetDirectoryEntriesValue), GetValueDirectoryEntriesFn>);
static_assert(std::is_same_v<decltype(&WrappedAddDirectoryEntriesFromLowerFsShared),
                             AddDirectoryEntriesFromLowerFsFn>);
static_assert(std::is_same_v<decltype(&WrappedAddDirectoryEntriesFromLowerFsValue),
                             AddValueDirectoryEntriesFromLowerFsFn>);
static_assert(std::is_same_v<decltype(&WrappedPfLookup), PfLookupFn>);
static_assert(std::is_same_v<decltype(&WrappedPfLookupPostfilter), PfLookupPostfilterFn>);
static_assert(std::is_same_v<decltype(&WrappedPfAccess), PfAccessFn>);
static_assert(std::is_same_v<decltype(&WrappedPfOpen), PfFileInfoFn>);
static_assert(std::is_same_v<decltype(&WrappedPfOpendir), PfFileInfoFn>);
static_assert(std::is_same_v<decltype(&WrappedPfMkdir), PfMkdirFn>);
static_assert(std::is_same_v<decltype(&WrappedPfMknod), PfMknodFn>);
static_assert(std::is_same_v<decltype(&WrappedPfUnlink), PfRemoveFn>);
static_assert(std::is_same_v<decltype(&WrappedPfRmdir), PfRemoveFn>);
static_assert(std::is_same_v<decltype(&WrappedPfRename), PfRenameFn>);
static_assert(std::is_same_v<decltype(&WrappedPfCreate), PfCreateFn>);
static_assert(std::is_same_v<decltype(&WrappedPfReaddir), PfReaddirFn>);
static_assert(std::is_same_v<decltype(&WrappedPfReaddirplus), PfReaddirFn>);
static_assert(std::is_same_v<decltype(&WrappedPfReaddirPostfilter), PfReaddirPostfilterFn>);
static_assert(std::is_same_v<decltype(&WrappedDoReaddirCommon), DoReaddirCommonFn>);
static_assert(std::is_same_v<decltype(&WrappedNotifyInvalEntry), NotifyInvalEntryFn>);
static_assert(std::is_same_v<decltype(&WrappedNotifyInvalInode), NotifyInvalInodeFn>);
static_assert(std::is_same_v<decltype(&WrappedReplyEntry), FuseReplyEntryFn>);
static_assert(std::is_same_v<decltype(&WrappedReplyAttr), FuseReplyAttrFn>);
static_assert(std::is_same_v<decltype(&WrappedReplyBuf), FuseReplyBufFn>);
static_assert(std::is_same_v<decltype(&WrappedReplyErr), FuseReplyErrFn>);
static_assert(std::is_same_v<decltype(&WrappedPfGetattr), PfFileInfoFn>);
static_assert(std::is_same_v<decltype(&WrappedLstat), LibcStatFn>);
static_assert(std::is_same_v<decltype(&WrappedStat), LibcStatFn>);
static_assert(std::is_same_v<decltype(&WrappedGetxattr), LibcXattrFn>);
static_assert(std::is_same_v<decltype(&WrappedLgetxattr), LibcXattrFn>);
static_assert(std::is_same_v<decltype(&WrappedMkdirLibc), LibcMkdirFn>);
static_assert(std::is_same_v<decltype(&WrappedMknod), LibcMknodFn>);
static_assert(std::is_same_v<decltype(&WrappedOpen), LibcOpenFn>);
static_assert(std::is_same_v<decltype(&WrappedOpen2), LibcOpen2Fn>);
static_assert(std::is_same_v<decltype(&WrappedIsAppAccessiblePath), IsAppAccessiblePathFn>);
static_assert(std::is_same_v<decltype(&WrappedIsPackageOwnedPath), IsPackageOwnedPathFn>);
static_assert(std::is_same_v<decltype(&WrappedIsBpfBackingPath), IsBpfBackingPathFn>);
static_assert(std::is_same_v<decltype(&WrappedStrcasecmp), StrcasecmpFn>);
static_assert(std::is_same_v<decltype(&WrappedEqualsIgnoreCaseAbi), EqualsIgnoreCaseAbiFn>);

struct HookInstallProcessState {
    void*& originalIsAppAccessiblePath = gOriginalIsAppAccessiblePath.rawStorage();
    void*& originalIsPackageOwnedPath = gOriginalIsPackageOwnedPath.rawStorage();
    void*& originalIsBpfBackingPath = gOriginalIsBpfBackingPath.rawStorage();
    void*& originalStrcasecmp = gOriginalStrcasecmp.rawStorage();
    void*& originalEqualsIgnoreCase = gOriginalEqualsIgnoreCase.rawStorage();
    void*& originalPfLookup = gOriginalPfLookup.rawStorage();
    void*& originalPfLookupPostfilter = gOriginalPfLookupPostfilter.rawStorage();
    void*& originalPfAccess = gOriginalPfAccess.rawStorage();
    void*& originalPfOpen = gOriginalPfOpen.rawStorage();
    void*& originalPfOpendir = gOriginalPfOpendir.rawStorage();
    void*& originalPfMknod = gOriginalPfMknod.rawStorage();
    void*& originalPfMkdir = gOriginalPfMkdir.rawStorage();
    void*& originalPfUnlink = gOriginalPfUnlink.rawStorage();
    void*& originalPfRmdir = gOriginalPfRmdir.rawStorage();
    void*& originalPfRename = gOriginalPfRename.rawStorage();
    void*& originalPfCreate = gOriginalPfCreate.rawStorage();
    void*& originalPfReaddir = gOriginalPfReaddir.rawStorage();
    void*& originalPfReaddirPostfilter = gOriginalPfReaddirPostfilter.rawStorage();
    void*& originalPfReaddirplus = gOriginalPfReaddirplus.rawStorage();
    void*& originalDoReaddirCommon = gOriginalDoReaddirCommon.rawStorage();
    void*& originalPfGetattr = gOriginalPfGetattr.rawStorage();
    void*& originalOpen = gOriginalOpen.rawStorage();
    void*& originalOpen2 = gOriginalOpen2.rawStorage();
    void*& fuseReqCtx = gFuseReqCtx.rawStorage();
    void*& originalMkdir = gOriginalMkdir.rawStorage();
    void*& originalMknod = gOriginalMknod.rawStorage();
    void*& originalLstat = gOriginalLstat.rawStorage();
    void*& originalStat = gOriginalStat.rawStorage();
    void*& originalGetxattr = gOriginalGetxattr.rawStorage();
    void*& originalLgetxattr = gOriginalLgetxattr.rawStorage();
    void*& originalShouldNotCache = gOriginalShouldNotCache.rawStorage();
    void*& originalNotifyInvalEntry = gOriginalNotifyInvalEntry.rawStorage();
    void*& originalNotifyInvalInode = gOriginalNotifyInvalInode.rawStorage();
    void*& originalReplyAttr = gOriginalReplyAttr.rawStorage();
    void*& originalReplyEntry = gOriginalReplyEntry.rawStorage();
    void*& originalReplyBuf = gOriginalReplyBuf.rawStorage();
    void*& originalReplyErr = gOriginalReplyErr.rawStorage();
    void*& originalGetDirectoryEntries = gOriginalGetDirectoryEntries.rawStorage();
    void*& originalAddDirectoryEntriesFromLowerFs =
        gOriginalAddDirectoryEntriesFromLowerFs.rawStorage();
};

static inline HookInstallProcessState& Process() {
    static HookInstallProcessState process;
    return process;
}

const char* DirectoryEntriesAbiName(DirectoryEntriesAbi abi) {
    switch (abi) {
        case DirectoryEntriesAbi::kSharedPtr:
            return "shared_ptr";
        case DirectoryEntriesAbi::kValue:
            return "value";
        case DirectoryEntriesAbi::kUnknown:
            return "unknown";
    }
    return "unknown";
}

void* GetDirectoryEntriesReplacement() {
    switch (gDirectoryEntriesAbi.load(std::memory_order_acquire)) {
        case DirectoryEntriesAbi::kSharedPtr:
            return reinterpret_cast<void*>(+WrappedGetDirectoryEntriesShared);
        case DirectoryEntriesAbi::kValue:
            return reinterpret_cast<void*>(+WrappedGetDirectoryEntriesValue);
        case DirectoryEntriesAbi::kUnknown:
            return nullptr;
    }
    return nullptr;
}

void* AddDirectoryEntriesFromLowerFsReplacement() {
    switch (gDirectoryEntriesAbi.load(std::memory_order_acquire)) {
        case DirectoryEntriesAbi::kSharedPtr:
            return reinterpret_cast<void*>(+WrappedAddDirectoryEntriesFromLowerFsShared);
        case DirectoryEntriesAbi::kValue:
            return reinterpret_cast<void*>(+WrappedAddDirectoryEntriesFromLowerFsValue);
        case DirectoryEntriesAbi::kUnknown:
            return nullptr;
    }
    return nullptr;
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
// Restores memory permissions to PROT_READ after patching.

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
    std::optional<MappedFile> mapped;
    if (module.path.find("!/") != std::string::npos) {
        mapped = MapEmbeddedStoredElf(module.path);
    } else {
        mapped = MapReadOnlyFile(module.path, module.fileOffset);
    }
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
        mapped = MapReadOnlyFile(module.path, module.fileOffset);
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

bool IsLibfuseAddress(void* address) {
    Dl_info info{};
    if (address == nullptr || dladdr(address, &info) == 0 || info.dli_fname == nullptr) {
        return false;
    }
    const std::string_view path(info.dli_fname);
    return path == "libfuse.so" || path.ends_with("/libfuse.so");
}

std::optional<void*> ResolveImportedFunctionTarget(const ModuleInfo& importingModule,
                                                   std::string_view symbolName) {
    const auto dynamicInfo = ParseRuntimeDynamicInfo(importingModule);
    if (!dynamicInfo.has_value()) {
        return std::nullopt;
    }
    const auto symbolIndex = FindRuntimeSymbolIndex(
        *dynamicInfo, reinterpret_cast<const uint8_t*>(symbolName.data()), symbolName.size());
    if (!symbolIndex.has_value()) {
        return std::nullopt;
    }

    const auto slots =
        FindRuntimeRelocationSlotsForSymbol(*dynamicInfo, *symbolIndex, importingModule.base);
    for (const uintptr_t slotAddress : slots) {
        void* target = *reinterpret_cast<void* const*>(slotAddress);
        if (IsLibfuseAddress(target)) {
            return target;
        }
    }
    return std::nullopt;
}

template <size_t N>
std::optional<uintptr_t> ResolveFirstAvailableSymbolOffset(const ModuleInfo& module,
                                                           const std::string_view (&symbols)[N]) {
    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    for (const auto& symbol : symbols) {
        auto resolved = useRuntimeElf ? ResolveTargetSymbolRuntime(module, symbol)
                                      : ResolveTargetSymbol(module, symbol);
        if (resolved.has_value()) {
            DebugLogPrint(4, "resolved exact symbol=%s offset=0x%zx target=%p path=%s runtime=%d",
                          std::string(symbol).c_str(),
                          static_cast<size_t>(reinterpret_cast<uintptr_t>(*resolved) - module.base),
                          *resolved, module.path.c_str(), useRuntimeElf ? 1 : 0);
            return reinterpret_cast<uintptr_t>(*resolved) - module.base;
        }
    }
    return std::nullopt;
}

DirectoryEntriesAbi DetectDirectoryEntriesAbi(const ModuleInfo& module) {
    // An ordinary Itanium C++ function name does not encode its return type, so the
    // GetDirectoryEntries symbol is identical for shared_ptr- and value-vector returns. Its helper
    // takes the vector by pointer, which does encode the element type; require one exact helper
    // signature and refuse these two STL hooks when neither (or both) can be proven.
    const bool hasShared =
        ResolveFirstAvailableSymbolOffset(module, kAddSharedDirectoryEntriesFromLowerFsSymbols)
            .has_value();
    const bool hasValue =
        ResolveFirstAvailableSymbolOffset(module, kAddValueDirectoryEntriesFromLowerFsSymbols)
            .has_value();
    if (hasShared == hasValue) {
        return DirectoryEntriesAbi::kUnknown;
    }
    if (hasShared) {
        return DirectoryEntriesAbi::kSharedPtr;
    }
#if defined(__aarch64__)
    return DirectoryEntriesAbi::kValue;
#else
    // The value-vector object layout and ownership boundary have only been verified on arm64.
    return DirectoryEntriesAbi::kUnknown;
#endif
}

enum class HookResolutionSource {
    kUnavailable,
    kProfileFallback,
    kResolvedSymbol,
    kResolvedContains,
    kDerivedLayout,
};

struct ResolvedHookFeatureOffsets {
    std::optional<uintptr_t> isAppAccessiblePathOffset;
    std::optional<uintptr_t> pfLookupOffset;
    std::optional<uintptr_t> pfLookupPostfilterOffset;
    std::optional<uintptr_t> pfGetattrOffset;
    std::optional<uintptr_t> shouldNotCacheOffset;
    std::optional<uintptr_t> doReaddirCommonOffset;
    std::optional<uintptr_t> getDirectoryEntriesOffset;
    std::optional<uintptr_t> addDirectoryEntriesFromLowerFsOffset;
    std::optional<uintptr_t> pfMkdirOffset;
    std::optional<uintptr_t> pfMknodOffset;
    std::optional<uintptr_t> pfUnlinkOffset;
    std::optional<uintptr_t> pfRmdirOffset;
    std::optional<uintptr_t> pfRenameOffset;
    std::optional<uintptr_t> pfCreateOffset;
    std::optional<uintptr_t> pfReaddirOffset;
    std::optional<uintptr_t> pfReaddirPostfilterOffset;
    std::optional<uintptr_t> pfReaddirplusOffset;
    HookResolutionSource pfReaddirSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource pfReaddirPostfilterSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource pfReaddirplusSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource shouldNotCacheSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource doReaddirCommonSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource getDirectoryEntriesSource = HookResolutionSource::kProfileFallback;
    HookResolutionSource addDirectoryEntriesFromLowerFsSource =
        HookResolutionSource::kProfileFallback;
};

std::optional<uintptr_t> ResolveLargestSymbolOffsetContaining(const ModuleInfo& module,
                                                              std::string_view needle) {
    std::optional<MappedFile> mapped;
    if (module.path.find("!/") != std::string::npos) {
        mapped = MapEmbeddedStoredElf(module.path);
    } else {
        mapped = MapReadOnlyFile(module.path, module.fileOffset);
    }
    if (!mapped.has_value()) {
        return std::nullopt;
    }
    auto match = FindLargestSymbolContaining(*mapped, needle);
    if (!match.has_value()) {
        return std::nullopt;
    }
    DebugLogPrint(4, "resolved contains needle=%s picked=%s offset=0x%zx target=%p path=%s",
                  std::string(needle).c_str(), match->name.c_str(),
                  static_cast<size_t>(match->value),
                  reinterpret_cast<void*>(module.base + match->value), module.path.c_str());
    return match->value;
}

template <size_t N>
std::optional<uintptr_t> ResolveFeatureOffsetBySymbols(const ModuleInfo& module,
                                                       const std::string_view (&symbols)[N],
                                                       HookResolutionSource* source) {
    auto offset = ResolveFirstAvailableSymbolOffset(module, symbols);
    if (offset.has_value() && source != nullptr) {
        *source = HookResolutionSource::kResolvedSymbol;
    }
    return offset;
}

std::optional<uintptr_t> ResolveFeatureOffsetByContains(const ModuleInfo& module,
                                                        std::string_view needle,
                                                        HookResolutionSource* source) {
    auto offset = ResolveLargestSymbolOffsetContaining(module, needle);
    if (offset.has_value() && source != nullptr) {
        *source = HookResolutionSource::kResolvedContains;
    }
    return offset;
}

const char* HookResolutionSourceName(HookResolutionSource source) {
    switch (source) {
        case HookResolutionSource::kUnavailable:
            return "unavailable";
        case HookResolutionSource::kProfileFallback:
            return "profile";
        case HookResolutionSource::kResolvedSymbol:
            return "resolved_symbol";
        case HookResolutionSource::kResolvedContains:
            return "resolved_contains";
        case HookResolutionSource::kDerivedLayout:
            return "derived_layout";
    }
    return "unknown";
}

#if defined(__aarch64__) || defined(__arm__)
inline constexpr bool kSupportsDeviceProfileOffsets = true;
#else
inline constexpr bool kSupportsDeviceProfileOffsets = false;
#endif

bool IsEmbeddedX86Module(const ModuleInfo& module) {
    return module.path.find("/lib/x86/") != std::string::npos ||
           module.path.find("/lib/x86_64/") != std::string::npos;
}

bool CanUseProfileBasedTarget(HookResolutionSource source) {
    if (source == HookResolutionSource::kUnavailable) {
        return false;
    }
    if constexpr (kSupportsDeviceProfileOffsets) {
        return true;
    }
    return source != HookResolutionSource::kProfileFallback &&
           source != HookResolutionSource::kDerivedLayout;
}

struct DerivedHookFeatureFlags {
    bool shouldNotCache = false;
    bool doReaddirCommon = false;
    bool getDirectoryEntries = false;
    bool addDirectoryEntriesFromLowerFs = false;
    bool addDirectoryEntriesFromLowerFsThunk = false;
    bool pfReaddir = false;
    bool pfReaddirPostfilter = false;
    bool pfReaddirplus = false;
};

struct CriticalHookTargetPlan {
    uintptr_t offset = 0;
    HookResolutionSource source = HookResolutionSource::kProfileFallback;
};

struct DeviceHookInstallPlan {
    DeviceHookProfile profile;
    bool profileTrusted = false;
    CriticalHookTargetPlan shouldNotCache;
    CriticalHookTargetPlan doReaddirCommon;
    CriticalHookTargetPlan getDirectoryEntries;
    CriticalHookTargetPlan addDirectoryEntriesFromLowerFs;
    CriticalHookTargetPlan addDirectoryEntriesFromLowerFsThunk;
    CriticalHookTargetPlan pfReaddir;
    CriticalHookTargetPlan pfReaddirPostfilter;
    CriticalHookTargetPlan pfReaddirplus;
};

bool HasVerifiedClassicStringAbi(const DeviceHookInstallPlan& installPlan) {
    return installPlan.profileTrusted &&
           installPlan.profile.stringLayout == AbiStringLayout::kClassic;
}

bool CanInstallDirectoryEntriesHooks(const DeviceHookInstallPlan& installPlan) {
    if (!HasVerifiedClassicStringAbi(installPlan)) {
        return false;
    }
    const DirectoryEntriesAbi abi = gDirectoryEntriesAbi.load(std::memory_order_acquire);
    if (abi == DirectoryEntriesAbi::kSharedPtr) {
        return true;
    }
    return abi == DirectoryEntriesAbi::kValue && installPlan.profileTrusted &&
           std::strcmp(installPlan.profile.name, kDeviceHookProfileApi37ValueEntries.name) == 0 &&
           installPlan.getDirectoryEntries.source == HookResolutionSource::kResolvedSymbol &&
           installPlan.getDirectoryEntries.offset ==
               kDeviceHookProfileApi37ValueEntries.getDirectoryEntriesOffset &&
           installPlan.addDirectoryEntriesFromLowerFs.source ==
               HookResolutionSource::kResolvedSymbol &&
           installPlan.addDirectoryEntriesFromLowerFs.offset ==
               kDeviceHookProfileApi37ValueEntries.addDirectoryEntriesFromLowerFsOffset;
}

bool TryInstallInlineHookAt(void* target, void* replacement, void** backup,
                            const char* failureMessage);

struct DerivedOffsetResult {
    uintptr_t offset = 0;
    int votes = 0;
    int inputs = 0;
};

using ProfileOffsetField = uintptr_t DeviceHookProfile::*;
using FeatureOffsetField = std::optional<uintptr_t> ResolvedHookFeatureOffsets::*;

struct LayoutAnchorDescriptor {
    const char* name;
    ProfileOffsetField profileField;
    FeatureOffsetField featureField;
};

inline constexpr LayoutAnchorDescriptor kLayoutAnchorDescriptors[] = {
    {"is_app_accessible_path", &DeviceHookProfile::isAppAccessiblePathOffset,
     &ResolvedHookFeatureOffsets::isAppAccessiblePathOffset},
    {"pf_lookup", &DeviceHookProfile::pfLookupOffset, &ResolvedHookFeatureOffsets::pfLookupOffset},
    {"pf_lookup_postfilter", &DeviceHookProfile::pfLookupPostfilterOffset,
     &ResolvedHookFeatureOffsets::pfLookupPostfilterOffset},
    {"pf_getattr", &DeviceHookProfile::pfGetattrOffset,
     &ResolvedHookFeatureOffsets::pfGetattrOffset},
    {"ShouldNotCache", &DeviceHookProfile::shouldNotCacheOffset,
     &ResolvedHookFeatureOffsets::shouldNotCacheOffset},
    {"do_readdir_common", &DeviceHookProfile::doReaddirCommonOffset,
     &ResolvedHookFeatureOffsets::doReaddirCommonOffset},
    {"GetDirectoryEntries", &DeviceHookProfile::getDirectoryEntriesOffset,
     &ResolvedHookFeatureOffsets::getDirectoryEntriesOffset},
    {"addDirectoryEntriesFromLowerFs", &DeviceHookProfile::addDirectoryEntriesFromLowerFsOffset,
     &ResolvedHookFeatureOffsets::addDirectoryEntriesFromLowerFsOffset},
    {"pf_mkdir", &DeviceHookProfile::pfMkdirOffset, &ResolvedHookFeatureOffsets::pfMkdirOffset},
    {"pf_mknod", &DeviceHookProfile::pfMknodOffset, &ResolvedHookFeatureOffsets::pfMknodOffset},
    {"pf_unlink", &DeviceHookProfile::pfUnlinkOffset, &ResolvedHookFeatureOffsets::pfUnlinkOffset},
    {"pf_rmdir", &DeviceHookProfile::pfRmdirOffset, &ResolvedHookFeatureOffsets::pfRmdirOffset},
    {"pf_rename", &DeviceHookProfile::pfRenameOffset, &ResolvedHookFeatureOffsets::pfRenameOffset},
    {"pf_create", &DeviceHookProfile::pfCreateOffset, &ResolvedHookFeatureOffsets::pfCreateOffset},
    {"pf_readdir", &DeviceHookProfile::pfReaddirOffset,
     &ResolvedHookFeatureOffsets::pfReaddirOffset},
    {"pf_readdir_postfilter", &DeviceHookProfile::pfReaddirPostfilterOffset,
     &ResolvedHookFeatureOffsets::pfReaddirPostfilterOffset},
    {"pf_readdirplus", &DeviceHookProfile::pfReaddirplusOffset,
     &ResolvedHookFeatureOffsets::pfReaddirplusOffset},
};

ResolvedHookFeatureOffsets ResolveHookFeatureOffsets(const ModuleInfo& module) {
    ResolvedHookFeatureOffsets features;
    features.isAppAccessiblePathOffset =
        ResolveFirstAvailableSymbolOffset(module, kIsAppAccessiblePathSymbols);
    features.pfLookupOffset = ResolveFirstAvailableSymbolOffset(module, kPfLookupSymbols);
    features.pfLookupPostfilterOffset =
        ResolveFirstAvailableSymbolOffset(module, kPfLookupPostfilterSymbols);
    features.pfGetattrOffset = ResolveFirstAvailableSymbolOffset(module, kPfGetattrSymbols);
    features.shouldNotCacheOffset = ResolveFeatureOffsetBySymbols(module, kShouldNotCacheSymbols,
                                                                  &features.shouldNotCacheSource);
    features.doReaddirCommonOffset = ResolveFeatureOffsetBySymbols(module, kDoReaddirCommonSymbols,
                                                                   &features.doReaddirCommonSource);
    const DirectoryEntriesAbi directoryEntriesAbi =
        gDirectoryEntriesAbi.load(std::memory_order_acquire);
    if (directoryEntriesAbi != DirectoryEntriesAbi::kUnknown) {
        features.getDirectoryEntriesOffset = ResolveFeatureOffsetBySymbols(
            module, kGetDirectoryEntriesSymbols, &features.getDirectoryEntriesSource);
        if (directoryEntriesAbi == DirectoryEntriesAbi::kSharedPtr) {
            features.addDirectoryEntriesFromLowerFsOffset =
                ResolveFeatureOffsetBySymbols(module, kAddSharedDirectoryEntriesFromLowerFsSymbols,
                                              &features.addDirectoryEntriesFromLowerFsSource);
        } else {
            features.addDirectoryEntriesFromLowerFsOffset =
                ResolveFeatureOffsetBySymbols(module, kAddValueDirectoryEntriesFromLowerFsSymbols,
                                              &features.addDirectoryEntriesFromLowerFsSource);
        }
    }
    features.pfMkdirOffset = ResolveFirstAvailableSymbolOffset(module, kPfMkdirSymbols);
    features.pfMknodOffset = ResolveFirstAvailableSymbolOffset(module, kPfMknodSymbols);
    features.pfUnlinkOffset = ResolveFirstAvailableSymbolOffset(module, kPfUnlinkSymbols);
    features.pfRmdirOffset = ResolveFirstAvailableSymbolOffset(module, kPfRmdirSymbols);
    features.pfRenameOffset = ResolveFirstAvailableSymbolOffset(module, kPfRenameSymbols);
    features.pfCreateOffset = ResolveFirstAvailableSymbolOffset(module, kPfCreateSymbols);
    features.pfReaddirOffset =
        ResolveFeatureOffsetBySymbols(module, kPfReaddirSymbols, &features.pfReaddirSource);
    features.pfReaddirPostfilterOffset = ResolveFeatureOffsetBySymbols(
        module, kPfReaddirPostfilterSymbols, &features.pfReaddirPostfilterSource);
    features.pfReaddirplusOffset =
        ResolveFeatureOffsetBySymbols(module, kPfReaddirplusSymbols, &features.pfReaddirplusSource);
    if (!features.isAppAccessiblePathOffset.has_value()) {
        features.isAppAccessiblePathOffset =
            ResolveFeatureOffsetByContains(module, "is_app_accessible_path", nullptr);
    }
    if (!features.pfLookupOffset.has_value()) {
        features.pfLookupOffset =
            ResolveFeatureOffsetByContains(module, "pf_lookupEP8fuse_req", nullptr);
    }
    if (!features.pfLookupPostfilterOffset.has_value()) {
        features.pfLookupPostfilterOffset =
            ResolveFeatureOffsetByContains(module, "pf_lookup_postfilter", nullptr);
    }
    if (!features.pfGetattrOffset.has_value()) {
        features.pfGetattrOffset =
            ResolveFeatureOffsetByContains(module, "pf_getattrEP8fuse_req", nullptr);
    }
    if (!features.pfMkdirOffset.has_value()) {
        features.pfMkdirOffset =
            ResolveFeatureOffsetByContains(module, "pf_mkdirEP8fuse_req", nullptr);
    }
    if (!features.pfMknodOffset.has_value()) {
        features.pfMknodOffset =
            ResolveFeatureOffsetByContains(module, "pf_mknodEP8fuse_req", nullptr);
    }
    if (!features.pfUnlinkOffset.has_value()) {
        features.pfUnlinkOffset =
            ResolveFeatureOffsetByContains(module, "pf_unlinkEP8fuse_req", nullptr);
    }
    if (!features.pfRmdirOffset.has_value()) {
        features.pfRmdirOffset =
            ResolveFeatureOffsetByContains(module, "pf_rmdirEP8fuse_req", nullptr);
    }
    if (!features.pfRenameOffset.has_value()) {
        features.pfRenameOffset =
            ResolveFeatureOffsetByContains(module, "pf_renameEP8fuse_req", nullptr);
    }
    if (!features.pfCreateOffset.has_value()) {
        features.pfCreateOffset =
            ResolveFeatureOffsetByContains(module, "pf_createEP8fuse_req", nullptr);
    }
    if (!features.shouldNotCacheOffset.has_value()) {
        features.shouldNotCacheOffset = ResolveFeatureOffsetByContains(
            module, "ShouldNotCache", &features.shouldNotCacheSource);
    }
    if (!features.doReaddirCommonOffset.has_value()) {
        features.doReaddirCommonOffset = ResolveFeatureOffsetByContains(
            module, "do_readdir_common", &features.doReaddirCommonSource);
    }
    if (!features.pfReaddirOffset.has_value()) {
        features.pfReaddirOffset = ResolveFeatureOffsetByContains(module, "pf_readdirEP8fuse_req",
                                                                  &features.pfReaddirSource);
    }
    if (!features.pfReaddirPostfilterOffset.has_value()) {
        features.pfReaddirPostfilterOffset = ResolveFeatureOffsetByContains(
            module, "pf_readdir_postfilterEP8fuse_req", &features.pfReaddirPostfilterSource);
    }
    if (!features.pfReaddirplusOffset.has_value()) {
        features.pfReaddirplusOffset = ResolveFeatureOffsetByContains(
            module, "pf_readdirplusEP8fuse_req", &features.pfReaddirplusSource);
    }
    return features;
}

int CountResolvedHookFeatures(const ResolvedHookFeatureOffsets& features) {
    int count = 0;
    auto add = [&](const std::optional<uintptr_t>& value) {
        if (value.has_value()) {
            ++count;
        }
    };
    add(features.isAppAccessiblePathOffset);
    add(features.pfLookupOffset);
    add(features.pfLookupPostfilterOffset);
    add(features.pfGetattrOffset);
    add(features.shouldNotCacheOffset);
    add(features.doReaddirCommonOffset);
    add(features.getDirectoryEntriesOffset);
    add(features.addDirectoryEntriesFromLowerFsOffset);
    add(features.pfMkdirOffset);
    add(features.pfMknodOffset);
    add(features.pfUnlinkOffset);
    add(features.pfRmdirOffset);
    add(features.pfRenameOffset);
    add(features.pfCreateOffset);
    add(features.pfReaddirOffset);
    add(features.pfReaddirPostfilterOffset);
    add(features.pfReaddirplusOffset);
    return count;
}

int ScoreHookProfile(const DeviceHookProfile& profile, const ResolvedHookFeatureOffsets& features) {
    int score = 0;
    auto match = [&](const std::optional<uintptr_t>& value, uintptr_t expected) {
        if (value.has_value() && *value == expected) {
            ++score;
        }
    };
    match(features.isAppAccessiblePathOffset, profile.isAppAccessiblePathOffset);
    match(features.pfLookupOffset, profile.pfLookupOffset);
    match(features.pfLookupPostfilterOffset, profile.pfLookupPostfilterOffset);
    match(features.pfGetattrOffset, profile.pfGetattrOffset);
    match(features.shouldNotCacheOffset, profile.shouldNotCacheOffset);
    match(features.doReaddirCommonOffset, profile.doReaddirCommonOffset);
    match(features.getDirectoryEntriesOffset, profile.getDirectoryEntriesOffset);
    match(features.addDirectoryEntriesFromLowerFsOffset,
          profile.addDirectoryEntriesFromLowerFsOffset);
    match(features.pfMkdirOffset, profile.pfMkdirOffset);
    match(features.pfMknodOffset, profile.pfMknodOffset);
    match(features.pfUnlinkOffset, profile.pfUnlinkOffset);
    match(features.pfRmdirOffset, profile.pfRmdirOffset);
    match(features.pfRenameOffset, profile.pfRenameOffset);
    match(features.pfCreateOffset, profile.pfCreateOffset);
    match(features.pfReaddirOffset, profile.pfReaddirOffset);
    match(features.pfReaddirPostfilterOffset, profile.pfReaddirPostfilterOffset);
    match(features.pfReaddirplusOffset, profile.pfReaddirplusOffset);
    return score;
}

void ApplyResolvedHookFeatureOverrides(const ResolvedHookFeatureOffsets& features,
                                       DeviceHookProfile* profile, int* overrideCount) {
    auto apply = [&](const std::optional<uintptr_t>& value, uintptr_t DeviceHookProfile::* field) {
        if (!value.has_value()) {
            return;
        }
        profile->*field = *value;
        ++(*overrideCount);
    };
    apply(features.isAppAccessiblePathOffset, &DeviceHookProfile::isAppAccessiblePathOffset);
    apply(features.pfLookupOffset, &DeviceHookProfile::pfLookupOffset);
    apply(features.pfLookupPostfilterOffset, &DeviceHookProfile::pfLookupPostfilterOffset);
    apply(features.pfGetattrOffset, &DeviceHookProfile::pfGetattrOffset);
    apply(features.shouldNotCacheOffset, &DeviceHookProfile::shouldNotCacheOffset);
    apply(features.doReaddirCommonOffset, &DeviceHookProfile::doReaddirCommonOffset);
    apply(features.getDirectoryEntriesOffset, &DeviceHookProfile::getDirectoryEntriesOffset);
    apply(features.addDirectoryEntriesFromLowerFsOffset,
          &DeviceHookProfile::addDirectoryEntriesFromLowerFsOffset);
    apply(features.pfMkdirOffset, &DeviceHookProfile::pfMkdirOffset);
    apply(features.pfMknodOffset, &DeviceHookProfile::pfMknodOffset);
    apply(features.pfUnlinkOffset, &DeviceHookProfile::pfUnlinkOffset);
    apply(features.pfRmdirOffset, &DeviceHookProfile::pfRmdirOffset);
    apply(features.pfRenameOffset, &DeviceHookProfile::pfRenameOffset);
    apply(features.pfCreateOffset, &DeviceHookProfile::pfCreateOffset);
    apply(features.pfReaddirOffset, &DeviceHookProfile::pfReaddirOffset);
    apply(features.pfReaddirPostfilterOffset, &DeviceHookProfile::pfReaddirPostfilterOffset);
    apply(features.pfReaddirplusOffset, &DeviceHookProfile::pfReaddirplusOffset);
}

void ClearUnresolvedHookProfileOffsets(const ResolvedHookFeatureOffsets& features,
                                       DeviceHookProfile* profile) {
    for (const auto& anchor : kLayoutAnchorDescriptors) {
        if (!(features.*(anchor.featureField)).has_value()) {
            profile->*(anchor.profileField) = 0;
        }
    }
    profile->addDirectoryEntriesFromLowerFsThunkOffset = 0;
}

std::optional<DerivedOffsetResult> DeriveOffsetFromProfileLayout(
    const DeviceHookProfile& profile, const ResolvedHookFeatureOffsets& features,
    ProfileOffsetField targetField) {
    std::unordered_map<uintptr_t, int> votes;
    int inputs = 0;
    for (const auto& anchor : kLayoutAnchorDescriptors) {
        const auto& featureValue = features.*(anchor.featureField);
        if (!featureValue.has_value()) {
            continue;
        }
        const int64_t delta = static_cast<int64_t>(profile.*targetField) -
                              static_cast<int64_t>(profile.*(anchor.profileField));
        const int64_t candidate = static_cast<int64_t>(*featureValue) + delta;
        if (candidate < 0) {
            return std::nullopt;
        }
        ++votes[static_cast<uintptr_t>(candidate)];
        ++inputs;
    }
    if (votes.empty()) {
        return std::nullopt;
    }

    uintptr_t bestOffset = 0;
    int bestVotes = -1;
    int ties = 0;
    for (const auto& [offset, count] : votes) {
        if (count > bestVotes) {
            bestOffset = offset;
            bestVotes = count;
            ties = 1;
        } else if (count == bestVotes) {
            ++ties;
        }
    }
    // Layout derivation is safe only when at least two independent anchors agree on one delta.
    if (ties > 1 || bestVotes < 2 || bestVotes != inputs) {
        return std::nullopt;
    }
    return DerivedOffsetResult{bestOffset, bestVotes, inputs};
}

void ApplyDerivedHookFeatureOverrides(const DeviceHookProfile& bestProfile,
                                      const ResolvedHookFeatureOffsets& features,
                                      DeviceHookProfile* effectiveProfile, int* derivedCount,
                                      DerivedHookFeatureFlags* derivedFlags) {
    bool shouldNotCacheDerived = false;
    bool doReaddirCommonDerived = false;
    bool getDirectoryEntriesDerived = false;
    bool addDirectoryEntriesBodyDerived = false;
    bool pfReaddirDerived = false;
    bool pfReaddirPostfilterDerived = false;
    bool pfReaddirplusDerived = false;
    auto derive = [&](const char* label, const std::optional<uintptr_t>& alreadyResolved,
                      ProfileOffsetField targetField, bool* derivedFlag = nullptr) {
        if (alreadyResolved.has_value()) {
            return;
        }
        auto derived = DeriveOffsetFromProfileLayout(bestProfile, features, targetField);
        if (!derived.has_value()) {
            return;
        }
        effectiveProfile->*targetField = derived->offset;
        ++(*derivedCount);
        if (derivedFlag != nullptr) {
            *derivedFlag = true;
        }
        __android_log_print(4, kLogTag, "derived hook offset %s=0x%zx votes=%d/%d base_profile=%s",
                            label, static_cast<size_t>(derived->offset), derived->votes,
                            derived->inputs, bestProfile.name);
    };

    derive("ShouldNotCache", features.shouldNotCacheOffset,
           &DeviceHookProfile::shouldNotCacheOffset, &shouldNotCacheDerived);
    derive("do_readdir_common", features.doReaddirCommonOffset,
           &DeviceHookProfile::doReaddirCommonOffset, &doReaddirCommonDerived);
    derive("GetDirectoryEntries", features.getDirectoryEntriesOffset,
           &DeviceHookProfile::getDirectoryEntriesOffset, &getDirectoryEntriesDerived);
    derive("addDirectoryEntriesFromLowerFs", features.addDirectoryEntriesFromLowerFsOffset,
           &DeviceHookProfile::addDirectoryEntriesFromLowerFsOffset,
           &addDirectoryEntriesBodyDerived);
    derive("pf_readdir", features.pfReaddirOffset, &DeviceHookProfile::pfReaddirOffset,
           &pfReaddirDerived);
    derive("pf_readdir_postfilter", features.pfReaddirPostfilterOffset,
           &DeviceHookProfile::pfReaddirPostfilterOffset, &pfReaddirPostfilterDerived);
    derive("pf_readdirplus", features.pfReaddirplusOffset, &DeviceHookProfile::pfReaddirplusOffset,
           &pfReaddirplusDerived);

    if (derivedFlags != nullptr) {
        derivedFlags->shouldNotCache = shouldNotCacheDerived;
        derivedFlags->doReaddirCommon = doReaddirCommonDerived;
        derivedFlags->getDirectoryEntries = getDirectoryEntriesDerived;
        derivedFlags->addDirectoryEntriesFromLowerFs = addDirectoryEntriesBodyDerived;
        derivedFlags->pfReaddir = pfReaddirDerived;
        derivedFlags->pfReaddirPostfilter = pfReaddirPostfilterDerived;
        derivedFlags->pfReaddirplus = pfReaddirplusDerived;
    }
}

CriticalHookTargetPlan BuildCriticalHookTargetPlan(uintptr_t effectiveOffset,
                                                   const std::optional<uintptr_t>& resolvedOffset,
                                                   HookResolutionSource resolvedSource,
                                                   bool derived, bool profileTrusted) {
    CriticalHookTargetPlan plan;
    plan.offset = effectiveOffset;
    if (resolvedOffset.has_value()) {
        plan.source = resolvedSource;
    } else if (derived) {
        plan.source = HookResolutionSource::kDerivedLayout;
    } else if (profileTrusted && effectiveOffset != 0) {
        plan.source = HookResolutionSource::kProfileFallback;
    } else {
        plan.offset = 0;
        plan.source = HookResolutionSource::kUnavailable;
    }
    return plan;
}

DeviceHookInstallPlan ResolveDeviceHookInstallPlan(const ModuleInfo& module) {
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, DeviceHookInstallPlan> cache;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto cached = cache.find(module.path);
        if (cached != cache.end()) {
            return cached->second;
        }
    }

    const ResolvedHookFeatureOffsets features = ResolveHookFeatureOffsets(module);
    const int resolvedCount = CountResolvedHookFeatures(features);
    const DeviceHookProfile* bestProfile = &kDeviceHookProfileLegacy;
    int bestScore = -1;
    int bestTies = 0;
    for (const auto& profile : kKnownDeviceHookProfiles) {
        const int score = ScoreHookProfile(profile, features);
        if (score > bestScore) {
            bestScore = score;
            bestProfile = &profile;
            bestTies = 1;
        } else if (score == bestScore) {
            ++bestTies;
        }
    }
    const bool profileTrusted = bestScore >= 2 && bestScore == resolvedCount && bestTies == 1;

    DeviceHookInstallPlan installPlan;
    installPlan.profile = *bestProfile;
    installPlan.profileTrusted = profileTrusted;
    int overrideCount = 0;
    ApplyResolvedHookFeatureOverrides(features, &installPlan.profile, &overrideCount);
    int derivedCount = 0;
    DerivedHookFeatureFlags derivedFlags;
    if (profileTrusted) {
        ApplyDerivedHookFeatureOverrides(*bestProfile, features, &installPlan.profile,
                                         &derivedCount, &derivedFlags);
    } else {
        ClearUnresolvedHookProfileOffsets(features, &installPlan.profile);
    }

    installPlan.shouldNotCache = BuildCriticalHookTargetPlan(
        installPlan.profile.shouldNotCacheOffset, features.shouldNotCacheOffset,
        features.shouldNotCacheSource, derivedFlags.shouldNotCache, profileTrusted);
    installPlan.doReaddirCommon = BuildCriticalHookTargetPlan(
        installPlan.profile.doReaddirCommonOffset, features.doReaddirCommonOffset,
        features.doReaddirCommonSource, derivedFlags.doReaddirCommon, profileTrusted);
    installPlan.getDirectoryEntries = BuildCriticalHookTargetPlan(
        installPlan.profile.getDirectoryEntriesOffset, features.getDirectoryEntriesOffset,
        features.getDirectoryEntriesSource, derivedFlags.getDirectoryEntries, profileTrusted);
    installPlan.addDirectoryEntriesFromLowerFs =
        BuildCriticalHookTargetPlan(installPlan.profile.addDirectoryEntriesFromLowerFsOffset,
                                    features.addDirectoryEntriesFromLowerFsOffset,
                                    features.addDirectoryEntriesFromLowerFsSource,
                                    derivedFlags.addDirectoryEntriesFromLowerFs, profileTrusted);
    installPlan.addDirectoryEntriesFromLowerFsThunk = {
        installPlan.profile.addDirectoryEntriesFromLowerFsThunkOffset,
        derivedFlags.addDirectoryEntriesFromLowerFsThunk
            ? HookResolutionSource::kDerivedLayout
            : (profileTrusted ? HookResolutionSource::kProfileFallback
                              : HookResolutionSource::kUnavailable),
    };
    installPlan.pfReaddir = BuildCriticalHookTargetPlan(
        installPlan.profile.pfReaddirOffset, features.pfReaddirOffset, features.pfReaddirSource,
        derivedFlags.pfReaddir, profileTrusted);
    installPlan.pfReaddirPostfilter = BuildCriticalHookTargetPlan(
        installPlan.profile.pfReaddirPostfilterOffset, features.pfReaddirPostfilterOffset,
        features.pfReaddirPostfilterSource, derivedFlags.pfReaddirPostfilter, profileTrusted);
    installPlan.pfReaddirplus = BuildCriticalHookTargetPlan(
        installPlan.profile.pfReaddirplusOffset, features.pfReaddirplusOffset,
        features.pfReaddirplusSource, derivedFlags.pfReaddirplus, profileTrusted);

    const int safeScore = std::max(bestScore, 0);
    if (resolvedCount == 0) {
        __android_log_print(5, kLogTag,
                            "device hook profile unavailable=%s without resolved features path=%s; "
                            "profile offsets disabled",
                            installPlan.profile.name, module.path.c_str());
    } else if (!profileTrusted) {
        __android_log_print(
            5, kLogTag,
            "device hook profile untrusted name=%s score=%d/%d ties=%d overrides=%d "
            "path=%s; unresolved offsets disabled",
            installPlan.profile.name, safeScore, resolvedCount, bestTies, overrideCount,
            module.path.c_str());
    } else {
        __android_log_print(4, kLogTag,
                            "selected device hook profile=%s score=%d/%d overrides=%d derived=%d "
                            "path=%s",
                            installPlan.profile.name, safeScore, resolvedCount, overrideCount,
                            derivedCount, module.path.c_str());
    }

    std::lock_guard<std::mutex> lock(cacheMutex);
    auto [it, _] = cache.insert_or_assign(module.path, installPlan);
    return it->second;
}

bool TryInstallCriticalHookFromPlan(const ModuleInfo& module, const CriticalHookTargetPlan& target,
                                    const char* hookName, void* replacement, void** backup,
                                    const char* failureMessage) {
    if (!CanUseProfileBasedTarget(target.source)) {
        DebugLogPrint(4, "skip profile-based hook %s source=%s on unsupported profile arch path=%s",
                      hookName, HookResolutionSourceName(target.source), module.path.c_str());
        return false;
    }
    __android_log_print(4, kLogTag, "using hook target %s source=%s offset=0x%zx target=%p",
                        hookName, HookResolutionSourceName(target.source),
                        static_cast<size_t>(target.offset),
                        reinterpret_cast<void*>(module.base + target.offset));
    return TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + target.offset), replacement,
                                  backup, failureMessage);
}

bool TryInstallDeviceProfileInlineHook(const ModuleInfo& module, uintptr_t offset,
                                       const char* hookName, void* replacement, void** backup,
                                       const char* failureMessage) {
    if (offset == 0) {
        DebugLogPrint(4, "skip unresolved device profile hook %s path=%s", hookName,
                      module.path.c_str());
        return false;
    }
    if constexpr (!kSupportsDeviceProfileOffsets) {
        DebugLogPrint(4, "skip device profile inline hook %s on unsupported profile arch path=%s",
                      hookName, module.path.c_str());
        return false;
    }
    return TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + offset), replacement,
                                  backup, failureMessage);
}

DeviceHookProfile ResolveEffectiveDeviceHookProfile(const ModuleInfo& module) {
    return ResolveDeviceHookInstallPlan(module).profile;
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
    status->appAccessible = Process().originalIsAppAccessiblePath != nullptr;
    status->packageCoveredByComparePath = Process().originalIsPackageOwnedPath == nullptr &&
                                          Process().originalEqualsIgnoreCase != nullptr &&
                                          Process().originalStrcasecmp != nullptr &&
                                          HasResolvableSymbol(module, kContainsMountSymbols);
    status->packageOwned =
        Process().originalIsPackageOwnedPath != nullptr || status->packageCoveredByComparePath;
    status->bpfBacking = Process().originalIsBpfBackingPath != nullptr;
    status->strcasecmp = Process().originalStrcasecmp != nullptr;
    status->equalsIgnoreCase = Process().originalEqualsIgnoreCase != nullptr;
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
    std::optional<MappedFile> mapped;
    if (module.path.find("!/") != std::string::npos) {
        mapped = MapEmbeddedStoredElf(module.path);
    } else {
        mapped = MapReadOnlyFile(module.path, module.fileOffset);
    }
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
        __android_log_print(4, kLogTag,
                            "hook already installed %s target=%p replacement=%p backup=%p",
                            failureMessage, target, replacement, *backup);
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
    __android_log_print(4, kLogTag, "hook installed %s target=%p replacement=%p backup=%p",
                        failureMessage, target, replacement, backup != nullptr ? *backup : nullptr);
    return true;
}

bool TryInstallFileInlineHook(const ModuleInfo& module, std::string_view symbolName,
                              void* replacement, void** backup, const char* failureMessage) {
    auto target = ResolveTargetSymbol(module, symbolName);
    if (!target.has_value()) {
        __android_log_print(3, kLogTag, "resolve failed %s", std::string(symbolName).c_str());
        return false;
    }
    DebugLogPrint(4, "install file inline symbol=%s target=%p replacement=%p path=%s",
                  std::string(symbolName).c_str(), *target, replacement, module.path.c_str());
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
    DebugLogPrint(4, "install runtime inline symbol=%s target=%p replacement=%p path=%s",
                  std::string(symbolName).c_str(), *target, replacement, module.path.c_str());
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
    auto& process = Process();
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
    const bool hasClassicStringAbi = HasVerifiedClassicStringAbi(installPlan);
    if (hasClassicStringAbi) {
        InstallFirstAvailableFileInlineHook(
            module, kIsAppAccessiblePathSymbols,
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&process.originalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
        InstallFirstAvailableFileInlineHook(
            module, kIsPackageOwnedPathSymbols, reinterpret_cast<void*>(+WrappedIsPackageOwnedPath),
            reinterpret_cast<void**>(&process.originalIsPackageOwnedPath),
            "hook is_package_owned_path failed");
        InstallFirstAvailableFileInlineHook(
            module, kIsBpfBackingPathSymbols, reinterpret_cast<void*>(+WrappedIsBpfBackingPath),
            reinterpret_cast<void**>(&process.originalIsBpfBackingPath),
            "hook is_bpf_backing_path failed");
    }

    InstallFileCompareHookIfNeeded(fileContext.elfInfo, kStrcasecmpSymbol, kStrcasecmpSymbol,
                                   reinterpret_cast<void*>(+WrappedStrcasecmp),
                                   &process.originalStrcasecmp, "strcasecmp");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, kEqualsIgnoreCaseSymbols[0],
                                   kEqualsIgnoreCaseSymbols[1],
                                   reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                   &process.originalEqualsIgnoreCase, "EqualsIgnoreCase");

    if (hasClassicStringAbi && process.originalIsAppAccessiblePath == nullptr) {
        // Reverse-engineered record: is_app_accessible_path @ 0x0017bb5c.
        // This is the shared access-policy gate reached by lookup/readdir/getattr and by several
        // inode-based handlers such as access/open/opendir. Those paths do not all have their own
        // dedicated wrappers, so leaving this unresolved would weaken hidden-path coverage on the
        // stripped production binary. Only use the device RVA after the name-based attempts above
        // have already failed.
        TryInstallDeviceProfileInlineHook(
            module, deviceProfile.isAppAccessiblePathOffset, "is_app_accessible_path",
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&process.originalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (hasClassicStringAbi && Process().originalShouldNotCache == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.shouldNotCache, "ShouldNotCache", (void*)WrappedShouldNotCache,
            &Process().originalShouldNotCache, "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// These hooks are functionally required for hidden-path semantics. Only the verbose trace logging
// inside the wrappers stays gated by kEnableDebugHooks.
void InstallMinimalDebugHooks(const ModuleInfo& module, const FileElfContext& fileContext) {
    auto& process = Process();
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
    const bool canInstallDirectoryEntries = CanInstallDirectoryEntriesHooks(installPlan);
    void* getDirectoryEntriesReplacement =
        canInstallDirectoryEntries ? GetDirectoryEntriesReplacement() : nullptr;
    void* addDirectoryEntriesReplacement =
        canInstallDirectoryEntries ? AddDirectoryEntriesFromLowerFsReplacement() : nullptr;
    InstallFileCompareHookIfNeeded(
        fileContext.elfInfo, "fuse_lowlevel_notify_inval_entry", "fuse_lowlevel_notify_inval_entry",
        (void*)WrappedNotifyInvalEntry, &process.originalNotifyInvalEntry, "notify_inval_entry");
    InstallFileCompareHookIfNeeded(
        fileContext.elfInfo, "fuse_lowlevel_notify_inval_inode", "fuse_lowlevel_notify_inval_inode",
        (void*)WrappedNotifyInvalInode, &process.originalNotifyInvalInode, "notify_inval_inode");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_entry", "fuse_reply_entry",
                                   (void*)WrappedReplyEntry, &process.originalReplyEntry,
                                   "reply_entry");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_attr", "fuse_reply_attr",
                                   (void*)WrappedReplyAttr, &process.originalReplyAttr,
                                   "reply_attr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_buf", "fuse_reply_buf",
                                   (void*)WrappedReplyBuf, &process.originalReplyBuf, "reply_buf");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "fuse_reply_err", "fuse_reply_err",
                                   (void*)WrappedReplyErr, &process.originalReplyErr, "reply_err");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "lstat", "lstat", (void*)WrappedLstat,
                                   &process.originalLstat, "lstat");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "stat", "stat", (void*)WrappedStat,
                                   &process.originalStat, "stat");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "getxattr", "getxattr",
                                   (void*)WrappedGetxattr, &process.originalGetxattr, "getxattr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "lgetxattr", "lgetxattr",
                                   (void*)WrappedLgetxattr, &process.originalLgetxattr,
                                   "lgetxattr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mkdir", "mkdir", (void*)WrappedMkdirLibc,
                                   &process.originalMkdir, "mkdir");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mknod", "mknod", (void*)WrappedMknod,
                                   &process.originalMknod, "mknod");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "open", "open", (void*)WrappedOpen,
                                   &process.originalOpen, "open");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "__open_2", "__open_2", (void*)WrappedOpen2,
                                   &process.originalOpen2, "__open_2");
    if (process.originalGetDirectoryEntries == nullptr &&
        getDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.getDirectoryEntries,
                                       "GetDirectoryEntries", getDirectoryEntriesReplacement,
                                       &process.originalGetDirectoryEntries,
                                       "hook GetDirectoryEntries failed");
    }
    if (process.originalAddDirectoryEntriesFromLowerFs == nullptr &&
        addDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.addDirectoryEntriesFromLowerFs, "addDirectoryEntriesFromLowerFs",
            addDirectoryEntriesReplacement, &process.originalAddDirectoryEntriesFromLowerFs,
            "hook addDirectoryEntriesFromLowerFs failed");
    }
    if (process.originalAddDirectoryEntriesFromLowerFs == nullptr &&
        addDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.addDirectoryEntriesFromLowerFsThunk,
                                       "addDirectoryEntriesFromLowerFsThunk",
                                       addDirectoryEntriesReplacement,
                                       &process.originalAddDirectoryEntriesFromLowerFs,
                                       "hook addDirectoryEntriesFromLowerFs thunk failed");
    }
    if (process.originalDoReaddirCommon == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.doReaddirCommon, "do_readdir_common", (void*)WrappedDoReaddirCommon,
            &process.originalDoReaddirCommon, "hook do_readdir_common failed");
    }
    if (process.originalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // mkdir policy lives in an internal static handler, so keep the device-specific offset as a
        // backup when symbol-based lookup is unavailable.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfMkdirOffset, "pf_mkdir",
                                          (void*)WrappedPfMkdir, &process.originalPfMkdir,
                                          "hook pf_mkdir failed");
    }
    if (process.originalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        // Some create paths go through pf_mknod instead of pf_create on device builds.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfMknodOffset, "pf_mknod",
                                          (void*)WrappedPfMknod, &process.originalPfMknod,
                                          "hook pf_mknod failed");
    }
    if (process.originalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        // unlink/rmdir/create handlers are internal statics in libfuse_jni, so retain the verified
        // offset fallback for devices that do not expose stable symbols.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfUnlinkOffset, "pf_unlink",
                                          (void*)WrappedPfUnlink, &process.originalPfUnlink,
                                          "hook pf_unlink failed");
    }
    if (process.originalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfRmdirOffset, "pf_rmdir",
                                          (void*)WrappedPfRmdir, &process.originalPfRmdir,
                                          "hook pf_rmdir failed");
    }
    if (process.originalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        // rename follows the same parent-only access pattern as create/delete handlers, so keep an
        // explicit device RVA fallback for builds that do not expose the local symbol.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfRenameOffset, "pf_rename",
                                          (void*)WrappedPfRename, &process.originalPfRename,
                                          "hook pf_rename failed");
    }
    if (process.originalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfCreateOffset, "pf_create",
                                          (void*)WrappedPfCreate, &process.originalPfCreate,
                                          "hook pf_create failed");
    }
    if (process.originalPfReaddir == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddir, "pf_readdir",
                                       (void*)WrappedPfReaddir, &process.originalPfReaddir,
                                       "hook pf_readdir failed");
    }
    if (process.originalPfReaddirplus == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirplus, "pf_readdirplus",
                                       (void*)WrappedPfReaddirplus, &process.originalPfReaddirplus,
                                       "hook pf_readdirplus failed");
    }
    if (process.originalPfReaddirPostfilter == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirPostfilter,
                                       "pf_readdir_postfilter", (void*)WrappedPfReaddirPostfilter,
                                       &process.originalPfReaddirPostfilter,
                                       "hook pf_readdir_postfilter failed");
    }

    if (process.originalPfLookup == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc",
                                 (void*)WrappedPfLookup, &process.originalPfLookup,
                                 "hook pf_lookup failed");
    }
    if (process.originalPfAccess == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_accessEP8fuse_reqmi",
                                 (void*)WrappedPfAccess, &process.originalPfAccess,
                                 "hook pf_access failed");
    }
    if (process.originalPfOpen == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL7pf_openEP8fuse_reqmP14fuse_file_info",
            (void*)WrappedPfOpen, &process.originalPfOpen, "hook pf_open failed");
    }
    if (process.originalPfOpendir == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL10pf_opendirEP8fuse_reqmP14fuse_file_info",
            (void*)WrappedPfOpendir, &process.originalPfOpendir, "hook pf_opendir failed");
    }
    if (process.originalPfMkdir == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL8pf_mkdirEP8fuse_reqmPKcj",
                                 (void*)WrappedPfMkdir, &process.originalPfMkdir,
                                 "hook pf_mkdir failed");
    }
    if (process.originalPfUnlink == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_unlinkEP8fuse_reqmPKc",
                                 (void*)WrappedPfUnlink, &process.originalPfUnlink,
                                 "hook pf_unlink failed");
    }
    if (process.originalPfRmdir == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL8pf_rmdirEP8fuse_reqmPKc",
                                 (void*)WrappedPfRmdir, &process.originalPfRmdir,
                                 "hook pf_rmdir failed");
    }
    if (process.originalPfRename == nullptr) {
        TryInstallFileInlineHook(module, "_ZN13mediaprovider4fuseL9pf_renameEP8fuse_reqmPKcmS4_j",
                                 (void*)WrappedPfRename, &process.originalPfRename,
                                 "hook pf_rename failed");
    }
    if (process.originalPfCreate == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL9pf_createEP8fuse_reqmPKcjP14fuse_file_info",
            (void*)WrappedPfCreate, &process.originalPfCreate, "hook pf_create failed");
    }
    if (process.originalPfLookupPostfilter == nullptr) {
        TryInstallFileInlineHook(module,
                                 "_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_"
                                 "reqmjPKcP14fuse_entry_outP18fuse_"
                                 "entry_bpf_out",
                                 (void*)WrappedPfLookupPostfilter,
                                 &process.originalPfLookupPostfilter,
                                 "hook pf_lookup_postfilter failed");
    }
    if (process.originalPfGetattr == nullptr) {
        TryInstallFileInlineHook(
            module, "_ZN13mediaprovider4fuseL10pf_getattrEP8fuse_reqmP14fuse_file_info",
            (void*)WrappedPfGetattr, &process.originalPfGetattr, "hook pf_getattr failed");
    }
    if (process.originalPfLookup == nullptr) {
        // Reverse-engineered record: pf_lookup @ 0x00175e48.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfLookupOffset, "pf_lookup",
                                          (void*)WrappedPfLookup, &process.originalPfLookup,
                                          "hook pf_lookup failed");
    }
    if (process.originalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfLookupPostfilterOffset,
                                          "pf_lookup_postfilter", (void*)WrappedPfLookupPostfilter,
                                          &process.originalPfLookupPostfilter,
                                          "hook pf_lookup_postfilter failed");
    }
    if (process.originalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfGetattrOffset, "pf_getattr",
                                          (void*)WrappedPfGetattr, &process.originalPfGetattr,
                                          "hook pf_getattr failed");
    }
}

// When file-backed symbol lookup is unavailable, fall back to runtime relocation patching and
// verified device offsets recovered from the reverse-engineered libfuse_jni build.
void InstallAdvancedCoreHooks(const ModuleInfo& module, CoreHookStatus* status) {
    auto& process = Process();
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
    const bool hasClassicStringAbi = HasVerifiedClassicStringAbi(installPlan);
    if (hasClassicStringAbi && !status->appAccessible) {
        InstallFirstAvailableInlineHook(
            kIsAppAccessiblePathSymbols, reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&process.originalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (hasClassicStringAbi && !status->packageOwned) {
        InstallFirstAvailableInlineHook(
            kIsPackageOwnedPathSymbols, reinterpret_cast<void*>(+WrappedIsPackageOwnedPath),
            reinterpret_cast<void**>(&process.originalIsPackageOwnedPath),
            "hook is_package_owned_path failed");
    }

    if (hasClassicStringAbi && !status->bpfBacking) {
        InstallFirstAvailableInlineHook(kIsBpfBackingPathSymbols,
                                        reinterpret_cast<void*>(+WrappedIsBpfBackingPath),
                                        reinterpret_cast<void**>(&process.originalIsBpfBackingPath),
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
                                            &process.originalStrcasecmp, "strcasecmp");
            }
            if (!status->equalsIgnoreCase) {
                PatchRuntimeRelocationSlots(*runtimeDyn, module.base, ps,
                                            kEqualsIgnoreCaseSymbols[0],
                                            kEqualsIgnoreCaseSymbols[1],
                                            reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                            &process.originalEqualsIgnoreCase, "EqualsIgnoreCase");
            }
        }
    } else if (auto fileContext = BuildFileElfContext(module); fileContext.has_value()) {
        if (!status->strcasecmp) {
            InstallFileCompareHookIfNeeded(fileContext->elfInfo, kStrcasecmpSymbol,
                                           kStrcasecmpSymbol,
                                           reinterpret_cast<void*>(+WrappedStrcasecmp),
                                           &process.originalStrcasecmp, "strcasecmp");
        }
        if (!status->equalsIgnoreCase) {
            InstallFileCompareHookIfNeeded(fileContext->elfInfo, kEqualsIgnoreCaseSymbols[0],
                                           kEqualsIgnoreCaseSymbols[1],
                                           reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                           &process.originalEqualsIgnoreCase, "EqualsIgnoreCase");
        }
    }

    if (hasClassicStringAbi && process.originalIsAppAccessiblePath == nullptr) {
        // Reverse-engineered record: is_app_accessible_path @ 0x0017bb5c.
        // Repeat the same last-resort fallback here because the advanced path runs when the
        // initial file-backed install was unavailable or still failed to resolve this stripped
        // internal helper by name.
        TryInstallDeviceProfileInlineHook(
            module, deviceProfile.isAppAccessiblePathOffset, "is_app_accessible_path",
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&process.originalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (hasClassicStringAbi && Process().originalShouldNotCache == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.shouldNotCache, "ShouldNotCache", (void*)WrappedShouldNotCache,
            &Process().originalShouldNotCache, "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// Advanced debug hooks extend the functional set with device-specific inline hooks for lookup,
// create, rename, readdir, and invalidation code paths that are not reliably exposed through
// imported symbols.
void InstallAdvancedDebugHooks(const ModuleInfo& module) {
    auto& process = Process();
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
    const bool canInstallDirectoryEntries = CanInstallDirectoryEntriesHooks(installPlan);
    void* getDirectoryEntriesReplacement =
        canInstallDirectoryEntries ? GetDirectoryEntriesReplacement() : nullptr;
    void* addDirectoryEntriesReplacement =
        canInstallDirectoryEntries ? AddDirectoryEntriesFromLowerFsReplacement() : nullptr;
    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    if (useRuntimeElf) {
        auto runtimeDyn = ParseRuntimeDynamicInfo(module);
        if (runtimeDyn) {
            PatchRuntimeRelocationSlots(
                *runtimeDyn, module.base, getpagesize(), "fuse_lowlevel_notify_inval_entry",
                "fuse_lowlevel_notify_inval_entry", (void*)WrappedNotifyInvalEntry,
                &process.originalNotifyInvalEntry, "notify_inval_entry");
            PatchRuntimeRelocationSlots(
                *runtimeDyn, module.base, getpagesize(), "fuse_lowlevel_notify_inval_inode",
                "fuse_lowlevel_notify_inval_inode", (void*)WrappedNotifyInvalInode,
                &process.originalNotifyInvalInode, "notify_inval_inode");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_entry",
                                        "fuse_reply_entry", (void*)WrappedReplyEntry,
                                        &process.originalReplyEntry, "reply_entry");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_attr",
                                        "fuse_reply_attr", (void*)WrappedReplyAttr,
                                        &process.originalReplyAttr, "reply_attr");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_buf",
                                        "fuse_reply_buf", (void*)WrappedReplyBuf,
                                        &process.originalReplyBuf, "reply_buf");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "fuse_reply_err",
                                        "fuse_reply_err", (void*)WrappedReplyErr,
                                        &process.originalReplyErr, "reply_err");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "lstat", "lstat",
                                        (void*)WrappedLstat, &process.originalLstat, "lstat");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "stat", "stat",
                                        (void*)WrappedStat, &process.originalStat, "stat");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "getxattr",
                                        "getxattr", (void*)WrappedGetxattr,
                                        &process.originalGetxattr, "getxattr");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "lgetxattr",
                                        "lgetxattr", (void*)WrappedLgetxattr,
                                        &process.originalLgetxattr, "lgetxattr");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "mkdir", "mkdir",
                                        (void*)WrappedMkdirLibc, &process.originalMkdir, "mkdir");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "mknod", "mknod",
                                        (void*)WrappedMknod, &process.originalMknod, "mknod");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "open", "open",
                                        (void*)WrappedOpen, &process.originalOpen, "open");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "__open_2",
                                        "__open_2", (void*)WrappedOpen2, &process.originalOpen2,
                                        "__open_2");
        }
    } else if (auto fileContext = BuildFileElfContext(module); fileContext.has_value()) {
        InstallMinimalDebugHooks(module, *fileContext);
    }

    if (process.originalGetDirectoryEntries == nullptr &&
        getDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.getDirectoryEntries,
                                       "GetDirectoryEntries", getDirectoryEntriesReplacement,
                                       &process.originalGetDirectoryEntries,
                                       "hook GetDirectoryEntries failed");
    }
    if (process.originalAddDirectoryEntriesFromLowerFs == nullptr &&
        addDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.addDirectoryEntriesFromLowerFs, "addDirectoryEntriesFromLowerFs",
            addDirectoryEntriesReplacement, &process.originalAddDirectoryEntriesFromLowerFs,
            "hook addDirectoryEntriesFromLowerFs failed");
    }
    if (process.originalAddDirectoryEntriesFromLowerFs == nullptr &&
        addDirectoryEntriesReplacement != nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.addDirectoryEntriesFromLowerFsThunk,
                                       "addDirectoryEntriesFromLowerFsThunk",
                                       addDirectoryEntriesReplacement,
                                       &process.originalAddDirectoryEntriesFromLowerFs,
                                       "hook addDirectoryEntriesFromLowerFs thunk failed");
    }
    if (process.originalDoReaddirCommon == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.doReaddirCommon, "do_readdir_common", (void*)WrappedDoReaddirCommon,
            &process.originalDoReaddirCommon, "hook do_readdir_common failed");
    }
    if (process.originalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // The advanced path still keeps explicit handler RVAs because these static functions may be
        // absent from runtime relocation metadata.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfMkdirOffset, "pf_mkdir",
                                          (void*)WrappedPfMkdir, &process.originalPfMkdir,
                                          "hook pf_mkdir failed");
    }
    if (process.originalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfMknodOffset, "pf_mknod",
                                          (void*)WrappedPfMknod, &process.originalPfMknod,
                                          "hook pf_mknod failed");
    }
    if (process.originalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfUnlinkOffset, "pf_unlink",
                                          (void*)WrappedPfUnlink, &process.originalPfUnlink,
                                          "hook pf_unlink failed");
    }
    if (process.originalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfRmdirOffset, "pf_rmdir",
                                          (void*)WrappedPfRmdir, &process.originalPfRmdir,
                                          "hook pf_rmdir failed");
    }
    if (process.originalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfRenameOffset, "pf_rename",
                                          (void*)WrappedPfRename, &process.originalPfRename,
                                          "hook pf_rename failed");
    }
    if (process.originalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfCreateOffset, "pf_create",
                                          (void*)WrappedPfCreate, &process.originalPfCreate,
                                          "hook pf_create failed");
    }
    if (process.originalPfReaddir == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddir, "pf_readdir",
                                       (void*)WrappedPfReaddir, &process.originalPfReaddir,
                                       "hook pf_readdir failed");
    }
    if (process.originalPfReaddirplus == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirplus, "pf_readdirplus",
                                       (void*)WrappedPfReaddirplus, &process.originalPfReaddirplus,
                                       "hook pf_readdirplus failed");
    }
    if (process.originalPfReaddirPostfilter == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirPostfilter,
                                       "pf_readdir_postfilter", (void*)WrappedPfReaddirPostfilter,
                                       &process.originalPfReaddirPostfilter,
                                       "hook pf_readdir_postfilter failed");
    }

    if (process.originalPfLookup == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc",
                             (void*)WrappedPfLookup, &process.originalPfLookup,
                             "hook pf_lookup failed");
    }
    if (process.originalPfAccess == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_accessEP8fuse_reqmi",
                             (void*)WrappedPfAccess, &process.originalPfAccess,
                             "hook pf_access failed");
    }
    if (process.originalPfOpen == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL7pf_openEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfOpen, &process.originalPfOpen, "hook pf_open failed");
    }
    if (process.originalPfOpendir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL10pf_opendirEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfOpendir, &process.originalPfOpendir,
                             "hook pf_opendir failed");
    }
    if (process.originalPfMkdir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_mkdirEP8fuse_reqmPKcj",
                             (void*)WrappedPfMkdir, &process.originalPfMkdir,
                             "hook pf_mkdir failed");
    }
    if (process.originalPfMknod == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_mknodEP8fuse_reqmPKcjm",
                             (void*)WrappedPfMknod, &process.originalPfMknod,
                             "hook pf_mknod failed");
    }
    if (process.originalPfUnlink == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_unlinkEP8fuse_reqmPKc",
                             (void*)WrappedPfUnlink, &process.originalPfUnlink,
                             "hook pf_unlink failed");
    }
    if (process.originalPfRmdir == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL8pf_rmdirEP8fuse_reqmPKc",
                             (void*)WrappedPfRmdir, &process.originalPfRmdir,
                             "hook pf_rmdir failed");
    }
    if (process.originalPfRename == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_renameEP8fuse_reqmPKcmS4_j",
                             (void*)WrappedPfRename, &process.originalPfRename,
                             "hook pf_rename failed");
    }
    if (process.originalPfCreate == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL9pf_createEP8fuse_reqmPKcjP14fuse_file_info",
                             (void*)WrappedPfCreate, &process.originalPfCreate,
                             "hook pf_create failed");
    }
    if (process.originalPfLookupPostfilter == nullptr) {
        InstallHookForSymbol(
            "_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_reqmjPKcP14fuse_entry_"
            "outP18fuse_"
            "entry_bpf_out",
            (void*)WrappedPfLookupPostfilter, &process.originalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (process.originalPfGetattr == nullptr) {
        InstallHookForSymbol("_ZN13mediaprovider4fuseL10pf_getattrEP8fuse_reqmP14fuse_file_info",
                             (void*)WrappedPfGetattr, &process.originalPfGetattr,
                             "hook pf_getattr failed");
    }
    if (process.originalPfLookup == nullptr) {
        // Reverse-engineered record: pf_lookup @ 0x00175e48.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfLookupOffset, "pf_lookup",
                                          (void*)WrappedPfLookup, &process.originalPfLookup,
                                          "hook pf_lookup failed");
    }
    if (process.originalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfLookupPostfilterOffset,
                                          "pf_lookup_postfilter", (void*)WrappedPfLookupPostfilter,
                                          &process.originalPfLookupPostfilter,
                                          "hook pf_lookup_postfilter failed");
    }
    if (process.originalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallDeviceProfileInlineHook(module, deviceProfile.pfGetattrOffset, "pf_getattr",
                                          (void*)WrappedPfGetattr, &process.originalPfGetattr,
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

    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(*module);
    if (Process().fuseReqCtx == nullptr) {
        // MediaProvider links libfuse.so separately, so fuse_req_ctx is normally an undefined
        // import in libfuse_jni.so. Prefer linker resolution, then its bound relocation, then
        // libfuse.so:
        // https://android.googlesource.com/platform/packages/providers/MediaProvider/+/f2abe4aec018f0522b4b1303fb25351db0604eb5/jni/Android.bp#46
        // https://android.googlesource.com/platform/external/libfuse/+/e877eedab4254ceb2af4b77c7327e4d0cde30824/lib/fuse_lowlevel.c#2771
        void* resolved = dlsym(RTLD_DEFAULT, "fuse_req_ctx");
        const char* resolutionSource = "RTLD_DEFAULT";
        if (resolved == nullptr) {
            const auto importedTarget = ResolveImportedFunctionTarget(*module, "fuse_req_ctx");
            if (importedTarget.has_value()) {
                resolved = *importedTarget;
                resolutionSource = "libfuse_jni relocation";
            }
        }
        if (resolved == nullptr) {
            const auto libfuseModule = FindModuleFromMaps("/libfuse.so");
            if (libfuseModule.has_value()) {
                const bool useRuntimeLibfuse = libfuseModule->path.find("!/") != std::string::npos;
                const auto libfuseSymbol =
                    useRuntimeLibfuse ? ResolveTargetSymbolRuntime(*libfuseModule, "fuse_req_ctx")
                                      : ResolveTargetSymbol(*libfuseModule, "fuse_req_ctx");
                if (libfuseSymbol.has_value()) {
                    resolved = *libfuseSymbol;
                    resolutionSource = "libfuse.so";
                }
            }
        }

        if (resolved != nullptr) {
            Process().fuseReqCtx = resolved;
            __android_log_print(4, kLogTag, "resolved fuse_req_ctx=%p source=%s", resolved,
                                resolutionSource);
        } else {
            __android_log_print(6, kLogTag,
                                "fuse_req_ctx unavailable; no verified libfuse layout fallback");
        }
    }

    const bool hasClassicStringAbi = HasVerifiedClassicStringAbi(installPlan);
    __android_log_print(hasClassicStringAbi ? 4 : 5, kLogTag,
                        "libc++ string ABI=%s profile=%s trusted=%d",
                        hasClassicStringAbi ? "classic" : "unverified", installPlan.profile.name,
                        installPlan.profileTrusted ? 1 : 0);
    if (!hasClassicStringAbi) {
        __android_log_print(5, kLogTag,
                            "skipping hooks that decode or construct libc++ string objects");
    }

    const DirectoryEntriesAbi directoryEntriesAbi = DetectDirectoryEntriesAbi(*module);
    gDirectoryEntriesAbi.store(directoryEntriesAbi, std::memory_order_release);
    __android_log_print(4, kLogTag, "directory entries ABI=%s",
                        DirectoryEntriesAbiName(directoryEntriesAbi));
    if (directoryEntriesAbi == DirectoryEntriesAbi::kUnknown) {
        __android_log_print(6, kLogTag,
                            "unknown DirectoryEntries ABI; skipping unsafe C++ container hooks");
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
        reinterpret_cast<void*>(Process().originalIsAppAccessiblePath),
        reinterpret_cast<void*>(Process().originalIsPackageOwnedPath),
        coreStatus.packageCoveredByComparePath,
        reinterpret_cast<void*>(Process().originalIsBpfBackingPath), Process().originalStrcasecmp,
        Process().originalEqualsIgnoreCase, reinterpret_cast<void*>(gUHasBinaryProperty));
}

}  // namespace fusehide
