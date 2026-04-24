#include "elf_utils.hpp"
#include "wrappers.hpp"

namespace fusehide {

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

template <size_t N>
std::optional<uintptr_t> ResolveFirstAvailableSymbolOffset(const ModuleInfo& module,
                                                           const std::string_view (&symbols)[N]) {
    const bool useRuntimeElf = module.path.find("!/") != std::string::npos;
    for (const auto& symbol : symbols) {
        auto resolved = useRuntimeElf ? ResolveTargetSymbolRuntime(module, symbol)
                                      : ResolveTargetSymbol(module, symbol);
        if (resolved.has_value()) {
            return reinterpret_cast<uintptr_t>(*resolved) - module.base;
        }
    }
    return std::nullopt;
}

enum class HookResolutionSource {
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
        mapped = MapReadOnlyFile(module.path);
    }
    if (!mapped.has_value()) {
        return std::nullopt;
    }
    auto match = FindLargestSymbolContaining(*mapped, needle);
    if (!match.has_value()) {
        return std::nullopt;
    }
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
    CriticalHookTargetPlan shouldNotCache;
    CriticalHookTargetPlan doReaddirCommon;
    CriticalHookTargetPlan getDirectoryEntries;
    CriticalHookTargetPlan addDirectoryEntriesFromLowerFs;
    CriticalHookTargetPlan addDirectoryEntriesFromLowerFsThunk;
    CriticalHookTargetPlan pfReaddir;
    CriticalHookTargetPlan pfReaddirPostfilter;
    CriticalHookTargetPlan pfReaddirplus;
};

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
    features.getDirectoryEntriesOffset = ResolveFeatureOffsetBySymbols(
        module, kGetDirectoryEntriesSymbols, &features.getDirectoryEntriesSource);
    features.addDirectoryEntriesFromLowerFsOffset =
        ResolveFeatureOffsetBySymbols(module, kAddDirectoryEntriesFromLowerFsSymbols,
                                      &features.addDirectoryEntriesFromLowerFsSource);
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
    if (!features.shouldNotCacheOffset.has_value()) {
        features.shouldNotCacheOffset = ResolveFeatureOffsetByContains(
            module, "ShouldNotCache", &features.shouldNotCacheSource);
    }
    if (!features.doReaddirCommonOffset.has_value()) {
        features.doReaddirCommonOffset = ResolveFeatureOffsetByContains(
            module, "do_readdir_common", &features.doReaddirCommonSource);
    }
    if (!features.getDirectoryEntriesOffset.has_value()) {
        features.getDirectoryEntriesOffset = ResolveFeatureOffsetByContains(
            module, "GetDirectoryEntries", &features.getDirectoryEntriesSource);
    }
    if (!features.addDirectoryEntriesFromLowerFsOffset.has_value()) {
        features.addDirectoryEntriesFromLowerFsOffset =
            ResolveFeatureOffsetByContains(module, "addDirectoryEntriesFromLowerFs",
                                           &features.addDirectoryEntriesFromLowerFsSource);
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
    auto apply = [&](const std::optional<uintptr_t>& value, uintptr_t DeviceHookProfile::*field) {
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
            continue;
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
    if (ties > 1 && bestVotes > 0) {
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

    if (features.addDirectoryEntriesFromLowerFsOffset.has_value() ||
        addDirectoryEntriesBodyDerived) {
        const int64_t bodyToThunkDelta =
            static_cast<int64_t>(bestProfile.addDirectoryEntriesFromLowerFsThunkOffset) -
            static_cast<int64_t>(bestProfile.addDirectoryEntriesFromLowerFsOffset);
        const int64_t thunkOffset =
            static_cast<int64_t>(effectiveProfile->addDirectoryEntriesFromLowerFsOffset) +
            bodyToThunkDelta;
        if (thunkOffset >= 0) {
            effectiveProfile->addDirectoryEntriesFromLowerFsThunkOffset =
                static_cast<uintptr_t>(thunkOffset);
            ++(*derivedCount);
            if (derivedFlags != nullptr) {
                derivedFlags->addDirectoryEntriesFromLowerFsThunk = true;
            }
            __android_log_print(
                4, kLogTag,
                "derived hook offset addDirectoryEntriesFromLowerFsThunk=0x%zx "
                "base_profile=%s",
                static_cast<size_t>(effectiveProfile->addDirectoryEntriesFromLowerFsThunkOffset),
                bestProfile.name);
        }
    }

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
                                                   bool derived) {
    CriticalHookTargetPlan plan;
    plan.offset = effectiveOffset;
    if (resolvedOffset.has_value()) {
        plan.source = resolvedSource;
    } else if (derived) {
        plan.source = HookResolutionSource::kDerivedLayout;
    } else {
        plan.source = HookResolutionSource::kProfileFallback;
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
    for (const auto& profile : kKnownDeviceHookProfiles) {
        const int score = ScoreHookProfile(profile, features);
        if (score > bestScore) {
            bestScore = score;
            bestProfile = &profile;
        }
    }

    DeviceHookInstallPlan installPlan;
    installPlan.profile = *bestProfile;
    int overrideCount = 0;
    ApplyResolvedHookFeatureOverrides(features, &installPlan.profile, &overrideCount);
    int derivedCount = 0;
    DerivedHookFeatureFlags derivedFlags;
    ApplyDerivedHookFeatureOverrides(*bestProfile, features, &installPlan.profile, &derivedCount,
                                     &derivedFlags);

    installPlan.shouldNotCache = BuildCriticalHookTargetPlan(
        installPlan.profile.shouldNotCacheOffset, features.shouldNotCacheOffset,
        features.shouldNotCacheSource, derivedFlags.shouldNotCache);
    installPlan.doReaddirCommon = BuildCriticalHookTargetPlan(
        installPlan.profile.doReaddirCommonOffset, features.doReaddirCommonOffset,
        features.doReaddirCommonSource, derivedFlags.doReaddirCommon);
    installPlan.getDirectoryEntries = BuildCriticalHookTargetPlan(
        installPlan.profile.getDirectoryEntriesOffset, features.getDirectoryEntriesOffset,
        features.getDirectoryEntriesSource, derivedFlags.getDirectoryEntries);
    installPlan.addDirectoryEntriesFromLowerFs = BuildCriticalHookTargetPlan(
        installPlan.profile.addDirectoryEntriesFromLowerFsOffset,
        features.addDirectoryEntriesFromLowerFsOffset,
        features.addDirectoryEntriesFromLowerFsSource, derivedFlags.addDirectoryEntriesFromLowerFs);
    installPlan.addDirectoryEntriesFromLowerFsThunk = {
        installPlan.profile.addDirectoryEntriesFromLowerFsThunkOffset,
        derivedFlags.addDirectoryEntriesFromLowerFsThunk ? HookResolutionSource::kDerivedLayout
                                                         : HookResolutionSource::kProfileFallback,
    };
    installPlan.pfReaddir =
        BuildCriticalHookTargetPlan(installPlan.profile.pfReaddirOffset, features.pfReaddirOffset,
                                    features.pfReaddirSource, derivedFlags.pfReaddir);
    installPlan.pfReaddirPostfilter = BuildCriticalHookTargetPlan(
        installPlan.profile.pfReaddirPostfilterOffset, features.pfReaddirPostfilterOffset,
        features.pfReaddirPostfilterSource, derivedFlags.pfReaddirPostfilter);
    installPlan.pfReaddirplus = BuildCriticalHookTargetPlan(
        installPlan.profile.pfReaddirplusOffset, features.pfReaddirplusOffset,
        features.pfReaddirplusSource, derivedFlags.pfReaddirplus);

    const int safeScore = std::max(bestScore, 0);
    if (resolvedCount == 0) {
        __android_log_print(5, kLogTag,
                            "device hook profile fallback=%s without resolved features path=%s",
                            installPlan.profile.name, module.path.c_str());
    } else if (safeScore == 0) {
        __android_log_print(5, kLogTag,
                            "device hook profile low confidence name=%s score=%d/%d overrides=%d "
                            "derived=%d path=%s",
                            installPlan.profile.name, safeScore, resolvedCount, overrideCount,
                            derivedCount, module.path.c_str());
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
    __android_log_print(4, kLogTag, "using hook target %s source=%s offset=0x%zx target=%p",
                        hookName, HookResolutionSourceName(target.source),
                        static_cast<size_t>(target.offset),
                        reinterpret_cast<void*>(module.base + target.offset));
    return TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + target.offset), replacement,
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
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
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
        // This is the shared access-policy gate reached by lookup/readdir/getattr and by several
        // inode-based handlers such as access/open/opendir. Those paths do not all have their own
        // dedicated wrappers, so leaving this unresolved would weaken hidden-path coverage on the
        // stripped production binary. Only use the device RVA after the name-based attempts above
        // have already failed.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + deviceProfile.isAppAccessiblePathOffset),
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (gOriginalShouldNotCache == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.shouldNotCache, "ShouldNotCache",
                                       (void*)WrappedShouldNotCache, &gOriginalShouldNotCache,
                                       "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// These hooks are functionally required for hidden-path semantics. Only the verbose trace logging
// inside the wrappers stays gated by kEnableDebugHooks.
void InstallMinimalDebugHooks(const ModuleInfo& module, const FileElfContext& fileContext) {
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
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
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "getxattr", "getxattr",
                                   (void*)WrappedGetxattr, &gOriginalGetxattr, "getxattr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "lgetxattr", "lgetxattr",
                                   (void*)WrappedLgetxattr, &gOriginalLgetxattr, "lgetxattr");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mkdir", "mkdir", (void*)WrappedMkdirLibc,
                                   &gOriginalMkdir, "mkdir");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "mknod", "mknod", (void*)WrappedMknod,
                                   &gOriginalMknod, "mknod");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "open", "open", (void*)WrappedOpen,
                                   &gOriginalOpen, "open");
    InstallFileCompareHookIfNeeded(fileContext.elfInfo, "__open_2", "__open_2", (void*)WrappedOpen2,
                                   &gOriginalOpen2, "__open_2");
    if (gOriginalGetDirectoryEntries == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.getDirectoryEntries,
                                       "GetDirectoryEntries", (void*)WrappedGetDirectoryEntries,
                                       &gOriginalGetDirectoryEntries,
                                       "hook GetDirectoryEntries failed");
    }
    if (gOriginalAddDirectoryEntriesFromLowerFs == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.addDirectoryEntriesFromLowerFs, "addDirectoryEntriesFromLowerFs",
            (void*)WrappedAddDirectoryEntriesFromLowerFs, &gOriginalAddDirectoryEntriesFromLowerFs,
            "hook addDirectoryEntriesFromLowerFs failed");
    }
    if (gOriginalAddDirectoryEntriesFromLowerFs == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.addDirectoryEntriesFromLowerFsThunk,
                                       "addDirectoryEntriesFromLowerFsThunk",
                                       (void*)WrappedAddDirectoryEntriesFromLowerFs,
                                       &gOriginalAddDirectoryEntriesFromLowerFs,
                                       "hook addDirectoryEntriesFromLowerFs thunk failed");
    }
    if (gOriginalDoReaddirCommon == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.doReaddirCommon, "do_readdir_common",
                                       (void*)WrappedDoReaddirCommon, &gOriginalDoReaddirCommon,
                                       "hook do_readdir_common failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // mkdir policy lives in an internal static handler, so keep the device-specific offset as a
        // backup when symbol-based lookup is unavailable.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfMkdirOffset),
                               (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        // Some create paths go through pf_mknod instead of pf_create on device builds.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfMknodOffset),
                               (void*)WrappedPfMknod, &gOriginalPfMknod, "hook pf_mknod failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        // unlink/rmdir/create handlers are internal statics in libfuse_jni, so retain the verified
        // offset fallback for devices that do not expose stable symbols.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfUnlinkOffset),
                               (void*)WrappedPfUnlink, &gOriginalPfUnlink, "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfRmdirOffset),
                               (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        // rename follows the same parent-only access pattern as create/delete handlers, so keep an
        // explicit device RVA fallback for builds that do not expose the local symbol.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfRenameOffset),
                               (void*)WrappedPfRename, &gOriginalPfRename, "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfCreateOffset),
                               (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfReaddir == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddir, "pf_readdir",
                                       (void*)WrappedPfReaddir, &gOriginalPfReaddir,
                                       "hook pf_readdir failed");
    }
    if (gOriginalPfReaddirplus == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirplus, "pf_readdirplus",
                                       (void*)WrappedPfReaddirplus, &gOriginalPfReaddirplus,
                                       "hook pf_readdirplus failed");
    }
    if (gOriginalPfReaddirPostfilter == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirPostfilter,
                                       "pf_readdir_postfilter", (void*)WrappedPfReaddirPostfilter,
                                       &gOriginalPfReaddirPostfilter,
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
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfLookupOffset),
                               (void*)WrappedPfLookup, &gOriginalPfLookup, "hook pf_lookup failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + deviceProfile.pfLookupPostfilterOffset),
            (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfGetattrOffset),
                               (void*)WrappedPfGetattr, &gOriginalPfGetattr,
                               "hook pf_getattr failed");
    }
}

// When file-backed symbol lookup is unavailable, fall back to runtime relocation patching and
// verified device offsets recovered from the reverse-engineered libfuse_jni build.
void InstallAdvancedCoreHooks(const ModuleInfo& module, CoreHookStatus* status) {
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
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
        // Repeat the same last-resort fallback here because the advanced path runs when the
        // initial file-backed install was unavailable or still failed to resolve this stripped
        // internal helper by name.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + deviceProfile.isAppAccessiblePathOffset),
            reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
            reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
            "hook is_app_accessible_path failed");
    }

    if (gOriginalShouldNotCache == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.shouldNotCache, "ShouldNotCache",
                                       (void*)WrappedShouldNotCache, &gOriginalShouldNotCache,
                                       "hook ShouldNotCache failed");
    }

    RefreshCoreHookStatus(module, status);
}

// Advanced debug hooks extend the functional set with device-specific inline hooks for lookup,
// create, rename, readdir, and invalidation code paths that are not reliably exposed through
// imported symbols.
void InstallAdvancedDebugHooks(const ModuleInfo& module) {
    const DeviceHookInstallPlan installPlan = ResolveDeviceHookInstallPlan(module);
    const DeviceHookProfile& deviceProfile = installPlan.profile;
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
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "getxattr",
                                        "getxattr", (void*)WrappedGetxattr, &gOriginalGetxattr,
                                        "getxattr");
            PatchRuntimeRelocationSlots(*runtimeDyn, module.base, getpagesize(), "lgetxattr",
                                        "lgetxattr", (void*)WrappedLgetxattr, &gOriginalLgetxattr,
                                        "lgetxattr");
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
        TryInstallCriticalHookFromPlan(module, installPlan.getDirectoryEntries,
                                       "GetDirectoryEntries", (void*)WrappedGetDirectoryEntries,
                                       &gOriginalGetDirectoryEntries,
                                       "hook GetDirectoryEntries failed");
    }
    if (gOriginalAddDirectoryEntriesFromLowerFs == nullptr) {
        TryInstallCriticalHookFromPlan(
            module, installPlan.addDirectoryEntriesFromLowerFs, "addDirectoryEntriesFromLowerFs",
            (void*)WrappedAddDirectoryEntriesFromLowerFs, &gOriginalAddDirectoryEntriesFromLowerFs,
            "hook addDirectoryEntriesFromLowerFs failed");
    }
    if (gOriginalAddDirectoryEntriesFromLowerFs == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.addDirectoryEntriesFromLowerFsThunk,
                                       "addDirectoryEntriesFromLowerFsThunk",
                                       (void*)WrappedAddDirectoryEntriesFromLowerFs,
                                       &gOriginalAddDirectoryEntriesFromLowerFs,
                                       "hook addDirectoryEntriesFromLowerFs thunk failed");
    }
    if (gOriginalDoReaddirCommon == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.doReaddirCommon, "do_readdir_common",
                                       (void*)WrappedDoReaddirCommon, &gOriginalDoReaddirCommon,
                                       "hook do_readdir_common failed");
    }
    if (gOriginalPfMkdir == nullptr) {
        // Reverse-engineered record: pf_mkdir @ 0x00177050.
        // The advanced path still keeps explicit handler RVAs because these static functions may be
        // absent from runtime relocation metadata.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfMkdirOffset),
                               (void*)WrappedPfMkdir, &gOriginalPfMkdir, "hook pf_mkdir failed");
    }
    if (gOriginalPfMknod == nullptr) {
        // Reverse-engineered record: pf_mknod @ 0x00176ba8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfMknodOffset),
                               (void*)WrappedPfMknod, &gOriginalPfMknod, "hook pf_mknod failed");
    }
    if (gOriginalPfUnlink == nullptr) {
        // Reverse-engineered record: pf_unlink @ 0x00177534.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfUnlinkOffset),
                               (void*)WrappedPfUnlink, &gOriginalPfUnlink, "hook pf_unlink failed");
    }
    if (gOriginalPfRmdir == nullptr) {
        // Reverse-engineered record: pf_rmdir @ 0x00177920.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfRmdirOffset),
                               (void*)WrappedPfRmdir, &gOriginalPfRmdir, "hook pf_rmdir failed");
    }
    if (gOriginalPfRename == nullptr) {
        // Reverse-engineered record: pf_rename @ 0x00177ef4.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfRenameOffset),
                               (void*)WrappedPfRename, &gOriginalPfRename, "hook pf_rename failed");
    }
    if (gOriginalPfCreate == nullptr) {
        // Reverse-engineered record: pf_create @ 0x0017a7c8.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfCreateOffset),
                               (void*)WrappedPfCreate, &gOriginalPfCreate, "hook pf_create failed");
    }
    if (gOriginalPfReaddir == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddir, "pf_readdir",
                                       (void*)WrappedPfReaddir, &gOriginalPfReaddir,
                                       "hook pf_readdir failed");
    }
    if (gOriginalPfReaddirplus == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirplus, "pf_readdirplus",
                                       (void*)WrappedPfReaddirplus, &gOriginalPfReaddirplus,
                                       "hook pf_readdirplus failed");
    }
    if (gOriginalPfReaddirPostfilter == nullptr) {
        TryInstallCriticalHookFromPlan(module, installPlan.pfReaddirPostfilter,
                                       "pf_readdir_postfilter", (void*)WrappedPfReaddirPostfilter,
                                       &gOriginalPfReaddirPostfilter,
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
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfLookupOffset),
                               (void*)WrappedPfLookup, &gOriginalPfLookup, "hook pf_lookup failed");
    }
    if (gOriginalPfLookupPostfilter == nullptr) {
        // Reverse-engineered record: pf_lookup_postfilter @ 0x00175f90.
        TryInstallInlineHookAt(
            reinterpret_cast<void*>(module.base + deviceProfile.pfLookupPostfilterOffset),
            (void*)WrappedPfLookupPostfilter, &gOriginalPfLookupPostfilter,
            "hook pf_lookup_postfilter failed");
    }
    if (gOriginalPfGetattr == nullptr) {
        // Reverse-engineered record: pf_getattr @ 0x001762bc.
        TryInstallInlineHookAt(reinterpret_cast<void*>(module.base + deviceProfile.pfGetattrOffset),
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

}  // namespace fusehide
