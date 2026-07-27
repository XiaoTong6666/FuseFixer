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

#include "fusehide/core/state.hpp"
#include "fusehide/policy/path_policy.hpp"

namespace fusehide {

UHasBinaryPropertyFn gUHasBinaryProperty = u_hasBinaryProperty;
HookInstaller gHookInstaller = nullptr;
JavaVM* gJavaVm = nullptr;
std::once_flag gXzCrcInitOnce;
HookOriginal<IsAppAccessiblePathFn> gOriginalIsAppAccessiblePath;
HookOriginal<IsPackageOwnedPathFn> gOriginalIsPackageOwnedPath;
HookOriginal<IsBpfBackingPathFn> gOriginalIsBpfBackingPath;
HookOriginal<StrcasecmpFn> gOriginalStrcasecmp;
HookOriginal<EqualsIgnoreCaseAbiFn> gOriginalEqualsIgnoreCase;

std::atomic<int> gAppAccessibleLogCount{0};
std::atomic<int> gPackageOwnedLogCount{0};
std::atomic<int> gBpfBackingLogCount{0};
std::atomic<int> gStrcasecmpLogCount{0};
std::atomic<int> gEqualsIgnoreCaseLogCount{0};
std::atomic<int> gReplyErrFallbackLogCount{0};
std::atomic<int> gErrnoRemapLogCount{0};
std::atomic<int> gSuspiciousDirectLogCount{0};
std::atomic<uint64_t> gHideConfigGeneration{1};
std::atomic<uint64_t> gUidPackageSetGeneration{1};
std::mutex gUidHideCacheMutex;
std::unordered_map<uint32_t, UidHideRuleCacheEntry> gUidHideRuleCache;
std::shared_ptr<const HideConfig> gHideConfig = std::make_shared<HideConfig>(DefaultHideConfig());
std::shared_ptr<const CompiledHideConfig> gCompiledHideConfig;

namespace {

struct CompiledHideRuleBuilder {
    bool enableHideAllRootEntries = false;
    std::vector<std::string> hideAllRootEntriesExemptions;
    std::vector<std::string> hiddenRootEntryNames;
    std::vector<std::string> hiddenRelativePaths;
};

constexpr uint64_t kFingerprintOffsetBasis = 1469598103934665603ULL;
constexpr uint64_t kFingerprintPrime = 1099511628211ULL;

void AppendUnique(std::vector<std::string>* out, const std::vector<std::string>& values) {
    for (const auto& value : values) {
        if (std::find(out->begin(), out->end(), value) == out->end()) {
            out->push_back(value);
        }
    }
}

void AppendNormalizedUnique(std::vector<std::string>* out, std::string_view value) {
    const std::string normalized = NormalizeRelativeHiddenPath(value);
    if (normalized.empty() || std::find(out->begin(), out->end(), normalized) != out->end()) {
        return;
    }
    out->push_back(normalized);
}

void MergeGlobalRule(const HideConfig& config, CompiledHideRuleBuilder* out) {
    out->enableHideAllRootEntries =
        out->enableHideAllRootEntries || config.enableHideAllRootEntries;
    AppendUnique(&out->hideAllRootEntriesExemptions, config.hideAllRootEntriesExemptions);
    AppendUnique(&out->hiddenRootEntryNames, config.hiddenRootEntryNames);
    for (const auto& hiddenRelativePath : config.hiddenRelativePaths) {
        AppendNormalizedUnique(&out->hiddenRelativePaths, hiddenRelativePath);
    }
}

void MergePackageRule(const PackageHideRule& rule, CompiledHideRuleBuilder* out) {
    AppendUnique(&out->hiddenRootEntryNames, rule.hiddenRootEntryNames);
    for (const auto& hiddenRelativePath : rule.hiddenRelativePaths) {
        AppendNormalizedUnique(&out->hiddenRelativePaths, hiddenRelativePath);
    }
}

bool RuleHasTargets(const CompiledHideRuleBuilder& rule) {
    return rule.enableHideAllRootEntries || !rule.hiddenRootEntryNames.empty() ||
           !rule.hiddenRelativePaths.empty();
}

void FingerprintBytes(uint64_t* hash, const void* data, size_t size) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        *hash ^= static_cast<uint64_t>(bytes[i]);
        *hash *= kFingerprintPrime;
    }
}

void FingerprintUint64(uint64_t* hash, uint64_t value) {
    FingerprintBytes(hash, &value, sizeof(value));
}

void FingerprintString(uint64_t* hash, std::string_view value) {
    FingerprintUint64(hash, value.size());
    if (!value.empty()) {
        FingerprintBytes(hash, value.data(), value.size());
    }
}

std::vector<std::string> SortedStringsFromSet(const std::unordered_set<std::string>& values) {
    std::vector<std::string> sorted(values.begin(), values.end());
    std::sort(sorted.begin(), sorted.end());
    return sorted;
}

uint64_t ComputeCompiledHideRuleFingerprint(const CompiledHideRule& rule) {
    uint64_t hash = kFingerprintOffsetBasis;
    FingerprintUint64(&hash, rule.enableHideAllRootEntries ? 1ULL : 0ULL);
    const auto sortedExemptions = SortedStringsFromSet(rule.hideAllRootEntriesExemptionSet);
    FingerprintUint64(&hash, sortedExemptions.size());
    for (const auto& value : sortedExemptions) {
        FingerprintString(&hash, value);
    }

    const auto sortedRootNames = SortedStringsFromSet(rule.hiddenRootEntryNameSet);
    FingerprintUint64(&hash, sortedRootNames.size());
    for (const auto& value : sortedRootNames) {
        FingerprintString(&hash, value);
    }

    const auto sortedRelativePaths =
        SortedStringsFromSet(rule.normalizedHiddenRelativePathExactSet);
    FingerprintUint64(&hash, sortedRelativePaths.size());
    for (const auto& value : sortedRelativePaths) {
        FingerprintString(&hash, value);
    }
    return hash != 0 ? hash : 1;
}

// Materialize the exact-match sets and prefix lists once per resolved rule so the hot policy path
// does not repeat normalization and linear scans.
std::shared_ptr<const CompiledHideRule> BuildCompiledHideRule(
    const CompiledHideRuleBuilder& builder) {
    if (!RuleHasTargets(builder)) {
        return nullptr;
    }

    auto compiled = std::make_shared<CompiledHideRule>();
    compiled->enableHideAllRootEntries = builder.enableHideAllRootEntries;
    compiled->hideAllRootEntriesExemptions = builder.hideAllRootEntriesExemptions;
    compiled->hiddenRootEntryNames = builder.hiddenRootEntryNames;
    compiled->hiddenRelativePaths = builder.hiddenRelativePaths;

    for (const auto& exemptEntry : compiled->hideAllRootEntriesExemptions) {
        const std::string canonicalExemptEntry = CanonicalizeHiddenEntryNameForMatch(exemptEntry);
        if (!canonicalExemptEntry.empty()) {
            compiled->hideAllRootEntriesExemptionSet.insert(canonicalExemptEntry);
        }
    }
    for (const auto& rootEntryName : compiled->hiddenRootEntryNames) {
        const std::string canonicalRootEntryName =
            CanonicalizeHiddenEntryNameForMatch(rootEntryName);
        if (!canonicalRootEntryName.empty()) {
            compiled->hiddenRootEntryNameSet.insert(canonicalRootEntryName);
        }
    }
    for (const auto& hiddenRelativePath : compiled->hiddenRelativePaths) {
        const std::string canonicalHiddenRelativePath =
            CanonicalizeRelativeHiddenPathForMatch(hiddenRelativePath);
        if (canonicalHiddenRelativePath.empty()) {
            continue;
        }
        compiled->normalizedHiddenRelativePathExactSet.insert(canonicalHiddenRelativePath);
        compiled->normalizedHiddenRelativePathPrefixes.push_back(canonicalHiddenRelativePath + "/");
        const size_t slash = canonicalHiddenRelativePath.find('/');
        const std::string_view firstComponent =
            slash == std::string::npos
                ? std::string_view(canonicalHiddenRelativePath)
                : std::string_view(canonicalHiddenRelativePath).substr(0, slash);
        if (!firstComponent.empty()) {
            compiled->hiddenRelativePathFirstComponentSet.emplace(firstComponent);
        }
        const size_t lastSlash = canonicalHiddenRelativePath.rfind('/');
        if (lastSlash != std::string::npos) {
            compiled->exactHiddenTargetParentRelativePathSet.emplace(
                canonicalHiddenRelativePath.substr(0, lastSlash));
        }
    }
    compiled->fingerprint = ComputeCompiledHideRuleFingerprint(*compiled);
    return compiled;
}

CompiledHideConfig BuildCompiledHideConfig(const HideConfig& config) {
    CompiledHideConfig compiledConfig;

    CompiledHideRuleBuilder globalBuilder;
    MergeGlobalRule(config, &globalBuilder);
    compiledConfig.globalRuleFragment = BuildCompiledHideRule(globalBuilder);

    CompiledHideRuleBuilder anyPackageBuilder = globalBuilder;
    std::unordered_map<std::string, CompiledHideRuleBuilder> packageBuilders;
    for (const auto& hiddenPackage : config.hiddenPackages) {
        compiledConfig.hiddenPackageSet.emplace(hiddenPackage);
    }
    for (const auto& packageRule : config.packageRules) {
        MergePackageRule(packageRule, &packageBuilders[packageRule.packageName]);
        MergePackageRule(packageRule, &anyPackageBuilder);
    }
    for (auto& [packageName, builder] : packageBuilders) {
        if (auto compiledRule = BuildCompiledHideRule(builder); compiledRule != nullptr) {
            compiledConfig.packageRuleFragments.emplace(packageName, std::move(compiledRule));
        }
    }
    compiledConfig.anyPackageRule = BuildCompiledHideRule(anyPackageBuilder);
    return compiledConfig;
}

std::shared_ptr<const CompiledHideConfig> MakeDefaultCompiledHideConfig() {
    return std::make_shared<const CompiledHideConfig>(BuildCompiledHideConfig(DefaultHideConfig()));
}

void InvalidateTrackedHideTargetsForCurrentConfig() {
    ScheduleHiddenEntryInvalidation();

    std::vector<uint64_t> inodesToInvalidate;
    {
        std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
        inodesToInvalidate.reserve(gInodePathCache.size());
        for (const auto& [ino, trackedPath] : gInodePathCache) {
            if (HiddenPathPolicy::IsAnyHiddenSubtreePath(trackedPath)) {
                inodesToInvalidate.push_back(ino);
            }
        }
    }
    for (const uint64_t ino : inodesToInvalidate) {
        RuntimeState::ScheduleHiddenInodeInvalidation(ino);
    }

    {
        std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
        gHiddenSubtreeInodeRules.clear();
    }
    {
        std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
        gRecentHiddenParentPaths.clear();
        gRecentHiddenParentPathUids.clear();
        gRecentHiddenParentPathAnyUid.clear();
        gRecentHiddenParentPathAnyUidOwner = 0;
    }
}

}  // namespace

HideConfig DefaultHideConfig() {
    HideConfig config;
    config.enableHideAllRootEntries = kEnableHideAllRootEntries;
    for (const auto& value : kHideAllRootEntriesExemptions) {
        config.hideAllRootEntriesExemptions.emplace_back(value);
    }
    for (const auto& value : kHiddenRootEntryNames) {
        config.hiddenRootEntryNames.emplace_back(value);
    }
    for (const auto& value : kHiddenRelativePaths) {
        config.hiddenRelativePaths.emplace_back(value);
    }
    for (const auto& value : kHiddenPackages) {
        config.hiddenPackages.emplace_back(value);
    }
    PackageHideRule fuseHideRule;
    fuseHideRule.packageName = std::string(kFuseHidePackageRulePackages[0]);
    for (const auto& value : kFuseHidePackageRuleRootEntries0) {
        fuseHideRule.hiddenRootEntryNames.emplace_back(value);
    }
    config.packageRules.emplace_back(std::move(fuseHideRule));

    PackageHideRule duckDetectorRule;
    duckDetectorRule.packageName = std::string(kFuseHidePackageRulePackages[1]);
    for (const auto& value : kFuseHidePackageRuleRootEntries1) {
        duckDetectorRule.hiddenRootEntryNames.emplace_back(value);
    }
    config.packageRules.emplace_back(std::move(duckDetectorRule));
    return config;
}

std::shared_ptr<const HideConfig> CurrentHideConfig() {
    return std::atomic_load_explicit(&gHideConfig, std::memory_order_acquire);
}

std::shared_ptr<const CompiledHideConfig> CurrentCompiledHideConfig() {
    auto compiledConfig =
        std::atomic_load_explicit(&gCompiledHideConfig, std::memory_order_acquire);
    if (compiledConfig != nullptr) {
        return compiledConfig;
    }
    static std::once_flag initOnce;
    // ApplyHideConfig() may publish a real config before lazy default init runs, so only install
    // the default when the shared pointer is still empty.
    std::call_once(initOnce, []() {
        if (std::atomic_load_explicit(&gCompiledHideConfig, std::memory_order_acquire) == nullptr) {
            std::atomic_store_explicit(&gCompiledHideConfig, MakeDefaultCompiledHideConfig(),
                                       std::memory_order_release);
        }
    });
    return std::atomic_load_explicit(&gCompiledHideConfig, std::memory_order_acquire);
}

void ApplyHideConfig(HideConfig config) {
    auto next = std::make_shared<const HideConfig>(std::move(config));
    auto compiledNext = std::make_shared<const CompiledHideConfig>(BuildCompiledHideConfig(*next));
    std::atomic_store_explicit(&gHideConfig, next, std::memory_order_release);
    std::atomic_store_explicit(&gCompiledHideConfig, std::move(compiledNext),
                               std::memory_order_release);
    const uint64_t generation = gHideConfigGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideRuleCache.clear();
    }
    ClearRootSnapshotCache();
    ClearHiddenPathClassificationCache();
    InvalidateTrackedHideTargetsForCurrentConfig();
    DebugLogPrint(4,
                  "applied hide config generation=%llu hide_all=%d exemptions=%zu roots=%zu "
                  "packages=%zu package_rules=%zu",
                  static_cast<unsigned long long>(generation),
                  CurrentHideConfig()->enableHideAllRootEntries ? 1 : 0,
                  CurrentHideConfig()->hideAllRootEntriesExemptions.size(),
                  CurrentHideConfig()->hiddenRootEntryNames.size(),
                  CurrentHideConfig()->hiddenPackages.size(),
                  CurrentHideConfig()->packageRules.size());
}

std::shared_ptr<const CompiledHideRule> RuleForAnyPackage() {
    return CurrentCompiledHideConfig()->anyPackageRule;
}

namespace {

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

}  // namespace

std::shared_ptr<const CompiledHideRule> ResolveHideRuleForUid(uint32_t uid) {
    const uint64_t configGeneration = gHideConfigGeneration.load(std::memory_order_acquire);
    const uint64_t packageSetGeneration = gUidPackageSetGeneration.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        const auto it = gUidHideRuleCache.find(uid);
        if (it != gUidHideRuleCache.end()) {
            if (it->second.configGeneration == configGeneration &&
                it->second.packageSetGeneration == packageSetGeneration) {
                return it->second.rule;
            }
            gUidHideRuleCache.erase(it);
        }
    }

    auto resolved = ResolveHideRuleForUidWithPackageManager(uid);
    if (!resolved.has_value()) {
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        if (gHideConfigGeneration.load(std::memory_order_acquire) == configGeneration &&
            gUidPackageSetGeneration.load(std::memory_order_acquire) == packageSetGeneration) {
            gUidHideRuleCache[uid] =
                UidHideRuleCacheEntry{configGeneration, packageSetGeneration, *resolved};
        }
    }
    return *resolved;
}

// Query PackageManager once per uid and cache the merged package rule for hot FUSE paths.
std::optional<std::shared_ptr<const CompiledHideRule>> ResolveHideRuleForUidWithPackageManager(
    uint32_t uid) {
    bool didAttach = false;
    JNIEnv* env = GetJniEnv(&didAttach);
    if (env == nullptr) {
        return std::nullopt;
    }

    auto finish = [&](std::optional<std::shared_ptr<const CompiledHideRule>> value) {
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
    if (applicationClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(application);
        return finish(std::nullopt);
    }
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
    if (packageManagerClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(packageManager);
        return finish(std::nullopt);
    }
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

    CompiledHideRuleBuilder merged;
    const auto compiledConfig = CurrentCompiledHideConfig();
    std::vector<std::string> packageNames;
    if (packages != nullptr) {
        const jsize count = env->GetArrayLength(packages);
        packageNames.reserve(static_cast<size_t>(count));
        for (jsize i = 0; i < count; ++i) {
            jstring packageName = static_cast<jstring>(env->GetObjectArrayElement(packages, i));
            if (packageName == nullptr) {
                continue;
            }
            const char* packageNameChars = env->GetStringUTFChars(packageName, nullptr);
            if (packageNameChars != nullptr) {
                packageNames.emplace_back(packageNameChars);
                env->ReleaseStringUTFChars(packageName, packageNameChars);
            }
            env->DeleteLocalRef(packageName);
        }
        env->DeleteLocalRef(packages);
    }

    // PackageManager order is not stable. Canonicalize the uid package set first so equivalent
    // inputs compile the same merged rule and fingerprint.
    std::sort(packageNames.begin(), packageNames.end());
    packageNames.erase(std::unique(packageNames.begin(), packageNames.end()), packageNames.end());
    for (const auto& packageName : packageNames) {
        if (compiledConfig->hiddenPackageSet.find(packageName) !=
                compiledConfig->hiddenPackageSet.end() &&
            compiledConfig->globalRuleFragment != nullptr) {
            merged.enableHideAllRootEntries =
                merged.enableHideAllRootEntries ||
                compiledConfig->globalRuleFragment->enableHideAllRootEntries;
            AppendUnique(&merged.hideAllRootEntriesExemptions,
                         compiledConfig->globalRuleFragment->hideAllRootEntriesExemptions);
            AppendUnique(&merged.hiddenRootEntryNames,
                         compiledConfig->globalRuleFragment->hiddenRootEntryNames);
            AppendUnique(&merged.hiddenRelativePaths,
                         compiledConfig->globalRuleFragment->hiddenRelativePaths);
        }
        const auto fragmentIt = compiledConfig->packageRuleFragments.find(packageName);
        if (fragmentIt != compiledConfig->packageRuleFragments.end() &&
            fragmentIt->second != nullptr) {
            AppendUnique(&merged.hiddenRootEntryNames, fragmentIt->second->hiddenRootEntryNames);
            AppendUnique(&merged.hiddenRelativePaths, fragmentIt->second->hiddenRelativePaths);
        }
    }

    if (!RuleHasTargets(merged)) {
        DebugLogPrint(4, "resolved uid=%u hide=0", static_cast<unsigned>(uid));
        return finish(std::shared_ptr<const CompiledHideRule>(nullptr));
    }
    auto compiledRule = BuildCompiledHideRule(merged);
    DebugLogPrint(4, "resolved uid=%u hide=1 roots=%zu rel=%zu hide_all=%d",
                  static_cast<unsigned>(uid), compiledRule->hiddenRootEntryNames.size(),
                  compiledRule->hiddenRelativePaths.size(),
                  compiledRule->enableHideAllRootEntries ? 1 : 0);
    return finish(compiledRule);
}

// Package add/remove can change the effective hide rule for an already-seen uid even when the
// serialized HideConfig stays the same, so invalidate every uid-derived cache on this edge.
void NotifyUidRulePackageSetChanged(std::string_view reason) {
    const uint64_t generation =
        gUidPackageSetGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideRuleCache.clear();
    }
    ClearRootSnapshotCache();
    ClearHiddenPathClassificationCache();
    InvalidateTrackedHideTargetsForCurrentConfig();
    DebugLogPrint(4, "invalidated uid hide rules reason=%s package_generation=%llu",
                  DebugPreview(reason).c_str(), static_cast<unsigned long long>(generation));
}

uint64_t EffectiveHideRuleFingerprint(const std::shared_ptr<const CompiledHideRule>& rule) {
    return rule != nullptr ? rule->fingerprint : 0;
}

// fingerprint only selects a cache bucket. Semantic equality turns the rare collision case into a
// cache miss instead of reusing a root snapshot built for different hide semantics.
bool CompiledHideRulesSemanticallyEqual(const std::shared_ptr<const CompiledHideRule>& lhs,
                                        const std::shared_ptr<const CompiledHideRule>& rhs) {
    if (lhs == rhs) {
        return true;
    }
    if (lhs == nullptr || rhs == nullptr) {
        return false;
    }
    return lhs->enableHideAllRootEntries == rhs->enableHideAllRootEntries &&
           lhs->hideAllRootEntriesExemptionSet == rhs->hideAllRootEntriesExemptionSet &&
           lhs->hiddenRootEntryNameSet == rhs->hiddenRootEntryNameSet &&
           lhs->normalizedHiddenRelativePathExactSet == rhs->normalizedHiddenRelativePathExactSet;
}

}  // namespace fusehide
