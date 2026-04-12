#include <android/log.h>
#include <dirent.h>
#include <elf.h>
#include <link.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "third_party/xz-embedded/linux_xz.h"
#ifdef __cplusplus
}
#endif

#include <algorithm>
#include <cctype>
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char* kLogTag = "FuseFixer";
constexpr const char* kTargetLibrary = "libfuse_jni.so";

// Original binary directly imports u_hasBinaryProperty from libicu.so.
using UHasBinaryPropertyFn = int8_t (*)(uint32_t codePoint, int32_t which);
extern "C" int8_t u_hasBinaryProperty(uint32_t codePoint, int32_t which);
UHasBinaryPropertyFn gUHasBinaryProperty = u_hasBinaryProperty;

constexpr int32_t kUCHAR_DEFAULT_IGNORABLE_CODE_POINT = 5;

// Hook symbol names

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
std::atomic<int> gSuspiciousDirectLogCount{0};
std::string EscapeForLog(const uint8_t* data, size_t length);

bool ShouldLogLimited(std::atomic<int>& counter, int limit = 8) {
    const int old = counter.fetch_add(1, std::memory_order_relaxed);
    return old < limit;
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

// Logging helpers — match original log format exactly

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

// UTF-8 decoder — inline, matching the original's hand-rolled decoder
// The original binary uses lookup tables at DAT_0010a21a and DAT_0010c3ac for
// 3-byte and 4-byte sequence validation. We replicate the logic with explicit
// range checks, which is equivalent.

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

// NeedsSanitization
// Checks if std::string contains any default-ignorable code point.
// Original reads from the SSO std::string representation directly.

bool NeedsSanitization(const std::string& input) {
    const auto* data = reinterpret_cast<const uint8_t*>(input.data());
    const size_t len = input.size();

    for (size_t i = 0; i < len;) {
        uint32_t cp = 0;
        size_t width = 0;

        if (data[i] < 0x80) {
            // ASCII — can never be default-ignorable
            cp = data[i];
            width = 1;
        } else {
            if (!DecodeUtf8CodePoint(data, len, i, &cp, &width)) {
                // Invalid UTF-8 — original returns 0 (not ignorable, skip)
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

// RewriteString
// Rewrites a std::string in-place, stripping default-ignorable code points.
// Original operates on the std::string's internal buffer, copying non-ignorable
// bytes forward with memmove-style logic, then truncating.
// When invalid UTF-8 is encountered, it logs the ENTIRE original string with
// "invalid char at %zu-%zu : %s" at level 5, then stops processing (leaves
// invalid bytes in place).

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

// ASCII case-fold table — matches DAT_0010c2ac in the original binary
// The original uses a 256-byte lookup table at DAT_0010c2ac for case folding.
// For ASCII letters, tolower; for everything else, identity.

static char FoldAscii(uint8_t ch) {
    return static_cast<char>(std::tolower(ch));
}

// CompareCaseFoldIgnoringDefaultIgnorables
// This is the core comparison function. The original's control flow:
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
// The final return is: FoldAscii(lhs[lhsIdx]) - FoldAscii(rhs[rhsIdx])
// (computed from the table lookup, matching the original's
//  DAT_0010c2ac[lhs_byte] - DAT_0010c2ac[rhs_byte])

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
        // --- Advance lhs past ignorables ---
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

        // --- Advance rhs past ignorables ---
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

        // --- Compare current bytes (case-folded) ---
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
    // Original returns: DAT_0010c2ac[lhs_byte] - DAT_0010c2ac[rhs_byte]
    // If both exhausted, both indices point past end, so we get 0.
    {
        const uint8_t lhsByte =
            (lhsIdx < lhsLen) ? static_cast<uint8_t>(FoldAscii(lhsData[lhsIdx])) : 0;
        const uint8_t rhsByte =
            (rhsIdx < rhsLen) ? static_cast<uint8_t>(FoldAscii(rhsData[rhsIdx])) : 0;
        return static_cast<int>(lhsByte) - static_cast<int>(rhsByte);
    }
}

// Path hook wrappers

// WrappedIsAppAccessiblePath
// Original: check NeedsSanitization → if no, call original directly.
// If yes: copy the string, RewriteString on the copy, call original with copy.
bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid) {
    if (gOriginalIsAppAccessiblePath == nullptr) {
        return false;
    }
    if (!NeedsSanitization(path)) {
        LogSuspiciousDirectPath("app_accessible", path);
        if (ShouldLogLimited(gAppAccessibleLogCount)) {
            __android_log_print(3, kLogTag, "app_accessible direct uid=%u path=%s", uid,
                                DebugPreview(path).c_str());
        }
        return gOriginalIsAppAccessiblePath(fuse, path, uid);
    }
    std::string sanitized(path);
    RewriteString(sanitized);
    if (ShouldLogLimited(gAppAccessibleLogCount)) {
        __android_log_print(3, kLogTag, "app_accessible rewrite uid=%u old=%s new=%s", uid,
                            DebugPreview(path).c_str(), DebugPreview(sanitized).c_str());
    }
    return gOriginalIsAppAccessiblePath(fuse, sanitized, uid);
}

// WrappedIsPackageOwnedPath
// Original: checks NeedsSanitization on FIRST param only (param_9, which is lhs).
// If no need, calls original directly.
// If needs sanitization: copy first param, rewrite it, call original with copy + original rhs.
bool WrappedIsPackageOwnedPath(const std::string& lhs, const std::string& rhs) {
    if (gOriginalIsPackageOwnedPath == nullptr) {
        return false;
    }
    if (!NeedsSanitization(lhs)) {
        LogSuspiciousDirectPath("package_owned", lhs);
        if (ShouldLogLimited(gPackageOwnedLogCount)) {
            __android_log_print(3, kLogTag, "package_owned direct lhs=%s rhs=%s",
                                DebugPreview(lhs).c_str(), DebugPreview(rhs).c_str());
        }
        return gOriginalIsPackageOwnedPath(lhs, rhs);
    }
    std::string sanitizedLhs(lhs);
    RewriteString(sanitizedLhs);
    if (ShouldLogLimited(gPackageOwnedLogCount)) {
        __android_log_print(3, kLogTag, "package_owned rewrite lhs=%s new=%s rhs=%s",
                            DebugPreview(lhs).c_str(), DebugPreview(sanitizedLhs).c_str(),
                            DebugPreview(rhs).c_str());
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
            __android_log_print(3, kLogTag, "bpf_backing direct path=%s",
                                DebugPreview(path).c_str());
        }
        return gOriginalIsBpfBackingPath(path);
    }
    std::string sanitized(path);
    RewriteString(sanitized);
    if (ShouldLogLimited(gBpfBackingLogCount)) {
        __android_log_print(3, kLogTag, "bpf_backing rewrite old=%s new=%s",
                            DebugPreview(path).c_str(), DebugPreview(sanitized).c_str());
    }
    return gOriginalIsBpfBackingPath(sanitized);
}

// WrappedStrcasecmp
// Original: strlen both, then call CompareCaseFoldIgnoringDefaultIgnorables
extern "C" int WrappedStrcasecmp(const char* lhs, const char* rhs) {
    const size_t lhsLen = (lhs != nullptr) ? std::strlen(lhs) : 0;
    const size_t rhsLen = (rhs != nullptr) ? std::strlen(rhs) : 0;
    const int result = CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhs ? lhs : ""), lhsLen,
        reinterpret_cast<const uint8_t*>(rhs ? rhs : ""), rhsLen);
    if (ShouldLogLimited(gStrcasecmpLogCount)) {
        __android_log_print(3, kLogTag, "strcasecmp lhs=%s rhs=%s result=%d",
                            DebugPreview(std::string_view(lhs ? lhs : "", lhsLen)).c_str(),
                            DebugPreview(std::string_view(rhs ? rhs : "", rhsLen)).c_str(), result);
    }
    return result;
}

// ABI wrapper for EqualsIgnoreCase — string_view is passed as (ptr, size) pairs
extern "C" bool WrappedEqualsIgnoreCaseAbi(const char* lhsData, size_t lhsSize, const char* rhsData,
                                           size_t rhsSize) {
    const int result = CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhsData ? lhsData : ""), lhsSize,
        reinterpret_cast<const uint8_t*>(rhsData ? rhsData : ""), rhsSize);
    if (ShouldLogLimited(gEqualsIgnoreCaseLogCount)) {
        __android_log_print(3, kLogTag, "equals_ignore_case lhs=%s rhs=%s result=%d",
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

        // Original does NOT restore mprotect permissions
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

bool InstallHookForSymbol(std::string_view symbolName, void* replacement, void** backup,
                          const char* failureMessage) {
    if (gHookInstaller == nullptr) {
        __android_log_print(6, kLogTag, "hook installer is null for %s", failureMessage);
        return false;
    }
    auto module = FindTargetModule();
    if (!module.has_value()) {
        __android_log_print(6, kLogTag, "no %s found", kTargetLibrary);
        return false;
    }
    const bool useRuntimeElf = module->path.find("!/") != std::string::npos;
    auto target = useRuntimeElf ? ResolveTargetSymbolRuntime(*module, symbolName)
                                : ResolveTargetSymbol(*module, symbolName);
    if (!target.has_value()) {
        __android_log_print(3, kLogTag, "resolve failed %s", std::string(symbolName).c_str());
        return false;
    }
    const int status = gHookInstaller(*target, replacement, backup);
    if (status != 0) {
        __android_log_print(6, kLogTag, "%s: %d", failureMessage, status);
        return false;
    }
    __android_log_print(4, kLogTag, "inline hook ok %s target=%p backup=%p",
                        std::string(symbolName).c_str(), *target,
                        backup != nullptr ? *backup : nullptr);
    return true;
}

// Main initialization — InstallFuseHooks

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

    // Path hooks (inline hook via framework installer)

    // is_app_accessible_path
    for (const auto& sym : kIsAppAccessiblePathSymbols) {
        if (InstallHookForSymbol(sym, reinterpret_cast<void*>(+WrappedIsAppAccessiblePath),
                                 reinterpret_cast<void**>(&gOriginalIsAppAccessiblePath),
                                 "hook is_app_accessible_path failed")) {
            break;
        }
    }

    // is_package_owned_path
    for (const auto& sym : kIsPackageOwnedPathSymbols) {
        auto target = useRuntimeElf ? ResolveTargetSymbolRuntime(*module, sym)
                                    : ResolveTargetSymbol(*module, sym);
        if (!target.has_value())
            continue;
        const int status =
            gHookInstaller(*target, reinterpret_cast<void*>(+WrappedIsPackageOwnedPath),
                           reinterpret_cast<void**>(&gOriginalIsPackageOwnedPath));
        if (status != 0) {
            __android_log_print(6, kLogTag, "hook is_package_owned_path failed: %d", status);
            continue;
        }
        break;
    }

    // is_bpf_backing_path
    for (const auto& sym : kIsBpfBackingPathSymbols) {
        auto target = useRuntimeElf ? ResolveTargetSymbolRuntime(*module, sym)
                                    : ResolveTargetSymbol(*module, sym);
        if (!target.has_value())
            continue;
        const int status =
            gHookInstaller(*target, reinterpret_cast<void*>(+WrappedIsBpfBackingPath),
                           reinterpret_cast<void**>(&gOriginalIsBpfBackingPath));
        if (status != 0) {
            __android_log_print(6, kLogTag, "hook is_bpf_backing_path failed: %d", status);
            continue;
        }
        break;
    }

    __android_log_print(4, kLogTag,
                        "hook summary app=%p package=%p bpf=%p strcasecmp=%p equals=%p icu=%p",
                        reinterpret_cast<void*>(gOriginalIsAppAccessiblePath),
                        reinterpret_cast<void*>(gOriginalIsPackageOwnedPath),
                        reinterpret_cast<void*>(gOriginalIsBpfBackingPath), gOriginalStrcasecmp,
                        gOriginalEqualsIgnoreCase, reinterpret_cast<void*>(gUHasBinaryProperty));

    // Compare hooks (relocation/GOT patching)

    // Need to build ELF info for compare hook installer
    const int ps = getpagesize();
    if (useRuntimeElf) {
        auto runtimeDyn = ParseRuntimeDynamicInfo(*module);
        if (!runtimeDyn.has_value()) {
            __android_log_print(6, kLogTag, "init runtime elf failed");
            return;
        }
        __android_log_print(
            4, kLogTag,
            "runtime dyn ok symtab=%p strtab=%p gnuHash=%p hash=%p jmprel=%p rela=%p rel=%p",
            runtimeDyn->symtab, runtimeDyn->strtab, runtimeDyn->gnuHash, runtimeDyn->hash,
            reinterpret_cast<void*>(runtimeDyn->jmprel), reinterpret_cast<void*>(runtimeDyn->rela),
            reinterpret_cast<void*>(runtimeDyn->rel));

        auto installRuntimeCompareHook = [&](std::string_view primary, std::string_view alt,
                                             void* replacement, void** backup, const char* label) {
            auto idx = FindRuntimeSymbolIndex(
                *runtimeDyn, reinterpret_cast<const uint8_t*>(primary.data()), primary.size());
            std::vector<uintptr_t> slots;
            if (idx.has_value()) {
                slots = FindRuntimeRelocationSlotsForSymbol(*runtimeDyn, *idx, module->base);
            }
            if (slots.empty() && !alt.empty()) {
                idx = FindRuntimeSymbolIndex(
                    *runtimeDyn, reinterpret_cast<const uint8_t*>(alt.data()), alt.size());
                if (idx.has_value()) {
                    slots = FindRuntimeRelocationSlotsForSymbol(*runtimeDyn, *idx, module->base);
                }
            }
            if (slots.empty()) {
                __android_log_print(6, kLogTag, "no %s found", label);
                return;
            }
            __android_log_print(4, kLogTag, "compare hook %s slots=%zu", label, slots.size());
            for (const auto slotAddr : slots) {
                auto* slot = reinterpret_cast<void**>(slotAddr);
                const uintptr_t pageMask = ~static_cast<uintptr_t>(ps - 1);
                auto* pageStart = reinterpret_cast<void*>(slotAddr & pageMask);
                if (mprotect(pageStart, ps, PROT_READ | PROT_WRITE) < 0) {
                    const int err = errno;
                    __android_log_print(6, kLogTag, "failed with %d %s: mprotect", err,
                                        strerror(err));
                    continue;
                }
                if (backup != nullptr) {
                    *backup = *slot;
                }
                *slot = replacement;
                __android_log_print(3, kLogTag, "patched %s slot=%p old=%p new=%p", label,
                                    reinterpret_cast<void*>(slotAddr),
                                    backup != nullptr ? *backup : nullptr, replacement);
                FlushCodeRange(pageStart, reinterpret_cast<void*>((slotAddr + ps) & pageMask));
            }
        };

        installRuntimeCompareHook(kStrcasecmpSymbol, kStrcasecmpSymbol,
                                  reinterpret_cast<void*>(+WrappedStrcasecmp), &gOriginalStrcasecmp,
                                  "strcasecmp");
        installRuntimeCompareHook(kEqualsIgnoreCaseSymbols[0], kEqualsIgnoreCaseSymbols[1],
                                  reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                                  &gOriginalEqualsIgnoreCase, "EqualsIgnoreCase");
    } else {
        auto mapped = MapReadOnlyFile(module->path);
        if (!mapped.has_value()) {
            __android_log_print(6, kLogTag, "init elf failed");
            return;
        }

        auto dynInfo = ParseDynamicInfo(*mapped);
        if (!dynInfo.has_value()) {
            __android_log_print(6, kLogTag, "init elf for dyn failed");
            return;
        }

        __android_log_print(
            4, kLogTag, "dyn ok symtab=%p strtab=%p gnuHash=%p hash=%p jmprel=%p rela=%p rel=%p",
            reinterpret_cast<void*>(dynInfo->symtab), reinterpret_cast<void*>(dynInfo->strtab),
            reinterpret_cast<void*>(dynInfo->gnuHash), reinterpret_cast<void*>(dynInfo->hash),
            reinterpret_cast<void*>(dynInfo->jmprel), reinterpret_cast<void*>(dynInfo->rela),
            reinterpret_cast<void*>(dynInfo->rel));

        ElfInfo elfInfo;
        elfInfo.loadBias = module->base;
        elfInfo.pageSize = ps;
        elfInfo.pageSizeRaw = ps;
        elfInfo.mapped = &*mapped;
        elfInfo.dynInfo = &*dynInfo;

        InstallCompareHook(elfInfo, kStrcasecmpSymbol, kStrcasecmpSymbol,
                           reinterpret_cast<void*>(+WrappedStrcasecmp), &gOriginalStrcasecmp,
                           "strcasecmp");
        InstallCompareHook(elfInfo, kEqualsIgnoreCaseSymbols[0], kEqualsIgnoreCaseSymbols[1],
                           reinterpret_cast<void*>(+WrappedEqualsIgnoreCaseAbi),
                           &gOriginalEqualsIgnoreCase, "EqualsIgnoreCase");
    }
}

// Entry points

extern "C" void PostNativeInit(const char* loadedLibrary, void*) {
    if (loadedLibrary == nullptr || std::strstr(loadedLibrary, kTargetLibrary) == nullptr) {
        return;
    }
    InstallFuseHooks();
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void* native_init(void* api) {
    __android_log_print(4, kLogTag, "Loaded");
    if (api != nullptr) {
        gHookInstaller = reinterpret_cast<const NativeApiEntries*>(api)->hookFunc;
    }
    return reinterpret_cast<void*>(+PostNativeInit);
}
