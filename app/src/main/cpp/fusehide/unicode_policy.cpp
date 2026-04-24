#include "state.hpp"

namespace fusehide {

std::string UnicodePolicy::DebugPreview(std::string_view value, size_t limit) {
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

void UnicodePolicy::LogSuspiciousDirectPath(const char* hookName, std::string_view path) {
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

// Logging helpers match the original log format closely enough to compare traces.

// Escape for logging: printable ASCII as-is, else \xHH.
// Original builds a std::string internally for the escaped form.
std::string UnicodePolicy::EscapeForLog(const uint8_t* data, size_t length) {
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
void UnicodePolicy::LogInvalidUtf8(const uint8_t* data, size_t dataLen, size_t begin, size_t end) {
    const std::string escaped = EscapeForLog(data, dataLen);
    __android_log_print(5, kLogTag, "invalid char at %zu-%zu : %s", begin, end, escaped.c_str());
}

// Inline UTF-8 decoder that mirrors the hand-rolled logic seen in the device binary.
// The reverse-engineered build validates 3-byte and 4-byte sequences through internal lookup
// tables; here we express the same rules with explicit range checks.

// Returns: true if a valid code point was decoded. Sets *cp and *width.
// On failure, returns false. Caller decides how to handle invalid bytes.
bool UnicodePolicy::DecodeUtf8CodePoint(const uint8_t* data, size_t len, size_t index, uint32_t* cp,
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

size_t UnicodePolicy::InvalidUtf8SpanEnd(const uint8_t* data, size_t len, size_t index) {
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

// Checks whether the path contains any default-ignorable code point that the original
// binary strips before comparing package-owned and app-accessible paths.

bool UnicodePolicy::NeedsSanitization(const std::string& input) {
    const auto* data = reinterpret_cast<const uint8_t*>(input.data());
    const size_t len = input.size();

    for (size_t i = 0; i < len;) {
        uint32_t cp = 0;
        size_t width = 0;

        if (data[i] < 0x80) {
            // ASCII code points are never default-ignorable.
            cp = data[i];
            width = 1;
        } else {
            if (!DecodeUtf8CodePoint(data, len, i, &cp, &width)) {
                // Invalid UTF-8 is treated as non-ignorable here, matching the device build.
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

// Rewrites a string in place, stripping default-ignorable code points the same way the
// device binary does before delegating to MediaProvider policy helpers.

void UnicodePolicy::RewriteString(std::string& input) {
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

// ASCII case folding matches the lookup-table behavior seen in the analyzed device binary.

static char FoldAscii(uint8_t ch) {
    return static_cast<char>(std::tolower(ch));
}

// This is the core comparison routine used by the sanitizing wrappers below.
// The control flow mirrors the device binary's case-folding compare logic.
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
// The final return is the byte-wise difference after ASCII folding, which matches the original
// table-driven implementation.

int UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(const uint8_t* lhsData, size_t lhsLen,
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
        // Advance lhs past ignorable code points.
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

        // Advance rhs past ignorable code points.
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

        // Compare the current bytes after ASCII folding.
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
    // If both sides are exhausted, return equality. Otherwise return the folded byte difference.
    {
        const uint8_t lhsByte =
            (lhsIdx < lhsLen) ? static_cast<uint8_t>(FoldAscii(lhsData[lhsIdx])) : 0;
        const uint8_t rhsByte =
            (rhsIdx < rhsLen) ? static_cast<uint8_t>(FoldAscii(rhsData[rhsIdx])) : 0;
        return static_cast<int>(lhsByte) - static_cast<int>(rhsByte);
    }
}

std::string DebugPreview(std::string_view value, size_t limit) {
    return UnicodePolicy::DebugPreview(value, limit);
}

std::string EscapeForLog(const uint8_t* data, size_t length) {
    return UnicodePolicy::EscapeForLog(data, length);
}

void LogInvalidUtf8(const uint8_t* data, size_t dataLen, size_t begin, size_t end) {
    UnicodePolicy::LogInvalidUtf8(data, dataLen, begin, end);
}

void LogSuspiciousDirectPath(const char* hookName, std::string_view path) {
    UnicodePolicy::LogSuspiciousDirectPath(hookName, path);
}

bool DecodeUtf8CodePoint(const uint8_t* data, size_t len, size_t index, uint32_t* cp,
                         size_t* width) {
    return UnicodePolicy::DecodeUtf8CodePoint(data, len, index, cp, width);
}

size_t InvalidUtf8SpanEnd(const uint8_t* data, size_t len, size_t index) {
    return UnicodePolicy::InvalidUtf8SpanEnd(data, len, index);
}

bool NeedsSanitization(const std::string& input) {
    return UnicodePolicy::NeedsSanitization(input);
}

void RewriteString(std::string& input) {
    UnicodePolicy::RewriteString(input);
}

int CompareCaseFoldIgnoringDefaultIgnorables(const uint8_t* lhsData, size_t lhsLen,
                                             const uint8_t* rhsData, size_t rhsLen) {
    return UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(lhsData, lhsLen, rhsData,
                                                                   rhsLen);
}

}  // namespace fusehide
