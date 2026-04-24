package io.github.xiaotong6666.fusehide

import java.util.regex.Pattern

object PathDebugText {
    private val unicodeEscapePattern: Pattern = Pattern.compile("\\\\u([0-9a-fA-F]{4})")

    fun escapeNonAscii(input: String): String {
        val builder = StringBuilder()
        input.forEach { ch ->
            if (ch < ' ' || ch > '~') {
                builder.append("\\u")
                builder.append(String.format("%04x", ch.code))
            } else {
                builder.append(ch)
            }
        }
        return builder.toString()
    }

    fun unescapeUnicodeLiterals(input: String?): String? {
        if (input == null) return null
        val matcher = unicodeEscapePattern.matcher(input)
        val buffer = StringBuffer()
        while (matcher.find()) {
            matcher.appendReplacement(buffer, Character.toString(matcher.group(1)!!.toInt(16).toChar()))
        }
        matcher.appendTail(buffer)
        return buffer.toString()
    }
}
