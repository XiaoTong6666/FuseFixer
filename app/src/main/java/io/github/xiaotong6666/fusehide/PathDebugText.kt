/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
