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

data class HideConfig(
    val enableHideAllRootEntries: Boolean,
    val hideAllRootEntriesExemptions: List<String>,
    val hiddenRootEntryNames: List<String>,
    val hiddenRelativePaths: List<String>,
    val hiddenPackages: List<String>,
)

object HideConfigDefaults {
    val value: HideConfig by lazy {
        HideConfig(
            enableHideAllRootEntries = HideConfigNativeBridge.getDefaultEnableHideAllRootEntries(),
            hideAllRootEntriesExemptions =
            HideConfigNativeBridge.getDefaultHideAllRootEntriesExemptions().toList(),
            hiddenRootEntryNames = HideConfigNativeBridge.getDefaultHiddenRootEntryNames().toList(),
            hiddenRelativePaths = HideConfigNativeBridge.getDefaultHiddenRelativePaths().toList(),
            hiddenPackages = HideConfigNativeBridge.getDefaultHiddenPackages().toList(),
        )
    }

    fun toEditorText(values: List<String>): String = values.joinToString("\n")

    fun parseEditorText(text: String): List<String> = text.lineSequence()
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinct()
        .toList()
}
