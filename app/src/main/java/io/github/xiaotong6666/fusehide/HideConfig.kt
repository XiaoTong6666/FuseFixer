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
