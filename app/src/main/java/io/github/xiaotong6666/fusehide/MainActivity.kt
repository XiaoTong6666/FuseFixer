package io.github.xiaotong6666.fusehide

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.IntentFilter
import android.os.Binder
import android.os.Build
import android.os.Bundle
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructUtsname
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.xiaotong6666.fusehide.ui.theme.fuseHideTheme
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Checkbox
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.basic.TabRowWithContour
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

private data class HideConfigDiff(
    val hasDifferences: Boolean,
    val summary: String,
    val details: String,
)

class MainActivity : ComponentActivity() {
    companion object {
        private const val APP_PACKAGE = "io.github.xiaotong6666.fusehide"
        private const val ACTION_GET_STATUS = "$APP_PACKAGE.GET_STATUS"
        private const val ACTION_SET_STATUS = "$APP_PACKAGE.SET_STATUS"
        private const val EXTRA_DEBUG_PATH = "debug_path"
        private const val EXTRA_DEBUG_ACTIONS = "debug_actions"

        fun onStatusBinderReleased(activity: MainActivity, referenceQueue: ReferenceQueue<Binder>) {
            try {
                Thread.sleep(2000L)
                Runtime.getRuntime().gc()
                Log.d("FuseHide", "polling ref ...")
                Log.d("FuseHide", "polled = ${referenceQueue.remove()}")
                activity.statusBinderReference = null
                activity.runOnUiThread(MainThreadTask(1, activity))
            } catch (_: InterruptedException) {
                Log.d("FuseHide", "return")
            }
        }

        fun getBooleanSystemProperty(name: String): Boolean = try {
            Class.forName("android.os.SystemProperties")
                .getDeclaredMethod("getBoolean", String::class.java, Boolean::class.javaPrimitiveType)
                .invoke(null, name, false) as Boolean
        } catch (th: Throwable) {
            Log.e("FuseHide", "getProp", th)
            false
        }
    }

    private var infoText by mutableStateOf("")
    private var statusText by mutableStateOf("")
    private var selectedTab by mutableStateOf(0)
    private var configStatusText by mutableStateOf("")
    private var lastAckTokenText by mutableStateOf("-")
    private var lastAckResultText by mutableStateOf("-")
    private var lastApplyTimeText by mutableStateOf("-")
    private var appliedHideConfig: HideConfig? by mutableStateOf(null)
    private var appliedConfigSnapshotText by mutableStateOf("")
    private var highlightConfigResults by mutableStateOf(false)
    private var configResultsScrollToken by mutableStateOf(0)
    private var shouldAutoScrollConfigResults by mutableStateOf(false)
    private var enableHideAllRootEntries by mutableStateOf(HideConfigDefaults.value.enableHideAllRootEntries)
    private var hideAllRootEntriesExemptionsText by mutableStateOf(
        HideConfigDefaults.toEditorText(HideConfigDefaults.value.hideAllRootEntriesExemptions),
    )
    private var hiddenTargetsText by mutableStateOf(
        HideConfigDefaults.toEditorText(
            HideConfigDefaults.value.hiddenRootEntryNames + HideConfigDefaults.value.hiddenRelativePaths,
        ),
    )
    private var hiddenPackagesText by mutableStateOf(
        HideConfigDefaults.toEditorText(HideConfigDefaults.value.hiddenPackages),
    )
    private var pathText by mutableStateOf(defaultPath())
    private var pathText2 by mutableStateOf("")
    private var outputText by mutableStateOf("")

    private var hookedPackage: String? = null
    private var hookedPid: Int = -1
    private var statusBinderReference: WeakReference<Binder>? = null
    private var hookCheckCompleted: Boolean = false
    private var statusCheckInFlight: Boolean = false
    private var statusCheckThread: Thread? = null
    private lateinit var statusReceiver: StatusBroadcastReceiver
    private lateinit var configStatusReceiver: BroadcastReceiver
    private lateinit var appliedConfigReceiver: BroadcastReceiver
    private var pendingReloadToken: String? = null
    private var pendingQueryToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        appendInfo()
        applyConfigToEditor(HideConfigStore.load(this))
        configStatusText = getString(R.string.config_loaded_saved) + "\n"
        appliedConfigSnapshotText = getString(R.string.config_snapshot_missing) + "\n"

        statusReceiver = StatusBroadcastReceiver(this, 1)
        val filter = IntentFilter(ACTION_SET_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, 2)
        } else {
            registerReceiver(statusReceiver, filter)
        }

        configStatusReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: android.content.Context?, intent: Intent?) {
                val token = intent?.getStringExtra(HideConfigStore.EXTRA_RELOAD_TOKEN)
                if (token == null || token != pendingReloadToken) {
                    return
                }
                pendingReloadToken = null
                val applied = intent.getBooleanExtra(HideConfigStore.EXTRA_RELOAD_APPLIED, false)
                val message = intent.getStringExtra(HideConfigStore.EXTRA_RELOAD_MESSAGE) ?: "unknown"
                lastAckTokenText = token
                lastAckResultText = getString(if (applied) R.string.ack_applied else R.string.ack_failed)
                lastApplyTimeText = formatNow()
                highlightConfigResults = !applied
                configStatusText = if (applied) {
                    refreshAppliedConfig(autoScrollToResults = true)
                    getString(R.string.config_applied_ok) + "\n"
                } else {
                    getString(R.string.config_applied_fail, message) + "\n"
                }
                if (!applied) {
                    shouldAutoScrollConfigResults = true
                    configResultsScrollToken += 1
                }
            }
        }
        val configFilter = IntentFilter(HideConfigStore.ACTION_SET_CONFIG_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(configStatusReceiver, configFilter, RECEIVER_EXPORTED)
        } else {
            registerReceiver(configStatusReceiver, configFilter)
        }

        appliedConfigReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: android.content.Context?, intent: Intent?) {
                val token = intent?.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN)
                if (token == null || token != pendingQueryToken) {
                    return
                }
                pendingQueryToken = null
                val config = HideConfigStore.fromBundle(intent.extras)
                appliedHideConfig = config
                appliedConfigSnapshotText = if (config == null) {
                    getString(R.string.config_snapshot_missing) + "\n"
                } else {
                    buildAppliedConfigSnapshot(config)
                }
                highlightConfigResults = config == null || buildDraftVsAppliedDiff(currentHideConfig(), config).hasDifferences
                if (shouldAutoScrollConfigResults) {
                    configResultsScrollToken += 1
                    shouldAutoScrollConfigResults = false
                }
            }
        }
        val appliedConfigFilter = IntentFilter(HideConfigStore.ACTION_SET_APPLIED_HIDE_CONFIG)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(appliedConfigReceiver, appliedConfigFilter, RECEIVER_EXPORTED)
        } else {
            registerReceiver(appliedConfigReceiver, appliedConfigFilter)
        }

        setContent {
            fuseHideTheme {
                fuseFixerHomeScreen(
                    selectedTab = selectedTab,
                    onTabSelected = { selectedTab = it },
                    infoText = infoText,
                    statusText = statusText,
                    isHooked = hookedPackage != null,
                    hookedPackage = hookedPackage,
                    hookedPid = hookedPid,
                    hookCheckCompleted = hookCheckCompleted,
                    configStatusText = configStatusText,
                    lastAckTokenText = lastAckTokenText,
                    lastAckResultText = lastAckResultText,
                    lastApplyTimeText = lastApplyTimeText,
                    draftVsAppliedDiff = buildDraftVsAppliedDiff(currentHideConfig(), appliedHideConfig),
                    appliedConfigSnapshotText = appliedConfigSnapshotText,
                    highlightConfigResults = highlightConfigResults,
                    configResultsScrollToken = configResultsScrollToken,
                    enableHideAllRootEntries = enableHideAllRootEntries,
                    hideAllRootEntriesExemptionsText = hideAllRootEntriesExemptionsText,
                    hiddenTargetsText = hiddenTargetsText,
                    hiddenPackagesText = hiddenPackagesText,
                    pathText = pathText,
                    pathText2 = pathText2,
                    outputText = outputText,
                    onStatusClick = ::startStatusCheck,
                    onEnableHideAllRootEntriesChanged = { enableHideAllRootEntries = it },
                    onHideAllRootEntriesExemptionsChanged = { hideAllRootEntriesExemptionsText = it },
                    onHiddenTargetsChanged = { hiddenTargetsText = it },
                    onHiddenPackagesChanged = { hiddenPackagesText = it },
                    onSaveConfigClick = ::saveHideConfig,
                    onApplyConfigClick = ::applyHideConfig,
                    onResetConfigClick = ::resetHideConfigToDefaults,
                    onRefreshAppliedConfigClick = ::refreshAppliedConfig,
                    onPathChanged = { pathText = it },
                    onPath2Changed = { pathText2 = it },
                    onStatClick = { runPathCheck(0) },
                    onAccessClick = { runPathCheck(1) },
                    onListClick = { runPathCheck(2) },
                    onOpenClick = { runPathCheck(3) },
                    onGetConClick = { runPathCheck(4) },
                    onCreateClick = { runPathCheck(5) },
                    onMkdirClick = { runPathCheck(6) },
                    onMoveClick = { runPathCheck(7) },
                    onRmdirClick = { runPathCheck(8) },
                    onUnlinkClick = { runPathCheck(9) },
                    onAllPkgClick = ::runAllPkgCheck,
                    onInsertZwjClick = ::insertZwj,
                    onClearClick = { outputText = "" },
                    onResetClick = { pathText = defaultPath() },
                    onCopyAllClick = ::copyAll,
                    onSelfDataClick = { appendOutput("external files dir: ${getExternalFilesDir("")}\n") },
                )
            }
        }

        startStatusCheck()
        refreshAppliedConfig(autoScrollToResults = false)
        handleDebugIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDebugIntent(intent)
    }

    private fun handleDebugIntent(intent: Intent?) {
        val debugPath = intent?.getStringExtra(EXTRA_DEBUG_PATH)
        if (debugPath.isNullOrEmpty()) {
            return
        }
        selectedTab = 1
        pathText = debugPath
        val debugActions = intent.getStringExtra(EXTRA_DEBUG_ACTIONS)
        Log.d("FuseHide", "handleDebugIntent path=$debugPath actions=$debugActions")
        appendOutput("ADB debug intent path=${PathDebugText.escapeNonAscii(debugPath)} actions=${debugActions ?: "(default)"}\n")
        window.decorView.postDelayed({ runDebugProbe() }, 1500L)
    }

    private fun runDebugProbe() {
        val actions = intent.getStringExtra(EXTRA_DEBUG_ACTIONS)
            ?.split(',')
            ?.map { it.trim().lowercase() }
            ?.filter { it.isNotEmpty() }
            ?: listOf("stat", "access", "list", "open")
        Log.d("FuseHide", "runDebugProbe path=$pathText actions=$actions")
        outputText = ""
        appendOutput("Running debug probe path=${PathDebugText.escapeNonAscii(pathText)} actions=${actions.joinToString(",")}\n")
        actions.forEach { action ->
            when (action) {
                "stat" -> runPathCheck(0)
                "access" -> runPathCheck(1)
                "list" -> runPathCheck(2)
                "open" -> runPathCheck(3)
                "getcon" -> runPathCheck(4)
                "create" -> runPathCheck(5)
                "mkdir" -> runPathCheck(6)
                "move", "rename" -> runPathCheck(7)
                "rmdir" -> runPathCheck(8)
                "unlink" -> runPathCheck(9)
            }
        }
    }

    fun onHookCheckTimeout() {
        hookCheckCompleted = true
        updateStatusText()
    }

    fun onHookStatusReceived(packageName: String, pid: Int) {
        hookedPackage = packageName
        hookedPid = pid
        statusCheckThread?.interrupt()
        hookCheckCompleted = true
        updateStatusText()
    }

    private fun appendInfo() {
        val utsname: StructUtsname = Os.uname()
        val sdk = if (Build.VERSION.SDK_INT < 36) Build.VERSION.SDK_INT * 100000 else Build.VERSION.SDK_INT_FULL
        buildString {
            append("FuseHide\n")
            append("Kernel: ${utsname.release}\n")
            append("Release: ${Build.VERSION.RELEASE}\n")
            append("Device: ${Build.DEVICE}\n")
            append("SDK: $sdk\n")
            if (getBooleanSystemProperty("external_storage.sdcardfs.enabled")) {
                append("sdcardfs=true\n")
            }
            val fuseBpf = getBooleanSystemProperty("ro.fuse.bpf.is_running")
            append("fuse bpf: ${if (fuseBpf) "supported" else "unsupported"}\n")
            val dataIsolation = getBooleanSystemProperty("persist.sys.vold_app_data_isolation_enabled")
            append("AppDataIsolation: ${if (dataIsolation) "enabled" else "disabled"}\n")
            if (!fuseBpf && !dataIsolation) {
                append("App data isolation is required to fix Android/data access.\n")
                append("Use `setprop persist.sys.vold_app_data_isolation_enabled 1` to enable it.\n")
            }
        }.also { infoText = it }
    }

    private fun startStatusCheck() {
        if (statusCheckInFlight) return

        hookedPackage = null
        hookedPid = -1
        hookCheckCompleted = false
        updateStatusText()
        statusCheckInFlight = true

        val binder = Binder()
        val referenceQueue = ReferenceQueue<Binder>()
        statusBinderReference = WeakReference(binder, referenceQueue)

        val intent = Intent(ACTION_GET_STATUS).setPackage(APP_PACKAGE)
        intent.putExtra("EXTRA_PENDING_INTENT", PendingIntent.getBroadcast(this, 1, intent, 67108864))
        intent.extras?.putBinder("EXTRA_BINDER", binder)

        listOf(
            "com.google.android.providers.media.module",
            "com.android.providers.media.module",
        ).forEach { packageName ->
            intent.setPackage(packageName)
            Log.d("FuseHide", "send GET_STATUS to ${intent.`package`}")
            sendBroadcast(intent)
        }

        statusCheckThread = Thread { onStatusBinderReleased(this, referenceQueue) }.also { it.start() }
    }

    fun updateStatusText() {
        statusCheckInFlight = false
        statusCheckThread = null
        Log.d("FuseHide", "updateStatusText hookedPackage=$hookedPackage hookCheckCompleted=$hookCheckCompleted pid=$hookedPid")
        statusText = when {
            hookedPackage != null -> getString(R.string.status_hooked, hookedPackage, hookedPid) + "\n"
            hookCheckCompleted -> getString(R.string.status_not_hooked) + "\n"
            else -> getString(R.string.status_checking) + "\n"
        }
        logUiText(statusText)
    }

    private fun runPathCheck(mode: Int) {
        val rawPath = PathDebugText.unescapeUnicodeLiterals(pathText) ?: return
        val displayPath = PathDebugText.escapeNonAscii(rawPath)
        try {
            when (mode) {
                0 -> appendOutput("Stat $displayPath -> OK\n${StructStatFormatter.format(Os.stat(rawPath))}\n")

                1 -> {
                    Os.access(rawPath, OsConstants.F_OK)
                    appendOutput("Access $displayPath -> OK\n")
                }

                2 -> {
                    val files = File(rawPath).list()
                    if (files == null) {
                        appendOutput("List $displayPath -> None\n")
                    } else {
                        appendOutput("List $displayPath -> ${files.size} file(s)\n")
                        files.forEach { appendOutput("$it\n") }
                    }
                }

                3 -> {
                    val fd = Os.open(rawPath, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
                    try {
                        Os.close(fd)
                    } catch (th: Throwable) {
                        Log.e("FuseHide", "could not close??", th)
                    }
                    appendOutput("Open $displayPath -> OK\n")
                }

                4 -> {
                    val selinuxContext = String(Os.getxattr(rawPath, "security.selinux"), StandardCharsets.UTF_8)
                    appendOutput("GetCon $displayPath -> OK\n$selinuxContext\n")
                }

                5 -> {
                    val res = Utils.create(rawPath)
                    if (res == 0) {
                        appendOutput("Create $displayPath -> OK\n")
                    } else {
                        appendOutput("Create $displayPath -> ${OsConstants.errnoName(res)}\n")
                    }
                }

                6 -> {
                    val res = Utils.mkdir(rawPath)
                    if (res == 0) {
                        appendOutput("Mkdir $displayPath -> OK\n")
                    } else {
                        appendOutput("Mkdir $displayPath -> ${OsConstants.errnoName(res)}\n")
                    }
                }

                7 -> {
                    val rawPath2 = PathDebugText.unescapeUnicodeLiterals(pathText2) ?: return
                    if (rawPath2.isEmpty()) {
                        appendOutput("Rename(Move) requires Path 2\n")
                        return
                    }
                    val displayPath2 = PathDebugText.escapeNonAscii(rawPath2)
                    val res = Utils.rename(rawPath, rawPath2)
                    if (res == 0) {
                        appendOutput("Rename(Move) $displayPath -> $displayPath2 -> OK\n")
                    } else {
                        appendOutput("Rename(Move) $displayPath -> $displayPath2 -> ${OsConstants.errnoName(res)}\n")
                    }
                }

                8 -> {
                    val res = Utils.rmdir(rawPath)
                    if (res == 0) {
                        appendOutput("Rmdir $displayPath -> OK\n")
                    } else {
                        appendOutput("Rmdir $displayPath -> ${OsConstants.errnoName(res)}\n")
                    }
                }

                // Use Utils for native rmdir/unlink
                9 -> {
                    val res = Utils.unlink(rawPath)
                    if (res == 0) {
                        appendOutput("Unlink $displayPath -> OK\n")
                    } else {
                        appendOutput("Unlink $displayPath -> ${OsConstants.errnoName(res)}\n")
                    }
                }
            }
        } catch (errno: ErrnoException) {
            appendOutput("${modeLabel(mode)} $displayPath -> ${OsConstants.errnoName(errno.errno)}\n")
        }
    }

    private fun runAllPkgCheck() {
        outputText = "Scanning all packages... (this may take a while)\n"
        Thread {
            val sb = StringBuilder()
            try {
                val pkgs = packageManager.getInstalledApplications(0)
                if (pkgs.size <= 1) {
                    sb.append("Could not get app list, please grant app list permission\n")
                } else {
                    val appDataPath = PathDebugText.unescapeUnicodeLiterals(pathText) ?: ""
                    if (appDataPath.isEmpty()) {
                        sb.append("Please enter a base path first\n")
                    } else {
                        val base = if (appDataPath.endsWith("/")) appDataPath else "$appDataPath/"
                        sb.append("Using base path: ${PathDebugText.escapeNonAscii(base)}\n")
                        var existCount = 0
                        val existPkgs = StringBuilder()
                        pkgs.forEach { pkg ->
                            try {
                                Os.stat(base + pkg.packageName)
                                existCount++
                                existPkgs.append(pkg.packageName).append("\n")
                            } catch (e: ErrnoException) {
                                // ignore
                            }
                        }
                        sb.append("Detected $existCount/${pkgs.size} packages\n")
                        sb.append(existPkgs)
                    }
                }
            } catch (t: Throwable) {
                sb.append("Error: ${t.message}\n")
            }
            runOnUiThread {
                appendOutput(sb.toString())
            }
        }.start()
    }

    private fun insertZwj() {
        pathText += "\\u200d"
    }

    private fun copyAll() {
        val clipboardManager = getSystemService(ClipboardManager::class.java) ?: return
        val allText = buildString {
            append("Info:\n")
            append(infoText)
            append("\nStatus:\n")
            append(statusText)
            append("\nTest:\n")
            append(outputText)
        }
        clipboardManager.setPrimaryClip(ClipData.newPlainText("", allText))
    }

    private fun applyConfigToEditor(config: HideConfig) {
        enableHideAllRootEntries = config.enableHideAllRootEntries
        hideAllRootEntriesExemptionsText = HideConfigDefaults.toEditorText(config.hideAllRootEntriesExemptions)
        hiddenTargetsText = HideConfigDefaults.toEditorText(config.hiddenRootEntryNames + config.hiddenRelativePaths)
        hiddenPackagesText = HideConfigDefaults.toEditorText(config.hiddenPackages)
    }

    private fun parseHiddenTargetRules(text: String): Pair<List<String>, List<String>> {
        val values = HideConfigDefaults.parseEditorText(text)
        val rootNames = mutableListOf<String>()
        val relativePaths = mutableListOf<String>()
        values.forEach { value ->
            if (value.contains('/')) {
                relativePaths += value
            } else {
                rootNames += value
            }
        }
        return rootNames to relativePaths
    }

    private fun currentHideConfig(): HideConfig {
        val (rootNames, relativePaths) = parseHiddenTargetRules(hiddenTargetsText)
        return HideConfig(
            enableHideAllRootEntries = enableHideAllRootEntries,
            hideAllRootEntriesExemptions = HideConfigDefaults.parseEditorText(hideAllRootEntriesExemptionsText),
            hiddenRootEntryNames = rootNames,
            hiddenRelativePaths = relativePaths,
            hiddenPackages = HideConfigDefaults.parseEditorText(hiddenPackagesText),
        )
    }

    private fun saveHideConfig() {
        HideConfigStore.save(this, currentHideConfig())
        configStatusText = getString(R.string.config_saved_local) + "\n"
    }

    private fun applyHideConfig() {
        val reloadToken = UUID.randomUUID().toString()
        pendingReloadToken = reloadToken
        HideConfigStore.save(this, currentHideConfig(), reloadToken)
        HideConfigStore.sendReloadBroadcast(this, reloadToken)
        configStatusText = getString(R.string.config_waiting_ack) + "\n"
        startStatusCheck()
    }

    private fun refreshAppliedConfig(autoScrollToResults: Boolean = false) {
        val queryToken = UUID.randomUUID().toString()
        pendingQueryToken = queryToken
        shouldAutoScrollConfigResults = autoScrollToResults
        appliedConfigSnapshotText = getString(R.string.config_snapshot_waiting) + "\n"
        HideConfigStore.sendAppliedConfigQueryBroadcast(this, queryToken)
    }

    private fun buildAppliedConfigSnapshot(config: HideConfig): String = buildString {
        append("MediaProvider current native config\n")
        append("enableHideAllRootEntries=${config.enableHideAllRootEntries}\n")
        append("hideAllRootEntriesExemptions=\n")
        if (config.hideAllRootEntriesExemptions.isEmpty()) append("(empty)\n")
        config.hideAllRootEntriesExemptions.forEach { append("- $it\n") }
        append("hiddenRootEntryNames=\n")
        if (config.hiddenRootEntryNames.isEmpty()) append("(empty)\n")
        config.hiddenRootEntryNames.forEach { append("- $it\n") }
        append("hiddenRelativePaths=\n")
        if (config.hiddenRelativePaths.isEmpty()) append("(empty)\n")
        config.hiddenRelativePaths.forEach { append("- $it\n") }
        append("hiddenPackages=\n")
        if (config.hiddenPackages.isEmpty()) append("(empty)\n")
        config.hiddenPackages.forEach { append("- $it\n") }
    }

    private fun buildDraftVsAppliedDiff(draft: HideConfig, applied: HideConfig?): HideConfigDiff {
        if (applied == null) {
            return HideConfigDiff(
                hasDifferences = false,
                summary = getString(R.string.diff_summary_missing),
                details = getString(R.string.label_draft_vs_applied) + "\n" + getString(R.string.diff_summary_missing) + "\n",
            )
        }

        fun section(title: String, draftValues: List<String>, appliedValues: List<String>): String {
            val draftSet = draftValues.toSet()
            val appliedSet = appliedValues.toSet()
            val draftOnly = (draftSet - appliedSet).sorted()
            val appliedOnly = (appliedSet - draftSet).sorted()
            val shared = (draftSet intersect appliedSet).sorted()
            return buildString {
                append(title).append("\n")
                append("draftOnly=\n")
                if (draftOnly.isEmpty()) append("(empty)\n")
                draftOnly.forEach { append("- ").append(it).append("\n") }
                append("appliedOnly=\n")
                if (appliedOnly.isEmpty()) append("(empty)\n")
                appliedOnly.forEach { append("- ").append(it).append("\n") }
                append("shared=\n")
                if (shared.isEmpty()) append("(empty)\n")
                shared.forEach { append("- ").append(it).append("\n") }
            }
        }

        val boolMatches = draft.enableHideAllRootEntries == applied.enableHideAllRootEntries
        val details = buildString {
            append("Draft vs applied diff\n")
            append("enableHideAllRootEntries: ")
            append(if (boolMatches) "MATCH" else "DIFF")
            append(" (draft=").append(draft.enableHideAllRootEntries)
            append(", applied=").append(applied.enableHideAllRootEntries).append(")\n\n")
            append(section("hideAllRootEntriesExemptions", draft.hideAllRootEntriesExemptions, applied.hideAllRootEntriesExemptions)).append("\n")
            append(section("hiddenRootEntryNames", draft.hiddenRootEntryNames, applied.hiddenRootEntryNames)).append("\n")
            append(section("hiddenRelativePaths", draft.hiddenRelativePaths, applied.hiddenRelativePaths)).append("\n")
            append(section("hiddenPackages", draft.hiddenPackages, applied.hiddenPackages))
        }
        val hasDifferences = !boolMatches ||
            draft.hideAllRootEntriesExemptions.toSet() != applied.hideAllRootEntriesExemptions.toSet() ||
            draft.hiddenRootEntryNames.toSet() != applied.hiddenRootEntryNames.toSet() ||
            draft.hiddenRelativePaths.toSet() != applied.hiddenRelativePaths.toSet() ||
            draft.hiddenPackages.toSet() != applied.hiddenPackages.toSet()
        val summary = if (hasDifferences) {
            getString(R.string.diff_summary_mismatch)
        } else {
            getString(R.string.diff_summary_match)
        }
        return HideConfigDiff(hasDifferences = hasDifferences, summary = summary, details = details)
    }

    private fun formatNow(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    private fun resetHideConfigToDefaults() {
        applyConfigToEditor(HideConfigDefaults.value)
        configStatusText = getString(R.string.config_restored_defaults) + "\n"
    }

    private fun appendOutput(text: String) {
        outputText += text
        logUiText(text)
    }

    private fun logUiText(text: String) {
        text.lineSequence()
            .map { it.trimEnd() }
            .filter { it.isNotEmpty() }
            .forEach { Log.i("FuseHide", it) }
    }

    private fun defaultPath(): String = "/storage/emulated/0/xinhao"

    private fun modeLabel(mode: Int): String = when (mode) {
        0 -> "Stat"
        1 -> "Access"
        2 -> "List"
        3 -> "Open"
        4 -> "GetCon"
        5 -> "Create"
        6 -> "Mkdir"
        7 -> "Rename(Move)"
        8 -> "Rmdir"
        9 -> "Unlink"
        else -> "Unknown"
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(statusReceiver)
        unregisterReceiver(configStatusReceiver)
        unregisterReceiver(appliedConfigReceiver)
        statusCheckThread?.interrupt()
    }
}

@Composable
private fun fuseFixerHomeScreen(
    selectedTab: Int,
    onTabSelected: (Int) -> Unit,
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    configStatusText: String,
    lastAckTokenText: String,
    lastAckResultText: String,
    lastApplyTimeText: String,
    draftVsAppliedDiff: HideConfigDiff,
    appliedConfigSnapshotText: String,
    highlightConfigResults: Boolean,
    configResultsScrollToken: Int,
    enableHideAllRootEntries: Boolean,
    hideAllRootEntriesExemptionsText: String,
    hiddenTargetsText: String,
    hiddenPackagesText: String,
    pathText: String,
    pathText2: String,
    outputText: String,
    onStatusClick: () -> Unit,
    onEnableHideAllRootEntriesChanged: (Boolean) -> Unit,
    onHideAllRootEntriesExemptionsChanged: (String) -> Unit,
    onHiddenTargetsChanged: (String) -> Unit,
    onHiddenPackagesChanged: (String) -> Unit,
    onSaveConfigClick: () -> Unit,
    onApplyConfigClick: () -> Unit,
    onResetConfigClick: () -> Unit,
    onRefreshAppliedConfigClick: () -> Unit,
    onPathChanged: (String) -> Unit,
    onPath2Changed: (String) -> Unit,
    onStatClick: () -> Unit,
    onAccessClick: () -> Unit,
    onListClick: () -> Unit,
    onOpenClick: () -> Unit,
    onGetConClick: () -> Unit,
    onCreateClick: () -> Unit,
    onMkdirClick: () -> Unit,
    onMoveClick: () -> Unit,
    onRmdirClick: () -> Unit,
    onUnlinkClick: () -> Unit,
    onAllPkgClick: () -> Unit,
    onInsertZwjClick: () -> Unit,
    onClearClick: () -> Unit,
    onResetClick: () -> Unit,
    onCopyAllClick: () -> Unit,
    onSelfDataClick: () -> Unit,
) {
    val pagerState = rememberPagerState(initialPage = selectedTab, pageCount = { 2 })
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(selectedTab) {
        if (pagerState.currentPage != selectedTab) {
            pagerState.animateScrollToPage(selectedTab)
        }
    }

    LaunchedEffect(pagerState.currentPage) {
        if (pagerState.currentPage != selectedTab) {
            onTabSelected(pagerState.currentPage)
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            SmallTopAppBar(
                title = stringResource(R.string.app_name),
                color = MiuixTheme.colorScheme.surface,
                titleColor = MiuixTheme.colorScheme.onSurface,
                subtitle = if (selectedTab == 0) {
                    stringResource(R.string.home_subtitle_policy)
                } else {
                    stringResource(R.string.home_subtitle_probe)
                },
                subtitleColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                bottomContent = {
                    TabRowWithContour(
                        tabs = listOf(
                            stringResource(R.string.tab_policy),
                            stringResource(R.string.tab_probe),
                        ),
                        selectedTabIndex = selectedTab,
                        onTabSelected = {
                            onTabSelected(it)
                            coroutineScope.launch { pagerState.animateScrollToPage(it) }
                        },
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                },
            )
        },
    ) { paddingValues ->
        HorizontalPager(
            state = pagerState,
            modifier = Modifier.fillMaxSize(),
        ) { page ->
            when (page) {
                0 -> configScreen(
                    infoText = infoText,
                    statusText = statusText,
                    isHooked = isHooked,
                    hookedPackage = hookedPackage,
                    hookedPid = hookedPid,
                    hookCheckCompleted = hookCheckCompleted,
                    configStatusText = configStatusText,
                    lastAckTokenText = lastAckTokenText,
                    lastAckResultText = lastAckResultText,
                    lastApplyTimeText = lastApplyTimeText,
                    draftVsAppliedDiff = draftVsAppliedDiff,
                    appliedConfigSnapshotText = appliedConfigSnapshotText,
                    highlightConfigResults = highlightConfigResults,
                    configResultsScrollToken = configResultsScrollToken,
                    enableHideAllRootEntries = enableHideAllRootEntries,
                    hideAllRootEntriesExemptionsText = hideAllRootEntriesExemptionsText,
                    hiddenTargetsText = hiddenTargetsText,
                    hiddenPackagesText = hiddenPackagesText,
                    onStatusClick = onStatusClick,
                    onEnableHideAllRootEntriesChanged = onEnableHideAllRootEntriesChanged,
                    onHideAllRootEntriesExemptionsChanged = onHideAllRootEntriesExemptionsChanged,
                    onHiddenTargetsChanged = onHiddenTargetsChanged,
                    onHiddenPackagesChanged = onHiddenPackagesChanged,
                    onSaveConfigClick = onSaveConfigClick,
                    onApplyConfigClick = onApplyConfigClick,
                    onResetConfigClick = onResetConfigClick,
                    onRefreshAppliedConfigClick = { onRefreshAppliedConfigClick() },
                    contentPadding = paddingValues,
                )

                else -> debugScreen(
                    infoText = infoText,
                    statusText = statusText,
                    isHooked = isHooked,
                    hookedPackage = hookedPackage,
                    hookedPid = hookedPid,
                    hookCheckCompleted = hookCheckCompleted,
                    pathText = pathText,
                    pathText2 = pathText2,
                    outputText = outputText,
                    onStatusClick = onStatusClick,
                    onPathChanged = onPathChanged,
                    onPath2Changed = onPath2Changed,
                    onStatClick = onStatClick,
                    onAccessClick = onAccessClick,
                    onListClick = onListClick,
                    onOpenClick = onOpenClick,
                    onGetConClick = onGetConClick,
                    onCreateClick = onCreateClick,
                    onMkdirClick = onMkdirClick,
                    onMoveClick = onMoveClick,
                    onRmdirClick = onRmdirClick,
                    onUnlinkClick = onUnlinkClick,
                    onAllPkgClick = onAllPkgClick,
                    onInsertZwjClick = onInsertZwjClick,
                    onClearClick = onClearClick,
                    onResetClick = onResetClick,
                    onCopyAllClick = onCopyAllClick,
                    onSelfDataClick = onSelfDataClick,
                    contentPadding = paddingValues,
                )
            }
        }
    }
}

@Composable
private fun configScreen(
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    configStatusText: String,
    lastAckTokenText: String,
    lastAckResultText: String,
    lastApplyTimeText: String,
    draftVsAppliedDiff: HideConfigDiff,
    appliedConfigSnapshotText: String,
    highlightConfigResults: Boolean,
    configResultsScrollToken: Int,
    enableHideAllRootEntries: Boolean,
    hideAllRootEntriesExemptionsText: String,
    hiddenTargetsText: String,
    hiddenPackagesText: String,
    onStatusClick: () -> Unit,
    onEnableHideAllRootEntriesChanged: (Boolean) -> Unit,
    onHideAllRootEntriesExemptionsChanged: (String) -> Unit,
    onHiddenTargetsChanged: (String) -> Unit,
    onHiddenPackagesChanged: (String) -> Unit,
    onSaveConfigClick: () -> Unit,
    onApplyConfigClick: () -> Unit,
    onResetConfigClick: () -> Unit,
    onRefreshAppliedConfigClick: () -> Unit,
    contentPadding: PaddingValues,
) {
    val scrollState = rememberScrollState()
    var showDetailedDiff by remember { mutableStateOf(false) }
    var showAppliedSnapshot by remember { mutableStateOf(false) }
    val resultsNeedAttention = highlightConfigResults || draftVsAppliedDiff.hasDifferences

    LaunchedEffect(configResultsScrollToken) {
        if (configResultsScrollToken > 0) {
            scrollState.animateScrollTo(scrollState.maxValue)
        }
    }

    LaunchedEffect(highlightConfigResults, draftVsAppliedDiff.hasDifferences) {
        if (highlightConfigResults || draftVsAppliedDiff.hasDifferences) {
            showAppliedSnapshot = true
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .consumeWindowInsets(contentPadding)
            .verticalScroll(scrollState)
            .navigationBarsPadding()
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        sectionCard {
            Text(
                stringResource(R.string.section_runtime_policy),
                style = MiuixTheme.textStyles.title3,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.section_runtime_policy_desc),
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                statusChip(
                    modifier = Modifier.weight(1f).heightIn(min = 130.dp),
                    label = stringResource(R.string.label_hook),
                    value = hookSummaryValue(isHooked = isHooked, hookCheckCompleted = hookCheckCompleted),
                    supportingText = hookSummarySupportingText(
                        isHooked = isHooked,
                        hookCheckCompleted = hookCheckCompleted,
                        hookedPackage = hookedPackage,
                    ),
                    metaText = hookSummaryMetaText(isHooked = isHooked, hookedPid = hookedPid),
                    emphasized = isHooked,
                    onClick = onStatusClick,
                )
                statusChip(
                    modifier = Modifier.weight(1f).heightIn(min = 130.dp),
                    label = stringResource(R.string.label_sync),
                    value = if (resultsNeedAttention) stringResource(R.string.state_sync_needs_review) else stringResource(R.string.state_sync_ok),
                    emphasized = !resultsNeedAttention,
                )
            }
            Spacer(Modifier.height(10.dp))
            infoPanel(title = stringResource(R.string.label_device), text = infoText, monospace = true)
        }

        sectionCard {
            Text(
                stringResource(R.string.section_editable_draft),
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.section_editable_draft_desc),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Card(
                colors = CardDefaults.defaultColors(
                    color = MiuixTheme.colorScheme.surfaceContainerHighest,
                    contentColor = MiuixTheme.colorScheme.onSurfaceContainerHighest,
                ),
                insideMargin = PaddingValues(0.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = androidx.compose.ui.Alignment.Top,
                ) {
                    Checkbox(
                        state = if (enableHideAllRootEntries) ToggleableState.On else ToggleableState.Off,
                        onClick = { onEnableHideAllRootEntriesChanged(!enableHideAllRootEntries) },
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.field_hide_all_title), style = MiuixTheme.textStyles.headline2)
                        Text(
                            text = stringResource(R.string.field_hide_all_desc),
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            TextField(
                value = hideAllRootEntriesExemptionsText,
                onValueChange = onHideAllRootEntriesExemptionsChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_visible_exemptions),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                minLines = 3,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_visible_exemptions_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = hiddenTargetsText,
                onValueChange = onHiddenTargetsChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_hidden_targets),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                minLines = 5,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_hidden_targets_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = hiddenPackagesText,
                onValueChange = onHiddenPackagesChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.field_hidden_package_names),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                minLines = 5,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_hidden_package_names_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(14.dp))
            dualActionRow(
                primaryLabel = stringResource(R.string.button_apply),
                onPrimaryClick = onApplyConfigClick,
                secondaryLabel = stringResource(R.string.button_save),
                onSecondaryClick = onSaveConfigClick,
            )
            Spacer(Modifier.height(8.dp))
            dualActionRow(
                primaryLabel = stringResource(R.string.button_refresh_applied),
                onPrimaryClick = onRefreshAppliedConfigClick,
                secondaryLabel = stringResource(R.string.button_restore_defaults),
                onSecondaryClick = onResetConfigClick,
                primaryFilled = false,
            )
        }

        sectionCard {
            Text(
                stringResource(R.string.section_apply_feedback),
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = androidx.compose.ui.Alignment.Top,
            ) {
                metricCard(stringResource(R.string.label_last_ack), lastAckResultText, Modifier.weight(1f))
                metricCard(stringResource(R.string.label_applied_at), lastApplyTimeText, Modifier.weight(1f))
            }
            Spacer(Modifier.height(10.dp))
            infoPanel(
                title = stringResource(R.string.label_last_token),
                text = lastAckTokenText,
                monospace = true,
            )
            Spacer(Modifier.height(10.dp))
            infoPanel(
                title = if (resultsNeedAttention) stringResource(R.string.label_attention) else stringResource(R.string.label_status),
                text = configStatusText.ifEmpty { draftVsAppliedDiff.summary },
                emphasized = resultsNeedAttention,
            )
            Spacer(Modifier.height(8.dp))
            infoPanel(
                title = stringResource(R.string.label_draft_vs_applied),
                text = draftVsAppliedDiff.summary,
                emphasized = draftVsAppliedDiff.hasDifferences,
            )
        }
        if (draftVsAppliedDiff.hasDifferences) {
            sectionCard {
                Text(
                    stringResource(R.string.section_detailed_diff),
                    style = MiuixTheme.textStyles.title4,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(6.dp))
                TextButton(
                    text = if (showDetailedDiff) stringResource(R.string.button_hide_detailed_diff) else stringResource(R.string.button_show_detailed_diff),
                    onClick = { showDetailedDiff = !showDetailedDiff },
                )
                if (showDetailedDiff) {
                    Spacer(Modifier.height(6.dp))
                    infoPanel(
                        title = stringResource(R.string.label_draft_vs_applied),
                        text = draftVsAppliedDiff.details,
                        monospace = true,
                    )
                }
            }
        }

        sectionCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        stringResource(R.string.section_snapshot),
                        style = MiuixTheme.textStyles.title4,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.section_snapshot_desc),
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                TextButton(
                    text = if (showAppliedSnapshot) stringResource(R.string.button_hide) else stringResource(R.string.button_show),
                    onClick = { showAppliedSnapshot = !showAppliedSnapshot },
                )
            }
            if (showAppliedSnapshot) {
                Spacer(Modifier.height(10.dp))
                infoPanel(
                    title = stringResource(R.string.label_current_native_config),
                    text = appliedConfigSnapshotText,
                    monospace = true,
                    emphasized = resultsNeedAttention,
                )
            }
        }
    }
}

@Composable
private fun debugScreen(
    infoText: String,
    statusText: String,
    isHooked: Boolean,
    hookedPackage: String?,
    hookedPid: Int,
    hookCheckCompleted: Boolean,
    pathText: String,
    pathText2: String,
    outputText: String,
    onStatusClick: () -> Unit,
    onPathChanged: (String) -> Unit,
    onPath2Changed: (String) -> Unit,
    onStatClick: () -> Unit,
    onAccessClick: () -> Unit,
    onListClick: () -> Unit,
    onOpenClick: () -> Unit,
    onGetConClick: () -> Unit,
    onCreateClick: () -> Unit,
    onMkdirClick: () -> Unit,
    onMoveClick: () -> Unit,
    onRmdirClick: () -> Unit,
    onUnlinkClick: () -> Unit,
    onAllPkgClick: () -> Unit,
    onInsertZwjClick: () -> Unit,
    onClearClick: () -> Unit,
    onResetClick: () -> Unit,
    onCopyAllClick: () -> Unit,
    onSelfDataClick: () -> Unit,
    contentPadding: PaddingValues,
) {
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .consumeWindowInsets(contentPadding)
            .verticalScroll(scrollState)
            .navigationBarsPadding()
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        sectionCard {
            Text(
                stringResource(R.string.section_probe_target),
                style = MiuixTheme.textStyles.title3,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.section_probe_target_desc),
                style = MiuixTheme.textStyles.body1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                statusChip(
                    modifier = Modifier.weight(1f),
                    label = stringResource(R.string.label_hook),
                    value = hookSummaryValue(isHooked = isHooked, hookCheckCompleted = hookCheckCompleted),
                    supportingText = hookSummarySupportingText(
                        isHooked = isHooked,
                        hookCheckCompleted = hookCheckCompleted,
                        hookedPackage = hookedPackage,
                    ),
                    metaText = hookSummaryMetaText(isHooked = isHooked, hookedPid = hookedPid),
                    emphasized = isHooked,
                    onClick = onStatusClick,
                )
            }
            Spacer(Modifier.height(10.dp))
            infoPanel(
                title = stringResource(R.string.label_path),
                text = pathText.ifBlank { "-" },
                monospace = true,
            )
            Spacer(Modifier.height(10.dp))
            infoPanel(title = stringResource(R.string.label_device), text = infoText, monospace = true)
        }

        sectionCard {
            Text(
                stringResource(R.string.section_paths),
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            TextField(
                value = pathText,
                onValueChange = onPathChanged,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.label_primary_path),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                singleLine = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_primary_path_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(10.dp))
            TextField(
                value = pathText2,
                onValueChange = onPath2Changed,
                modifier = Modifier.fillMaxWidth(),
                label = stringResource(R.string.label_secondary_path),
                backgroundColor = MiuixTheme.colorScheme.surfaceContainerHighest,
                labelColor = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                borderColor = MiuixTheme.colorScheme.primary,
                textStyle = MiuixTheme.textStyles.main.copy(color = MiuixTheme.colorScheme.onSurface),
                singleLine = false,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.field_secondary_path_help),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }

        sectionCard {
            Text(
                stringResource(R.string.section_common_probes),
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            actionGrid(
                listOf(
                    stringResource(R.string.button_stat) to onStatClick,
                    stringResource(R.string.button_access) to onAccessClick,
                    stringResource(R.string.button_list) to onListClick,
                    stringResource(R.string.button_open) to onOpenClick,
                ),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.section_mutation_probes),
                style = MiuixTheme.textStyles.headline2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            actionGrid(
                listOf(
                    stringResource(R.string.button_get_con) to onGetConClick,
                    stringResource(R.string.button_create) to onCreateClick,
                    stringResource(R.string.button_mkdir) to onMkdirClick,
                    stringResource(R.string.button_rename_move) to onMoveClick,
                    stringResource(R.string.button_rmdir) to onRmdirClick,
                    stringResource(R.string.button_unlink) to onUnlinkClick,
                ),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.section_utilities),
                style = MiuixTheme.textStyles.headline2,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            actionGrid(
                listOf(
                    stringResource(R.string.button_all_pkg) to onAllPkgClick,
                    stringResource(R.string.button_insert_zwj) to onInsertZwjClick,
                    stringResource(R.string.button_clear_output) to onClearClick,
                    stringResource(R.string.button_reset_path) to onResetClick,
                    stringResource(R.string.button_copy_output) to onCopyAllClick,
                    stringResource(R.string.button_self_data) to onSelfDataClick,
                ),
            )
        }

        sectionCard {
            Text(
                stringResource(R.string.section_probe_output),
                style = MiuixTheme.textStyles.title4,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(10.dp))
            infoPanel(
                title = stringResource(R.string.label_runtime_output),
                text = outputText.ifEmpty { stringResource(R.string.probe_output_empty) },
                monospace = true,
            )
        }
    }
}

@Composable
private fun dualActionRow(
    primaryLabel: String,
    onPrimaryClick: () -> Unit,
    secondaryLabel: String,
    onSecondaryClick: () -> Unit,
    primaryFilled: Boolean = true,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (primaryFilled) {
            Button(
                onClick = onPrimaryClick,
                modifier = Modifier.weight(1f).height(56.dp),
                colors = ButtonDefaults.buttonColorsPrimary(),
            ) {
                Text(primaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button)
            }
        } else {
            Button(
                onClick = onPrimaryClick,
                modifier = Modifier.weight(1f).height(56.dp),
                colors = ButtonDefaults.buttonColors(),
            ) {
                Text(primaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button)
            }
        }
        Button(
            onClick = onSecondaryClick,
            modifier = Modifier.weight(1f).height(56.dp),
            colors = ButtonDefaults.buttonColors(),
        ) {
            Text(secondaryLabel, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button)
        }
    }
}

@Composable
private fun actionGrid(actions: List<Pair<String, () -> Unit>>) {
    actions.chunked(2).forEach { rowActions ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            rowActions.forEach { (label, action) ->
                Button(
                    onClick = action,
                    modifier = Modifier.weight(1f).height(56.dp),
                    colors = ButtonDefaults.buttonColors(),
                    insideMargin = PaddingValues(horizontal = 12.dp, vertical = 14.dp),
                ) {
                    Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.Center, style = MiuixTheme.textStyles.button)
                }
            }
            if (rowActions.size == 1) {
                Spacer(modifier = Modifier.weight(1f))
            }
        }
        Spacer(Modifier.height(10.dp))
    }
}

@Composable
private fun sectionCard(content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.surfaceContainerHigh,
            contentColor = MiuixTheme.colorScheme.onSurfaceContainerHigh,
        ),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            content = content,
        )
    }
}

@Composable
private fun statusChip(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    supportingText: String? = null,
    metaText: String? = null,
    emphasized: Boolean = false,
    onClick: (() -> Unit)? = null,
) {
    val containerColor = if (emphasized) {
        MiuixTheme.colorScheme.primaryVariant
    } else {
        MiuixTheme.colorScheme.surfaceContainerHighest
    }
    val contentColor = if (emphasized) {
        MiuixTheme.colorScheme.onPrimaryVariant
    } else {
        MiuixTheme.colorScheme.onSurfaceContainerHighest
    }
    Card(
        modifier = modifier
            .heightIn(min = 118.dp),
        colors = CardDefaults.defaultColors(color = containerColor, contentColor = contentColor),
        onClick = onClick,
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label.uppercase(Locale.US),
                style = MiuixTheme.textStyles.footnote2,
                color = if (emphasized) {
                    MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.72f)
                } else {
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                },
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.body1,
                color = if (emphasized) Color.White else MiuixTheme.colorScheme.onSurfaceContainerHighest,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (supportingText != null) {
                Text(
                    text = supportingText,
                    style = MiuixTheme.textStyles.footnote1,
                    color = if (emphasized) {
                        MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.84f)
                    } else {
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    },
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (metaText != null) {
                Text(
                    text = metaText,
                    style = MiuixTheme.textStyles.footnote1,
                    color = if (emphasized) {
                        MiuixTheme.colorScheme.onPrimaryVariant.copy(alpha = 0.84f)
                    } else {
                        MiuixTheme.colorScheme.onSurfaceVariantSummary
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun metricCard(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    valueMaxLines: Int = 2,
    monospace: Boolean = false,
) {
    Card(
        modifier = modifier.heightIn(min = 96.dp),
        colors = CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.surfaceContainerHighest,
            contentColor = MiuixTheme.colorScheme.onSurfaceContainerHighest,
        ),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label.uppercase(Locale.US),
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = value,
                style = MiuixTheme.textStyles.main,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                maxLines = valueMaxLines,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun hookSummaryValue(isHooked: Boolean, hookCheckCompleted: Boolean): String = when {
    isHooked -> stringResource(R.string.state_hooked_short)
    hookCheckCompleted -> stringResource(R.string.state_not_hooked_short)
    else -> stringResource(R.string.state_checking_short)
}

@Composable
private fun hookSummarySupportingText(
    isHooked: Boolean,
    hookCheckCompleted: Boolean,
    hookedPackage: String?,
): String = if (isHooked && hookedPackage != null) {
    hookedPackage
} else {
    stringResource(R.string.status_tap_recheck)
}

@Composable
private fun hookSummaryMetaText(isHooked: Boolean, hookedPid: Int): String = if (isHooked && hookedPid > 0) {
    stringResource(R.string.status_pid, hookedPid)
} else {
    ""
}

@Composable
private fun infoPanel(
    title: String,
    text: String,
    monospace: Boolean = false,
    emphasized: Boolean = false,
) {
    val containerColor = if (emphasized) {
        MiuixTheme.colorScheme.errorContainer
    } else {
        MiuixTheme.colorScheme.surfaceContainerHighest
    }
    val contentColor = if (emphasized) {
        MiuixTheme.colorScheme.onErrorContainer
    } else {
        MiuixTheme.colorScheme.onSurfaceContainerHighest
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = containerColor, contentColor = contentColor),
        insideMargin = PaddingValues(0.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (title.isNotEmpty()) {
                Text(title, style = MiuixTheme.textStyles.headline2)
            }
            SelectionContainer {
                Text(
                    text = text,
                    modifier = Modifier
                        .fillMaxWidth()
                        .wrapContentHeight(),
                    fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                    style = MiuixTheme.textStyles.body1,
                )
            }
        }
    }
}

@Composable
private fun monospaceBlock(text: String, modifier: Modifier = Modifier) {
    SelectionContainer {
        Text(
            text = text,
            modifier = modifier
                .fillMaxWidth()
                .wrapContentHeight(),
            fontFamily = FontFamily.Monospace,
            style = MiuixTheme.textStyles.body1,
        )
    }
}
