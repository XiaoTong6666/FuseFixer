package io.github.xiaotong6666.fusefixer

import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.IntentFilter
import android.os.Binder
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructUtsname
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import fusefixer.MainThreadTask
import fusefixer.StatusBroadcastReceiver
import fusefixer.StructStatFormatter
import io.github.xiaotong6666.fusefixer.ui.theme.fuseFixerTheme
import java.io.File
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.charset.StandardCharsets
import java.util.regex.Pattern

class MainActivity : ComponentActivity() {
    companion object {
        private const val APP_PACKAGE = "io.github.xiaotong6666.fusefixer"
        private const val ACTION_GET_STATUS = "$APP_PACKAGE.GET_STATUS"
        private const val ACTION_SET_STATUS = "$APP_PACKAGE.SET_STATUS"
        private const val EXTRA_DEBUG_PATH = "debug_path"
        private const val EXTRA_DEBUG_ACTIONS = "debug_actions"
        val unicodeEscapePattern: Pattern = Pattern.compile("\\\\u([0-9a-fA-F]{4})")

        fun onStatusBinderReleased(activity: MainActivity, referenceQueue: ReferenceQueue<Binder>) {
            try {
                Thread.sleep(2000L)
                Runtime.getRuntime().gc()
                Log.d("FuseFixer", "polling ref ...")
                Log.d("FuseFixer", "polled = ${referenceQueue.remove()}")
                activity.statusBinderReference = null
                activity.runOnUiThread(MainThreadTask(1, activity))
            } catch (_: InterruptedException) {
                Log.d("FuseFixer", "return")
            }
        }

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

        fun getBooleanSystemProperty(name: String): Boolean {
            return try {
                Class.forName("android.os.SystemProperties")
                    .getDeclaredMethod("getBoolean", String::class.java, Boolean::class.javaPrimitiveType)
                    .invoke(null, name, false) as Boolean
            } catch (th: Throwable) {
                Log.e("FuseFixer", "getProp", th)
                false
            }
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

    private var infoText by mutableStateOf("")
    private var statusText by mutableStateOf("Module status: checking ...\n")
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        appendInfo()

        statusReceiver = StatusBroadcastReceiver(this, 1)
        val filter = IntentFilter(ACTION_SET_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, 2)
        } else {
            registerReceiver(statusReceiver, filter)
        }

        setContent {
            fuseFixerTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
                    fuseFixerScreen(
                        infoText = infoText,
                        statusText = statusText,
                        pathText = pathText,
                        pathText2 = pathText2,
                        outputText = outputText,
                        onStatusClick = ::startStatusCheck,
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
        }

        startStatusCheck()

        val debugPath = intent.getStringExtra(EXTRA_DEBUG_PATH)
        if (!debugPath.isNullOrEmpty()) {
            pathText = debugPath
            window.decorView.postDelayed({ runDebugProbe() }, 1500L)
        }
    }

    private fun runDebugProbe() {
        val actions = intent.getStringExtra(EXTRA_DEBUG_ACTIONS)
            ?.split(',')
            ?.map { it.trim().lowercase() }
            ?.filter { it.isNotEmpty() }
            ?: listOf("stat", "access", "list", "open")
        Log.d("FuseFixer", "runDebugProbe path=$pathText actions=$actions")
        outputText = ""
        actions.forEach { action ->
            when (action) {
                "stat" -> runPathCheck(0)
                "access" -> runPathCheck(1)
                "list" -> runPathCheck(2)
                "open" -> runPathCheck(3)
                "getcon" -> runPathCheck(4)
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
            append("FuseFixer\n")
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
            Log.d("FuseFixer", "send GET_STATUS to ${intent.`package`}")
            sendBroadcast(intent)
        }

        statusCheckThread = Thread { onStatusBinderReleased(this, referenceQueue) }.also { it.start() }
    }

    fun updateStatusText() {
        statusCheckInFlight = false
        statusCheckThread = null
        Log.d("FuseFixer", "updateStatusText hookedPackage=$hookedPackage hookCheckCompleted=$hookCheckCompleted pid=$hookedPid")
        statusText = when {
            hookedPackage != null -> "Module status: hooked $hookedPackage pid=$hookedPid\n"
            hookCheckCompleted -> "Module status: not hooked (touch to recheck)\n"
            else -> "Module status: checking ...\n"
        }
        logUiText(statusText)
    }

    private fun runPathCheck(mode: Int) {
        val rawPath = unescapeUnicodeLiterals(pathText) ?: return
        val displayPath = escapeNonAscii(rawPath)
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
                        Log.e("FuseFixer", "could not close??", th)
                    }
                    appendOutput("Open $displayPath -> OK\n")
                }
                4 -> {
                    val selinuxContext = String(Os.getxattr(rawPath, "security.selinux"), StandardCharsets.UTF_8)
                    appendOutput("GetCon $displayPath -> OK\n$selinuxContext\n")
                }
                5 -> {
                    try {
                        File(rawPath).createNewFile()
                        appendOutput("Create $displayPath -> OK\n")
                    } catch (e: Exception) {
                        appendOutput("Create $displayPath -> ${e.message}\n")
                    }
                }
                6 -> {
                    try {
                        File(rawPath).mkdirs()
                        appendOutput("Mkdir $displayPath -> OK\n")
                    } catch (e: Exception) {
                        appendOutput("Mkdir $displayPath -> ${e.message}\n")
                    }
                }
                7 -> {
                    val rawPath2 = unescapeUnicodeLiterals(pathText2) ?: return
                    val displayPath2 = escapeNonAscii(rawPath2)
                    try {
                        if (File(rawPath).renameTo(File(rawPath2))) {
                            appendOutput("Move $displayPath -> $displayPath2 -> OK\n")
                        } else {
                            appendOutput("Move $displayPath -> $displayPath2 -> Failed\n")
                        }
                    } catch (e: Exception) {
                        appendOutput("Move $displayPath -> $displayPath2 -> ${e.message}\n")
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
                    val appDataPath = unescapeUnicodeLiterals(pathText) ?: ""
                    if (appDataPath.isEmpty()) {
                        sb.append("Please enter a base path first\n")
                    } else {
                        val base = if (appDataPath.endsWith("/")) appDataPath else "$appDataPath/"
                        sb.append("Using base path: ${escapeNonAscii(base)}\n")
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

    private fun appendOutput(text: String) {
        outputText += text
        logUiText(text)
    }

    private fun logUiText(text: String) {
        text.lineSequence()
            .map { it.trimEnd() }
            .filter { it.isNotEmpty() }
            .forEach { Log.i("FuseFixer", it) }
    }

    private fun defaultPath(): String = "/storage/emulated/${Process.myUid() / 100000}/Android/\\u200ddata"

    private fun modeLabel(mode: Int): String = when (mode) {
        0 -> "Stat"
        1 -> "Access"
        2 -> "List"
        3 -> "Open"
        4 -> "GetCon"
        5 -> "Create"
        6 -> "Mkdir"
        7 -> "Move"
        8 -> "Rmdir"
        9 -> "Unlink"
        else -> "Unknown"
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(statusReceiver)
        statusCheckThread?.interrupt()
    }
}

@Composable
private fun fuseFixerScreen(
    infoText: String,
    statusText: String,
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
) {
    val scrollState = rememberScrollState()
    val insets = WindowInsets.systemBars.asPaddingValues()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(insets)
            .verticalScroll(scrollState)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        monospaceBlock(infoText)
        monospaceBlock(statusText, Modifier.clickable(onClick = onStatusClick))
        OutlinedTextField(
            value = pathText,
            onValueChange = onPathChanged,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Path") },
            singleLine = false,
        )
        OutlinedTextField(
            value = pathText2,
            onValueChange = onPath2Changed,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Path 2 (for Move)") },
            singleLine = false,
        )
        actionRows(
            onStatClick,
            onAccessClick,
            onListClick,
            onOpenClick,
            onGetConClick,
            onCreateClick,
            onMkdirClick,
            onMoveClick,
            onRmdirClick,
            onUnlinkClick,
            onAllPkgClick,
            onInsertZwjClick,
            onClearClick,
            onResetClick,
            onCopyAllClick,
            onSelfDataClick,
        )
        monospaceBlock(outputText)
    }
}

@Composable
private fun actionRows(
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
    actionRow(
        listOf(
            "Stat" to onStatClick,
            "Access" to onAccessClick,
            "List" to onListClick,
            "Open" to onOpenClick,
        ),
    )
    actionRow(
        listOf(
            "Get Con" to onGetConClick,
            "Create" to onCreateClick,
            "Mkdir" to onMkdirClick,
            "Move" to onMoveClick,
        ),
    )
    actionRow(
        listOf(
            "Rmdir" to onRmdirClick,
            "Unlink" to onUnlinkClick,
            "All PKG" to onAllPkgClick,
            "Insert ZWJ" to onInsertZwjClick,
        ),
    )
    actionRow(
        listOf(
            "Clear" to onClearClick,
            "Reset" to onResetClick,
            "Copy All" to onCopyAllClick,
            "Self Data" to onSelfDataClick,
        ),
    )
}

@Composable
private fun actionRow(actions: List<Pair<String, () -> Unit>>) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        actions.forEach { (label, action) ->
            Button(onClick = action, modifier = Modifier.widthIn(min = 96.dp)) {
                Text(label)
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
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
