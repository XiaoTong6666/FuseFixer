package io.github.xiaotong6666.fusehide

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

object HideConfigStore {
    const val APP_PACKAGE: String = "io.github.xiaotong6666.fusehide"
    const val PACKAGE_MEDIA: String = "com.android.providers.media.module"
    const val PACKAGE_MEDIA_GOOGLE: String = "com.google.android.providers.media.module"
    const val ACTION_RELOAD_HIDE_CONFIG: String = "io.github.xiaotong6666.fusehide.RELOAD_HIDE_CONFIG"
    const val ACTION_SET_CONFIG_STATUS: String = "io.github.xiaotong6666.fusehide.SET_CONFIG_STATUS"
    const val ACTION_GET_APPLIED_HIDE_CONFIG: String = "io.github.xiaotong6666.fusehide.GET_APPLIED_HIDE_CONFIG"
    const val ACTION_SET_APPLIED_HIDE_CONFIG: String = "io.github.xiaotong6666.fusehide.SET_APPLIED_HIDE_CONFIG"
    const val ACTION_REQUEST_HIDE_CONFIG: String = "io.github.xiaotong6666.fusehide.REQUEST_HIDE_CONFIG"
    const val ACTION_SET_HIDE_CONFIG: String = "io.github.xiaotong6666.fusehide.SET_HIDE_CONFIG"
    const val EXTRA_RELOAD_TOKEN: String = "reload_token"
    const val EXTRA_RELOAD_APPLIED: String = "reload_applied"
    const val EXTRA_RELOAD_MESSAGE: String = "reload_message"
    const val EXTRA_QUERY_TOKEN: String = "query_token"
    const val EXTRA_REPLY_PACKAGE: String = "reply_package"
    const val EXTRA_REPLY_ACTION: String = "reply_action"
    private const val PREFS_NAME = "hide_config"
    private const val METHOD_GET_HIDE_CONFIG = "get_hide_config"
    private const val AUTHORITY = "io.github.xiaotong6666.fusehide.hideconfig"
    private const val KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES = "enable_hide_all_root_entries"
    private const val KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS = "hide_all_root_entries_exemptions"
    private const val KEY_HIDDEN_ROOT_ENTRY_NAMES = "hidden_root_entry_names"
    private const val KEY_HIDDEN_RELATIVE_PATHS = "hidden_relative_paths"
    private const val KEY_HIDDEN_PACKAGES = "hidden_packages"
    private const val KEY_RELOAD_TOKEN = "reload_token"
    private const val REQUEST_TIMEOUT_MS = 3000L

    private val providerUri: Uri = Uri.parse("content://$AUTHORITY")

    fun interface ConfigBundleCallback {
        fun onBundle(bundle: Bundle?)
    }

    fun interface ReloadConfigCallback {
        fun onResult(applied: Boolean)
    }

    fun load(context: Context): HideConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val defaults = HideConfigDefaults.value
        return HideConfig(
            enableHideAllRootEntries = prefs.getBoolean(
                KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES,
                defaults.enableHideAllRootEntries,
            ),
            hideAllRootEntriesExemptions = parseStoredList(
                prefs.getString(
                    KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                    encodeList(defaults.hideAllRootEntriesExemptions),
                ),
            ),
            hiddenRootEntryNames = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_ROOT_ENTRY_NAMES,
                    encodeList(defaults.hiddenRootEntryNames),
                ),
            ),
            hiddenRelativePaths = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_RELATIVE_PATHS,
                    encodeList(defaults.hiddenRelativePaths),
                ),
            ),
            hiddenPackages = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_PACKAGES,
                    encodeList(defaults.hiddenPackages),
                ),
            ),
        )
    }

    fun save(context: Context, config: HideConfig) {
        save(context, config, null)
    }

    fun save(context: Context, config: HideConfig, reloadToken: String?) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
            .putString(
                KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                encodeList(config.hideAllRootEntriesExemptions),
            )
            .putString(KEY_HIDDEN_ROOT_ENTRY_NAMES, encodeList(config.hiddenRootEntryNames))
            .putString(KEY_HIDDEN_RELATIVE_PATHS, encodeList(config.hiddenRelativePaths))
            .putString(KEY_HIDDEN_PACKAGES, encodeList(config.hiddenPackages))
            .putString(KEY_RELOAD_TOKEN, reloadToken)
            .apply()
    }

    @JvmStatic
    fun toBundle(config: HideConfig): Bundle = Bundle().apply {
        putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
        putStringArray(
            KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
            config.hideAllRootEntriesExemptions.toTypedArray(),
        )
        putStringArray(KEY_HIDDEN_ROOT_ENTRY_NAMES, config.hiddenRootEntryNames.toTypedArray())
        putStringArray(KEY_HIDDEN_RELATIVE_PATHS, config.hiddenRelativePaths.toTypedArray())
        putStringArray(KEY_HIDDEN_PACKAGES, config.hiddenPackages.toTypedArray())
    }

    @JvmStatic
    fun fromBundle(bundle: Bundle?): HideConfig? {
        if (bundle == null) return null
        return HideConfig(
            enableHideAllRootEntries = bundle.getBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, false),
            hideAllRootEntriesExemptions =
            bundle.getStringArray(KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS)?.toList().orEmpty(),
            hiddenRootEntryNames = bundle.getStringArray(KEY_HIDDEN_ROOT_ENTRY_NAMES)?.toList().orEmpty(),
            hiddenRelativePaths = bundle.getStringArray(KEY_HIDDEN_RELATIVE_PATHS)?.toList().orEmpty(),
            hiddenPackages = bundle.getStringArray(KEY_HIDDEN_PACKAGES)?.toList().orEmpty(),
        )
    }

    @JvmStatic
    fun loadViaProviderBundle(context: Context): Bundle? = try {
        context.contentResolver.call(providerUri, METHOD_GET_HIDE_CONFIG, null, null)
    } catch (t: Throwable) {
        Log.e("FuseHide", "loadViaProvider", t)
        null
    }

    @JvmStatic
    fun loadViaProvider(context: Context): HideConfig? = fromBundle(loadViaProviderBundle(context))

    @JvmStatic
    fun reloadTokenFromBundle(bundle: Bundle?): String? = bundle?.getString(KEY_RELOAD_TOKEN)

    @JvmStatic
    fun applyBundleToNative(bundle: Bundle?): Boolean {
        val config = fromBundle(bundle) ?: return false
        return try {
            HideConfigNativeBridge.applyHideConfig(
                config.enableHideAllRootEntries,
                config.hideAllRootEntriesExemptions.toTypedArray(),
                config.hiddenRootEntryNames.toTypedArray(),
                config.hiddenRelativePaths.toTypedArray(),
                config.hiddenPackages.toTypedArray(),
            )
            true
        } catch (t: Throwable) {
            Log.e("FuseHide", "applyBundleToNative", t)
            false
        }
    }

    @JvmStatic
    fun requestInjectedProcessConfigBundle(context: Context, callback: ConfigBundleCallback) {
        val appContext = context.applicationContext ?: context
        val requestToken = UUID.randomUUID().toString()
        val finished = AtomicBoolean(false)
        val mainHandler = Handler(Looper.getMainLooper())
        lateinit var receiver: BroadcastReceiver

        fun finish(bundle: Bundle?) {
            if (!finished.compareAndSet(false, true)) {
                return
            }
            try {
                appContext.unregisterReceiver(receiver)
            } catch (_: Throwable) {
            }
            callback.onBundle(bundle)
        }

        receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action != ACTION_SET_HIDE_CONFIG) {
                    return
                }
                val responseToken = intent.getStringExtra(EXTRA_QUERY_TOKEN)
                if (responseToken != requestToken) {
                    return
                }
                finish(intent.extras?.let { Bundle(it) })
            }
        }

        val filter = IntentFilter(ACTION_SET_HIDE_CONFIG)
        if (Build.VERSION.SDK_INT >= 33) {
            appContext.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            ContextCompat.registerReceiver(appContext, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
        }

        mainHandler.postDelayed({ finish(null) }, REQUEST_TIMEOUT_MS)

        appContext.sendBroadcast(
            Intent(ACTION_REQUEST_HIDE_CONFIG)
                .setComponent(ComponentName(APP_PACKAGE, "$APP_PACKAGE.HideConfigRequestReceiver"))
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                .putExtra(EXTRA_QUERY_TOKEN, requestToken)
                .putExtra(EXTRA_REPLY_PACKAGE, appContext.packageName)
                .putExtra(EXTRA_REPLY_ACTION, ACTION_SET_HIDE_CONFIG),
        )
        Log.d("FuseHide", "requested hide config replyPackage=${appContext.packageName} queryToken=$requestToken")
    }

    @JvmStatic
    fun reloadInjectedProcessConfig(context: Context): Boolean = reloadInjectedProcessConfig(context, null)

    @JvmStatic
    fun reloadInjectedProcessConfig(context: Context, callback: ReloadConfigCallback?): Boolean {
        val providerBundle = loadViaProviderBundle(context)
        if (applyBundleToNative(providerBundle)) {
            callback?.onResult(true)
            return true
        }
        requestInjectedProcessConfigBundle(context) { bundle ->
            val applied = applyBundleToNative(bundle)
            Log.d("FuseHide", "initial config fallback applied=$applied")
            callback?.onResult(applied)
        }
        return false
    }

    fun sendReloadBroadcast(context: Context, reloadToken: String) {
        listOf(
            PACKAGE_MEDIA_GOOGLE,
            PACKAGE_MEDIA,
        ).forEach { packageName ->
            context.sendBroadcast(
                android.content.Intent(ACTION_RELOAD_HIDE_CONFIG)
                    .setPackage(packageName)
                    .putExtra(EXTRA_RELOAD_TOKEN, reloadToken),
            )
        }
    }

    fun sendAppliedConfigQueryBroadcast(context: Context, queryToken: String) {
        listOf(
            PACKAGE_MEDIA_GOOGLE,
            PACKAGE_MEDIA,
        ).forEach { packageName ->
            context.sendBroadcast(
                android.content.Intent(ACTION_GET_APPLIED_HIDE_CONFIG)
                    .setPackage(packageName)
                    .putExtra(EXTRA_QUERY_TOKEN, queryToken),
            )
        }
    }

    private fun encodeList(values: List<String>): String = values.joinToString("\n")

    private fun parseStoredList(value: String?): List<String> {
        if (value.isNullOrBlank()) return emptyList()
        return HideConfigDefaults.parseEditorText(value)
    }
}
