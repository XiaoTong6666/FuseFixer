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

package io.github.xiaotong6666.fusehide.config

import android.app.PendingIntent
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
import androidx.core.content.edit
import org.json.JSONArray
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

object HideConfigStore {
    const val APP_PACKAGE: String = io.github.xiaotong6666.fusehide.BuildConfig.APPLICATION_ID
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
    const val EXTRA_REPLY_PENDING_INTENT: String = "reply_pending_intent"
    private const val PREFS_NAME = "hide_config"
    private const val SNAPSHOT_PREFS_NAME = "hide_config_snapshot"
    private const val SNAPSHOT_VERSION = 1
    private const val METHOD_GET_HIDE_CONFIG = "get_hide_config"
    private const val AUTHORITY = "${io.github.xiaotong6666.fusehide.BuildConfig.APPLICATION_ID}.hideconfig"
    private const val KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES = "enable_hide_all_root_entries"
    private const val KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS = "hide_all_root_entries_exemptions"
    private const val KEY_HIDDEN_ROOT_ENTRY_NAMES = "hidden_root_entry_names"
    private const val KEY_HIDDEN_RELATIVE_PATHS = "hidden_relative_paths"
    private const val KEY_HIDDEN_PACKAGES = "hidden_packages"
    private const val KEY_PACKAGE_RULE_PACKAGES = "package_rule_packages"
    private const val KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES = "package_rule_root_entry_names"
    private const val KEY_PACKAGE_RULE_RELATIVE_PATHS = "package_rule_relative_paths"
    private const val KEY_RELOAD_TOKEN = "reload_token"
    private const val KEY_SNAPSHOT_VERSION = "snapshot_version"
    private const val REQUEST_TIMEOUT_MS = 3000L

    private val providerUri: Uri = Uri.parse("content://$AUTHORITY")

    private fun snapshotContext(context: Context): Context = context.createDeviceProtectedStorageContext()

    private fun hasValidSnapshot(prefs: android.content.SharedPreferences): Boolean = prefs.getInt(KEY_SNAPSHOT_VERSION, 0) == SNAPSHOT_VERSION

    private fun hasMatchingReloadToken(lhs: Bundle?, rhs: Bundle?): Boolean {
        val lhsToken = reloadTokenFromBundle(lhs)
        val rhsToken = reloadTokenFromBundle(rhs)
        return !lhsToken.isNullOrEmpty() && lhsToken == rhsToken
    }

    fun interface ConfigBundleCallback {
        fun onBundle(bundle: Bundle?)
    }

    fun interface ReloadConfigCallback {
        fun onResult(applied: Boolean)
    }

    @JvmStatic
    fun hasSavedConfig(context: Context): Boolean = hasSavedConfig(
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    )

    fun loadSavedConfigOrNull(context: Context): HideConfig? {
        if (!hasSavedConfig(context)) {
            return null
        }
        return load(context)
    }

    @JvmStatic
    fun savedReloadToken(context: Context): String? = context
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getString(KEY_RELOAD_TOKEN, null)

    fun load(context: Context): HideConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val defaults = HideConfigDefaults.value
        val packageRules = readStoredPackageRules(prefs, defaults)
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
            packageRules = packageRules,
        )
    }

    fun save(context: Context, config: HideConfig) {
        save(context, config, null)
    }

    fun save(context: Context, config: HideConfig, reloadToken: String?) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit {
                putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
                    .putString(
                        KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                        encodeList(config.hideAllRootEntriesExemptions),
                    )
                    .putString(KEY_HIDDEN_ROOT_ENTRY_NAMES, encodeList(config.hiddenRootEntryNames))
                    .putString(KEY_HIDDEN_RELATIVE_PATHS, encodeList(config.hiddenRelativePaths))
                    .putString(KEY_HIDDEN_PACKAGES, encodeList(config.hiddenPackages))
                    .putString(
                        KEY_PACKAGE_RULE_PACKAGES,
                        encodeList(config.packageRules.map { it.packageName }),
                    )
                    .putString(
                        KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES,
                        encodeNestedList(config.packageRules.map { it.hiddenRootEntryNames }),
                    )
                    .putString(
                        KEY_PACKAGE_RULE_RELATIVE_PATHS,
                        encodeNestedList(config.packageRules.map { it.hiddenRelativePaths }),
                    )
                    .putString(KEY_RELOAD_TOKEN, reloadToken)
            }
    }

    @JvmStatic
    fun saveInjectedProcessSnapshot(context: Context, config: HideConfig, reloadToken: String?): Boolean {
        val snapshotContext = snapshotContext(context)
        val saved = snapshotContext.getSharedPreferences(SNAPSHOT_PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
            .putString(
                KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                encodeList(config.hideAllRootEntriesExemptions),
            )
            .putString(KEY_HIDDEN_ROOT_ENTRY_NAMES, encodeList(config.hiddenRootEntryNames))
            .putString(KEY_HIDDEN_RELATIVE_PATHS, encodeList(config.hiddenRelativePaths))
            .putString(KEY_HIDDEN_PACKAGES, encodeList(config.hiddenPackages))
            .putString(KEY_PACKAGE_RULE_PACKAGES, encodeList(config.packageRules.map { it.packageName }))
            .putString(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES, encodeNestedList(config.packageRules.map { it.hiddenRootEntryNames }))
            .putString(KEY_PACKAGE_RULE_RELATIVE_PATHS, encodeNestedList(config.packageRules.map { it.hiddenRelativePaths }))
            .putString(KEY_RELOAD_TOKEN, reloadToken)
            .putInt(KEY_SNAPSHOT_VERSION, SNAPSHOT_VERSION)
            .commit()
        if (saved) {
            Log.d("FuseHide", "save injected snapshot ok token=$reloadToken")
        } else {
            Log.e("FuseHide", "save injected snapshot failed token=$reloadToken")
        }
        return saved
    }

    @JvmStatic
    fun loadInjectedProcessSnapshotBundle(context: Context): Bundle? {
        val snapshotContext = snapshotContext(context)
        val prefs = snapshotContext.getSharedPreferences(SNAPSHOT_PREFS_NAME, Context.MODE_PRIVATE)
        if (!hasValidSnapshot(prefs)) {
            return null
        }
        val defaults = HideConfigDefaults.value
        val packageRules = readStoredPackageRules(prefs, defaults)
        return toBundle(
            HideConfig(
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
                packageRules = packageRules,
            ),
        ).apply {
            putString(KEY_RELOAD_TOKEN, prefs.getString(KEY_RELOAD_TOKEN, null))
        }
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
        putStringArray(KEY_PACKAGE_RULE_PACKAGES, config.packageRules.map { it.packageName }.toTypedArray())
        putStringArray(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES, config.packageRules.map { encodeList(it.hiddenRootEntryNames) }.toTypedArray())
        putStringArray(KEY_PACKAGE_RULE_RELATIVE_PATHS, config.packageRules.map { encodeList(it.hiddenRelativePaths) }.toTypedArray())
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
            packageRules = parseBundledPackageRules(
                bundle.getStringArray(KEY_PACKAGE_RULE_PACKAGES)?.toList().orEmpty(),
                bundle.getStringArray(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES)?.toList().orEmpty(),
                bundle.getStringArray(KEY_PACKAGE_RULE_RELATIVE_PATHS)?.toList().orEmpty(),
            ),
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
                config.packageRules.map { it.packageName }.toTypedArray(),
                config.packageRules.map { encodeList(it.hiddenRootEntryNames) }.toTypedArray(),
                config.packageRules.map { encodeList(it.hiddenRelativePaths) }.toTypedArray(),
            )
            Log.i("FuseHide", buildAppliedConfigSnapshot(config))
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
        val pendingIntentFlags = PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_MUTABLE or
            if (Build.VERSION.SDK_INT >= 34) PendingIntent.FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT else 0
        val replyPendingIntent = PendingIntent.getBroadcast(
            appContext,
            requestToken.hashCode(),
            Intent(ACTION_SET_HIDE_CONFIG).setPackage(appContext.packageName),
            pendingIntentFlags,
        )

        fun finish(bundle: Bundle?) {
            if (!finished.compareAndSet(false, true)) {
                return
            }
            replyPendingIntent.cancel()
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
                .setComponent(ComponentName(APP_PACKAGE, "$APP_PACKAGE.config.HideConfigRequestReceiver"))
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                .putExtra(EXTRA_QUERY_TOKEN, requestToken)
                .putExtra(EXTRA_REPLY_PENDING_INTENT, replyPendingIntent),
        )
        Log.d("FuseHide", "requested hide config queryToken=$requestToken")
    }

    @JvmStatic
    fun reloadInjectedProcessConfig(context: Context): Boolean = reloadInjectedProcessConfig(context, null)

    @JvmStatic
    fun reloadInjectedProcessConfig(
        context: Context,
        callback: ReloadConfigCallback?,
    ): Boolean {
        val localSnapshotBundle = loadInjectedProcessSnapshotBundle(context)
        val snapshotApplied = applyBundleToNative(localSnapshotBundle)
        if (snapshotApplied) {
            Log.d("FuseHide", "initial config loaded from media snapshot")
        }
        val providerBundle = loadViaProviderBundle(context)
        val providerApplied = when {
            providerBundle == null -> false

            snapshotApplied && hasMatchingReloadToken(localSnapshotBundle, providerBundle) -> {
                Log.d("FuseHide", "provider config matches local snapshot token=${reloadTokenFromBundle(providerBundle)}")
                true
            }

            else -> applyBundleToNative(providerBundle)
        }
        if (providerApplied) {
            fromBundle(providerBundle)?.let {
                saveInjectedProcessSnapshot(context, it, reloadTokenFromBundle(providerBundle))
            }
            callback?.onResult(true)
            return true
        }
        requestInjectedProcessConfigBundle(context) { bundle ->
            val applied = when {
                bundle == null -> false

                snapshotApplied && hasMatchingReloadToken(localSnapshotBundle, bundle) -> {
                    Log.d("FuseHide", "fallback config matches local snapshot token=${reloadTokenFromBundle(bundle)}")
                    true
                }

                else -> applyBundleToNative(bundle)
            }
            if (applied) {
                fromBundle(bundle)?.let {
                    saveInjectedProcessSnapshot(context, it, reloadTokenFromBundle(bundle))
                }
            }
            val result = applied || snapshotApplied
            Log.d("FuseHide", "initial config fallback applied=$applied snapshotApplied=$snapshotApplied")
            callback?.onResult(result)
        }
        return snapshotApplied
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

    private fun encodeNestedList(values: List<List<String>>): String = JSONArray().apply {
        values.forEach { put(JSONArray(it)) }
    }.toString()

    private fun parseStoredList(value: String?): List<String> {
        if (value.isNullOrBlank()) return emptyList()
        return HideConfigDefaults.parseEditorText(value)
    }

    private fun parseStoredPackageRules(
        packageNamesText: String?,
        rootNamesText: String?,
        relativePathsText: String?,
    ): List<PackageHideRule> = parseBundledPackageRules(
        parseStoredList(packageNamesText),
        parseNestedList(rootNamesText).map { encodeList(it) },
        parseNestedList(relativePathsText).map { encodeList(it) },
    )

    private fun parseBundledPackageRules(
        packageNames: List<String>,
        rootNamesByPackage: List<String>,
        relativePathsByPackage: List<String>,
    ): List<PackageHideRule> = packageNames.mapIndexedNotNull { index, packageName ->
        val rootNames = parseStoredList(rootNamesByPackage.getOrNull(index))
        val relativePaths = parseStoredList(relativePathsByPackage.getOrNull(index))
        if (packageName.isBlank() || (rootNames.isEmpty() && relativePaths.isEmpty())) {
            null
        } else {
            PackageHideRule(packageName, rootNames, relativePaths)
        }
    }

    private fun parseNestedList(value: String?): List<List<String>> {
        if (value.isNullOrBlank()) return emptyList()
        return try {
            val array = JSONArray(value)
            List(array.length()) { index ->
                val child = array.optJSONArray(index) ?: JSONArray()
                List(child.length()) { childIndex -> child.optString(childIndex) }
                    .filter { it.isNotBlank() }
            }
        } catch (t: Throwable) {
            Log.e("FuseHide", "parseNestedList", t)
            emptyList()
        }
    }

    private fun readStoredPackageRules(
        prefs: android.content.SharedPreferences,
        defaults: HideConfig,
    ): List<PackageHideRule> {
        val hasAnyStoredPackageRuleKey =
            prefs.contains(KEY_PACKAGE_RULE_PACKAGES) ||
                prefs.contains(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES) ||
                prefs.contains(KEY_PACKAGE_RULE_RELATIVE_PATHS)
        if (!hasAnyStoredPackageRuleKey) {
            return defaults.packageRules
        }
        return parseStoredPackageRules(
            prefs.getString(KEY_PACKAGE_RULE_PACKAGES, null),
            prefs.getString(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES, null),
            prefs.getString(KEY_PACKAGE_RULE_RELATIVE_PATHS, null),
        )
    }

    private fun hasSavedConfig(prefs: android.content.SharedPreferences): Boolean = prefs.contains(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES) ||
        prefs.contains(KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS) ||
        prefs.contains(KEY_HIDDEN_ROOT_ENTRY_NAMES) ||
        prefs.contains(KEY_HIDDEN_RELATIVE_PATHS) ||
        prefs.contains(KEY_HIDDEN_PACKAGES) ||
        prefs.contains(KEY_PACKAGE_RULE_PACKAGES) ||
        prefs.contains(KEY_PACKAGE_RULE_ROOT_ENTRY_NAMES) ||
        prefs.contains(KEY_PACKAGE_RULE_RELATIVE_PATHS)
}
