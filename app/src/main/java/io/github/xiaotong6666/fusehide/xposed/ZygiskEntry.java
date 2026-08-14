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

package io.github.xiaotong6666.fusehide.xposed;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.core.content.ContextCompat;
import io.github.xiaotong6666.fusehide.config.HideConfig;
import io.github.xiaotong6666.fusehide.config.HideConfigNativeBridge;
import io.github.xiaotong6666.fusehide.config.HideConfigStore;
import io.github.xiaotong6666.fusehide.config.PackageHideRule;
import io.github.xiaotong6666.fusehide.status.StatusBroadcastReceiver;

/**
 * Zygisk configuration sync entry, injected by the wrapper without LSPosed.
 * Native code calls init(Context) via reflection after libfuse_jni.so is loaded.
 */
public final class ZygiskEntry {
    private static final String APP_PACKAGE = io.github.xiaotong6666.fusehide.BuildConfig.APPLICATION_ID;
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final long CONFIG_RETRY_DELAY_MS = 15000L;
    private static final int CONFIG_MAX_RETRIES = 8;

    private static volatile Handler mainHandler;
    private static Context appContext;
    private static boolean configLoadCompleted;
    private static boolean configLoadInFlight;
    private static int pendingConfigRetryCount;
    private static final Runnable configRetryRunnable = new Runnable() {
        @Override
        public void run() {
            startConfigReload("delayed_retry_" + pendingConfigRetryCount);
        }
    };

    private ZygiskEntry() {}

    private static Handler getMainHandler() {
        Handler h = mainHandler;
        if (h == null) {
            synchronized (ZygiskEntry.class) {
                h = mainHandler;
                if (h == null) {
                    h = new Handler(Looper.getMainLooper());
                    mainHandler = h;
                }
            }
        }
        return h;
    }

    private static java.util.List<String> splitRuleLines(String value) {
        if (value == null || value.isEmpty()) {
            return java.util.Collections.emptyList();
        }
        final java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String line : value.split("\\n")) {
            final String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    private static HideConfig currentNativeHideConfig() {
        final String[] rulePackages = HideConfigNativeBridge.getCurrentPackageRulePackages();
        final String[] ruleRoots = HideConfigNativeBridge.getCurrentPackageRuleHiddenRootEntryNames();
        final String[] ruleRelatives = HideConfigNativeBridge.getCurrentPackageRuleHiddenRelativePaths();
        final java.util.ArrayList<PackageHideRule> packageRules = new java.util.ArrayList<>();
        for (int i = 0; i < rulePackages.length; i++) {
            final java.util.List<String> roots =
                    i < ruleRoots.length ? splitRuleLines(ruleRoots[i]) : java.util.Collections.emptyList();
            final java.util.List<String> relatives =
                    i < ruleRelatives.length ? splitRuleLines(ruleRelatives[i]) : java.util.Collections.emptyList();
            packageRules.add(new PackageHideRule(rulePackages[i], roots, relatives));
        }
        return new HideConfig(
                HideConfigNativeBridge.getCurrentEnableHideAllRootEntries(),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHideAllRootEntriesExemptions()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRootEntryNames()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRelativePaths()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenPackages()),
                packageRules);
    }

    private static void sendConfigStatus(Context context, String requestedToken, boolean applied, String message) {
        context.sendBroadcast(new Intent(HideConfigStore.ACTION_SET_CONFIG_STATUS)
                .setPackage(APP_PACKAGE)
                .putExtra(HideConfigStore.EXTRA_RELOAD_TOKEN, requestedToken)
                .putExtra(HideConfigStore.EXTRA_RELOAD_APPLIED, applied)
                .putExtra(HideConfigStore.EXTRA_RELOAD_MESSAGE, message));
    }

    private static void finishConfigReload(
            Context context,
            String requestedToken,
            android.os.Bundle bundle,
            String source,
            BroadcastReceiver.PendingResult pendingResult) {
        try {
            final HideConfig config = HideConfigStore.fromBundle(bundle);
            final String bundleToken = HideConfigStore.reloadTokenFromBundle(bundle);
            final boolean tokenMatches = requestedToken != null && requestedToken.equals(bundleToken);
            boolean applied = false;
            String message;
            if (bundle == null || config == null) {
                message = "hide config unavailable";
            } else if (!tokenMatches) {
                message = "reload token mismatch";
            } else {
                applied = HideConfigStore.applyBundleToNative(bundle);
                if (applied) {
                    applied = HideConfigStore.saveInjectedProcessSnapshot(context, config, bundleToken);
                    message = applied ? "hide config applied" : "snapshot save failed";
                } else {
                    message = "apply failed";
                }
            }
            sendConfigStatus(context, requestedToken, applied, message);
            Log.d(
                    "FuseHide",
                    "config reload source=" + source + " applied=" + applied + " tokenMatches=" + tokenMatches);
        } finally {
            pendingResult.finish();
        }
    }

    private static void onConfigReloadFinished(String source, boolean applied) {
        configLoadInFlight = false;
        if (applied) {
            configLoadCompleted = true;
            pendingConfigRetryCount = 0;
            getMainHandler().removeCallbacks(configRetryRunnable);
            Log.d("FuseHide", "config reload source=" + source + " applied=true");
            return;
        }
        Log.d("FuseHide", "config reload source=" + source + " applied=false");
        scheduleConfigRetry(source);
    }

    private static void scheduleConfigRetry(String source) {
        if (appContext == null || configLoadCompleted) {
            return;
        }
        if (pendingConfigRetryCount >= CONFIG_MAX_RETRIES) {
            Log.w("FuseHide", "config retry exhausted source=" + source);
            return;
        }
        pendingConfigRetryCount += 1;
        getMainHandler().removeCallbacks(configRetryRunnable);
        getMainHandler().postDelayed(configRetryRunnable, CONFIG_RETRY_DELAY_MS);
        Log.d(
                "FuseHide",
                "scheduled config retry source="
                        + source
                        + " attempt="
                        + pendingConfigRetryCount
                        + " delayMs="
                        + CONFIG_RETRY_DELAY_MS);
    }

    private static void startConfigReload(String source) {
        final Context context = appContext;
        if (context == null || configLoadCompleted || configLoadInFlight) {
            return;
        }
        configLoadInFlight = true;
        HideConfigStore.reloadInjectedProcessConfig(context, applied -> onConfigReloadFinished(source, applied));
    }

    /** 由 native 侧在 libfuse_jni.so 加载完成后调用。 */
    @SuppressLint({"DiscouragedPrivateApi", "PrivateApi"})
    public static void init(Context context) {
        appContext = context;
        Log.d("FuseHide", "ZygiskEntry init, context=" + context);
        getMainHandler().post(new Runnable() {
            @Override
            public void run() {
                registerStatusReceiver();
            }
        });
    }

    @SuppressLint({"DiscouragedPrivateApi", "PrivateApi"})
    private static void registerStatusReceiver() {
        try {
            final Context app = appContext;
            if (app == null) {
                return;
            }
            StatusBroadcastReceiver receiver = new StatusBroadcastReceiver(new android.content.ContextWrapper(app), 0);
            IntentFilter filter = new IntentFilter(ACTION_GET_STATUS);
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(app, receiver, filter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver configReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final PendingResult pendingResult = goAsync();
                    final String requestedToken = intent.getStringExtra(HideConfigStore.EXTRA_RELOAD_TOKEN);
                    new Thread(() -> {
                                final android.os.Bundle bundle = HideConfigStore.loadViaProviderBundle(app);
                                final String providerToken = HideConfigStore.reloadTokenFromBundle(bundle);
                                final boolean providerTokenMatches =
                                        requestedToken != null && requestedToken.equals(providerToken);
                                if (bundle != null && providerTokenMatches) {
                                    finishConfigReload(app, requestedToken, bundle, "provider", pendingResult);
                                    return;
                                }
                                HideConfigStore.requestInjectedProcessConfigBundle(
                                        app,
                                        fallbackBundle -> finishConfigReload(
                                                app,
                                                requestedToken,
                                                fallbackBundle,
                                                "broadcast_fallback",
                                                pendingResult));
                            })
                            .start();
                }
            };
            IntentFilter configFilter = new IntentFilter(HideConfigStore.ACTION_RELOAD_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(configReceiver, configFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(app, configReceiver, configFilter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver queryReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String queryToken = intent.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN);
                    final HideConfig config = currentNativeHideConfig();
                    Intent reply = new Intent(HideConfigStore.ACTION_SET_APPLIED_HIDE_CONFIG)
                            .setPackage(APP_PACKAGE)
                            .putExtra(HideConfigStore.EXTRA_QUERY_TOKEN, queryToken)
                            .putExtras(HideConfigStore.toBundle(config));
                    app.sendBroadcast(reply);
                    Log.d("FuseHide", "reported applied hide config queryToken=" + queryToken);
                }
            };
            IntentFilter queryFilter = new IntentFilter(HideConfigStore.ACTION_GET_APPLIED_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(queryReceiver, queryFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(app, queryReceiver, queryFilter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver systemStateReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String action = intent != null ? intent.getAction() : null;
                    if (action == null || configLoadCompleted) {
                        return;
                    }
                    pendingConfigRetryCount = 0;
                    getMainHandler().removeCallbacks(configRetryRunnable);
                    Log.d("FuseHide", "system config trigger action=" + action);
                    startConfigReload(action);
                }
            };
            IntentFilter systemFilter = new IntentFilter();
            systemFilter.addAction(Intent.ACTION_LOCKED_BOOT_COMPLETED);
            systemFilter.addAction(Intent.ACTION_BOOT_COMPLETED);
            systemFilter.addAction(Intent.ACTION_USER_UNLOCKED);
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(systemStateReceiver, systemFilter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        app, systemStateReceiver, systemFilter, ContextCompat.RECEIVER_NOT_EXPORTED);
            }

            // The native uid-rule caches depend on PackageManager's package set, not only on the
            // serialized hide config pushed through the provider.
            BroadcastReceiver packageStateReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String action = intent != null ? intent.getAction() : null;
                    if (action == null) {
                        return;
                    }
                    // Package replacement emits remove/add pairs for the same app. Skip that churn
                    // and only invalidate when the uid-visible package set really changes.
                    if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                        return;
                    }
                    final String pkg =
                            intent.getData() != null ? intent.getData().getSchemeSpecificPart() : null;
                    final String reason = pkg == null ? action : action + ":" + pkg;
                    HideConfigNativeBridge.notifyPackageSetChanged(reason);
                    Log.d("FuseHide", "package set changed reason=" + reason);
                }
            };
            IntentFilter packageFilter = new IntentFilter();
            packageFilter.addAction(Intent.ACTION_PACKAGE_ADDED);
            packageFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
            packageFilter.addDataScheme("package");
            if (Build.VERSION.SDK_INT >= 33) {
                app.registerReceiver(packageStateReceiver, packageFilter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        app, packageStateReceiver, packageFilter, ContextCompat.RECEIVER_NOT_EXPORTED);
            }

            startConfigReload("initial");
            Log.d("FuseHide", "registered");
        } catch (Throwable th) {
            Log.e("FuseHide", "register", th);
        }
    }
}
