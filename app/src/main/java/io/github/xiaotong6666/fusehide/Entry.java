package io.github.xiaotong6666.fusehide;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.core.content.ContextCompat;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Entry implements IXposedHookLoadPackage {
    private static final String APP_PACKAGE = "io.github.xiaotong6666.fusehide";
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final String PACKAGE_MEDIA = "com.android.providers.media.module";
    private static final String PACKAGE_MEDIA_GOOGLE = "com.google.android.providers.media.module";
    private static final long CONFIG_RETRY_DELAY_MS = 15000L;
    private static final int CONFIG_MAX_RETRIES = 8;

    private Handler mainHandler;
    private Application hookedApplication;
    private boolean configLoadCompleted;
    private boolean configLoadInFlight;
    private int pendingConfigRetryCount;
    private final Runnable configRetryRunnable = new Runnable() {
        @Override
        public void run() {
            startConfigReload("delayed_retry_" + pendingConfigRetryCount);
        }
    };

    private Handler getMainHandler() {
        if (mainHandler == null) {
            mainHandler = new Handler(Looper.getMainLooper());
        }
        return mainHandler;
    }

    private static HideConfig currentNativeHideConfig() {
        return new HideConfig(
                HideConfigNativeBridge.getCurrentEnableHideAllRootEntries(),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHideAllRootEntriesExemptions()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRootEntryNames()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRelativePaths()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenPackages()));
    }

    private static void sendConfigStatus(
            Application application, String requestedToken, boolean applied, String message) {
        application.sendBroadcast(new Intent(HideConfigStore.ACTION_SET_CONFIG_STATUS)
                .setPackage(APP_PACKAGE)
                .putExtra(HideConfigStore.EXTRA_RELOAD_TOKEN, requestedToken)
                .putExtra(HideConfigStore.EXTRA_RELOAD_APPLIED, applied)
                .putExtra(HideConfigStore.EXTRA_RELOAD_MESSAGE, message));
    }

    private static void finishConfigReload(
            Application application,
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
                message = applied ? "hide config applied" : "apply failed";
            }
            sendConfigStatus(application, requestedToken, applied, message);
            Log.d(
                    "FuseHide",
                    "config reload source=" + source + " applied=" + applied + " tokenMatches=" + tokenMatches);
        } finally {
            pendingResult.finish();
        }
    }

    private void onConfigReloadFinished(String source, boolean applied) {
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

    private void scheduleConfigRetry(String source) {
        if (hookedApplication == null || configLoadCompleted) {
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

    private void startConfigReload(String source) {
        final Application application = hookedApplication;
        if (application == null || configLoadCompleted || configLoadInFlight) {
            return;
        }
        configLoadInFlight = true;
        HideConfigStore.reloadInjectedProcessConfig(application, applied -> onConfigReloadFinished(source, applied));
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            if (PACKAGE_MEDIA.equals(loadPackageParam.packageName)
                    || PACKAGE_MEDIA_GOOGLE.equals(loadPackageParam.packageName)) {
                System.loadLibrary("fusehide");
                Log.d("FuseHide", "injected");
                if ((loadPackageParam.appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    try {
                        XposedHelpers.findAndHookMethod(
                                "com.android.providers.media.MediaProvider",
                                loadPackageParam.classLoader,
                                "isUidAllowedAccessToDataOrObbPathForFuse",
                                int.class,
                                String.class,
                                new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) {
                                        Log.d(
                                                "FuseHide",
                                                "isUidAllowedAccessToDataOrObbPathForFuse uid="
                                                        + param.args[0]
                                                        + " path="
                                                        + param.args[1]
                                                        + " result="
                                                        + param.getResult());
                                    }
                                });
                    } catch (Throwable th) {
                        Log.e("FuseHide", "hook isUidAllowedAccessToDataOrObbPathForFuse", th);
                    }
                }
                new Handler(Looper.getMainLooper()).post(new MainThreadTask(0, this));
            }
        } catch (Throwable th) {
            Log.e("FuseHide", "handleLoadPackage", th);
        }
    }

    public void registerStatusReceiver() {
        try {
            Application application = AndroidAppHelper.currentApplication();
            if (application == null) {
                Log.e("FuseHide", "app is null??");
                return;
            }
            hookedApplication = application;
            StatusBroadcastReceiver receiver = new StatusBroadcastReceiver(application, 0);
            IntentFilter filter = new IntentFilter(ACTION_GET_STATUS);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(application, receiver, filter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver configReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final PendingResult pendingResult = goAsync();
                    final String requestedToken = intent.getStringExtra(HideConfigStore.EXTRA_RELOAD_TOKEN);
                    final android.os.Bundle bundle = HideConfigStore.loadViaProviderBundle(application);
                    final String providerToken = HideConfigStore.reloadTokenFromBundle(bundle);
                    final boolean providerTokenMatches = requestedToken != null && requestedToken.equals(providerToken);
                    if (bundle != null && providerTokenMatches) {
                        finishConfigReload(application, requestedToken, bundle, "provider", pendingResult);
                        return;
                    }
                    HideConfigStore.requestInjectedProcessConfigBundle(
                            application,
                            fallbackBundle -> finishConfigReload(
                                    application, requestedToken, fallbackBundle, "broadcast_fallback", pendingResult));
                }
            };
            IntentFilter configFilter = new IntentFilter(HideConfigStore.ACTION_RELOAD_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(configReceiver, configFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        application, configReceiver, configFilter, ContextCompat.RECEIVER_EXPORTED);
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
                    application.sendBroadcast(reply);
                    Log.d("FuseHide", "reported applied hide config queryToken=" + queryToken);
                }
            };
            IntentFilter queryFilter = new IntentFilter(HideConfigStore.ACTION_GET_APPLIED_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(queryReceiver, queryFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        application, queryReceiver, queryFilter, ContextCompat.RECEIVER_EXPORTED);
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
                application.registerReceiver(systemStateReceiver, systemFilter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        application, systemStateReceiver, systemFilter, ContextCompat.RECEIVER_NOT_EXPORTED);
            }

            startConfigReload("initial");
            Log.d("FuseHide", "registered");
        } catch (Throwable th) {
            Log.e("FuseHide", "register", th);
        }
    }
}
