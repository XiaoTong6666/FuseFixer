package io.github.xiaotong6666.fusefixer;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import fusefixer.MainThreadTask;
import fusefixer.StatusBroadcastReceiver;

public class Entry implements IXposedHookLoadPackage {
    private static final String APP_PACKAGE = "io.github.xiaotong6666.fusefixer";
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final String PACKAGE_MEDIA = "com.android.providers.media.module";
    private static final String PACKAGE_MEDIA_GOOGLE = "com.google.android.providers.media.module";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        if (PACKAGE_MEDIA.equals(loadPackageParam.packageName)
                || PACKAGE_MEDIA_GOOGLE.equals(loadPackageParam.packageName)) {
            System.loadLibrary("fusefixer");
            Log.d("LSPosedFuseFixer", "injected");
            new Handler(Looper.getMainLooper()).post(new MainThreadTask(0, this));
        }
    }

    public void registerStatusReceiver() {
        try {
            Application application = AndroidAppHelper.currentApplication();
            if (application == null) {
                Log.e("LSPosedFuseFixer", "app is null??");
                return;
            }
            StatusBroadcastReceiver receiver = new StatusBroadcastReceiver(application, 0);
            IntentFilter filter = new IntentFilter(ACTION_GET_STATUS);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(receiver, filter, 2);
            } else {
                application.registerReceiver(receiver, filter);
            }
            Log.d("LSPosedFuseFixer", "registered");
        } catch (Throwable th) {
            Log.e("LSPosedFuseFixer", "register", th);
        }
    }
}
