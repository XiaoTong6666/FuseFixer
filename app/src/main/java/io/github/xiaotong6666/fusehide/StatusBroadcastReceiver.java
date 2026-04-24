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

package io.github.xiaotong6666.fusehide;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Process;
import android.util.Log;

public final class StatusBroadcastReceiver extends BroadcastReceiver {
    private static final String APP_PACKAGE = "io.github.xiaotong6666.fusehide";
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final String ACTION_SET_STATUS = APP_PACKAGE + ".SET_STATUS";
    private static final String PACKAGE_MEDIA = "com.android.providers.media.module";
    private static final String PACKAGE_MEDIA_GOOGLE = "com.google.android.providers.media.module";
    private final int mode;
    private final ContextWrapper owner;

    public StatusBroadcastReceiver(ContextWrapper owner, int mode) {
        this.mode = mode;
        this.owner = owner;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (mode == 0) {
            handleGetStatus(intent);
        } else {
            handleSetStatus(intent);
        }
    }

    private void handleGetStatus(Intent intent) {
        try {
            Log.d("FuseHide", "recv " + intent);
            PendingIntent pendingIntent = intent.getParcelableExtra("EXTRA_PENDING_INTENT");
            if (pendingIntent == null) {
                Log.e("FuseHide", "no pendingintent?");
                return;
            }
            if (!APP_PACKAGE.equals(pendingIntent.getCreatorPackage())) {
                Log.e("FuseHide", "invalid pkg " + pendingIntent.getCreatorPackage());
                return;
            }

            Intent statusIntent = new Intent(ACTION_SET_STATUS).setPackage(APP_PACKAGE);
            statusIntent.putExtra("EXTRA_PENDING_INTENT", PendingIntent.getBroadcast(owner, 1, statusIntent, 67108864));
            statusIntent.putExtra("EXTRA_PID", Process.myPid());
            if (statusIntent.getExtras() != null) {
                statusIntent
                        .getExtras()
                        .putBinder("EXTRA_BINDER", statusIntent.getExtras().getBinder("EXTRA_BINDER"));
            }
            owner.sendBroadcast(statusIntent);
        } catch (Throwable th) {
            Log.e("FuseHide", "send: ", th);
        }
    }

    private void handleSetStatus(Intent intent) {
        MainActivity mainActivity = (MainActivity) owner;
        try {
            Log.d("FuseHide", "recv status " + intent);
            PendingIntent pendingIntent = intent.getParcelableExtra("EXTRA_PENDING_INTENT");
            if (pendingIntent == null) {
                Log.e("FuseHide", "status pendingintent missing");
                return;
            }
            String creatorPackage = pendingIntent.getCreatorPackage();
            if (PACKAGE_MEDIA.equals(creatorPackage) || PACKAGE_MEDIA_GOOGLE.equals(creatorPackage)) {
                mainActivity.onHookStatusReceived(creatorPackage, intent.getIntExtra("EXTRA_PID", -1));
            }
        } catch (Throwable th) {
            Log.e("FuseHide", "send: ", th);
        }
    }
}
