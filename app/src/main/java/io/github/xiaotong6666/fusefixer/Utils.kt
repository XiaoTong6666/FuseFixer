package io.github.xiaotong6666.fusefixer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.os.Build

object Utils {
    @JvmStatic
    external fun rmdir(path: String): Int

    @JvmStatic
    external fun unlink(path: String): Int

    fun registerExportedReceiver(context: Context, receiver: BroadcastReceiver, filter: IntentFilter) {
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, 2) // RECEIVER_EXPORTED
        } else {
            context.registerReceiver(receiver, filter)
        }
    }
}
