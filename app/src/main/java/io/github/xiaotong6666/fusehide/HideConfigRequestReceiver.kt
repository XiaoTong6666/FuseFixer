package io.github.xiaotong6666.fusehide

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.util.Log

private val allowedConfigRequestPackages = setOf(
    HideConfigStore.APP_PACKAGE,
    HideConfigStore.PACKAGE_MEDIA,
    HideConfigStore.PACKAGE_MEDIA_GOOGLE,
    "android",
)

class HideConfigRequestReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != HideConfigStore.ACTION_REQUEST_HIDE_CONFIG) {
            return
        }
        if (!isTrustedCaller(context)) {
            Log.e("FuseHide", "reject hide config request callerUid=${Binder.getCallingUid()}")
            return
        }

        val queryToken = intent.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN)
        val replyPackage = intent.getStringExtra(HideConfigStore.EXTRA_REPLY_PACKAGE)
        val replyAction = intent.getStringExtra(HideConfigStore.EXTRA_REPLY_ACTION)
        if (queryToken.isNullOrEmpty() || replyPackage.isNullOrEmpty() || replyAction.isNullOrEmpty()) {
            Log.e("FuseHide", "hide config request missing reply metadata")
            return
        }

        val response = Intent(replyAction)
            .setPackage(replyPackage)
            .addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
            .putExtra(HideConfigStore.EXTRA_QUERY_TOKEN, queryToken)
            .putExtras(HideConfigStore.toBundle(HideConfigStore.load(context)))
            .putExtra(
                HideConfigStore.EXTRA_RELOAD_TOKEN,
                context.getSharedPreferences("hide_config", Context.MODE_PRIVATE)
                    .getString("reload_token", null),
            )
        context.sendBroadcast(response)
        Log.d("FuseHide", "served hide config request callerUid=${Binder.getCallingUid()} replyPackage=$replyPackage queryToken=$queryToken")
    }

    private fun isTrustedCaller(context: Context): Boolean {
        val callingUid = Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) {
            return true
        }
        if (callingUid == android.os.Process.SYSTEM_UID || callingUid == android.os.Process.SHELL_UID) {
            return true
        }
        val packages = context.packageManager.getPackagesForUid(callingUid).orEmpty()
        return packages.any { it in allowedConfigRequestPackages }
    }
}
