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
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

private val allowedConfigRequestPackages = setOf(
    HideConfigStore.PACKAGE_MEDIA,
    HideConfigStore.PACKAGE_MEDIA_GOOGLE,
)

@Suppress("DEPRECATION")
private fun Intent.getReplyPendingIntent(): PendingIntent? = if (Build.VERSION.SDK_INT >= 33) {
    getParcelableExtra(HideConfigStore.EXTRA_REPLY_PENDING_INTENT, PendingIntent::class.java)
} else {
    getParcelableExtra(HideConfigStore.EXTRA_REPLY_PENDING_INTENT)
}

class HideConfigRequestReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != HideConfigStore.ACTION_REQUEST_HIDE_CONFIG) {
            return
        }
        val replyPendingIntent = intent.getReplyPendingIntent()
        if (replyPendingIntent == null || !isTrustedRequester(context, replyPendingIntent)) {
            Log.e(
                "FuseHide",
                "reject hide config request creatorPackage=${replyPendingIntent?.creatorPackage} creatorUid=${replyPendingIntent?.creatorUid}",
            )
            return
        }

        val queryToken = intent.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN)
        if (queryToken.isNullOrEmpty()) {
            Log.e("FuseHide", "hide config request missing query token")
            return
        }
        val config = HideConfigStore.loadSavedConfigOrNull(context)
        if (config == null) {
            Log.e("FuseHide", "hide config request ignored because no saved app config exists")
            return
        }

        val response = Intent()
            .putExtra(HideConfigStore.EXTRA_QUERY_TOKEN, queryToken)
            .putExtras(HideConfigStore.toBundle(config))
            .putExtra(HideConfigStore.EXTRA_RELOAD_TOKEN, HideConfigStore.savedReloadToken(context))
        try {
            replyPendingIntent.send(context, 0, response)
            Log.d(
                "FuseHide",
                "served hide config request creatorPackage=${replyPendingIntent.creatorPackage} queryToken=$queryToken",
            )
        } catch (e: PendingIntent.CanceledException) {
            Log.e("FuseHide", "hide config reply pending intent was canceled", e)
        }
    }

    private fun isTrustedRequester(context: Context, replyPendingIntent: PendingIntent): Boolean {
        val creatorPackage = replyPendingIntent.creatorPackage ?: return false
        if (creatorPackage !in allowedConfigRequestPackages) {
            return false
        }
        return creatorPackage in context.packageManager.getPackagesForUid(replyPendingIntent.creatorUid).orEmpty()
    }
}
