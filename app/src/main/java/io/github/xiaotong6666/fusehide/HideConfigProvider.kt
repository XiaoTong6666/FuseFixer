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

package io.github.xiaotong6666.fusehide

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle

private val allowedCallerPackages = setOf(
    HideConfigStore.APP_PACKAGE,
    HideConfigStore.PACKAGE_MEDIA,
    HideConfigStore.PACKAGE_MEDIA_GOOGLE,
)

class HideConfigProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method == "get_hide_config") {
            val appContext = context ?: return null
            if (!isTrustedCaller(appContext)) {
                return null
            }
            return HideConfigStore.toBundle(HideConfigStore.load(appContext))
                .apply {
                    putString(
                        "reload_token",
                        appContext.getSharedPreferences("hide_config", android.content.Context.MODE_PRIVATE)
                            .getString("reload_token", null),
                    )
                }
        }
        return super.call(method, arg, extras)
    }

    private fun isTrustedCaller(appContext: android.content.Context): Boolean {
        val callingUid = Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) {
            return true
        }
        val packages = appContext.packageManager.getPackagesForUid(callingUid).orEmpty()
        return packages.any { it in allowedCallerPackages }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
