#!/system/bin/sh

MODDIR=${0%/*}
DB=/data/adb/lspd/config/modules_config.db
FLAG=$MODDIR/lsp_scope_enabled
MODULE=io.github.xiaotong6666.fusehide
TARGET_AOSP=com.android.providers.media.module
TARGET_GOOGLE=com.google.android.providers.media.module

rm -f "$FLAG"

if [ ! -x /system/bin/sqlite3 ] || [ ! -f "$DB" ]; then
  exit 0
fi

result=$(
  /system/bin/sqlite3 "$DB" \
    "SELECT 1 FROM modules m JOIN scope s ON m.mid = s.mid WHERE m.module_pkg_name='$MODULE' AND s.app_pkg_name IN ('$TARGET_AOSP', '$TARGET_GOOGLE') AND s.user_id=0 AND m.enabled=1 LIMIT 1;" \
    2>/dev/null
)

if [ "$result" != "1" ]; then
  result=$(
    /system/bin/sqlite3 "$DB" \
      "SELECT 1 FROM modules_state ms JOIN scope s ON ms.module_pkg_name = s.module_pkg_name AND ms.user_id = s.user_id WHERE ms.module_pkg_name='$MODULE' AND s.app_pkg_name IN ('$TARGET_AOSP', '$TARGET_GOOGLE') AND ms.user_id=0 AND ms.enabled=1 LIMIT 1;" \
      2>/dev/null
  )
fi

if [ "$result" = "1" ]; then
  : > "$MODDIR/disable"
  chmod 0600 "$MODDIR/disable"
  : > "$FLAG"
  chmod 0600 "$FLAG"
else
  rm -f "$MODDIR/disable"
  rm -f "$FLAG"
fi

exit 0
