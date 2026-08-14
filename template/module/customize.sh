#!/system/bin/sh
# FuseHide Zygisk module installer.

SKIPUNZIP=1

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
[ -f "$TMPDIR/verify.sh" ] || abort "Unable to extract verify.sh"
. "$TMPDIR/verify.sh"

ui_print "- Extracting util_functions.sh"
extract "$ZIPFILE" 'util_functions.sh' "$TMPDIR"
. "$TMPDIR/util_functions.sh"

print_install_context
check_android_version
check_arch

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop' "$MODPATH"
extract "$ZIPFILE" 'skip_mount' "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh' "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule' "$MODPATH"

ui_print "- Extracting FuseHide zygisk files"
unzip -o "$ZIPFILE" "lib/*/libfusehide.so" "zygisk/*" "framework/*" -d "$MODPATH" >&2 || abort "Failed to extract module files"

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

ui_print "FuseHide zygisk module installed"
ui_print "Reboot is required to take effect"
