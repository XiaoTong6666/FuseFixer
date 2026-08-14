MIN_API=31

print_install_context() {
  if [ "$KSU" ]; then
    ui_print "- Installing from KernelSU app"
  elif [ "$MAGISK_VER_CODE" ]; then
    ui_print "- Installing from Magisk app"
  elif [ "$BOOTMODE" ]; then
    ui_print "- Installing from a compatible root manager"
  else
    ui_print "- Installing from recovery environment"
  fi
}

check_android_version() {
  if [ "$API" -lt "$MIN_API" ]; then
    abort "! Unsupported sdk: $API (min $MIN_API)"
  fi
  ui_print "- Device sdk: $API"
}

check_arch() {
  case "$ARCH" in
    arm|arm64|x86|x64)
      ui_print "- Device platform: $ARCH"
      ;;
    *)
      abort "! Unsupported platform: $ARCH"
      ;;
  esac
}
