TMPDIR_FOR_VERIFY="$TMPDIR/.vunzip"
mkdir -p "$TMPDIR_FOR_VERIFY"

abort_verify() {
  ui_print "*********************************************************"
  ui_print "! $1"
  abort    "*********************************************************"
}

verify_apk_signature() {
  zip=$1
  [ "$BOOTMODE" = true ] || abort_verify "APK signature verification requires boot mode"

  apk_size=$(wc -c < "$zip" 2>/dev/null | tr -d '[:space:]')
  case "$apk_size" in
    ''|*[!0-9]*) abort_verify "Unable to determine APK size" ;;
    0) abort_verify "APK is empty" ;;
  esac

  ui_print "- Verifying APK signature and installing frontend"
  install_output=$(cat "$zip" | pm install -r -d -S "$apk_size" 2>&1)
  install_status=$?
  if [ "$install_status" -ne 0 ]; then
    ui_print "$install_output"
    abort_verify "APK signature verification failed"
  fi
  ui_print "- APK signature verified"
}

# extract <zip> <file> <target dir> <junk paths>
extract() {
  zip=$1
  file=$2
  dir=$3
  junk_paths=$4
  [ -z "$junk_paths" ] && junk_paths=false
  opts="-o"
  [ "$junk_paths" = true ] && opts="-oj"

  if [ "$junk_paths" = true ]; then
    file_path="$dir/$(basename "$file")"
  else
    file_path="$dir/$file"
  fi

  unzip $opts "$zip" "$file" -d "$dir" >&2
  [ -e "$file_path" ] || abort_verify "$file not exists"
}
