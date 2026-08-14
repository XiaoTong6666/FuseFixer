TMPDIR_FOR_VERIFY="$TMPDIR/.vunzip"
mkdir -p "$TMPDIR_FOR_VERIFY"

abort_verify() {
  ui_print "*********************************************************"
  ui_print "! $1"
  abort    "*********************************************************"
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
