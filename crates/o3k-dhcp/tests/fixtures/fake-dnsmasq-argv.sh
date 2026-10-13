#!/bin/sh
set -eu
for arg in "$@"; do
  case "$arg" in
    --test) exit 0 ;;
    --conf-file=*) root=$(dirname "${arg#--conf-file=}") ;;
  esac
done
# Publish only complete serving arguments, never config-probe arguments.
printf '%s\n' "$@" > "$root/argv.pending"
mv -- "$root/argv.pending" "$root/argv.txt"
exec sleep 30
