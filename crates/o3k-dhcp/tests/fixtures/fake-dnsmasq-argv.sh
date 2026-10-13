#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --conf-file=*) root=$(dirname "${arg#--conf-file=}") ;;
  esac
done
printf '%s\n' "$@" > "$root/argv.txt"
trap 'exit 0' TERM INT HUP
for arg in "$@"; do
  [ "$arg" = "--test" ] && exit 0
done
sleep 30
