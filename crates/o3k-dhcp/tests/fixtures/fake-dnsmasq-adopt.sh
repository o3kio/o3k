#!/bin/sh
if [ "$1" = "--test" ]; then exit 0; fi
for arg in "$@"; do
  case "$arg" in
    --pid-file=*) echo $$ > "${arg#--pid-file=}" ;;
  esac
done
trap 'exit 0' TERM INT HUP
sleep 30
