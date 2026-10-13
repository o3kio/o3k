#!/bin/sh
if [ "$1" = "--test" ]; then exit 0; fi
for arg in "$@"; do
  case "$arg" in
    --pid-file=*) echo $$ > "${arg#--pid-file=}" ;;
  esac
done
# Replace the shell so the supervisor owns the only long-lived process.
exec sleep 30
