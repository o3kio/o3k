#!/bin/sh
[ "$1" = "--test" ] && exit 1
# Replace the shell so the supervisor owns the only long-lived process.
exec sleep 30
