#!/bin/sh
for arg in "$@"; do
  [ "$arg" = "--test" ] && exit 0
done
sleep 0.02
exit 1
