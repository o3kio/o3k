#!/bin/sh
[ "$1" = "--test" ] && exit 1
trap 'exit 0' TERM INT HUP
sleep 30
