#!/usr/bin/env bash

fabric_v3_host_slot() {
  case "${1:-}" in
    a) printf '2' ;;
    b) printf '3' ;;
    c) printf '4' ;;
    *)
      printf 'unsupported compute host identity: %s\n' "${1:-}" >&2
      return 2
      ;;
  esac
}
