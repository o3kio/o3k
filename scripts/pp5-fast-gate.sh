#!/usr/bin/env bash
set -Eeuo pipefail

# Canonical, cheap PP.5 PostgreSQL prerequisite entrypoint.  Both the
# protected workflow and manual qualification invoke this wrapper; it only
# delegates to the repository-owned purpose-map authority and never performs
# TestLab/VM provisioning.

phase="${1:-}"
case "${phase}" in
  preflight|provision|verify|cleanup)
    exec python3 scripts/provision_pp5_postgres.py "${phase}"
    ;;
  *)
    printf 'usage: %s {preflight|provision|verify|cleanup}\n' "$0" >&2
    exit 2
    ;;
esac
