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
  qualification)
    cleanup_on_exit() {
      rc=$?
      if [[ -f "${O3K_PP5_ARTIFACT_DIR:-target/real-host-workflow-artifacts}/pp5-postgres-purpose-map.json" ]]; then
        python3 scripts/provision_pp5_postgres.py cleanup || rc=1
      fi
      exit "${rc}"
    }
    trap cleanup_on_exit EXIT
    python3 scripts/provision_pp5_postgres.py preflight
    python3 scripts/provision_pp5_postgres.py provision
    set -a
    # The mode-0600 file is run-owned and is never echoed or traced.
    . "${O3K_PP5_ENV_FILE:-target/pp5-postgres.env}"
    set +a
    export O3K_DATABASE_BACKEND=postgres
    export O3K_TEST_DATABASE_PURPOSE=p13
    export O3K_DATABASE_URL="${O3K_PP5_P13_DATABASE_URL}"
    cargo test --locked -p o3k-store --test postgres_p13_f1 --all-features -- --ignored --nocapture
    cargo test --locked -p o3k-store --test postgres_p13_b1 --all-features -- --ignored --nocapture
    cargo test --locked -p o3k-store --test postgres_p13_4_storage --all-features -- --ignored --nocapture
    python3 scripts/provision_pp5_postgres.py verify
    trap - EXIT
    python3 scripts/provision_pp5_postgres.py cleanup
    ;;
  *)
    printf 'usage: %s {preflight|qualification|provision|verify|cleanup}\n' "$0" >&2
    exit 2
    ;;
esac
