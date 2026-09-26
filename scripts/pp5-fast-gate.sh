#!/usr/bin/env bash
set -Eeuo pipefail

# Canonical, cheap PP.5 PostgreSQL prerequisite entrypoint. Both the protected
# workflow and manual qualification invoke this wrapper; it only delegates to
# the repository-owned purpose-map authority and never performs TestLab/VM
# provisioning.

phase="${1:-}"
case "${phase}" in
  preflight|provision|verify|cleanup)
    exec python3 scripts/provision_pp5_postgres.py "${phase}"
    ;;
  qualification)
    (
      repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
      cd "${repo_root}"
      expected_sha="${O3K_PP5_SOURCE_SHA:?O3K_PP5_SOURCE_SHA must identify the exact checkout}"
      [[ "${expected_sha}" =~ ^[0-9a-fA-F]{40}$ ]] || {
        printf 'PP5 fast gate requires a full source SHA\n' >&2
        exit 2
      }
      actual_sha="$(git rev-parse HEAD)"
      expected_sha="$(printf '%s' "${expected_sha}" | tr '[:upper:]' '[:lower:]')"
      test "${actual_sha}" = "${expected_sha}" || {
        printf 'PP5 fast gate source mismatch: expected %s, got %s\n' "${expected_sha}" "${actual_sha}" >&2
        exit 2
      }
      git diff --quiet && git diff --cached --quiet || {
        printf 'PP5 fast gate requires a clean tracked tree\n' >&2
        exit 2
      }
      # Generated build outputs may remain on the shared runner, but no
      # untracked source or harness file may be executed under an exact SHA.
      while IFS= read -r entry; do
        [[ -n "${entry}" ]] || continue
        [[ "${entry}" == '?? '* ]] || {
          printf 'PP5 fast gate requires a clean execution tree: %s\n' "${entry}" >&2
          exit 2
        }
        path="${entry#?? }"
        case "${path}" in
          target/*|bins/o3kd/bins/*|bins/o3kd/target/*|dist/*) ;;
          *)
            printf 'PP5 fast gate rejects untracked source/harness path: %s\n' "${path}" >&2
            exit 2
            ;;
        esac
      done < <(git status --porcelain=v1 --untracked-files=all)
      python3 scripts/pp5-runner-prerequisite.py
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
      # Destructive tests receive only their purpose-owned URL. Keep the other
      # purpose URLs in the parent shell for verify-p13, but never expose them
      # to a test process that could accidentally select a different database.
      (
        export O3K_DATABASE_BACKEND=postgres
        export O3K_TEST_DATABASE_PURPOSE=p13
        export O3K_DATABASE_URL="${O3K_PP5_P13_DATABASE_URL}"
        unset O3K_PP5_CAMPAIGN_DATABASE_URL O3K_PP5_WORKSPACE_DATABASE_URL O3K_PP5_ENDPOINT_DATABASE_URL
        cargo test --locked -p o3k-store --test postgres_p13_f1 --all-features -- --ignored --nocapture
        cargo test --locked -p o3k-store --test postgres_p13_b1 --all-features -- --ignored --nocapture
        cargo test --locked -p o3k-store --test postgres_p13_4_storage --all-features -- --ignored --nocapture
      )
      unset O3K_DATABASE_BACKEND O3K_TEST_DATABASE_PURPOSE O3K_DATABASE_URL
      python3 scripts/provision_pp5_postgres.py verify-p13
      trap - EXIT
      python3 scripts/provision_pp5_postgres.py cleanup
    )
    ;;
  *)
    printf 'usage: %s {preflight|qualification|provision|verify|cleanup}\n' "$0" >&2
    exit 2
    ;;
esac
