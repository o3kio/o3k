#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guard="$root/scripts/assert_disposable_postgres_test_database.py"

O3K_TEST_DATABASE_PURPOSE=p13 O3K_DATABASE_URL=postgres://postgres@127.0.0.1/o3k_p13_test_run python3 "$guard"
O3K_TEST_DATABASE_PURPOSE=p137 O3K_TEST_DATABASE_NAME=o3k_p137_run-25 python3 "$guard"
for purpose_url in \
  'p13|postgres://postgres@127.0.0.1/o3k_pp5_s5_run' \
  'p13|postgres://postgres@127.0.0.1/o3k_workspace_test_run' \
  'p13|postgres://postgres@127.0.0.1/o3k_endpoint_test_run' \
  'workspace|postgres://postgres@127.0.0.1/o3k_p13_test_run' \
  'endpoint|postgres://postgres@127.0.0.1/o3k_p13_test_run' \
  'p137|postgres://postgres@127.0.0.1/o3k_pp5_s5_run' \
  'p137|postgres://postgres@127.0.0.1/o3k_p13_test_run' \
  'p13|postgres://postgres@127.0.0.1/o3k_p13_test_'; do
  purpose="${purpose_url%%|*}"
  url="${purpose_url#*|}"
  if O3K_TEST_DATABASE_PURPOSE="$purpose" O3K_DATABASE_URL="$url" python3 "$guard"; then
    echo "unsafe PostgreSQL test database accepted: purpose=$purpose url=$url" >&2
    exit 1
  fi
done
if O3K_DATABASE_URL=postgres://postgres@127.0.0.1/o3k_p13_test_run python3 "$guard"; then
  echo "PostgreSQL test database accepted without an explicit purpose" >&2
  exit 1
fi
if O3K_TEST_DATABASE_PURPOSE=p137 O3K_TEST_DATABASE_NAME='o3k_p137_bad;drop' python3 "$guard"; then
  echo "P13.7 database name accepted SQL metacharacters" >&2
  exit 1
fi
echo "PostgreSQL destructive test database guards PASS"
