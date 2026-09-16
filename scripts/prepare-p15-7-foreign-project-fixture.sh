#!/usr/bin/env bash
set -Eeuo pipefail

: "${GITHUB_ENV:?GITHUB_ENV must be set by the protected workflow}"
[[ "$GITHUB_ENV" == /* && -f "$GITHUB_ENV" && ! -L "$GITHUB_ENV" ]] \
  || { echo "P15.7 foreign-project fixture requires a regular workflow environment file" >&2; exit 1; }

password="$(openssl rand -hex 32)"
[[ "$password" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "could not generate P15.7 foreign-project password" >&2; exit 1; }
printf '::add-mask::%s\n' "$password"

# The protected TestLab database is fresh for each workflow run.
{
  printf 'O3K_EXTRA_TENANT_PROJECT_ID=9f3c2b6e-5f2d-4b3a-9c8e-1a2b3c4d5e6f\n'
  printf 'O3K_EXTRA_TENANT_PROJECT_NAME=tenant-b\n'
  printf 'O3K_EXTRA_TENANT_USER_ID=6b0f5a2e-8c4d-4a7e-9b1f-2d3e4f5a6b7c\n'
  printf 'O3K_EXTRA_TENANT_USER_NAME=tenant-b-user\n'
  printf 'O3K_EXTRA_TENANT_PASSWORD=%s\n' "$password"
  printf 'O3K_P15_7_FOREIGN_PROJECT_ID=9f3c2b6e-5f2d-4b3a-9c8e-1a2b3c4d5e6f\n'
  printf 'O3K_P15_7_FOREIGN_USER_NAME=tenant-b-user\n'
  printf 'O3K_P15_7_FOREIGN_PASSWORD=%s\n' "$password"
} >>"$GITHUB_ENV"
unset password
