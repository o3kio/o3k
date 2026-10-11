#!/usr/bin/env bash
# Canonical credentials must never be traced, even if the caller used bash -x.
set +xv
set -euo pipefail

# Validation reads the canonical file without executing it and emits only
# shell-quoted campaign values over this private channel. The generic epoch's
# blank GITHUB_ENV values are deliberately not treated as canonical authority.
canonical_binding="$(python3 scripts/provision_pp5_postgres.py campaign-env)"
# shellcheck disable=SC1091
source /dev/stdin <<<"${canonical_binding}"
unset canonical_binding
unset O3K_PP5_WORKSPACE_DATABASE_URL O3K_PP5_ENDPOINT_DATABASE_URL O3K_PP5_P13_DATABASE_URL
python3 scripts/provision_pp5_postgres.py bind-campaign
