#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/packaging/config-env.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

env_file="$work/o3kd.env"
cat >"$env_file" <<'EOF'
O3K_COMPUTE_CLIENT_CA=/etc/o3k/tls/ca.pem
O3K_COMPUTE_AUTHORIZED_AGENTS=node-a=abcd
O3K_ENROLLMENT_SIGNER=/run/o3k/enrollment-issuer.sock
EOF
before="$(sha256sum "$env_file" | awk '{print $1}')"
o3k_upsert_env_setting "$env_file" O3K_COMPUTE_CLIENT_CA=/etc/o3k/tls/ca.pem
after="$(sha256sum "$env_file" | awk '{print $1}')"
[[ "$before" == "$after" ]]

# A necessary migration replaces the old value in place and keeps the rest of
# the environment file byte-for-byte ordered.
o3k_upsert_env_setting "$env_file" O3K_COMPUTE_CLIENT_CA=/etc/o3k/ea/compute-client-ca.pem
expected="$work/expected.env"
cat >"$expected" <<'EOF'
O3K_COMPUTE_CLIENT_CA=/etc/o3k/ea/compute-client-ca.pem
O3K_COMPUTE_AUTHORIZED_AGENTS=node-a=abcd
O3K_ENROLLMENT_SIGNER=/run/o3k/enrollment-issuer.sock
EOF
cmp -s "$expected" "$env_file"

ledger_digest="$(sha256sum "$env_file" | awk '{print $1}')"
printf 'o3k-config-file-v1\to3kd.env\t%s\n' "$ledger_digest" >"$work/.o3k-config-files"
o3k_verify_config_ledger "$work"
printf '\n# operator edit\n' >>"$env_file"
if o3k_verify_config_ledger "$work"; then
  echo 'modified config unexpectedly passed its ownership ledger' >&2
  exit 1
fi

echo 'Configuration environment migration contract: PASS'
