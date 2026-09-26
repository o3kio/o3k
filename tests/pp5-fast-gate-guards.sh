#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
helper="${ROOT_DIR}/scripts/pp5-fast-gate.sh"
workflow="${ROOT_DIR}/.github/workflows/real-host-validation.yml"

test -x "${helper}"
bash -n "${helper}"
grep -Fq 'exec python3 scripts/provision_pp5_postgres.py "${phase}"' "${helper}"
grep -Fq 'scripts/pp5-fast-gate.sh qualification' "${workflow}"
grep -Fq 'postgres_p13_f1' "${helper}"
grep -Fq 'postgres_p13_b1' "${helper}"
grep -Fq 'postgres_p13_4_storage' "${helper}"
! grep -Fq 'provision_pp5_postgres.py preflight' "${workflow}"
! grep -Eq 'pp5-fast-gate.sh.*(cargo|lvm|virsh|qemu|docker)' "${helper}"

printf 'PP5 fast-gate guards PASS\n'
