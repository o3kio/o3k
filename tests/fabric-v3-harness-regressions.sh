#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Portable checks only; this suite never provisions guests or mutates a host.
for regression in \
  fabric-v3-campaign-result-test.py \
  fabric-v3-three-host-gate-regression.py \
  fabric-v3-guest-control-regression.py \
  fabric-v3-host-preflight-test.py \
  fabric-v3-retirement-evidence-test.py \
  fabric-v3-restart-dhcp-regression.py \
  fabric-v3-foreign-fdb-test.py \
  fabric-v3-agent-readiness-regression.py \
  fabric-v3-delete-operation-evidence-test.py \
  fabric-v3-port-detach-evidence-test.py \
  fabric-v3-dhcp-teardown-evidence-test.py \
  fabric-v3-canonical-endpoint-retention-evidence-test.py \
  fabric-v3-shared-fabric-namespace-test.py \
  fabric-v3-owned-domain-storage-test.py \
  fabric-v3-remote-dhcp-boundary-capture-regression.py; do
  python3 "tests/$regression"
done
bash tests/fabric-v3-wireguard-key-root-regression.sh
