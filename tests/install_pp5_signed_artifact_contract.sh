#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bootstrap="$(<"$ROOT_DIR/scripts/bootstrap-disposable-testlab.sh")"
helper="$(<"$ROOT_DIR/scripts/install-pp5-signed-artifact.sh")"
grep -Fq 'O3K_PP5_SIGNED_ARTIFACT_MODE' <<<"$bootstrap"
grep -Fq 'O3K_PP5_RELEASE_DIST_DIR' <<<"$bootstrap"
grep -Fq 'O3K_PP5_RELEASE_SOURCE_SHA' <<<"$bootstrap"
grep -Fq 'cargo build --locked --release --bin o3kd --bin o3k' <<<"$bootstrap"
grep -Fq 'verify-release-sigstore.sh' <<<"$helper"
grep -Fq 'release-digests.txt' <<<"$helper"
grep -Fq 'c1-policy-o3kio-lab-2026-11' <<<"$helper"
grep -Fq 'O3K_PP5_LAB_C1_PUBLIC_KEY' <<<"$helper"
grep -Fq 'ed25519_public_key' <<<"$helper"
grep -Fq 'harness_source_sha' <<<"$helper"
for binary in o3kd o3k o3k-compute o3k-network; do grep -Fq "\"$binary\"" <<<"$helper"; done
grep -Fq 'verify-release-bundle.sh' <<<"$helper"
grep -Fq 'cmp -s' <<<"$helper"
echo 'signed PP.5 artifact contract passed'
