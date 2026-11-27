#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source="$root/bins/o3kd/src/composition/mod.rs"
block="$(sed -n '/let _enrollment_task/,/let _compute_task/p' "$source")"
grep -Fq 'UnixSocketEnrollmentSigner::new(signer_path)' <<<"$block"
if grep -Fq 'RootHelperEnrollmentSigner::new(signer_path)' <<<"$block"; then
  echo "EA enrollment selected the incompatible executable helper signer" >&2
  exit 1
fi
echo "EA enrollment signer selection: PASS"
