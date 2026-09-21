#!/usr/bin/env bash
# PP.4 Core installer boundary contract (issue #973).
# The default installer still preserves the PP.4A Araf integration path, while
# a core campaign can explicitly omit that separately versioned client.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/packaging/get-o3k.sh"
DEMO="$ROOT/packaging/o3k-araf-demo.sh"

grep -q 'O3K_SKIP_ARAF' "$INSTALLER"
grep -q 'PP.4A #1029' "$INSTALLER"
grep -q 'Araf demo stage skipped' "$INSTALLER"
test -x "$DEMO" || test -f "$DEMO"

# The historical default remains intact: the Araf entrypoint is still copied
# and invoked when the explicit core-only switch is absent.
grep -q 'packaging/o3k-araf-demo.sh" install' "$INSTALLER"
grep -q 'Araf demo deployed' "$INSTALLER"

echo 'PP.4 Core installer contract: PASS'
