#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT_DIR/tests/pp5-small-edge-campaign/teardown-hosts.sh" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")

# Teardown must enumerate only names this run could have generated. Prefix
# substring matching can overlap a different valid RUN_ID.
assert 'grep -F -e "$PREFIX-"' not in text, "teardown must not select resources by an ambiguous prefix"
assert 'host_count=' in text and 'host_count' in text, "teardown must validate the marked host count"
assert '^[A-Za-z0-9][A-Za-z0-9_.-]*$' in text, "teardown must reject dot and dot-dot run IDs"
assert 'for idx in $(seq 1 "$host_count")' in text, "teardown must derive exact host names from the marker"

# Removing a domain must not implicitly unlink arbitrary attached storage.
# The script explicitly removes only its exact per-host COW disk and seed ISO.
assert "--remove-all-storage" not in text, "teardown must not delete storage through libvirt"
assert '"$IMGS_DIR/$PREFIX-host-$letter.qcow2"' in text
assert '"$IMGS_DIR/$PREFIX-host-$letter-seed.iso"' in text
assert 'for glob in ' not in text, "teardown must not wildcard-delete run artifacts"
PY

echo "PP.5 small-edge ownership guards passed"
