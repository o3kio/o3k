#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOURNEY="$ROOT_DIR/scripts/p15-7-real-host-journey.sh"

# The public P15.7 run identity and the disposable TestLab epoch identity are
# separate: the latter owns the suffixed state root and ownership marker.
python3 - "$JOURNEY" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert 'TESTLAB_RUN_ID="${O3K_TESTLAB_RUN_ID:-$RUN_ID}"' in source
assert 'STATE_ROOT="${O3K_TESTLAB_STATE_ROOT:-/var/lib/o3k-testlab/$TESTLAB_RUN_ID}"' in source
assert '[[ "$TESTLAB_RUN_ID" =~ ^([0-9]+|local-[0-9]+)(-(generic|pp5))?$ ]]' in source

helper = re.search(r"(?ms)^observe_protected_testlab_state\(\) \{\n(.*?)^\}", source)
assert helper is not None, "protected TestLab observer helper is missing"
body = helper.group(1)
assert '"$TESTLAB_RUN_ID"' in body
assert '"$STATE_ROOT"' in body
assert '"$SOURCE_SHA"' in body
assert 'scripts/pp5-protected-state-observer.py' in body
assert source.count('scripts/pp5-protected-state-observer.py') == 1, \
    "journey observer calls must stay centralized"
assert source.count('observe_protected_testlab_state bootstrap-agent-id') == 3
assert source.count('observe_protected_testlab_state verify-marker') == 1
PY

# Test the real failure classifier extracted from the journey. This mismatch is
# a harness epoch/ownership error, not an unknown product failure.
# shellcheck disable=SC1090
source <(sed -n '/^classify_failure() {/,/^}/p' "$JOURNEY")
[[ "$(classify_failure 'TestLab ownership marker failed privileged verification')" == harness_gap ]]

echo "P15.7 TestLab epoch identity guards PASS"
