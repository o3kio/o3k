#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "${ROOT_DIR}/tests/supply-chain-governance.sh"

temporary_dir="$(mktemp -d)"
trap 'rm -rf "${temporary_dir}"' EXIT
cp "${ROOT_DIR}/Cargo.lock" "${temporary_dir}/Cargo.lock"

python3 - "${temporary_dir}/Cargo.lock" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_text(encoding="utf-8")
pattern = re.compile(
    r'(\[\[package\]\]\nname = "webpki-roots"\nversion = "0\.26\.11"'
    r'.*?dependencies = \[\n\s*)"webpki-roots 1\.0\.10"',
    re.DOTALL,
)
updated, replacements = pattern.subn(r'\1"webpki-roots 1.0.9"', contents, count=1)
if replacements != 1:
    raise SystemExit("could not construct the stale-shim lockfile regression")
path.write_text(updated, encoding="utf-8")
PY

if O3K_SUPPLY_CHAIN_CARGO_LOCK="${temporary_dir}/Cargo.lock" \
    bash "${ROOT_DIR}/tests/supply-chain-governance.sh" \
    >"${temporary_dir}/validator.log" 2>&1; then
    echo "supply-chain governance accepted a stale webpki-roots shim edge" >&2
    exit 1
fi
if ! grep -Fq \
    "RUSTSEC-2026-0381 exception requires the shim to resolve to webpki-roots 1.0.10" \
    "${temporary_dir}/validator.log"; then
    cat "${temporary_dir}/validator.log" >&2
    echo "supply-chain governance rejected the stale lockfile for an unexpected reason" >&2
    exit 1
fi

echo "supply-chain lockfile exception regression passed"

cp "${ROOT_DIR}/Cargo.lock" "${temporary_dir}/Cargo.lock"

python3 - "${temporary_dir}/Cargo.lock" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_text(encoding="utf-8")
updated, replacements = re.subn(
    r'(\[\[package\]\]\nname = "libsqlite3-sys"\nversion = ")0\.30\.1(")',
    r"\g<1>0.30.2\g<2>",
    contents,
    count=1,
)
if replacements != 1:
    raise SystemExit("could not construct the libsqlite3-sys drift lockfile regression")
path.write_text(updated, encoding="utf-8")
PY

if O3K_SUPPLY_CHAIN_CARGO_LOCK="${temporary_dir}/Cargo.lock" \
    bash "${ROOT_DIR}/tests/supply-chain-governance.sh" \
    >"${temporary_dir}/validator-sqlite.log" 2>&1; then
    echo "supply-chain governance accepted a drifted libsqlite3-sys under the exception" >&2
    exit 1
fi
if ! grep -Fq \
    "RUSTSEC-2026-0459 exception requires exactly one locked libsqlite3-sys 0.30.1" \
    "${temporary_dir}/validator-sqlite.log"; then
    cat "${temporary_dir}/validator-sqlite.log" >&2
    echo "supply-chain governance rejected the drifted lockfile for an unexpected reason" >&2
    exit 1
fi

echo "supply-chain libsqlite3-sys exception regression passed"

cp "${ROOT_DIR}/Cargo.lock" "${temporary_dir}/Cargo.lock"

python3 - "${temporary_dir}/Cargo.lock" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
contents = path.read_text(encoding="utf-8")
updated, replacements = re.subn(
    r'(\[\[package\]\]\nname = "chrono"\nversion = ")0\.4\.45(")',
    r"\g<1>0.4.46\g<2>",
    contents,
    count=1,
)
if replacements != 1:
    raise SystemExit("could not construct the chrono drift lockfile regression")
path.write_text(updated, encoding="utf-8")
PY

if O3K_SUPPLY_CHAIN_CARGO_LOCK="${temporary_dir}/Cargo.lock" \
    bash "${ROOT_DIR}/tests/supply-chain-governance.sh" \
    >"${temporary_dir}/validator-chrono.log" 2>&1; then
    echo "supply-chain governance accepted a drifted chrono under the exception" >&2
    exit 1
fi
if ! grep -Fq \
    "RUSTSEC-2026-0543 exception requires exactly one locked chrono 0.4.45" \
    "${temporary_dir}/validator-chrono.log"; then
    cat "${temporary_dir}/validator-chrono.log" >&2
    echo "supply-chain governance rejected the drifted lockfile for an unexpected reason" >&2
    exit 1
fi

echo "supply-chain chrono exception regression passed"
