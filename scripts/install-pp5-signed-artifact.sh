#!/usr/bin/env bash
set -Eeuo pipefail
DIST_DIR="${1:?usage: install-pp5-signed-artifact.sh DIST_DIR STATE_ROOT SOURCE_SHA}"
STATE_ROOT="${2:?usage: install-pp5-signed-artifact.sh DIST_DIR STATE_ROOT SOURCE_SHA}"
SOURCE_SHA="${3:?usage: install-pp5-signed-artifact.sh DIST_DIR STATE_ROOT RELEASE_SOURCE_SHA}"
HARNESS_SHA="${O3K_P15_7_SOURCE_SHA:-${GITHUB_SHA:-}}"
[[ "$HARNESS_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "invalid harness SHA" >&2; exit 1; }
EXPECTED_C1_KEY="${O3K_PP5_LAB_C1_PUBLIC_KEY:-}"
[[ "$EXPECTED_C1_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "signed PP.5 mode requires the expected C1 public authority key" >&2; exit 1; }
TAG=v0.4.0-rc.28
[[ "$SOURCE_SHA" =~ ^[0-9a-fA-F]{40}$ ]] || { echo "invalid source SHA" >&2; exit 1; }
[[ -d "$DIST_DIR" && ! -L "$DIST_DIR" ]] || { echo "release distribution is not a directory" >&2; exit 1; }
RELEASE_SOURCE_COMMIT="$SOURCE_SHA" bash "$(dirname "${BASH_SOURCE[0]}")/../packaging/verify-release-sigstore.sh" "$TAG" "$DIST_DIR"
ARCHIVE="$DIST_DIR/o3k-0.4.0-rc.28-linux-x86_64.tar.gz"
[[ -f "$ARCHIVE" && ! -L "$ARCHIVE" ]] || { echo "rc.28 archive is missing" >&2; exit 1; }
EXPECTED="$(awk -v name="$(basename "$ARCHIVE")" '$2 == name {print $1}' "$DIST_DIR/release-digests.txt")"
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || { echo "authenticated archive digest is missing" >&2; exit 1; }
ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "authenticated archive digest mismatch" >&2; exit 1; }
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-pp5-release.XXXXXX")"; trap 'rm -rf -- "$TMP_DIR"' EXIT
LIST="$TMP_DIR/archive.list"; tar -tzf "$ARCHIVE" >"$LIST"
while IFS= read -r entry; do [[ "$entry" == ./* && "$entry" != *'/../'* && "$entry" != *'/..' && "$entry" != '..' ]] || { echo "unsafe archive entry" >&2; exit 1; }; done <"$LIST"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
ROOT="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'o3k-0.4.0-rc.28' -print -quit)"
[[ -n "$ROOT" && ! -L "$ROOT" ]] || { echo "rc.28 archive root is missing" >&2; exit 1; }
bash "$(dirname "${BASH_SOURCE[0]}")/../packaging/verify-release-bundle.sh" "$ROOT"
IDENTITY_JSON="${O3K_REAL_HOST_ARTIFACT_DIR:-$DIST_DIR}/p15-7-signed-release-identity.json"
python3 - "$ROOT" "$SOURCE_SHA" "$HARNESS_SHA" "$IDENTITY_JSON" "$ACTUAL" "$EXPECTED_C1_KEY" <<'PY'
import hashlib, json, pathlib, stat, sys
root = pathlib.Path(sys.argv[1]); source = sys.argv[2].lower(); harness = sys.argv[3].lower(); evidence = pathlib.Path(sys.argv[4]); archive_sha = sys.argv[5]; expected_key = sys.argv[6].lower()
data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
if data.get("version") not in ("0.4.0-rc.28", "v0.4.0-rc.28") or data.get("source_commit", "").lower() != source: raise SystemExit("release manifest tag/version/source identity mismatch")
authority = data.get("installation_policy_authority", {})
if authority.get("key_id") != "c1-policy-o3kio-lab-2026-11": raise SystemExit("release manifest C1 authority is not the approved lab authority")
if authority.get("ed25519_public_key", "").lower() != expected_key: raise SystemExit("release manifest C1 public authority key mismatch")
checksums = {}
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1); checksums[name[2:] if name.startswith("./") else name] = digest
for name in ("o3kd", "o3k", "o3k-compute", "o3k-network"):
    path = root / "bin" / name
    if not path.is_file() or path.is_symlink() or not (path.stat().st_mode & stat.S_IXUSR): raise SystemExit(f"signed executable missing: {name}")
    if checksums.get(f"bin/{name}") != hashlib.sha256(path.read_bytes()).hexdigest(): raise SystemExit(f"signed executable hash mismatch: {name}")
evidence.parent.mkdir(parents=True, exist_ok=True)
evidence.write_text(json.dumps({"artifact_type":"o3k-pp5-signed-release-identity","tag":"v0.4.0-rc.28","release_source_sha":source,"harness_source_sha":harness,"archive_sha256":archive_sha,"installation_policy_authority_key_id":authority["key_id"],"executable_sha256":{name:hashlib.sha256((root/"bin"/name).read_bytes()).hexdigest() for name in ("o3kd","o3k","o3k-compute","o3k-network")}}, sort_keys=True)+"\n", encoding="utf-8")
PY
sudo -n install -d -m 0755 "$STATE_ROOT/bin"
for binary in o3kd o3k o3k-compute o3k-network; do sudo -n install -m 0755 "$ROOT/bin/$binary" "$STATE_ROOT/bin/$binary"; cmp -s "$ROOT/bin/$binary" "$STATE_ROOT/bin/$binary" || exit 1; done
