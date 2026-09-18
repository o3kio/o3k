#!/usr/bin/env bash
# o3k upgrade campaign — in-VM UPGRADE/ROLLBACK phase (issue #626).
#
# Runs INSIDE the VM AFTER the doctor phase (v0.3.0-alpha.1 installed with a
# working TestLab: o3kd + o3k-compute running, test-vm ACTIVE with fixed IP
# 192.0.2.2, doctor HEALTHY) and BEFORE phase 2's teardown. Proves the
# REAL-release upgrade journey with REAL published artifacts (plan §15):
#   (1) identity capture BEFORE: installed release version, server UUID,
#       fixed IP, libvirt domain UUID, placement allocation count,
#       credential/TLS sha256 fingerprints + file modes (never contents),
#       doctor HEALTHY on the old binary -> identity-before.json;
#   (2) delegated download through the EXACT public installer command
#       (curl -sfL <release-base>/v<target>/install.sh | sudo sh -): exit 0,
#       the exact
#       `Run: sudo /var/lib/o3k/upgrade-download/o3k-<target>/bin/o3k upgrade`
#       line printed, and NO mutation yet (manifest + binary hashes
#       unchanged, o3kd still active);
#   (3) upgrade via the staged verified entry point
#       (.../bin/o3k upgrade --to <target> --yes --json): exit 0, status committed, phase
#       COMMITTED, backup_id present, doctor_status healthy|warning (the
#       engine's own gate accepts both — see the JSON assert below);
#   (4) identity AFTER upgrade: manifest == target, same server UUID / fixed
#       IP / libvirt domain UUID, allocations preserved, credential/TLS
#       fingerprints identical, token issue, doctor HEALTHY on the NEW
#       binary, console boot marker, one stop/start lifecycle round trip;
#   (5) reboot recovery: writes the UPGRADE-REBOOT-PENDING marker + `sudo
#       reboot` as the LAST statements. The host re-runs this SAME script
#       after the reboot; the resume branch (marker present) verifies
#       recovery (services, doctor, server/domain identity, allocations)
#       and continues — the script is idempotent across the reboot boundary
#       through the marker file in the evidence dir;
#   (6) rollback (sudo o3k rollback --yes --json): exit 0, status
#       rolled_back, phase ROLLED_BACK, manifest + binary hashes back to the
#       OLD release, doctor HEALTHY, identity + allocations preserved;
#   (7) re-upgrade through the same staged entry point: committed again,
#       doctor HEALTHY, identity preserved;
#   (8) one-line-<distro>-upgrade.json + the UPGRADE-COMPLETE status=passed
#       marker as the LAST statements.
# Any failure writes `UPGRADE-FAILED <code>` to the same marker file and
# exits non-zero. Secrets are never printed: only sha256 fingerprints of
# credential/TLS files are captured, never their contents.
#
# Usage: sudo bash in-vm-upgrade.sh <ubuntu|debian> <evidence-dir> <source-sha>
# Env:   O3K_UPGRADE_TARGET_VERSION (default v0.4.0-alpha.1),
#        O3K_UPGRADE_RELEASE_BASE (default
#        https://github.com/o3kio/o3k/releases/download)
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/o3k-campaign-evidence}"
SOURCE_SHA="${3:-unknown}"
TARGET_VERSION="${O3K_UPGRADE_TARGET_VERSION:-v0.4.0-alpha.1}"
RELEASE_BASE="${O3K_UPGRADE_RELEASE_BASE:-https://github.com/o3kio/o3k/releases/download}"
TARGET="${TARGET_VERSION#v}"
[[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] \
  || { echo "invalid O3K_UPGRADE_TARGET_VERSION: $TARGET_VERSION" >&2; exit 2; }
MANIFEST=/usr/local/share/o3k/release-manifest.json
STAGED="/var/lib/o3k/upgrade-download/o3k-$TARGET/bin/o3k"
REBOOT_MARKER="$EVID/UPGRADE-REBOOT-PENDING"
DONE_MARKER="$EVID/upgrade-done"
ID_FILE_BEFORE="$EVID/identity-before.json"
ID_FILE_AFTER="$EVID/identity-after.json"
mkdir -p "$EVID"
cd /

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

fail() { printf 'UPGRADE-FAILED %s\n' "$1" >"$DONE_MARKER"; log "FAILED: $2"; exit "$1"; }
on_error() {
  local code=$?
  if [ ! -f "$DONE_MARKER" ]; then
    printf 'UPGRADE-FAILED %s\n' "$code" >"$DONE_MARKER" 2>/dev/null || true
  fi
  log "error at line $1 (exit $code)"
  exit "$code"
}
trap 'on_error $LINENO' ERR

# ------------------------------------------------------------ helpers --------

LISTEN_ADDR="$(sed -n 's/^O3K_LISTEN_ADDR=//p' /etc/o3k/o3kd.env 2>/dev/null | head -1 || true)"
[ -n "$LISTEN_ADDR" ] || LISTEN_ADDR="127.0.0.1:18080"
COMPUTE_HEALTH_ADDR="$(sed -n 's/^O3K_COMPUTE_HEALTH_ADDR=//p' /etc/o3k/o3k-compute.env 2>/dev/null | head -1 || true)"
[ -n "$COMPUTE_HEALTH_ADDR" ] || COMPUTE_HEALTH_ADDR="127.0.0.1:9100"

# shellcheck disable=SC1091
source /etc/o3k/admin-openrc

manifest_version() {
  python3 - "$MANIFEST" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
}

field_of() { # json-file dotted-path — prints one non-secret scalar
  python3 - "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2].split("."):
    value = value[key]
print(value)
PY
}
identity_field() { field_of "$ID_FILE_BEFORE" "$1"; }
after_field() { field_of "$ID_FILE_AFTER" "$1"; }

server_id() { openstack server show test-vm -f value -c id 2>/dev/null || true; }
server_status() { openstack server show test-vm -f value -c status 2>/dev/null || true; }

server_fixed_ip() {
  openstack server show test-vm -f json 2>/dev/null | python3 -c '
import json, sys
def collect(node, out):
    if isinstance(node, dict):
        if "addr" in node:
            out.append(str(node["addr"]))
        for child in node.values():
            collect(child, out)
    elif isinstance(node, list):
        for child in node:
            collect(child, out)
    elif isinstance(node, str):
        # openstackclient flattens addresses into {network: ["<ip>", ...]}.
        out.append(node)
value = json.load(sys.stdin)
addresses = []
collect(value.get("addresses", {}), addresses)
print(addresses[0] if addresses else "")
' || true
}

# The libvirt domain name is the stable sha256-derived name
# (crates/o3k-libvirt: stable_domain_name), NOT a literal server-uuid prefix:
# o3k-<first 20 hex chars of sha256(server_id)>.
domain_for_server() { # server-id -> domain name matching the stable derived name
  local expected="o3k-$(printf '%s' "$1" | sha256sum | cut -c1-20)"
  virsh -c qemu:///system list --all --name 2>/dev/null | grep -Fx "$expected" || true
}

domain_uuid() { # domain-name -> libvirt domain UUID
  virsh -c qemu:///system domuuid "$1" 2>/dev/null | tr -d '[:space:]' || true
}

allocation_count() {
  python3 - <<'PY'
import sqlite3
conn = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
print(conn.execute("SELECT COUNT(*) FROM placement_allocations").fetchone()[0])
PY
}

token_ok() { openstack token issue >/dev/null 2>&1; }

wait_http() { # URL SECONDS
  local url="$1" seconds="$2" attempt=1 max=0
  max=$((seconds / 2))
  while [ "$attempt" -le "$max" ]; do
    curl -sf -o /dev/null --max-time 5 "$url" && return 0
    sleep 2
    attempt=$((attempt + 1))
  done
  return 1
}

console_marker_ok() { # attempts
  local attempts="$1" attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    if timeout 15 openstack console log show test-vm 2>/dev/null \
      | grep -Eiq 'cirros|login:'; then
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  return 1
}

lifecycle_ok() { # stop -> SHUTOFF -> start -> ACTIVE round trip
  local i status=""
  openstack server stop test-vm >/dev/null 2>&1 || return 1
  for i in $(seq 1 30); do
    status="$(server_status)"
    [ "$status" = SHUTOFF ] && break
    sleep 2
  done
  [ "$status" = SHUTOFF ] || return 1
  openstack server start test-vm >/dev/null 2>&1 || return 1
  for i in $(seq 1 60); do
    status="$(server_status)"
    [ "$status" = ACTIVE ] && break
    sleep 2
  done
  [ "$status" = ACTIVE ]
}

wait_domain_running() { # trajectory-file attempts — bounded wait for a running O3K domain
  local out="$1" attempts="${2:-24}" i
  : >"$out"
  for i in $(seq 1 "$attempts"); do
    virsh -c qemu:///system list --all 2>/dev/null >>"$out"
    if virsh -c qemu:///system list --all 2>/dev/null | grep -qE '^\s*[0-9]+\s+o3k-.*\s+running\s*$'; then
      echo "domain running after $((i * 5))s" >>"$out"
      return 0
    fi
    sleep 5
  done
  echo "no O3K-owned domain running within $((attempts * 5))s" >>"$out"
  return 1
}

doctor_json() { # out-file — runs the INSTALLED /usr/local/bin/o3k doctor --json
  local rc=0
  sudo env -i "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    /usr/local/bin/o3k doctor --json >"$1" 2>"$1.err" || rc=$?
  printf '%d' "$rc" >"$1.exit"
}

overall_status() { # doctor-json-file
  python3 - "$1" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["overall_status"])
PY
}

doctor_version() { # doctor-json-file
  python3 - "$1" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("version", ""))
PY
}

capture_binaries() { # out-file — sha256 of the three installed binaries
  python3 - "$1" <<'PY'
import hashlib, json, sys
out = {}
for path in ["/usr/local/bin/o3kd", "/usr/local/bin/o3k", "/usr/local/bin/o3k-compute"]:
    with open(path, "rb") as stream:
        out[path] = hashlib.sha256(stream.read()).hexdigest()
json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=2)
PY
}

compare_binaries() { # file-a file-b — exit 1 on mismatch (paths only, never digests)
  python3 - "$1" "$2" <<'PY'
import json, sys
a = json.load(open(sys.argv[1], encoding="utf-8"))
b = json.load(open(sys.argv[2], encoding="utf-8"))
mismatch = False
for path in sorted(set(a) | set(b)):
    if a.get(path) != b.get(path):
        print(f"BINARY MISMATCH {path}")
        mismatch = True
sys.exit(1 if mismatch else 0)
PY
}

capture_fingerprints() { # out-file — sha256 + modes of credential/TLS files, never contents
  python3 - "$1" <<'PY'
import hashlib, json, os, stat, sys
paths = ["/etc/o3k/admin-openrc", "/etc/o3k/clouds.yaml"]
tls_dir = "/etc/o3k/tls"
paths += sorted(os.path.join(tls_dir, name) for name in os.listdir(tls_dir)
                if os.path.isfile(os.path.join(tls_dir, name)))
fingerprints = {}
for path in paths:
    with open(path, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    fingerprints[path] = {"sha256": digest, "mode": oct(stat.S_IMODE(os.stat(path).st_mode))}
json.dump({"fingerprints": fingerprints}, open(sys.argv[1], "w", encoding="utf-8"), indent=2)
PY
}

compare_fingerprints() { # file-a file-b — exit 1 on mismatch (paths only, never digests)
  python3 - "$1" "$2" <<'PY'
import json, sys
a = json.load(open(sys.argv[1], encoding="utf-8"))["fingerprints"]
b = json.load(open(sys.argv[2], encoding="utf-8"))["fingerprints"]
mismatch = False
for path in sorted(set(a) | set(b)):
    if a.get(path) != b.get(path):
        print(f"FINGERPRINT MISMATCH {path}")
        mismatch = True
sys.exit(1 if mismatch else 0)
PY
}

# JSON contract assert for the upgrade/rollback machine output. The exact
# status/phase strings and exit codes are pinned from the engine:
#   bins/o3k/src/upgrade/output.rs:14-27 — status is snake_case ("committed",
#       "failed", "rolled_back", "check_passed", "check_blocked");
#   bins/o3k/src/upgrade/state.rs:20        — phase is SCREAMING_SNAKE_CASE
#       ("COMMITTED", "ROLLED_BACK", ...);
#   bins/o3k/src/main.rs:243-248            — exit 0 for committed /
#       rolled_back / check_passed, exit 1 for failed / check_blocked.
# The engine's own doctor gate accepts "healthy" OR "warning"
# (bins/o3k/src/upgrade/runner.rs:1483), and on a real host the in-flight
# doctor run reports "warning" (the in-progress state file makes
# release.upgrade_state WARN and the not-yet-committed chain makes
# release.backup_available WARN) — so the campaign accepts both here and
# gates actual health on its own post-commit doctor runs.
assert_engine_json() { # desc file mode source target
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY' \
    || fail 30 "$1: engine JSON contract mismatch (see $2)"
import json, sys
desc, path, mode, source, target = sys.argv[1:6]
document = json.load(open(path, encoding="utf-8"))
if mode == "upgrade":
    assert document["status"] == "committed", f'status={document["status"]!r}'
    assert document["phase"] == "COMMITTED", f'phase={document["phase"]!r}'
    assert document["backup_id"], "backup_id is empty"
    assert document["doctor_status"] in ("healthy", "warning"), \
        f'doctor_status={document["doctor_status"]!r}'
    assert document["rollback_performed"] is False, \
        f'rollback_performed={document["rollback_performed"]!r}'
    assert document["source_version"] == source, \
        f'source_version={document["source_version"]!r} expected {source!r}'
    assert document["target_version"] == target, \
        f'target_version={document["target_version"]!r} expected {target!r}'
    print(document["backup_id"])
else:
    assert document["status"] == "rolled_back", f'status={document["status"]!r}'
    assert document["phase"] == "ROLLED_BACK", f'phase={document["phase"]!r}'
    assert document["rollback_performed"] is True, \
        f'rollback_performed={document["rollback_performed"]!r}'
    assert document["backup_id"], "backup_id is empty"
    assert "doctor_status" not in document, \
        "doctor_status must be omitted on a successful rollback"
    assert document["source_version"] == source, \
        f'source_version={document["source_version"]!r} expected {source!r}'
    assert document["target_version"] == target, \
        f'target_version={document["target_version"]!r} expected {target!r}'
    print(document["backup_id"])
PY
}

IDENTITY_BEFORE=pending
DELEGATION=pending
UPGRADE=pending
IDENTITY_AFTER=pending
REBOOT_RECOVERY=pending
ROLLBACK=pending
RE_UPGRADE=pending

# ------------------------------------------------- phase 1/8: identity -------

phase_identity_before() {
  log "phase 1/8: identity capture (before)"
  SOURCE_VERSION="$(manifest_version)"
  [ "$SOURCE_VERSION" != "$TARGET" ] || fail 11 "installed version ($SOURCE_VERSION) already equals the target $TARGET"
  if [ "$SOURCE_VERSION" != 0.3.0-alpha.1 ]; then
    log "WARNING: expected the v0.3.0-alpha.1 source install, found $SOURCE_VERSION"
  fi
  token_ok || fail 11 "token issue failed before the upgrade"
  SRV_ID="$(server_id)"
  [ -n "$SRV_ID" ] || fail 11 "test-vm cannot be resolved"
  [ "$(server_status)" = ACTIVE ] || fail 11 "test-vm not ACTIVE before the upgrade"
  FIXED_IP="$(server_fixed_ip)"
  [ "$FIXED_IP" = 192.0.2.2 ] || fail 11 "unexpected fixed IP before the upgrade: $FIXED_IP"
  DOMAIN_NAME="$(domain_for_server "$SRV_ID")"
  [ -n "$DOMAIN_NAME" ] || fail 11 "no libvirt domain with the stable name for $SRV_ID"
  DOMAIN_UUID="$(domain_uuid "$DOMAIN_NAME")"
  [ -n "$DOMAIN_UUID" ] || fail 11 "cannot resolve the libvirt domain UUID for $DOMAIN_NAME"
  ALLOCATIONS="$(allocation_count)"
  [[ "$ALLOCATIONS" =~ ^[0-9]+$ ]] || fail 11 "placement allocation count unreadable"
  virsh -c qemu:///system list --all >"$EVID/upgrade-virsh-before.txt" 2>&1 || true
  doctor_json "$EVID/upgrade-doctor-before.json"
  [ "$(cat "$EVID/upgrade-doctor-before.json.exit")" = 0 ] || fail 11 "doctor exited non-zero before the upgrade"
  [ "$(overall_status "$EVID/upgrade-doctor-before.json")" = healthy ] || fail 11 "doctor not healthy before the upgrade"
  [ "$(doctor_version "$EVID/upgrade-doctor-before.json")" = "$SOURCE_VERSION" ] \
    || fail 11 "doctor did not run the installed binary before the upgrade"
  capture_binaries "$EVID/upgrade-binaries-before.json"
  capture_fingerprints "$EVID/upgrade-fingerprints-before.json"
  python3 - "$ID_FILE_BEFORE" "$SOURCE_VERSION" "$SRV_ID" "$FIXED_IP" "$DOMAIN_NAME" \
    "$DOMAIN_UUID" "$ALLOCATIONS" "$EVID/upgrade-doctor-before.json" \
    "$EVID/upgrade-binaries-before.json" "$EVID/upgrade-fingerprints-before.json" <<'PY'
import json, sys, time
path, version, server, fixed_ip, domain, domain_uuid, allocations = sys.argv[1:8]
doctor_path, binaries_path, fingerprints_path = sys.argv[8:11]
doctor = json.load(open(doctor_path, encoding="utf-8"))
document = {
    "captured_at": int(time.time()),
    "installed_version": version,
    "doctor": {"overall": doctor["overall_status"],
               "version": doctor.get("version", "unknown")},
    "server": {"id": server, "fixed_ip": fixed_ip},
    "libvirt_domain": {"name": domain, "uuid": domain_uuid},
    "placement_allocations": int(allocations),
    "binaries": json.load(open(binaries_path, encoding="utf-8")),
    "fingerprints": json.load(open(fingerprints_path, encoding="utf-8"))["fingerprints"],
}
json.dump(document, open(path, "w", encoding="utf-8"), indent=2)
PY
  IDENTITY_BEFORE=passed
  log "identity-before: version=$SOURCE_VERSION server=$SRV_ID ip=$FIXED_IP domain=$DOMAIN_NAME uuid=$DOMAIN_UUID allocations=$ALLOCATIONS"
}

# ------------------------------------------------ phase 2/8: delegation ------

phase_delegation() {
  log "phase 2/8: delegated download via the exact public installer command"
  O3KD_HASH_BEFORE="$(sha256sum /usr/local/bin/o3kd | awk '{print $1}')"
  O3K_HASH_BEFORE="$(sha256sum /usr/local/bin/o3k | awk '{print $1}')"
  log "installer command: curl -sfL $RELEASE_BASE/v$TARGET/install.sh | sudo sh -"
  if curl -sfL "$RELEASE_BASE/v$TARGET/install.sh" \
      | sudo sh - 2>&1 \
      | tee "$EVID/upgrade-delegation-output.txt"; then
    log "installer exited 0"
  else
    fail 21 "delegation: installer exited non-zero (see upgrade-delegation-output.txt)"
  fi
  grep -Fq "Run: sudo /var/lib/o3k/upgrade-download/o3k-$TARGET/bin/o3k upgrade" \
    "$EVID/upgrade-delegation-output.txt" \
    || fail 21 "delegation: missing the exact 'Run:' next-command line"
  grep -Fq 'the installer never upgrades an existing installation automatically' \
    "$EVID/upgrade-delegation-output.txt" \
    || fail 21 "delegation: missing the no-auto-upgrade notice"
  # No mutation yet: the installer must only download + verify + extract the
  # staged entry point (§12), never touch the running installation.
  [ "$(manifest_version)" = "$SOURCE_VERSION" ] \
    || fail 21 "delegation: release manifest mutated by the installer"
  [ "$(sha256sum /usr/local/bin/o3kd | awk '{print $1}')" = "$O3KD_HASH_BEFORE" ] \
    || fail 21 "delegation: o3kd binary mutated by the installer"
  [ "$(sha256sum /usr/local/bin/o3k | awk '{print $1}')" = "$O3K_HASH_BEFORE" ] \
    || fail 21 "delegation: o3k binary mutated by the installer"
  systemctl is-active --quiet o3kd \
    || fail 21 "delegation: o3kd is not active after the installer run"
  [ -x "$STAGED" ] || fail 21 "delegation: staged entry point missing: $STAGED"
  DELEGATION=passed
  log "delegation: verified download, no mutation, staged entry point present"
}

# ---------------------------------------------------- phase 3/8: upgrade -----

phase_upgrade() {
  log "phase 3/8: upgrade through the staged verified entry point"
  [ -x "$STAGED" ] || fail 31 "staged entry point missing: $STAGED"
  local rc=0
  sudo timeout 1800 "$STAGED" upgrade --to "$TARGET_VERSION" --yes --json \
    >"$EVID/upgrade-command.json" 2>"$EVID/upgrade-command.stderr" || rc=$?
  [ "$rc" = 0 ] || fail 31 "upgrade exited $rc: $(tail -n 5 "$EVID/upgrade-command.stderr" 2>/dev/null | tr '\n' ' ')"
  UPGRADE_BACKUP_ID="$(assert_engine_json upgrade "$EVID/upgrade-command.json" upgrade "$SOURCE_VERSION" "$TARGET")"
  UPGRADE=passed
  log "upgrade committed: $SOURCE_VERSION -> $TARGET (backup $UPGRADE_BACKUP_ID)"
}

# ---------------------------------------------- phase 4/8: identity after ----

phase_identity_after() {
  log "phase 4/8: identity after upgrade"
  [ "$(manifest_version)" = "$TARGET" ] || fail 41 "manifest version not upgraded to $TARGET"
  local srv ip dname duuid alloc
  srv="$(server_id)"
  [ "$srv" = "$SRV_ID" ] || fail 41 "server UUID changed after upgrade"
  [ "$(server_status)" = ACTIVE ] || fail 41 "test-vm not ACTIVE after upgrade"
  ip="$(server_fixed_ip)"
  [ "$ip" = "$FIXED_IP" ] || fail 41 "fixed IP changed after upgrade: $ip"
  dname="$(domain_for_server "$srv")"
  [ "$dname" = "$DOMAIN_NAME" ] || fail 41 "libvirt domain name changed after upgrade"
  duuid="$(domain_uuid "$dname")"
  [ "$duuid" = "$DOMAIN_UUID" ] || fail 41 "libvirt domain UUID changed (recreated?) after upgrade"
  alloc="$(allocation_count)"
  [ "$alloc" -ge "$ALLOCATIONS" ] || fail 41 "placement allocations lost after upgrade ($alloc < $ALLOCATIONS)"
  capture_fingerprints "$EVID/upgrade-fingerprints-after.json"
  compare_fingerprints "$EVID/upgrade-fingerprints-before.json" "$EVID/upgrade-fingerprints-after.json" \
    || fail 41 "credential/TLS fingerprints changed after upgrade"
  token_ok || fail 41 "token issue failed after upgrade"
  doctor_json "$EVID/upgrade-doctor-after.json"
  [ "$(cat "$EVID/upgrade-doctor-after.json.exit")" = 0 ] || fail 41 "doctor exited non-zero after upgrade"
  [ "$(overall_status "$EVID/upgrade-doctor-after.json")" = healthy ] || fail 41 "doctor not healthy after upgrade"
  [ "$(doctor_version "$EVID/upgrade-doctor-after.json")" = "$TARGET" ] \
    || fail 41 "doctor did not run the NEW binary after upgrade"
  console_marker_ok 30 || fail 41 "no console boot marker after upgrade"
  lifecycle_ok || fail 41 "server stop/start lifecycle failed after upgrade"
  virsh -c qemu:///system list --all >"$EVID/upgrade-virsh-after.txt" 2>&1 || true
  capture_binaries "$EVID/upgrade-binaries-after.json"
  if compare_binaries "$EVID/upgrade-binaries-before.json" "$EVID/upgrade-binaries-after.json"; then
    fail 41 "binary hashes did not change after the upgrade"
  fi
  # identity-after.json anchors the post-reboot recovery comparison.
  python3 - "$ID_FILE_AFTER" "$TARGET" "$UPGRADE_BACKUP_ID" "$srv" "$ip" "$dname" "$duuid" \
    "$alloc" "$EVID/upgrade-binaries-after.json" "$EVID/upgrade-fingerprints-after.json" <<'PY'
import json, sys, time
path, version, backup_id, server, fixed_ip, domain, domain_uuid, allocations = sys.argv[1:9]
binaries_path, fingerprints_path = sys.argv[9:11]
document = {
    "captured_at": int(time.time()),
    "installed_version": version,
    "backup_id": backup_id,
    "server": {"id": server, "fixed_ip": fixed_ip},
    "libvirt_domain": {"name": domain, "uuid": domain_uuid},
    "placement_allocations": int(allocations),
    "binaries": json.load(open(binaries_path, encoding="utf-8")),
    "fingerprints": json.load(open(fingerprints_path, encoding="utf-8"))["fingerprints"],
}
json.dump(document, open(path, "w", encoding="utf-8"), indent=2)
PY
  IDENTITY_AFTER=passed
  log "identity-after: manifest=$TARGET server=$srv domain=$duuid allocations=$alloc"
}

# ------------------------------------------- phase 5/8: reboot + recovery ----

phase_reboot_request() {
  log "phase 5/8: reboot recovery — writing the UPGRADE-REBOOT-PENDING marker and rebooting"
  printf 'UPGRADE-REBOOT-PENDING %s\n' "$(date +%s)" >"$REBOOT_MARKER"
  sync
  sudo reboot
  # `sudo reboot` must not return; if it ever does (a failed shutdown), end
  # the run here: the pending marker stays behind and the host fails loudly
  # when SSH never drops. The resume branch below takes over on the next
  # invocation.
  exit 0
}

phase_reboot_recovery() {
  log "phase 5/8 (resume): reboot recovery verification"
  rm -f "$REBOOT_MARKER"
  [ -f "$ID_FILE_BEFORE" ] || fail 51 "identity-before.json missing on resume"
  [ -f "$ID_FILE_AFTER" ] || fail 51 "identity-after.json missing on resume"
  UPGRADE_BACKUP_ID="$(after_field backup_id)"
  if systemctl is-active --quiet o3kd; then :; else fail 51 "o3kd not active after the reboot"; fi
  if systemctl is-active --quiet o3k-compute; then :; else fail 51 "o3k-compute not active after the reboot"; fi
  wait_http "http://$LISTEN_ADDR/healthz" 120 || fail 51 "o3kd healthz not ready after the reboot"
  wait_http "http://$COMPUTE_HEALTH_ADDR/readyz" 120 || fail 51 "compute readyz not ready after the reboot"
  # The upgraded release persisted across the reboot.
  [ "$(manifest_version)" = "$TARGET" ] || fail 51 "manifest not the upgraded version after the reboot"
  capture_binaries "$EVID/upgrade-binaries-reboot.json"
  compare_binaries "$EVID/upgrade-binaries-after.json" "$EVID/upgrade-binaries-reboot.json" \
    || fail 51 "upgraded binary set did not survive the reboot"
  wait_domain_running "$EVID/upgrade-domain-trajectory-reboot.txt" 24 \
    || fail 51 "no O3K-owned domain running after the reboot"
  doctor_json "$EVID/upgrade-doctor-reboot.json"
  [ "$(cat "$EVID/upgrade-doctor-reboot.json.exit")" = 0 ] || fail 51 "doctor exited non-zero after the reboot"
  [ "$(overall_status "$EVID/upgrade-doctor-reboot.json")" = healthy ] || fail 51 "doctor not healthy after the reboot"
  local srv ip dname duuid alloc
  srv="$(server_id)"
  [ "$srv" = "$SRV_ID" ] || fail 51 "server UUID changed after the reboot"
  [ "$(server_status)" = ACTIVE ] || fail 51 "test-vm not ACTIVE after the reboot"
  ip="$(server_fixed_ip)"
  [ "$ip" = "$FIXED_IP" ] || fail 51 "fixed IP changed after the reboot: $ip"
  dname="$(domain_for_server "$srv")"
  [ "$dname" = "$DOMAIN_NAME" ] || fail 51 "libvirt domain name changed after the reboot"
  duuid="$(domain_uuid "$dname")"
  [ "$duuid" = "$DOMAIN_UUID" ] || fail 51 "libvirt domain UUID changed after the reboot"
  alloc="$(allocation_count)"
  [ "$alloc" -ge "$ALLOCATIONS" ] || fail 51 "placement allocations lost after the reboot ($alloc < $ALLOCATIONS)"
  REBOOT_RECOVERY=passed
  log "reboot recovery verified: services active, doctor healthy, identity preserved"
}

# ----------------------------------------------------- phase 6/8: rollback ----

phase_rollback() {
  log "phase 6/8: rollback via the installed (new) o3k binary"
  local rc=0
  sudo timeout 1800 o3k rollback --yes --json \
    >"$EVID/rollback-command.json" 2>"$EVID/rollback-command.stderr" || rc=$?
  [ "$rc" = 0 ] || fail 61 "rollback exited $rc: $(tail -n 5 "$EVID/rollback-command.stderr" 2>/dev/null | tr '\n' ' ')"
  ROLLBACK_BACKUP_ID="$(assert_engine_json rollback "$EVID/rollback-command.json" rollback "$SOURCE_VERSION" "$TARGET")"
  [ "$(manifest_version)" = "$SOURCE_VERSION" ] || fail 61 "manifest not restored to $SOURCE_VERSION after rollback"
  capture_binaries "$EVID/upgrade-binaries-rollback.json"
  compare_binaries "$EVID/upgrade-binaries-before.json" "$EVID/upgrade-binaries-rollback.json" \
    || fail 61 "binary hashes not restored to the old release after rollback"
  local srv ip dname duuid alloc
  srv="$(server_id)"
  [ "$srv" = "$SRV_ID" ] || fail 61 "server UUID changed after rollback"
  [ "$(server_status)" = ACTIVE ] || fail 61 "test-vm not ACTIVE after rollback"
  ip="$(server_fixed_ip)"
  [ "$ip" = "$FIXED_IP" ] || fail 61 "fixed IP changed after rollback: $ip"
  dname="$(domain_for_server "$srv")"
  [ "$dname" = "$DOMAIN_NAME" ] || fail 61 "libvirt domain name changed after rollback"
  duuid="$(domain_uuid "$dname")"
  [ "$duuid" = "$DOMAIN_UUID" ] || fail 61 "libvirt domain UUID changed after rollback"
  alloc="$(allocation_count)"
  [ "$alloc" -ge "$ALLOCATIONS" ] || fail 61 "placement allocations lost after rollback ($alloc < $ALLOCATIONS)"
  capture_fingerprints "$EVID/upgrade-fingerprints-rollback.json"
  compare_fingerprints "$EVID/upgrade-fingerprints-before.json" "$EVID/upgrade-fingerprints-rollback.json" \
    || fail 61 "credential/TLS fingerprints changed after rollback"
  token_ok || fail 61 "token issue failed after rollback"
  doctor_json "$EVID/upgrade-doctor-rollback.json"
  [ "$(cat "$EVID/upgrade-doctor-rollback.json.exit")" = 0 ] || fail 61 "doctor exited non-zero after rollback"
  [ "$(overall_status "$EVID/upgrade-doctor-rollback.json")" = healthy ] || fail 61 "doctor not healthy after rollback"
  [ "$(doctor_version "$EVID/upgrade-doctor-rollback.json")" = "$SOURCE_VERSION" ] \
    || fail 61 "doctor did not run the OLD binary after rollback"
  ROLLBACK=passed
  log "rollback: $TARGET -> $SOURCE_VERSION restored (backup $ROLLBACK_BACKUP_ID), doctor healthy, identity preserved"
}

# --------------------------------------------------- phase 7/8: re-upgrade ----

phase_re_upgrade() {
  log "phase 7/8: re-upgrade through the same staged entry point"
  [ -x "$STAGED" ] || fail 71 "staged entry point missing: $STAGED"
  local rc=0
  sudo timeout 1800 "$STAGED" upgrade --to "$TARGET_VERSION" --yes --json \
    >"$EVID/reupgrade-command.json" 2>"$EVID/reupgrade-command.stderr" || rc=$?
  [ "$rc" = 0 ] || fail 71 "re-upgrade exited $rc: $(tail -n 5 "$EVID/reupgrade-command.stderr" 2>/dev/null | tr '\n' ' ')"
  REUPGRADE_BACKUP_ID="$(assert_engine_json re-upgrade "$EVID/reupgrade-command.json" upgrade "$SOURCE_VERSION" "$TARGET")"
  [ "$(manifest_version)" = "$TARGET" ] || fail 71 "manifest not back to $TARGET after re-upgrade"
  capture_binaries "$EVID/upgrade-binaries-reupgrade.json"
  compare_binaries "$EVID/upgrade-binaries-after.json" "$EVID/upgrade-binaries-reupgrade.json" \
    || fail 71 "binary set after re-upgrade differs from the first upgrade"
  local srv ip dname duuid alloc
  srv="$(server_id)"
  [ "$srv" = "$SRV_ID" ] || fail 71 "server UUID changed after re-upgrade"
  [ "$(server_status)" = ACTIVE ] || fail 71 "test-vm not ACTIVE after re-upgrade"
  ip="$(server_fixed_ip)"
  [ "$ip" = "$FIXED_IP" ] || fail 71 "fixed IP changed after re-upgrade: $ip"
  dname="$(domain_for_server "$srv")"
  [ "$dname" = "$DOMAIN_NAME" ] || fail 71 "libvirt domain name changed after re-upgrade"
  duuid="$(domain_uuid "$dname")"
  [ "$duuid" = "$DOMAIN_UUID" ] || fail 71 "libvirt domain UUID changed after re-upgrade"
  alloc="$(allocation_count)"
  [ "$alloc" -ge "$ALLOCATIONS" ] || fail 71 "placement allocations lost after re-upgrade ($alloc < $ALLOCATIONS)"
  capture_fingerprints "$EVID/upgrade-fingerprints-reupgrade.json"
  compare_fingerprints "$EVID/upgrade-fingerprints-before.json" "$EVID/upgrade-fingerprints-reupgrade.json" \
    || fail 71 "credential/TLS fingerprints changed after re-upgrade"
  token_ok || fail 71 "token issue failed after re-upgrade"
  doctor_json "$EVID/upgrade-doctor-reupgrade.json"
  [ "$(cat "$EVID/upgrade-doctor-reupgrade.json.exit")" = 0 ] || fail 71 "doctor exited non-zero after re-upgrade"
  [ "$(overall_status "$EVID/upgrade-doctor-reupgrade.json")" = healthy ] || fail 71 "doctor not healthy after re-upgrade"
  [ "$(doctor_version "$EVID/upgrade-doctor-reupgrade.json")" = "$TARGET" ] \
    || fail 71 "doctor did not run the NEW binary after re-upgrade"
  RE_UPGRADE=passed
  log "re-upgrade: committed again (backup $REUPGRADE_BACKUP_ID), doctor healthy, identity preserved"
}

# ------------------------------------------------------- phase 8/8: evidence --

phase_evidence() {
  log "phase 8/8: evidence"
  OVERALL=passed
  for status in "$IDENTITY_BEFORE" "$DELEGATION" "$UPGRADE" "$IDENTITY_AFTER" \
    "$REBOOT_RECOVERY" "$ROLLBACK" "$RE_UPGRADE"; do
    [ "$status" = passed ] || OVERALL=failed
  done
  [ "$OVERALL" = passed ] || fail 81 "an upgrade phase did not pass"
  python3 - "$EVID/one-line-$DISTRO-upgrade.json" "$DISTRO" "$SOURCE_SHA" \
    "$SOURCE_VERSION" "$TARGET" "$UPGRADE_BACKUP_ID" "$RELEASE_BASE" <<'PY'
import json, sys, time
path, distro, sha, source, target, backup_id, release_base = sys.argv[1:8]
document = {
    "artifact_type": "one-line-upgrade-acceptance",
    "distro": distro,
    "profile": "libvirt-testlab",
    "status": "passed",
    "redacted": True,
    "finished_at": int(time.time()),
    "source_commit": sha,
    "source_version": source,
    "target_version": target,
    "install_method": "public-installer-delegation",
    "installer_command": f"curl -sfL {release_base}/v{target}/install.sh | sudo sh -",
    "upgrade_command": f"sudo /var/lib/o3k/upgrade-download/o3k-{target}/bin/o3k upgrade --to {target} --yes --json",
    "rollback_command": "sudo o3k rollback --yes --json",
    "upgrade_backup_id": backup_id,
    "identity_preserved": {
        "server_uuid": True,
        "fixed_ip": True,
        "libvirt_domain_uuid": True,
        "placement_allocations": True,
        "credential_tls_fingerprints": True,
    },
    "phases": {
        "identity_before": "passed",
        "delegation": "passed",
        "upgrade": "passed",
        "identity_after": "passed",
        "reboot_recovery": "passed",
        "rollback": "passed",
        "re_upgrade": "passed",
    },
}
json.dump(document, open(path, "w", encoding="utf-8"), indent=2)
print(f"wrote {path}")
PY
  log "evidence written: $EVID/one-line-$DISTRO-upgrade.json"
  printf 'UPGRADE-COMPLETE status=passed\n' >"$DONE_MARKER"
}

# ------------------------------------------------------------- main flow ------

if [ -f "$DONE_MARKER" ] && grep -Fq 'UPGRADE-COMPLETE status=passed' "$DONE_MARKER"; then
  log "upgrade already complete ($DONE_MARKER present); nothing to do"
  exit 0
fi

# Idempotency across the reboot boundary: when the reboot marker is present
# the host re-ran this script after the real reboot. Reload the captured
# pre-upgrade identity (it anchors every later comparison) and resume at the
# reboot-recovery verification. Phases 1-4 completed before the marker was
# written, so they are recorded as passed.
if [ -f "$ID_FILE_BEFORE" ]; then
  SOURCE_VERSION="$(identity_field installed_version)"
  SRV_ID="$(identity_field server.id)"
  FIXED_IP="$(identity_field server.fixed_ip)"
  DOMAIN_NAME="$(identity_field libvirt_domain.name)"
  DOMAIN_UUID="$(identity_field libvirt_domain.uuid)"
  ALLOCATIONS="$(identity_field placement_allocations)"
fi

if [ -f "$REBOOT_MARKER" ]; then
  log "resuming after the upgrade reboot (marker: $(cat "$REBOOT_MARKER"))"
  IDENTITY_BEFORE=passed
  DELEGATION=passed
  UPGRADE=passed
  IDENTITY_AFTER=passed
  phase_reboot_recovery
else
  phase_identity_before
  phase_delegation
  phase_upgrade
  phase_identity_after
  phase_reboot_request
fi
phase_rollback
phase_re_upgrade
phase_evidence
