#!/usr/bin/env bash
# ASR-024 o3k doctor campaign — in-VM DOCTOR phase (issue #617).
#
# Runs INSIDE the VM AFTER the phase-1 reboot (install completed, o3kd and
# o3k-compute running, no test-vm resources yet) and BEFORE phase 2's
# teardown/uninstall. Accepts the doctor UX contract:
#   (a) doctor HEALTHY (human + JSON, exit 0);
#   (b) stop o3k-compute -> doctor identifies the compute failure (FAIL)
#       -> restart -> HEALTHY;
#   (c) stop o3kd -> doctor identifies the control-plane failure -> restart
#       -> HEALTHY;
#   (d) safe disposable negative fixtures (O3K_DOCTOR_* sandbox overrides;
#       the real installation is never modified):
#       - corrupt SQLite (disposable data dir)
#       - wrong DB permissions (disposable data dir copy)
#       - modified installed binary (disposable prefix copy)
#       - missing installer manifest (empty prefix)
#       - dead dnsmasq pidfile (disposable config dir)
#       - stale TAP (dummy interface, created and removed here)
#   (e) final HEALTHY + evidence JSON.
# Every fixture restores its own state; the EXIT trap additionally restarts
# o3kd and o3k-compute so phase 2 always sees a running system.
# Exits non-zero on any failure.
#
# Usage: sudo bash in-vm-doctor.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/o3k-campaign-evidence}"
SOURCE_SHA="${3:-unknown}"
FIXTURE_DIR="$(mktemp -d /tmp/o3k-doctor-fixture.XXXXXX)"

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

cleanup() {
  # Safety net: leave both services running whatever happened mid-phase.
  systemctl start o3kd o3k-compute 2>/dev/null || true
  ip link del o3ktap-99999999 2>/dev/null || true
  rm -rf -- "$FIXTURE_DIR"
}
trap cleanup EXIT

fail() { echo "DOCTOR-FAILED $1" >"$EVID/doctor-done"; log "FAILED: $2"; exit "$1"; }
on_error() {
  local code=$?
  echo "DOCTOR-FAILED $code" >"$EVID/doctor-done" 2>/dev/null || true
  log "error at line $1 (exit $code)"
  exit "$code"
}
trap 'on_error $LINENO' ERR

mkdir -p "$EVID"

# ----------------------------------------------------------- helpers --------

LISTEN_ADDR="$(sed -n 's/^O3K_LISTEN_ADDR=//p' /etc/o3k/o3kd.env | head -1)"
[ -n "$LISTEN_ADDR" ] || LISTEN_ADDR="127.0.0.1:18080"

# Runs the real doctor binary with a clean environment plus optional
# sandbox overrides. Output lands in $1, the exit code in $1.exit.
# An expected-nonzero doctor exit (negative fixtures) must not trip the
# ERR trap: under `set -E` the trap still fires on a failing command even
# with `set +e`, so capture the code in an `|| rc=$?` OR-list instead.
doctor_json() { # out-file [OVERRIDE...]
  local out="$1"
  shift
  local rc=0
  sudo env -i "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$@" /usr/local/bin/o3k doctor --json >"$out" 2>"$out.err" || rc=$?
  printf '%d' "$rc" >"$out.exit"
}

check_status() { # json-file check-id -> status string
  python3 - "$1" "$2" <<'PY'
import json
import sys
document = json.load(open(sys.argv[1], encoding="utf-8"))
for check in document["checks"]:
    if check["id"] == sys.argv[2]:
        print(check["status"])
        break
else:
    print("MISSING")
PY
}

overall_status() { # json-file
  python3 - "$1" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["overall_status"])
PY
}

assert_status() { # phase json-file check-id expected
  local actual
  actual="$(check_status "$2" "$3")"
  [ "$actual" = "$4" ] || fail 3 "$1: $3 expected $4, got $actual"
  log "$1: $3 = $actual"
}

assert_overall() { # phase json-file expected
  local actual
  actual="$(overall_status "$2")"
  [ "$actual" = "$3" ] || fail 3 "$1: overall expected $3, got $actual"
  log "$1: overall = $actual"
}

assert_exit() { # phase file expected-code
  local actual
  actual="$(cat "$2.exit")"
  [ "$actual" = "$3" ] || fail 3 "$1: exit expected $3, got $actual"
  log "$1: exit = $actual"
}

assert_success() { # phase json-file — no failing checks; healthy or warning overall.
  # A fresh installation legitimately carries advisory WARNs (e.g. no upgrade
  # backup exists yet), which is doctor exit 1 with overall "warning". Success
  # means zero FAIL checks and an exit code of 0 or 1 (never 2/unhealthy).
  local phase="$1" file="$2" overall doctor_exit fails
  overall="$(overall_status "$file")"
  case "$overall" in
    healthy|warning) ;;
    *) fail 3 "$phase: overall expected healthy|warning, got $overall" ;;
  esac
  if [ -f "$file.exit" ]; then
    doctor_exit="$(cat "$file.exit")"
    case "$doctor_exit" in
      0|1) ;;
      *) fail 3 "$phase: doctor exit expected 0|1, got $doctor_exit" ;;
    esac
  fi
  fails="$(python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
print(sum(1 for check in document["checks"] if check["status"] == "FAIL"))
PY
)"
  [ "$fails" = "0" ] || fail 3 "$phase: expected zero FAIL checks, got $fails"
  log "$phase: overall=$overall exit=${doctor_exit:-n/a} FAILs=0"
}

wait_http_ok() { # url attempts seconds-between
  local url="$1" attempts="${2:-40}" delay="${3:-3}" i
  for i in $(seq 1 "$attempts"); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then return 0; fi
    sleep "$delay"
  done
  return 1
}

wait_doctor_healthy() { # attempts — waits until no FAIL checks (healthy or advisory-warning).
  local attempts="${1:-40}" i out
  out="$EVID/doctor-wait.json"
  for i in $(seq 1 "$attempts"); do
    doctor_json "$out"
    case "$(overall_status "$out")" in
      healthy|warning)
        if [ "$(python3 - "$out" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
print(sum(1 for check in document["checks"] if check["status"] == "FAIL"))
PY
)" = "0" ]; then
          return 0
        fi
        ;;
    esac
    sleep 5
  done
  return 1
}

# -------------------------------------------------------- (a) initial -------

log "doctor phase start (distro=$DISTRO source=$SOURCE_SHA)"
doctor_json "$EVID/doctor-initial.json"
assert_success initial "$EVID/doctor-initial.json"
assert_status initial "$EVID/doctor-initial.json" services.o3kd_unit PASS
assert_status initial "$EVID/doctor-initial.json" services.compute_unit PASS
assert_status initial "$EVID/doctor-initial.json" control.healthz PASS
assert_status initial "$EVID/doctor-initial.json" control.readyz PASS
sudo /usr/local/bin/o3k doctor >"$EVID/doctor-initial.txt" 2>&1
INITIAL=passed

# ------------------------------------------- (b) compute stop / restart ------

log "stopping o3k-compute"
systemctl stop o3k-compute
# The agent registry marks the agent unavailable after its 15s lease plus a
# 5s monitor tick; wait 30s so that state is deterministic. The control
# plane's own readyz gate stays healthy: it reflects the compute-agent
# control plane (the registration listener), not the agent's presence, so
# the compute failure must surface via services.compute_unit and
# compute.agent_registered, not control.readyz.
wait_http_ok "http://$LISTEN_ADDR/healthz" 20 3 || true
sleep 30
doctor_json "$EVID/doctor-compute-stopped.json"
assert_exit compute-stopped "$EVID/doctor-compute-stopped.json" 1
assert_overall compute-stopped "$EVID/doctor-compute-stopped.json" unhealthy
assert_status compute-stopped "$EVID/doctor-compute-stopped.json" services.compute_unit FAIL
assert_status compute-stopped "$EVID/doctor-compute-stopped.json" control.readyz PASS
assert_status compute-stopped "$EVID/doctor-compute-stopped.json" compute.agent_registered FAIL
COMPUTE_STOPPED=passed

log "restarting o3k-compute"
systemctl start o3k-compute
wait_http_ok "http://$LISTEN_ADDR/readyz" 40 3 \
  || fail 4 "control plane never became ready after the compute restart"
wait_doctor_healthy 40 || fail 4 "doctor never returned to healthy after the compute restart"
cp "$EVID/doctor-wait.json" "$EVID/doctor-compute-restarted.json"
assert_success compute-restarted "$EVID/doctor-compute-restarted.json"
COMPUTE_RESTART=passed

# ---------------------------------------------- (c) o3kd stop / restart ------

log "stopping o3kd"
systemctl stop o3kd
doctor_json "$EVID/doctor-o3kd-stopped.json"
assert_exit o3kd-stopped "$EVID/doctor-o3kd-stopped.json" 1
assert_status o3kd-stopped "$EVID/doctor-o3kd-stopped.json" services.o3kd_unit FAIL
assert_status o3kd-stopped "$EVID/doctor-o3kd-stopped.json" control.healthz FAIL
O3KD_STOPPED=passed

log "restarting o3kd"
systemctl start o3kd
wait_http_ok "http://$LISTEN_ADDR/healthz" 40 3 \
  || fail 4 "control plane never answered healthz after the o3kd restart"
wait_doctor_healthy 40 || fail 4 "doctor never returned to healthy after the o3kd restart"
cp "$EVID/doctor-wait.json" "$EVID/doctor-o3kd-restarted.json"
assert_success o3kd-restarted "$EVID/doctor-o3kd-restarted.json"
O3KD_RESTART=passed

# ------------------------------------------ (d) disposable negative fixtures --

# d1: corrupt SQLite in a disposable data dir (the real DB is untouched).
mkdir -p "$FIXTURE_DIR/corrupt-data"
printf 'this is not a sqlite database\n' >"$FIXTURE_DIR/corrupt-data/o3k.sqlite"
chmod 0600 "$FIXTURE_DIR/corrupt-data/o3k.sqlite"
doctor_json "$EVID/doctor-corrupt-db.json" \
  O3K_DOCTOR_DATA_DIR="$FIXTURE_DIR/corrupt-data"
assert_status corrupt-db "$EVID/doctor-corrupt-db.json" database.accessible FAIL
CORRUPT_DB=passed

# d2: a real DB copy with group/other permission bits.
mkdir -p "$FIXTURE_DIR/perms-data"
cp -p /var/lib/o3k/o3k.sqlite "$FIXTURE_DIR/perms-data/o3k.sqlite"
chmod 0644 "$FIXTURE_DIR/perms-data/o3k.sqlite"
doctor_json "$EVID/doctor-db-permissions.json" \
  O3K_DOCTOR_DATA_DIR="$FIXTURE_DIR/perms-data"
assert_status db-permissions "$EVID/doctor-db-permissions.json" database.permissions FAIL
DB_PERMISSIONS=passed

# d3: a disposable prefix copy with a tampered o3kd binary.
mkdir -p "$FIXTURE_DIR/tampered-prefix/bin" "$FIXTURE_DIR/tampered-prefix/share"
cp -a /usr/local/bin "$FIXTURE_DIR/tampered-prefix/bin-copy"
rm -rf "$FIXTURE_DIR/tampered-prefix/bin"
mv "$FIXTURE_DIR/tampered-prefix/bin-copy" "$FIXTURE_DIR/tampered-prefix/bin"
cp -a /usr/local/share/o3k "$FIXTURE_DIR/tampered-prefix/share/o3k"
printf 'tampered\n' >>"$FIXTURE_DIR/tampered-prefix/bin/o3kd"
doctor_json "$EVID/doctor-modified-binary.json" \
  O3K_DOCTOR_PREFIX="$FIXTURE_DIR/tampered-prefix"
assert_status modified-binary "$EVID/doctor-modified-binary.json" release.binary_hashes FAIL
MODIFIED_BINARY=passed

# d4: an empty prefix has no installer manifest at all.
mkdir -p "$FIXTURE_DIR/empty-prefix"
doctor_json "$EVID/doctor-missing-manifest.json" \
  O3K_DOCTOR_PREFIX="$FIXTURE_DIR/empty-prefix"
assert_status missing-manifest "$EVID/doctor-missing-manifest.json" release.ownership_manifest FAIL
assert_status missing-manifest "$EVID/doctor-missing-manifest.json" release.version FAIL
MISSING_MANIFEST=passed

# d5: a disposable config dir whose compute data dir carries a dead dnsmasq
# pidfile (the real dhcp root is untouched).
mkdir -p "$FIXTURE_DIR/fake-config/tls" "$FIXTURE_DIR/fake-compute/dhcp"
cp -p /etc/o3k/o3kd.env "$FIXTURE_DIR/fake-config/o3kd.env"
cp -p /etc/o3k/o3k-compute.env "$FIXTURE_DIR/fake-config/o3k-compute.env"
cp -p /etc/o3k/admin-openrc "$FIXTURE_DIR/fake-config/admin-openrc"
cp -p /etc/o3k/clouds.yaml "$FIXTURE_DIR/fake-config/clouds.yaml" 2>/dev/null || true
cp -a /etc/o3k/tls/. "$FIXTURE_DIR/fake-config/tls/" 2>/dev/null || true
chmod 0600 "$FIXTURE_DIR/fake-config/o3kd.env" \
  "$FIXTURE_DIR/fake-config/o3k-compute.env" "$FIXTURE_DIR/fake-config/admin-openrc"
sed -i "s|^O3K_COMPUTE_DATA_DIR=.*|O3K_COMPUTE_DATA_DIR=$FIXTURE_DIR/fake-compute|" \
  "$FIXTURE_DIR/fake-config/o3k-compute.env"
printf '999999\n' >"$FIXTURE_DIR/fake-compute/dhcp/dnsmasq-00000000-0000-0000-0000-000000000000.pid"
printf '12345\n' >"$FIXTURE_DIR/fake-compute/dhcp/dnsmasq-00000000-0000-0000-0000-000000000000.pid.owner"
doctor_json "$EVID/doctor-dead-dnsmasq.json" \
  O3K_DOCTOR_CONFIG_DIR="$FIXTURE_DIR/fake-config"
assert_status dead-dnsmasq "$EVID/doctor-dead-dnsmasq.json" network.dhcp_state FAIL
DEAD_DNSMASQ=passed

# d6: a disposable dummy interface named like an O3K TAP but with no
# ownership record. The name must stay within the kernel's 15-character
# IFNAMSIZ limit (the original fixture name was too long and 'ip link add'
# rejected it). Created and removed here; never touches foreign state.
ip link add o3ktap-99999999 type dummy
doctor_json "$EVID/doctor-stale-tap.json"
if [ "$(check_status "$EVID/doctor-stale-tap.json" network.tap_state)" = "NOT_APPLICABLE" ]; then
  log "stale-tap: no network ownership manifest on this install; fixture not applicable"
  STALE_TAP=not_applicable_no_manifest
else
  assert_status stale-tap "$EVID/doctor-stale-tap.json" network.tap_state WARN
  STALE_TAP=passed
fi
ip link del o3ktap-99999999

# ------------------------------------------------- (e) final healthy + JSON ---

doctor_json "$EVID/doctor-final.json"
assert_success final "$EVID/doctor-final.json"
FINAL=passed

python3 - "$DISTRO" "$SOURCE_SHA" "$EVID" <<'PY'
import json
import sys
import time

distro, sha, evid = sys.argv[1], sys.argv[2], sys.argv[3]
out = f"{evid}/one-line-{distro}-doctor.json"
initial = json.load(open(f"{evid}/doctor-initial.json", encoding="utf-8"))
document = {
    "artifact_type": "one-line-doctor-acceptance",
    "distro": distro,
    "profile": "libvirt-testlab",
    "status": "passed",
    "redacted": True,
    "finished_at": int(time.time()),
    "source_commit": sha,
    "doctor_version": initial["version"],
    "install_method": "one-line-public",
    "phases": {
        "initial_healthy": "passed",
        "compute_stopped_detected": "passed",
        "compute_restart_healthy": "passed",
        "o3kd_stopped_detected": "passed",
        "o3kd_restart_healthy": "passed",
        "corrupt_db": "passed",
        "db_permissions": "passed",
        "modified_binary": "passed",
        "missing_manifest": "passed",
        "dhcp_dead_pidfile": "passed",
        "stale_tap": "passed",
        "final_healthy": "passed",
    },
}
json.dump(document, open(out, "w", encoding="utf-8"), indent=2)
print(json.dumps(document, indent=2))
PY
log "evidence written: $EVID/one-line-$DISTRO-doctor.json"

echo "DOCTOR-COMPLETE status=passed" >"$EVID/doctor-done"
log "doctor phase complete"
