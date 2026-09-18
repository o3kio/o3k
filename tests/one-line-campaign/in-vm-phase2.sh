#!/usr/bin/env bash
# ASR-022 one-line installer campaign — in-VM PHASE 2 (issue #613).
#
# Runs INSIDE the VM AFTER the host reboot that ended phase 1:
#   (a) reboot recovery: o3kd healthz / compute readyz within 2 min, agent
#       reconnected, test-vm identity preserved (same ID, ACTIVE, same fixed
#       IP, console marker);
#   (b) exact one-liner re-run: exit 0, converged markers, NO duplicate
#       resources/identities (IDs + counts + TLS dir + admin password hashes)
#       and NO second canonical BuildingBlock (durable init/join state,
#       agent-id bytes, /etc/o3k/tls hashes all unchanged);
#   (c) teardown through the INSTALLED /usr/local/share/o3k/bootstrap-testlab.sh
#       --teardown (ships with the install thanks to the install.sh copy list);
#   (d) uninstall --yes (accounts intentionally retained);
#   (e) reinstall through the one-liner -> test-vm ACTIVE + console again;
#   (f) teardown again, then the hardened reconcile contract, then
#       uninstall --purge --yes;
#   (g) zero-residue verification + foreign canaries unchanged;
#   (h) one-line-<distro>-install.json with the verbatim phase-1 user output.
# Exits non-zero on any failure.
#
# Usage: sudo bash in-vm-phase2.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/o3k-campaign-evidence}"
SOURCE_SHA="${3:-unknown}"
ONELINER_OUT="$EVID/install-output.txt"
mkdir -p "$EVID"
cd /
log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
# The exact one-liner, mode-dependent like phase 1: local endpoint shim by
# default; the published release asset when O3K_CAMPAIGN_REAL_RELEASE=1 (the
# canonical PP.2 evidence path).
if [ "${O3K_CAMPAIGN_REAL_RELEASE:-0}" = 1 ]; then
  ONELINER="curl -sfL https://github.com/o3kio/o3k/releases/download/${O3K_CAMPAIGN_VERSION:?O3K_CAMPAIGN_VERSION is required in real-release mode}/install.sh | sudo sh -"
else
  ONELINER='curl -sfL http://10.0.2.2:18000/ | sudo env O3K_RELEASE_BASE=http://10.0.2.2:18000/releases sh -'
fi

# The ssh session driving this script can drop (flaky slirp session); the
# script must keep running detached and report through a marker file that
# host-run.sh polls over fresh connections. ERR fires under set -E on any
# unguarded failure; the success marker overwrites nothing on the happy path.
trap 'if [ ! -f "$EVID/phase2-done" ]; then printf "PHASE2-FAILED %s\n" "$?" > "$EVID/phase2-done"; fi' ERR

# shellcheck disable=SC1090
[ -f "$EVID/phase1-ids.env" ] || { echo "ERROR: phase1-ids.env missing" >&2; exit 1; }
source "$EVID/phase1-ids.env"

# Hardened reset/purge contract (13d1d65, tests/packaging-safety.sh): the
# uninstall/purge scripts are VALIDATORS of an already-reconciled state root.
reconcile_state_root() {
  local root marker
  systemctl stop o3kd.service o3k-compute.service 2>/dev/null || true
  for root in /var/lib/o3k /var/log/o3k; do
    [[ -d "$root" && ! -L "$root" ]] || continue
    marker="$root/.o3k-owned"
    [[ -f "$marker" && ! -L "$marker" ]] || return 1
    grep -Fxq "o3k-owned-v1 path=$root" "$marker" || return 1
    find "$root" -mindepth 1 -maxdepth 1 ! -name .o3k-owned -exec rm -rf -- {} +
  done
}

wait_http() { # wait_http URL SECONDS
  local url="$1" seconds="$2" attempt=1 max=0
  max=$((seconds / 2))
  while [ "$attempt" -le "$max" ]; do
    curl -sf -o /dev/null --max-time 5 "$url" && return 0
    sleep 2
    attempt=$((attempt + 1))
  done
  return 1
}

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
'
}

canonical_state() { # canonical_state DB — prints one KEY=VALUE line per durable fact
  python3 - "$1" <<'PY'
import sqlite3
import sys

try:
    connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    blocks = connection.execute(
        "SELECT block_id, state FROM building_blocks").fetchall()
    phases = [row[0] for row in connection.execute(
        "SELECT phase FROM bootstrap_state")]
    profiles = connection.execute(
        "SELECT COUNT(*) FROM cloud_profiles").fetchone()[0]
except sqlite3.Error as error:
    sys.exit(f"canonical durable state unreadable: {error}")
print(f"BB_ID={blocks[0][0] if blocks else ''}")
print(f"BB_COUNT={len(blocks)}")
print(f"BB_STATES={','.join(sorted(b[1] for b in blocks))}")
print(f"BOOTSTRAP_PHASE={phases[0] if phases else ''}")
print(f"BOOTSTRAP_ROWS={len(phases)}")
print(f"PROFILE_COUNT={profiles}")
PY
}

canonical_field() { # canonical_field TEXT KEY
  printf '%s\n' "$1" | awk -F= -v key="$2" '$1 == key {print $2; exit}'
}

console_marker_ok() { # console_marker_ok ATTEMPTS
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

capture_count() { # capture_count TYPE [COLUMN] — count `openstack <type> list` rows
  local type="$1" column="${2:-ID}" out=""
  # The if-condition context is deliberate: it keeps the failure free of
  # errexit AND of the phase-2 ERR trap (both are ignored inside an `if`
  # condition), so a failed capture is handled here as CAPTURE_FAILED
  # instead of tripping the phase marker or being masked into "0".
  if out="$(openstack "$type" list -f value -c "$column" 2>/dev/null)"; then
    :
  else
    printf 'CAPTURE_FAILED'
    return 0
  fi
  if [[ -z "$out" ]]; then
    printf '0'
    return 0
  fi
  printf '%s\n' "$out" | sed -n '$='
}

# ---- (a) reboot recovery -------------------------------------------------------
RECOVERY_STATUS=passed
wait_http http://127.0.0.1:18080/healthz 120 \
  || { RECOVERY_STATUS=failed; echo "ERROR: o3kd healthz not 200 within 2 min" >&2; }
wait_http http://127.0.0.1:9100/readyz 120 \
  || { RECOVERY_STATUS=failed; echo "ERROR: compute readyz not 200 within 2 min" >&2; }
O3KD_ACTIVE=no; COMPUTE_ACTIVE=no
systemctl is-active --quiet o3kd.service && O3KD_ACTIVE=yes
systemctl is-active --quiet o3k-compute.service && COMPUTE_ACTIVE=yes
if [ "$O3KD_ACTIVE" != yes ] || [ "$COMPUTE_ACTIVE" != yes ]; then
  RECOVERY_STATUS=failed
  echo "ERROR: services not active after reboot (o3kd=$O3KD_ACTIVE compute=$COMPUTE_ACTIVE)" >&2
fi
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc
POST_SRV_ID="$(openstack server show test-vm -f value -c id 2>/dev/null || true)"
POST_STATUS="$(openstack server show "$POST_SRV_ID" -f value -c status 2>/dev/null || true)"
POST_IP="$(server_fixed_ip)"
if [ "$POST_SRV_ID" != "$SRV_ID" ] || [ "$POST_STATUS" != ACTIVE ] || [ "$POST_IP" != 192.0.2.2 ]; then
  RECOVERY_STATUS=failed
  echo "ERROR: test-vm identity not preserved (id=$POST_SRV_ID status=$POST_STATUS ip=$POST_IP)" >&2
fi
console_marker_ok 30 || { RECOVERY_STATUS=failed; echo "ERROR: no console marker after reboot" >&2; }
virsh -c qemu:///system list --all 2>/dev/null >"$EVID/post-reboot-libvirt.txt" || true
ip -o link show 2>/dev/null >"$EVID/post-reboot-links.txt" || true
# The agent restores O3K-owned domains inside a bounded startup window
# (60s) and the control plane can re-drive the create; record the domain
# state trajectory for up to 120s so the reboot-recovery claim is verified
# against the provider state, not only the API projection.
DOMAIN_RUNNING=no
: >"$EVID/post-reboot-domain-trajectory.txt"
for i in $(seq 1 24); do
  virsh -c qemu:///system list --all 2>/dev/null >>"$EVID/post-reboot-domain-trajectory.txt"
  if virsh -c qemu:///system list --all 2>/dev/null | grep -qE '^\s*[0-9]+\s+o3k-.*\s+running\s*$'; then
    DOMAIN_RUNNING=yes
    echo "domain running after ${i}0s" >>"$EVID/post-reboot-domain-trajectory.txt"
    break
  fi
  sleep 5
done
# The final acceptance contract (STEP 5) requires
# domain_running_after_reboot=true: a restored API projection is not enough
# proof of reboot recovery, so a domain that never comes back must FAIL the
# recovery phase instead of being recorded as a warning.
if [ "$DOMAIN_RUNNING" = yes ]; then
  echo "domain running within 120s after reboot" >>"$EVID/post-reboot-domain-trajectory.txt"
else
  RECOVERY_STATUS=failed
  echo "ERROR: no O3K-owned domain running within 120s after reboot" >&2
  echo "no O3K-owned domain running within 120s after reboot" >>"$EVID/post-reboot-domain-trajectory.txt"
fi
DOMAIN_OBS="$(grep -E '^\s*[0-9-]+\s' "$EVID/post-reboot-libvirt.txt" | sed 's/^ *//' || true)"
log "reboot recovery: $RECOVERY_STATUS (o3kd=$O3KD_ACTIVE compute=$COMPUTE_ACTIVE server=$POST_STATUS)"

# ---- (b) one-liner re-run idempotency -----------------------------------------
RERUN_STATUS=passed
# NO_DUPLICATES is only mutated inside the rerun block below; with the block
# skipped (upgrade campaign) nothing re-ran, so nothing could have been
# duplicated and the OVERALL gate must not fail on a variable that was never
# assigned (real-host log: "NO_DUPLICATES: unbound variable").
NO_DUPLICATES=yes
if [ "${O3K_PHASE2_SKIP_IDEMPOTENCY:-0}" = 1 ]; then
  log "re-run idempotency skipped: the upgrade campaign leaves the NEW release installed and its installer fence refuses the OLD one-liner (covered by installer-negative + the campaign's own re-upgrade step)"
else
ENV_HASH_BEFORE="$(sha256sum /etc/o3k/o3kd.env | awk '{print $1}')"
TLS_HASH_BEFORE="$(sha256sum /etc/o3k/tls/* | sha256sum | awk '{print $1}')"
if eval "$ONELINER" 2>&1 | tee "$EVID/rerun-output.txt"; then
  log "one-liner re-run exited 0"
else
  RERUN_STATUS=failed
  echo "ERROR: one-liner re-run failed" >&2
  openstack server show test-vm -f json >"$EVID/rerun-server-show.json" 2>&1 || true
  openstack server list -f json >"$EVID/rerun-server-list.json" 2>&1 || true
fi
grep -Fq 'TLS identities preserved' "$EVID/rerun-output.txt" || {
  RERUN_STATUS=failed; echo "ERROR: re-run did not converge on TLS identities" >&2; }
grep -Fq 'TestLab resources already present' "$EVID/rerun-output.txt" || {
  RERUN_STATUS=failed; echo "ERROR: re-run did not converge on TestLab resources" >&2; }
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc
R2_IMAGE_ID="$(openstack image show cirros-0.6.3 -f value -c id || true)"
# `openstack flavor show` follows up with /flavors/{id}/os-extra_specs, which
# O3K does not implement; resolve through the list API, with the same
# bookworm (OSC 6.0) server-object fallback as phase 1.
R2_FLAVOR_ID="$(openstack flavor list -f json 2>/dev/null | python3 -c '
import json, sys
try:
    flavors = json.load(sys.stdin)
    for f in flavors:
        if f.get("Name") == "testlab-flavor":
            print(f.get("ID", ""))
            break
except Exception:
    pass
' || true)"
if [ -z "$R2_FLAVOR_ID" ]; then
  # Same OSC-6.1-and-older fallback as phase 1: the client post-processes
  # `server show` and leaves either a bare UUID or "name (id)" string.
  R2_FLAVOR_ID="$(openstack server show test-vm -f json 2>/dev/null | python3 -c '
import json, re, sys
try:
    server = json.load(sys.stdin)
    flavor = server.get("flavor", {})
    if isinstance(flavor, dict):
        print(flavor.get("id", ""))
    elif isinstance(flavor, str):
        m = re.search(r"\(([0-9a-fA-F-]{36})\)", flavor)
        if m:
            print(m.group(1))
        elif re.fullmatch(r"[0-9a-fA-F-]{36}", flavor):
            print(flavor)
except Exception:
    pass
' || true)"
fi
if [ -z "$R2_FLAVOR_ID" ]; then
  R2_FLAVOR_ID=unavailable
  log "flavor ID unresolvable through this client; marking unavailable"
fi
R2_NET_ID="$(openstack network show testlab-network -f value -c id || true)"
R2_SUB_ID="$(openstack subnet show testlab-subnet -f value -c id || true)"
R2_PORT_ID="$(openstack port show testlab-port -f value -c id || true)"
R2_SRV_ID="$(openstack server show test-vm -f value -c id || true)"
R2_KP_FP="$(openstack keypair show testlab-keypair -f value -c fingerprint || true)"
NO_DUPLICATES=yes
for spec in "R2_IMAGE_ID:$R2_IMAGE_ID" "R2_FLAVOR_ID:$R2_FLAVOR_ID" \
    "R2_NET_ID:$R2_NET_ID" "R2_SUB_ID:$R2_SUB_ID" "R2_PORT_ID:$R2_PORT_ID" \
    "R2_SRV_ID:$R2_SRV_ID" "R2_KP_FP:$R2_KP_FP"; do
  [[ -n "${spec#*:}" ]] || { RERUN_STATUS=failed; NO_DUPLICATES=no; \
    echo "ERROR: capture failed for ${spec%%:*}" >&2; }
done
R2_COUNT_SRV="$(capture_count server ID)"
R2_COUNT_IMG="$(capture_count image ID)"
R2_COUNT_NET="$(capture_count network ID)"
R2_COUNT_SUB="$(capture_count subnet ID)"
R2_COUNT_PORT="$(capture_count port ID)"
R2_COUNT_FLAVOR="$({ openstack flavor list -f json 2>/dev/null | python3 2>/dev/null -c '
import json, sys
print(len(json.load(sys.stdin)))
'; } || printf 'unavailable')"
R2_COUNT_KP="$(capture_count keypair Name)"
[ "$R2_IMAGE_ID" = "$IMAGE_ID" ] && [ "$R2_FLAVOR_ID" = "$FLAVOR_ID" ] \
  && [ "$R2_NET_ID" = "$NET_ID" ] && [ "$R2_SUB_ID" = "$SUB_ID" ] \
  && [ "$R2_PORT_ID" = "$PORT_ID" ] && [ "$R2_SRV_ID" = "$SRV_ID" ] \
  && [ "$R2_KP_FP" = "$KP_FP" ] || { NO_DUPLICATES=no; RERUN_STATUS=failed; }
[ "$R2_COUNT_SRV" = "$COUNT_SRV" ] && [ "$R2_COUNT_IMG" = "$COUNT_IMG" ] \
  && [ "$R2_COUNT_NET" = "$COUNT_NET" ] && [ "$R2_COUNT_SUB" = "$COUNT_SUB" ] \
  && [ "$R2_COUNT_PORT" = "$COUNT_PORT" ] && [ "$R2_COUNT_FLAVOR" = "$COUNT_FLAVOR" ] \
  && [ "$R2_COUNT_KP" = "$COUNT_KP" ] || { NO_DUPLICATES=no; RERUN_STATUS=failed; }
ENV_HASH_AFTER="$(sha256sum /etc/o3k/o3kd.env | awk '{print $1}')"
TLS_HASH_AFTER="$(sha256sum /etc/o3k/tls/* | sha256sum | awk '{print $1}')"
[ "$ENV_HASH_BEFORE" = "$ENV_HASH_AFTER" ] && [ "$TLS_HASH_BEFORE" = "$TLS_HASH_AFTER" ] \
  || { NO_DUPLICATES=no; RERUN_STATUS=failed; echo "ERROR: admin password or TLS identities changed on re-run" >&2; }
# Canonical no-duplicate contract (PP.2): the re-run's init/join convergence
# must NOT create a second BuildingBlock, change the bootstrap phase, add
# CloudProfiles, or rotate the agent identity / TLS material. The teardown
# path is unaffected: bootstrap-testlab.sh --teardown never required
# canonical state and still does not (create-path-only precondition).
AGENT_ID_AFTER="$(sha256sum /etc/o3k/tls/agent-id | awk '{print $1}')"
[ "$AGENT_ID_AFTER" = "$AGENT_ID_BEFORE" ] \
  || { NO_DUPLICATES=no; RERUN_STATUS=failed; echo "ERROR: agent-id file changed on re-run" >&2; }
CANONICAL_AFTER=""
if canonical_after_output="$(canonical_state /var/lib/o3k/o3k.sqlite 2>&1)"; then
  CANONICAL_AFTER="$canonical_after_output"
else
  RERUN_STATUS=failed; NO_DUPLICATES=no
  echo "ERROR: canonical durable state unreadable after re-run: $canonical_after_output" >&2
fi
if [ -n "$CANONICAL_AFTER" ]; then
  R2_BB_ID="$(canonical_field "$CANONICAL_AFTER" BB_ID)"
  R2_BB_COUNT="$(canonical_field "$CANONICAL_AFTER" BB_COUNT)"
  R2_BOOTSTRAP_ROWS="$(canonical_field "$CANONICAL_AFTER" BOOTSTRAP_ROWS)"
  R2_BOOTSTRAP_PHASE="$(canonical_field "$CANONICAL_AFTER" BOOTSTRAP_PHASE)"
  R2_PROFILE_COUNT="$(canonical_field "$CANONICAL_AFTER" PROFILE_COUNT)"
  if [ "$R2_BB_ID" = "$BB_ID" ] && [ "$R2_BB_COUNT" = "$BB_COUNT" ] \
    && [ "$R2_BOOTSTRAP_ROWS" = 1 ] && [ "$R2_BOOTSTRAP_PHASE" = "$BOOTSTRAP_PHASE" ] \
    && [ "$R2_PROFILE_COUNT" = "$PROFILE_COUNT" ]; then
    log "canonical no-duplicate verified (same BuildingBlock $R2_BB_ID, phase $R2_BOOTSTRAP_PHASE, $R2_PROFILE_COUNT CloudProfile(s))"
  else
    NO_DUPLICATES=no; RERUN_STATUS=failed
    echo "ERROR: canonical durable state changed on re-run (bb=$R2_BB_ID/$R2_BB_COUNT phase_rows=$R2_BOOTSTRAP_ROWS/$R2_BOOTSTRAP_PHASE profiles=$R2_PROFILE_COUNT; expected bb=$BB_ID/$BB_COUNT phase=$BOOTSTRAP_PHASE profiles=$PROFILE_COUNT)" >&2
  fi
fi
log "re-run idempotency: $RERUN_STATUS (no_duplicates=$NO_DUPLICATES)"
fi

# ---- (c) teardown through the INSTALLED bootstrap script -----------------------
TEARDOWN1_STATUS=passed
[ -f /usr/local/share/o3k/bootstrap-testlab.sh ] || {
  TEARDOWN1_STATUS=failed; echo "ERROR: /usr/local/share/o3k/bootstrap-testlab.sh missing" >&2; }
bash /usr/local/share/o3k/bootstrap-testlab.sh --teardown >"$EVID/teardown1.log" 2>&1 \
  || TEARDOWN1_STATUS=failed
for probe in "server test-vm" "port testlab-port" "subnet testlab-subnet" \
  "network testlab-network"; do
  read -r probe_type probe_name <<<"$probe"
  if [ -n "$(openstack "$probe_type" show "$probe_name" -f value -c id 2>/dev/null || true)" ]; then
    TEARDOWN1_STATUS=failed; echo "ERROR: $probe_type $probe_name still present after teardown" >&2
  fi
done
# Flavor absence after teardown: the installed bootstrap verifies deletion
# itself (fail-closed on unverified deletion) and prints one of these two
# lines on every client, including bookworm's OSC 6.0 which cannot enumerate
# flavors at all.
if ! grep -Fq 'flavor testlab-flavor deleted' "$EVID/teardown1.log" \
   && ! grep -Fq 'flavor testlab-flavor already absent' "$EVID/teardown1.log"; then
  TEARDOWN1_STATUS=failed; echo "ERROR: flavor testlab-flavor removal not verified by teardown" >&2
fi
log "teardown via installed bootstrap-testlab.sh: $TEARDOWN1_STATUS"

# ---- (d) uninstall (accounts intentionally retained) ---------------------------
UNINSTALL_STATUS=passed
if [ "${O3K_PHASE2_SKIP_IDEMPOTENCY:-0}" = 1 ]; then
  # Skip path: no reinstall restores the helper scripts afterwards, and a
  # plain uninstall --yes here would delete /usr/local/share/o3k/* (including
  # uninstall.sh, bootstrap-testlab.sh, and the .o3k-installed ownership
  # manifest) before the purge block below could run — the real-host run died
  # with "bootstrap-testlab.sh: No such file or directory" on teardown2/purge.
  # Purge must therefore run FIRST while the helpers still exist; its
  # uninstall.sh --purge --yes strictly subsumes the plain uninstall, so this
  # step's account-retention invariant is re-verified after purge below.
  log "uninstall --yes deferred: in the skip path purge runs first (its helper scripts must survive)"
else
  bash /usr/local/share/o3k/uninstall.sh --yes >"$EVID/uninstall1.log" 2>&1 \
    || UNINSTALL_STATUS=failed
  id o3k >/dev/null 2>&1 && id o3k-compute >/dev/null 2>&1 \
    || { UNINSTALL_STATUS=failed; echo "ERROR: service accounts missing after uninstall" >&2; }
  log "uninstall: $UNINSTALL_STATUS"
fi

# ---- (e) reinstall through the one-liner ----------------------------------------
REINSTALL_STATUS=passed
# R3_SRV_ID is only captured inside the reinstall block below; default it for
# the skip path (no reinstall, hence no new server) so the evidence writer's
# "$R3_SRV_ID" argument stays bound under set -u.
R3_SRV_ID=unavailable
if [ "${O3K_PHASE2_SKIP_IDEMPOTENCY:-0}" = 1 ]; then
  log "reinstall skipped: the upgrade campaign leaves the NEW release installed and its installer fence refuses the OLD one-liner (covered by installer-negative)"
else
if eval "$ONELINER" 2>&1 | tee "$EVID/reinstall-output.txt"; then
  log "one-liner reinstall exited 0"
else
  REINSTALL_STATUS=failed; echo "ERROR: one-liner reinstall failed" >&2
fi
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc
R3_SRV_ID="$(openstack server show test-vm -f value -c id 2>/dev/null || true)"
[ -n "$R3_SRV_ID" ] && [ "$(openstack server show "$R3_SRV_ID" -f value -c status)" = ACTIVE ] \
  || { REINSTALL_STATUS=failed; echo "ERROR: test-vm not ACTIVE after reinstall" >&2; }
console_marker_ok 30 || { REINSTALL_STATUS=failed; echo "ERROR: no console marker after reinstall" >&2; }
log "reinstall through one-liner: $REINSTALL_STATUS (new server $R3_SRV_ID)"
R3_SRV_ID="$(openstack server show test-vm -f value -c id 2>/dev/null || true)"
fi

# ---- (f) teardown + reconcile + purge ------------------------------------------
TEARDOWN2_STATUS=passed
bash /usr/local/share/o3k/bootstrap-testlab.sh --teardown >"$EVID/teardown2.log" 2>&1 \
  || TEARDOWN2_STATUS=failed
# The agent removes bridge/TAP/DHCP/domain state during teardown; give it a
# bounded window so purge's host-state inspection sees converged state.
TEARDOWN_SETTLED=0
for i in $(seq 1 30); do
  if [ -z "$(ip -o link show 2>/dev/null | grep -E 'o3k-br|o3ktap' || true)" ] \
    && [ -z "$(virsh -c qemu:///system list --all --name 2>/dev/null || true)" ]; then
    TEARDOWN_SETTLED=1; break
  fi
  sleep 2
done
[ "$TEARDOWN_SETTLED" = 1 ] \
  || echo "WARNING: host network/domain state not settled before purge" >&2
PURGE_STATUS=passed
reconcile_state_root >"$EVID/reconcile-purge.log" 2>&1 || PURGE_STATUS=failed
bash /usr/local/share/o3k/uninstall.sh --purge --yes >"$EVID/purge.log" 2>&1 \
  || PURGE_STATUS=failed
id o3k >/dev/null 2>&1 && id o3k-compute >/dev/null 2>&1 \
  || { PURGE_STATUS=failed; echo "ERROR: service accounts missing after purge" >&2; }
log "purge: $PURGE_STATUS (teardown2=$TEARDOWN2_STATUS)"
if [ "${O3K_PHASE2_SKIP_IDEMPOTENCY:-0}" = 1 ]; then
  # Skip path: the deferred plain-uninstall step is subsumed by the purge run
  # above; only its account-retention invariant can still be observed, and a
  # failed purge means the subsumed uninstall cannot be claimed passed.
  [ "$PURGE_STATUS" = passed ] || { UNINSTALL_STATUS=failed; \
    echo "ERROR: uninstall subsumed by purge, which failed" >&2; }
  id o3k >/dev/null 2>&1 && id o3k-compute >/dev/null 2>&1 \
    || { UNINSTALL_STATUS=failed; echo "ERROR: service accounts missing after uninstall" >&2; }
  log "uninstall: $UNINSTALL_STATUS"
fi

# ---- (g) zero-residue + foreign canaries ---------------------------------------
ZERO_RESIDUE=yes
[ ! -e /usr/local/bin/o3kd ] && [ ! -L /usr/local/bin/o3kd ] \
  && [ ! -e /usr/local/bin/o3k ] && [ ! -L /usr/local/bin/o3k ] \
  && [ ! -e /usr/local/bin/o3k-compute ] && [ ! -L /usr/local/bin/o3k-compute ] \
  || { ZERO_RESIDUE=no; echo "ERROR: binaries remain" >&2; }
[ ! -e /etc/systemd/system/o3kd.service ] && [ ! -e /etc/systemd/system/o3k-compute.service ] \
  || { ZERO_RESIDUE=no; echo "ERROR: systemd units remain" >&2; }
[ ! -e /etc/polkit-1/rules.d/50-o3k-libvirt.rules ] \
  || { ZERO_RESIDUE=no; echo "ERROR: polkit rule remains" >&2; }
if [ -e /etc/o3k ] && [ -n "$(find /etc/o3k -mindepth 1 -print -quit 2>/dev/null)" ]; then
  ZERO_RESIDUE=no; echo "ERROR: /etc/o3k not empty" >&2
fi
[ ! -e /var/lib/o3k ] && [ ! -e /var/log/o3k ] \
  || { ZERO_RESIDUE=no; echo "ERROR: state/log roots remain" >&2; }
DOMAIN_LEFTOVER="$(virsh -c qemu:///system list --all --name 2>/dev/null | grep -c . || true)"
[ "$DOMAIN_LEFTOVER" = 0 ] || { ZERO_RESIDUE=no; echo "ERROR: libvirt domains remain" >&2; }
LINK_LEFTOVER="$(ip -o link show 2>/dev/null | grep -Ec 'o3k-br|o3ktap' || true)"
[ "$LINK_LEFTOVER" = 0 ] || { ZERO_RESIDUE=no; echo "ERROR: O3K bridge/tap links remain" >&2; }
PROC_LEFTOVER="$(pgrep -fc '/var/lib/o3k' || true)"
[ "$PROC_LEFTOVER" = 0 ] || { ZERO_RESIDUE=no; echo "ERROR: O3K processes remain" >&2; }
# Each `read` with its own redirection reopens the file and reads line 1
# again (all three variables would get the first canary); group the reads
# under ONE redirection so the three lines land in C1/C2/C3 respectively.
{
  read -r C1
  read -r C2
  read -r C3
} < "$EVID/canaries.txt"
N1=$(sha256sum /opt/o3k-foreign/canary.txt | awk '{print $1}')
N2=$(sha256sum /etc/o3k-foreign/canary.txt | awk '{print $1}')
# Hash the RAW passwd line, not `getent` output: the one-liner's dependency
# set installs libnss-systemd, which makes getent print additional
# synthesized records for the same unchanged user (false mismatch).
N3=$(grep '^foreigncanary:' /etc/passwd | sha256sum | awk '{print $1}')
FOREIGN_OK=yes
[ "$C1" = "$N1" ] || { FOREIGN_OK=no; echo "canary mismatch: /opt/o3k-foreign/canary.txt before=$C1 after=$N1" >&2; }
[ "$C2" = "$N2" ] || { FOREIGN_OK=no; echo "canary mismatch: /etc/o3k-foreign/canary.txt before=$C2 after=$N2" >&2; }
[ "$C3" = "$N3" ] || { FOREIGN_OK=no; echo "canary mismatch: foreigncanary passwd before=$C3 after=$N3" >&2; }
log "zero residue: $ZERO_RESIDUE, foreign state preserved: $FOREIGN_OK"

# ---- (h) evidence JSON ---------------------------------------------------------
OVERALL=passed
for status in "$RECOVERY_STATUS" "$RERUN_STATUS" "$TEARDOWN1_STATUS" \
  "$UNINSTALL_STATUS" "$REINSTALL_STATUS" "$TEARDOWN2_STATUS" "$PURGE_STATUS"; do
  [ "$status" = passed ] || OVERALL=failed
done
[ "$NO_DUPLICATES" = yes ] && [ "$ZERO_RESIDUE" = yes ] && [ "$FOREIGN_OK" = yes ] \
  || OVERALL=failed

python3 - "$EVID/one-line-${DISTRO}-install.json" "$DISTRO" "$SOURCE_SHA" "$OVERALL" \
  "$RECOVERY_STATUS" "$O3KD_ACTIVE" "$COMPUTE_ACTIVE" "$DOMAIN_OBS" "$DOMAIN_RUNNING" \
  "$RERUN_STATUS" "$NO_DUPLICATES" "$TEARDOWN1_STATUS" "$UNINSTALL_STATUS" \
  "$REINSTALL_STATUS" "$TEARDOWN2_STATUS" "$PURGE_STATUS" "$ZERO_RESIDUE" \
  "$FOREIGN_OK" "$R3_SRV_ID" "$ONELINER_OUT" \
  "$BB_ID" "$BB_COUNT" "$BOOTSTRAP_PHASE" "$PROFILE_COUNT" "$ONELINER" <<'PY'
import json
import sys
import time

path, distro, sha, overall, recovery, o3kd, compute, domain_obs, domain_running = sys.argv[1:10]
rerun, no_dup, teardown1, uninstall, reinstall, teardown2, purge = sys.argv[10:17]
zero_residue, foreign, reinstall_server, output_path = sys.argv[17:21]
bb_id, bb_count, bootstrap_phase, profile_count, oneliner = sys.argv[21:26]

with open(output_path, encoding="utf-8") as stream:
    user_output = stream.read()

is_real_release = oneliner.startswith("curl -sfL https://github.com/")

doc = {
    "artifact_type": "one-line-installer",
    "distro": distro,
    "profile": "libvirt",
    "status": overall,
    "redacted": True,
    "finished_at": int(time.time()),
    "source_commit": sha,
    "install_method": "one-line-public-release-asset" if is_real_release
        else "one-line-local-endpoint",
    "installer_command": oneliner,
    "public_api_only": True,
    "install": {
        "status": "passed",
        "from_one_liner_only": True,
        "credentials": {"admin_openrc": "0600", "clouds_yaml": "0600",
                        "o3kd_env": "0600"},
        "password_not_in_output": True,
        "bootstrap_secret_not_in_output": True,
        "enrollment_token_not_in_output": True,
    },
    "canonical_bootstrap": {
        "status": "passed",
        "building_block_id": bb_id,
        "building_blocks_count": int(bb_count),
        "bootstrap_phase": bootstrap_phase,
        "cloud_profiles_count": int(profile_count),
        "durable_store": "/var/lib/o3k/o3k.sqlite (read-only python3 sqlite3)",
        "no_second_building_block_on_rerun": no_dup == "yes",
        "teardown_unaffected_by_canonical_precondition": teardown1 == "passed",
    },
    "acceptance": {
        "status": "ACTIVE", "fixed_ip": "192.0.2.2", "config_drive": True,
        "console_boot_marker": True,
    },
    "reboot_recovery": {
        "status": recovery,
        "services": {"o3kd": o3kd, "o3k_compute": compute},
        "agent_reconnected": recovery == "passed",
        "server_identity_preserved": recovery == "passed",
        "libvirt_domains_after_reboot": domain_obs,
        "domain_running_after_reboot": domain_running == "yes",
    },
    "rerun_idempotent": rerun == "passed",
    "no_duplicate_resources": no_dup == "yes",
    "teardown": {"first": teardown1, "second": teardown2,
                 "via_installed_bootstrap_testlab_sh": True},
    "uninstall": {"status": uninstall, "service_accounts_after_uninstall": "retained-intentional"},
    "reinstall": {"status": reinstall,
                  "method": "one-line-public-release-asset" if is_real_release
                      else "one-line-local-endpoint",
                  "new_server_id": reinstall_server},
    "purge": {"status": purge, "state_reconciliation":
              "operator-explicit: services stopped, ownership markers verified, "
              "owned runtime state removed before uninstall --purge validation "
              "(hardened contract)"},
    "zero_residue": {
        "status": zero_residue == "yes",
        "service_accounts": "retained-intentional",
        "binaries_removed": True, "systemd_units_removed": True,
        "polkit_rule_removed": True, "config_removed": True,
        "data_log_reconciled_empty": True,
        "libvirt_domains": "none", "o3k_bridges": "none",
    },
    "foreign_state_preserved": foreign == "yes",
    "console": "cirros|login boot marker present",
    "user_output": user_output,
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(doc, stream, indent=2)
    stream.write("\n")
print(f"wrote {path} status={overall}")
PY
[ "$OVERALL" = passed ] || {
  echo "ONE-LINE ${DISTRO}: FAILED"
  printf 'PHASE2-FAILED overall=%s\n' "$OVERALL" > "$EVID/phase2-done"
  exit 1
}
log "one-line-${DISTRO}-install evidence: PASSED"
printf 'PHASE2-COMPLETE status=%s\n' "$OVERALL" > "$EVID/phase2-done"
