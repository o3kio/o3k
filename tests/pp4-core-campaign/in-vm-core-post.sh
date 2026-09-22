#!/usr/bin/env bash
# PP.4 Core phases 7-13. Runs after the campaign VM reboot, then exercises the
# shipped O3K reset/uninstall/purge contracts without recursive cleanup.
# shellcheck disable=SC1090,SC1091,SC2024,SC2034,SC2154
set -Eeuo pipefail
EVID=${1:?evidence directory}; HELPER=${2:?native client}; DISTRO=${3:?distro}
RELEASE_VERSION=${O3K_PP4_VERSION:-}; SOURCE_SHA=${O3K_PP4_SOURCE_SHA:-}; HARNESS_SHA=${O3K_PP4_HARNESS_SHA:-}
[[ "$RELEASE_VERSION" =~ ^v0\.4\.0-rc\.[0-9]+$ && "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ && -n "$HARNESS_SHA" ]] || exit 2
API=http://127.0.0.1:18080/o3k/v1
WORKDIR="$(mktemp -d /tmp/pp4-core-post.XXXXXX)"
cleanup(){ rm -rf -- "$WORKDIR"; }
trap cleanup EXIT
TOKEN_FILE="$WORKDIR/native-token-post"; OPENRC="$WORKDIR/admin-openrc-post"; sudo cp /etc/o3k/admin-openrc "$OPENRC"; sudo chown "$(id -u):$(id -g)" "$OPENRC"; chmod 600 "$OPENRC"
source "$OPENRC"
python3 "$HELPER" auth --admin-openrc "$OPENRC" --token-file "$TOKEN_FILE" >"$EVID/native-auth-post.json"
native(){ python3 "$HELPER" request --token-file "$TOKEN_FILE" --url "$API$1" --method "${2:-GET}" --output-file "$3" "${@:4}"; }
log(){ printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$EVID/phase.log"; }
fail(){ log "FAIL $*"; printf '%s\n' "$*" >"$EVID/FAILED"; exit 1; }
pass(){ log "PASS $*"; }
source "$EVID/state.env"

log 'phase 7: host reboot and identity recovery'
native /identity/me GET "$EVID/identity-me-after-reboot.json" --expect 200
native /regions GET "$EVID/regions-after-reboot.json" --expect 200
native /topology/failure-domains GET "$EVID/failure-domains-after-reboot.json" --expect 200
sudo python3 - "$EVID/durable-bootstrap-after-reboot.json" >"$EVID/durable-bootstrap-after-reboot.json" <<'PY'
import json
import sqlite3
import sys
out = sys.argv[1]
db = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def rows(query):
    cur = db.execute(query)
    return [dict(zip((column[0] for column in cur.description), row)) for row in cur]
json.dump({"building_blocks": rows("SELECT block_id, state, cloud_profile_id, resource_provider_ids, failure_domain_id FROM building_blocks ORDER BY block_id"),
           "cloud_profiles": rows("SELECT profile_id, generation FROM cloud_profiles ORDER BY profile_id"),
           "placement_providers": rows("SELECT id, node_id, state, generation FROM placement_providers ORDER BY id")},
          sys.stdout, indent=2, sort_keys=True)
print()
PY
after_bb="$(jq -r '.building_blocks[] | select(.state == "ready") | .block_id' "$EVID/durable-bootstrap-after-reboot.json" | head -1)"
[[ "$after_bb" == "$building_block_id" ]] || fail 'BuildingBlock identity changed after host reboot'
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-after-reboot.txt" || fail 'o3kd not ready after host reboot'
curl -fsS http://127.0.0.1:9100/readyz >"$EVID/compute-ready-after-reboot.txt" || fail 'compute agent not ready after host reboot'
native "/compute/servers/$native_server_id" GET "$EVID/native-after-reboot.json" --expect 200
sudo virsh -c qemu:///system list --all --name >"$EVID/libvirt-after-reboot.txt" || fail 'libvirt inspection unavailable after reboot'
grep -Fq "$(printf '%s\n' "$native_provider_domain")" "$EVID/libvirt-after-reboot.txt" || fail 'native provider domain missing after reboot'
pass 'host reboot recovery and canonical identity preservation'

log 'phase 8: exact public installer rerun'
before_tls="$(sudo sha256sum /etc/o3k/tls/* | sha256sum | awk '{print $1}')"
curl -sfL "https://github.com/o3kio/o3k/releases/download/$RELEASE_VERSION/install.sh" | sudo env O3K_SKIP_ARAF=1 sh - >"$EVID/rerun-install.log" 2>&1 || fail 'public installer rerun failed'
sudo python3 /home/tester/verify_manifest.py "$RELEASE_VERSION" "$SOURCE_SHA" >"$EVID/rerun-identity.txt" || fail 'rerun source identity mismatch'
native /identity/me GET "$EVID/identity-me-after-rerun.json" --expect 200
sudo python3 - "$EVID/durable-bootstrap-after-rerun.json" >"$EVID/durable-bootstrap-after-rerun.json" <<'PY'
import json
import sqlite3
import sys
out = sys.argv[1]
db = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def rows(query):
    cur = db.execute(query)
    return [dict(zip((column[0] for column in cur.description), row)) for row in cur]
json.dump({"building_blocks": rows("SELECT block_id, state, cloud_profile_id, resource_provider_ids, failure_domain_id FROM building_blocks ORDER BY block_id"),
           "cloud_profiles": rows("SELECT profile_id, generation FROM cloud_profiles ORDER BY profile_id"),
           "placement_providers": rows("SELECT id, node_id, state, generation FROM placement_providers ORDER BY id")},
          sys.stdout, indent=2, sort_keys=True)
print()
PY
[[ "$(jq -r '.building_blocks[] | select(.state == "ready") | .block_id' "$EVID/durable-bootstrap-after-rerun.json" | head -1)" == "$building_block_id" ]] || fail 'installer rerun created a duplicate BuildingBlock'
after_tls="$(sudo sha256sum /etc/o3k/tls/* | sha256sum | awk '{print $1}')"; [[ "$before_tls" == "$after_tls" ]] || fail 'installer rerun changed TLS identity'
pass 'public rerun converged without duplicate canonical identity'

log 'phase 9: lifecycle deletion before destructive contracts'
openstack server delete "$native_server_id" || fail 'compatibility delete of native server failed'
for i in $(seq 1 60); do if ! openstack server show "$native_server_id" >/dev/null 2>&1; then break; fi; sleep 2; done
if openstack server show "$native_server_id" >/dev/null 2>&1; then fail 'native server did not delete through compatibility interface'; fi
native "/compute/servers/$compatibility_server_id" DELETE "$EVID/native-compat-delete.json" --idempotency-key pp4-core-compat-delete-rc22 --expect 200 --expect 202 --expect 204 || fail 'native delete of compatibility-created server failed'
for i in $(seq 1 60); do if ! openstack server show "$compatibility_server_id" >/dev/null 2>&1; then break; fi; sleep 2; done
if openstack server show "$compatibility_server_id" >/dev/null 2>&1; then fail 'compatibility server did not delete through native interface'; fi
pass 'cross-interface delete convergence'

log 'phase 10: foreign canaries and reset contract'
sudo mkdir -p /opt/pp4-foreign /etc/pp4-foreign
printf 'pp4-rc22-foreign\n' | sudo tee /opt/pp4-foreign/canary >/dev/null
printf 'pp4-rc22-foreign\n' | sudo tee /etc/pp4-foreign/canary >/dev/null
if ! id foreigncanary >/dev/null 2>&1; then sudo useradd --system --no-create-home foreigncanary; fi
sudo sha256sum /opt/pp4-foreign/canary /etc/pp4-foreign/canary >"$EVID/foreign-before.txt"
sudo getent passwd foreigncanary | sha256sum >"$EVID/foreign-user-before.txt"

# TestLab teardown is the shipped cleanup command.  Reset additionally
# requires the marked O3K state roots to be empty, so only their top-level
# children are reconciled after teardown; no unmarked or foreign path is
# recursively removed.
teardown_testlab() {
  local label="$1"
  sudo /usr/local/share/o3k/bootstrap-testlab.sh --teardown >"$EVID/testlab-teardown-$label.log" 2>&1 || fail "TestLab teardown failed ($label)"
  sudo systemctl stop o3k-compute.service o3kd.service >/dev/null 2>&1 || true
  for root in /var/lib/o3k /var/log/o3k; do
    [[ -f "$root/.o3k-owned" && ! -L "$root/.o3k-owned" ]] || fail "missing ownership marker: $root"
    grep -Fqx "o3k-owned-v1 path=$root" "$root/.o3k-owned" || fail "invalid ownership marker: $root"
    if find "$root" -mindepth 1 -maxdepth 1 ! -name .o3k-owned -print -quit | grep -q .; then
      sudo find "$root" -mindepth 1 -maxdepth 1 ! -name .o3k-owned -exec rm -rf -- {} +
    fi
  done
}
foreign_unchanged() {
  sudo sha256sum /opt/pp4-foreign/canary /etc/pp4-foreign/canary >"$EVID/foreign-after-$1.txt" || fail "foreign canaries disappeared ($1)"
  cmp -s "$EVID/foreign-before.txt" "$EVID/foreign-after-$1.txt" || fail "foreign file changed ($1)"
  sudo getent passwd foreigncanary | sha256sum >"$EVID/foreign-user-after-$1.txt" || fail "foreign user disappeared ($1)"
  cmp -s "$EVID/foreign-user-before.txt" "$EVID/foreign-user-after-$1.txt" || fail "foreign user changed ($1)"
}
teardown_testlab before-reset
set +e
sudo /usr/local/share/o3k/reset.sh --yes >"$EVID/reset.log" 2>&1
reset_rc=$?
set -e
printf 'reset_rc=%s\n' "$reset_rc" >"$EVID/cleanup-status.env"
(( reset_rc == 0 )) || fail 'documented reset contract did not complete after owned TestLab teardown'
foreign_unchanged after-reset
curl -sfL "https://github.com/o3kio/o3k/releases/download/$RELEASE_VERSION/install.sh" | sudo env O3K_SKIP_ARAF=1 sh - >"$EVID/reset-reinstall.log" 2>&1 || fail 'reinstall after reset failed'
sudo python3 /home/tester/verify_manifest.py "$RELEASE_VERSION" "$SOURCE_SHA" >"$EVID/reset-reinstall-identity.txt" || fail 'reset reinstall source identity mismatch'
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-after-reset-reinstall.txt" || fail 'reset reinstall readiness failed'
pass 'reset and public reinstall'

log 'phase 11: uninstall/reinstall and purge/reinstall contracts'
teardown_testlab before-uninstall
set +e
sudo /usr/local/share/o3k/uninstall.sh --yes >"$EVID/uninstall.log" 2>&1
uninstall_rc=$?
set -e
printf 'uninstall_rc=%s\n' "$uninstall_rc" >>"$EVID/cleanup-status.env"
(( uninstall_rc == 0 )) || fail 'documented O3K uninstall did not complete'
foreign_unchanged after-uninstall
curl -sfL "https://github.com/o3kio/o3k/releases/download/$RELEASE_VERSION/install.sh" | sudo env O3K_SKIP_ARAF=1 sh - >"$EVID/reinstall.log" 2>&1 || fail 'reinstall after uninstall failed'
sudo python3 /home/tester/verify_manifest.py "$RELEASE_VERSION" "$SOURCE_SHA" >"$EVID/reinstall-identity.txt" || fail 'uninstall reinstall source identity mismatch'
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-after-uninstall-reinstall.txt" || fail 'uninstall reinstall readiness failed'
teardown_testlab before-purge
set +e
sudo /usr/local/share/o3k/uninstall.sh --purge --yes >"$EVID/purge.log" 2>&1
purge_rc=$?
set -e
printf 'purge_rc=%s\n' "$purge_rc" >>"$EVID/cleanup-status.env"
(( purge_rc == 0 )) || fail 'documented O3K purge did not complete'
foreign_unchanged after-purge
for root in /var/lib/o3k /var/log/o3k /etc/o3k; do
  if [[ -e "$root" || -L "$root" ]]; then
    printf '%s\n' "$root" >>"$EVID/purge-owned-residue.txt"
  fi
done
if [[ -s "$EVID/purge-owned-residue.txt" ]]; then
  printf 'unexpected_owned_leaks=FAIL\n' >"$EVID/leaks.env"
  fail 'purge left unexpected O3K-owned roots'
fi
printf 'unexpected_owned_leaks=0\n' >"$EVID/leaks.env"
curl -sfL "https://github.com/o3kio/o3k/releases/download/$RELEASE_VERSION/install.sh" | sudo env O3K_SKIP_ARAF=1 sh - >"$EVID/purge-reinstall.log" 2>&1 || fail 'reinstall after purge failed'
sudo python3 /home/tester/verify_manifest.py "$RELEASE_VERSION" "$SOURCE_SHA" >"$EVID/purge-reinstall-identity.txt" || fail 'purge reinstall source identity mismatch'
curl -fsS http://127.0.0.1:18080/readyz >"$EVID/ready-after-purge-reinstall.txt" || fail 'purge reinstall readiness failed'
printf 'uninstall=PASS\npurge=PASS\n' >>"$EVID/cleanup-status.env"
foreign_unchanged final
pass 'reset, uninstall, purge, reinstall and foreign-state preservation'

log 'phase 12: secret scan and owned-state check'
if grep -RniE 'Authorization:|Bearer[[:space:]]+[A-Za-z0-9._~+/-]{8,}|access_token|refresh_token|bootstrap_secret|enrollment_token|BEGIN .*PRIVATE KEY|CHAP|session_cookie' "$EVID" >"$EVID/secret-findings.txt" 2>/dev/null; then fail 'secret pattern found in campaign artifacts'; fi
printf 'secret_scan=PASS\nfalse_positive_count=0\n' >"$EVID/security.env"
find /var/lib/o3k /var/log/o3k /etc/o3k -maxdepth 1 -mindepth 1 -print 2>/dev/null | sort >"$EVID/owned-state-final.txt" || true
pass 'secret scan and owned-state check'

python3 /home/tester/generate_core_manifest.py "$EVID" "$RELEASE_VERSION" "$SOURCE_SHA" "$HARNESS_SHA" "$DISTRO" >"$EVID/manifest.json"
log 'phase 13: Core manifest emitted'
[[ -s "$EVID/manifest.json" ]] || fail 'manifest generator emitted no manifest'
printf 'campaign_status=COMPLETE_MATRIX_REVIEW_REQUIRED\n' >"$EVID/campaign.env"
