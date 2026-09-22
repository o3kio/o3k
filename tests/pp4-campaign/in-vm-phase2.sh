#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 2 (runs after the host reboot + browser relogin):
#   recovery asserts -> same-version one-liner rerun convergence (incl. the
#   "refusing to overwrite operator-modified configuration file" regression
#   check and the O3K config-file ledger) -> failure/recovery matrix (Araf
#   restart, o3kd restart, IdP outage, interrupted Araf deployment) ->
#   uninstall/reinstall -> purge/reinstall -> foreign canaries + final secret
#   scans.
# A crash writes phase2-done with status=failed (host fails fast).
#
# Usage: sudo bash in-vm-phase2.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/pp4-evidence}"
SOURCE_SHA="${3:-unknown}"
source /home/tester/pp4-campaign/in-vm-lib.sh
export PP4_PHASE=phase2
pp4_install_phase_trap phase2 "$EVID/phase2-done" PHASE2
DEMO=/usr/local/share/o3k/araf-demo/o3k-araf-demo.sh
ADMIN_PROJECT_ID="eba29e2d-53de-461d-ae91-ede7402713cb"
EXPECTED_DEMO_SERVICES=(idp tenant-bff operator-bff tenant-console operator-console tls-proxy api-relay)
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc

building_block_ids() {
  python3 -c 'import sqlite3; print("\n".join(sorted(r[0] for r in sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True).execute("select block_id from building_blocks"))))'
}

# One canonical-state snapshot used to compare ID SETS (not counts) across the
# convergent rerun.
canonical_snapshot() { # out.json
  python3 - "$1" <<'PY'
import json, sqlite3, sys
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def ids(query):
    return sorted(r[0] for r in c.execute(query))
snapshot = {
    "building_blocks": ids("select block_id from building_blocks"),
    "cloud_profiles": ids("select profile_id from cloud_profiles"),
    "placement_providers": ids("select id from placement_providers"),
}
json.dump(snapshot, open(sys.argv[1], "w", encoding="utf-8"), indent=1)
PY
}

running_demo_containers() {
  docker ps --format '{{.Names}}' | grep '^o3k-araf-demo-' | sort
}

# ---------------------------------------------------------------------------
# Demo federation wiring + O3K config-ledger convergence
#
# The demo OIDC federation must never live in /etc/o3k/o3kd.env: O3K's
# installer keeps an install-time content ledger for that file and refuses to
# re-run when its bytes changed. The federation travels in the demo-owned 0600
# env file pulled in by the demo-owned systemd drop-in, and /etc/o3k/o3kd.env
# must stay byte-identical across every install/uninstall cycle.
# ---------------------------------------------------------------------------
DEMO_FED_ENV=/etc/o3k/o3kd-araf-demo.env
DEMO_FED_DROPIN=/etc/systemd/system/o3kd.service.d/araf-demo.conf
O3KD_ENV_LEDGER_BASELINE="$(awk -F= '$1=="o3kd_env_sha256_after_install"{print $2}' \
  "$EVID/12b-o3k-o3kd-env-ledger.txt" 2>/dev/null || true)"
[ -n "$O3KD_ENV_LEDGER_BASELINE" ] \
  || die "phase1a did not record the O3K config-ledger baseline (12b-o3k-o3kd-env-ledger.txt)"
: > "$EVID/27b-o3k-o3kd-env-ledger-convergence.txt"

assert_o3kd_env_unchanged() { # CONTEXT
  local ctx="$1" now
  now="$(sha256sum /etc/o3k/o3kd.env | awk '{print $1}')" \
    || die "cannot hash /etc/o3k/o3kd.env (cannot verify convergence)"
  printf '%s o3kd_env_sha256=%s baseline=%s\n' "$ctx" "$now" "$O3KD_ENV_LEDGER_BASELINE" \
    >> "$EVID/27b-o3k-o3kd-env-ledger-convergence.txt"
  [ "$now" = "$O3KD_ENV_LEDGER_BASELINE" ] \
    || die "${ctx}: /etc/o3k/o3kd.env changed (${now} != ${O3KD_ENV_LEDGER_BASELINE}); the O3K config-file ledger regression is back"
  grep -q 'O3K_OIDC_TRUST_ID' /etc/o3k/o3kd.env \
    && die "${ctx}: the demo federation leaked into the O3K-owned /etc/o3k/o3kd.env"
  return 0
}

assert_demo_federation() { # STATE(present|absent) CONTEXT
  local want="$1" ctx="$2"
  printf '%s demo_fed_env=%s demo_fed_dropin=%s want=%s\n' "$ctx" \
    "$([ -f "$DEMO_FED_ENV" ] && echo present || echo absent)" \
    "$([ -f "$DEMO_FED_DROPIN" ] && echo present || echo absent)" "$want" \
    >> "$EVID/27b-o3k-o3kd-env-ledger-convergence.txt"
  if [ "$want" = present ]; then
    [ -f "$DEMO_FED_ENV" ] || die "${ctx}: ${DEMO_FED_ENV} is missing while the demo is installed"
    [ "$(stat -c %a "$DEMO_FED_ENV")" = 600 ] || die "${ctx}: ${DEMO_FED_ENV} is not 0600"
    grep -q '^O3K_OIDC_TRUST_ID=' "$DEMO_FED_ENV" || die "${ctx}: ${DEMO_FED_ENV} carries no O3K_OIDC_TRUST_ID"
    [ -f "$DEMO_FED_DROPIN" ] || die "${ctx}: ${DEMO_FED_DROPIN} is missing while the demo is installed"
    grep -q "EnvironmentFile=-${DEMO_FED_ENV}" "$DEMO_FED_DROPIN" \
      || die "${ctx}: the drop-in does not pull in ${DEMO_FED_ENV}"
  else
    [ ! -e "$DEMO_FED_ENV" ] || die "${ctx}: ${DEMO_FED_ENV} survived (demo state not removed)"
    [ ! -e "$DEMO_FED_DROPIN" ] || die "${ctx}: ${DEMO_FED_DROPIN} survived (demo state not removed)"
  fi
}

expected_demo_containers() {
  local n
  for n in "${EXPECTED_DEMO_SERVICES[@]}"; do printf 'o3k-araf-demo-%s-1\n' "$n"; done | sort
}

assert_demo_container_set() { # CONTEXT -> dies unless the running set == expected 7
  local ctx="$1"
  expected_demo_containers > "$EVID/22b-expected-containers.txt"
  running_demo_containers > "$EVID/22c-running-containers.txt"
  docker ps -a --format '{{.Names}} {{.Status}}' > "$EVID/22d-containers-all.txt"
  if ! diff -u "$EVID/22b-expected-containers.txt" "$EVID/22c-running-containers.txt" > "$EVID/22e-container-diff.txt"; then
    cat "$EVID/22e-container-diff.txt" >&2
    die "$ctx: running demo container set != expected compose service set (see 22c/22e)"
  fi
}

araf_image_digests() {
  docker inspect -f '{{.Image}}' o3k-araf-demo-tenant-bff-1 o3k-araf-demo-tenant-console-1 \
    o3k-araf-demo-operator-console-1
}

araf_image_revisions() {
  docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    o3k-araf-demo-tenant-bff-1 o3k-araf-demo-tenant-console-1 \
    o3k-araf-demo-operator-console-1
}

# ---- post-reboot recovery -------------------------------------------------------------
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd not ready after reboot"
curl -sf http://127.0.0.1:9100/readyz >/dev/null || die "o3k-compute not ready after reboot"
bash "$DEMO" status > "$EVID/22-status-post-reboot.txt" 2>&1 || true
docker ps --format '{{.Names}} {{.Status}}' > "$EVID/22b-containers-post-reboot.txt"
for n in "${EXPECTED_DEMO_SERVICES[@]}"; do
  c="o3k-araf-demo-${n}-1"
  grep -Eq "^${c}[[:space:]]+Up" "$EVID/22b-containers-post-reboot.txt" \
    || die "demo container not up after reboot: $c (observed: $(tr '\n' ';' < "$EVID/22b-containers-post-reboot.txt"))"
done
[ "$(openstack server show test-vm -c status -f value)" = ACTIVE ] || die "test-vm not ACTIVE after reboot"
bash "$DEMO" verify > "$EVID/24-verify-post-reboot.log" 2>&1 || die "post-reboot verify failed"
case_ok R1 "post-reboot recovery: O3K + Araf + workload healthy"

# ---- same-version rerun convergence ----------------------------------------------------
assert_demo_container_set "pre-rerun"
araf_image_digests > "$EVID/25-image-digests-before.txt"
araf_image_revisions > "$EVID/25-image-revisions-before.txt"
canonical_snapshot "$EVID/25-canonical-state-before.json" || die "cannot snapshot canonical state before the rerun"
cp /var/lib/o3k/install-timestamps.env "$EVID/25-timestamps-before-rerun.env"
openstack server list -f json > "$EVID/25-servers-before-rerun.json" \
  || die "cannot list servers before the rerun (cannot verify convergence)"
ONELINER="curl -sfL https://github.com/o3kio/o3k/releases/download/${O3K_CAMPAIGN_VERSION:?}/install.sh | sudo sh -"
log "re-running the one-liner for convergence: $ONELINER"
if eval "$ONELINER" > "$EVID/25-rerun-install.log" 2>&1; then
  log "rerun exit 0"
else
  tail -50 "$EVID/25-rerun-install.log" >&2
  die "one-liner rerun failed"
fi
grep -q 'O3K demo ready' "$EVID/25-rerun-install.log" || die "rerun success output missing"
# THE PP.4 REGRESSION THIS CANDIDATE FIXES: O3K's installer refuses to re-run
# when an O3K-ledgered config file changed. The demo used to append its
# federation block to /etc/o3k/o3kd.env, so the rerun aborted with exactly this
# string. It must never appear again.
if grep -Fq 'refusing to overwrite operator-modified configuration file' "$EVID/25-rerun-install.log"; then
  grep -F 'refusing to overwrite operator-modified configuration file' "$EVID/25-rerun-install.log" >&2
  die "the one-liner rerun refused to overwrite an operator-modified config file: the demo mutated O3K-owned configuration"
fi
assert_o3kd_env_unchanged "after the one-liner rerun"
assert_demo_federation present "after the one-liner rerun"
CURRENT_CASE=R3 CURRENT_NAME="one-liner rerun converges without the operator-modified-config refusal" \
  case_ok R3 "rerun exit 0 with no 'refusing to overwrite operator-modified configuration file'; /etc/o3k/o3kd.env byte-identical; demo federation drop-in re-applied"
[ "$(building_block_ids | wc -l)" = 1 ] || die "expected exactly one BuildingBlock after the rerun"
python3 - "$EVID/25-canonical-state-before.json" "$EVID/25-canonical-state-after.json" <<'PY' || die "canonical identity/state changed across the rerun"
import json, sqlite3, sys
before_path, after_path = sys.argv[1:3]
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def ids(query):
    return sorted(r[0] for r in c.execute(query))
after = {
    "building_blocks": ids("select block_id from building_blocks"),
    "cloud_profiles": ids("select profile_id from cloud_profiles"),
    "placement_providers": ids("select id from placement_providers"),
}
json.dump(after, open(after_path, "w", encoding="utf-8"), indent=1)
before = json.load(open(before_path))
for key in ("building_blocks", "cloud_profiles", "placement_providers"):
    assert before[key] == after[key], (
        f"{key} id set changed across the rerun: {before[key]} -> {after[key]}"
    )
# minimum expected canonical inventory (not just "unchanged")
assert len(after["building_blocks"]) == 1, after["building_blocks"]
assert len(after["cloud_profiles"]) >= 1, after["cloud_profiles"]
assert len(after["placement_providers"]) >= 1, after["placement_providers"]
PY
assert_demo_container_set "post-rerun"
araf_image_digests > "$EVID/25-image-digests-after.txt"
araf_image_revisions > "$EVID/25-image-revisions-after.txt"
diff "$EVID/25-image-digests-before.txt" "$EVID/25-image-digests-after.txt" \
  || die "demo image digests changed across the rerun (silent image swap)"
diff "$EVID/25-image-revisions-before.txt" "$EVID/25-image-revisions-after.txt" \
  || die "demo image source revisions changed across the rerun (silent image swap)"
python3 - "$EVID/25-image-digests-after.txt" "$EVID/25-image-revisions-after.txt" \
  "$EVID/10-araf-production-tuple.txt" <<'PY' || die "demo images no longer match the pinned tuple after the rerun"
import sys
after = [line.strip() for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
revisions = [line.strip() for line in open(sys.argv[2], encoding="utf-8")]
pinned = {}
for line in open(sys.argv[3], encoding="utf-8"):
    if "=" in line:
        key, _, value = line.strip().partition("=")
        pinned[key] = value
expected = [
    pinned["ARAF_BFF_IMAGE_DIGEST"],
    pinned["ARAF_TENANT_CONSOLE_IMAGE_DIGEST"],
    pinned["ARAF_OPERATOR_CONSOLE_IMAGE_DIGEST"],
]
assert len(after) == len(expected) == len(revisions), (after, expected, revisions)
for observed, revision, digest in zip(after, revisions, expected):
    assert observed == digest or revision == pinned["ARAF_SOURCE_SHA"], (
        f"image identity drift after rerun: observed={observed} revision={revision} "
        f"expected_digest={digest} source={pinned['ARAF_SOURCE_SHA']}"
    )
PY
python3 - "$(cat /usr/local/share/o3k/release-manifest.json)" "$O3K_CAMPAIGN_VERSION" <<'PY' || die "release identity drifted across rerun"
import json, sys
m = json.loads(sys.argv[1])
assert m["version"].lstrip("v") == sys.argv[2].lstrip("v"), m["version"]
PY
[ "$(openstack image list -f json | python3 -c 'import json,sys; print(len([i for i in json.load(sys.stdin) if i["Name"]=="cirros-0.6.3"]))')" = 1 ] \
  || die "duplicate testlab image after rerun"
# Convergence of the workload id SET (not a magic count): the rerun must not
# lose, duplicate, or re-create servers. Canonical tombstones/orphan rows from
# the failed native creates of earlier phases are part of the baseline and must
# stay stable — a bare "count == 1" would either miss a duplicate or fail on
# truthful state.
openstack server list -f json > "$EVID/25-servers-after-rerun.json" \
  || die "cannot list servers after the rerun (cannot verify convergence)"
python3 - "$EVID/25-servers-before-rerun.json" "$EVID/25-servers-after-rerun.json" <<'PY' || die "server id set changed across the rerun"
import json, sys
def ids(path):
    return sorted(server["ID"] for server in json.load(open(path, encoding="utf-8")))
def names(path):
    return [server["Name"] for server in json.load(open(path, encoding="utf-8"))]
before, after = ids(sys.argv[1]), ids(sys.argv[2])
assert before == after, f"server id set changed across the rerun: {before} -> {after}"
assert any(name == "test-vm" for name in names(sys.argv[2])), "test-vm is missing after the rerun"
PY
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after rerun"
case_ok R2 "same-version rerun converges: identical BB/profile/provider id sets, pinned images, no duplicates"

# ---- failure/recovery matrix -------------------------------------------------------------
log "matrix: Araf restart while O3K healthy"
docker restart o3k-araf-demo-tenant-bff-1 o3k-araf-demo-operator-bff-1 >/dev/null 2>&1 \
  || docker restart "$(docker ps -q --filter name=tenant-bff)" "$(docker ps -q --filter name=operator-bff)" >/dev/null
for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1 && curl -sf http://127.0.0.1:8081/readyz >/dev/null 2>&1 && break
  sleep 2
done
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd unhealthy during Araf restart"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after Araf restart"
case_ok F1 "Araf restart: bounded recovery, O3K unaffected, sessions per architecture"

log "matrix: o3kd restart while Araf running"
systemctl restart o3kd
for i in $(seq 1 90); do curl -sf http://127.0.0.1:18080/readyz >/dev/null 2>&1 && break; sleep 2; done
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd did not recover"
for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:8080/readyz >/dev/null 2>&1 && curl -sf http://127.0.0.1:8081/readyz >/dev/null 2>&1 && break
  sleep 2
done
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after o3kd restart"
case_ok F2 "o3kd restart: Araf recovers against canonical authority"

log "matrix: Araf dependency outage (demo IdP down)"
# (a) Establish the tenant session BEFORE the IdP goes away: the meaningful
#     claim is that an already-authenticated session keeps serving canonical
#     truth while the identity provider is unreachable.
araf_login tenant
bff_post /api/v1/auth/scope "{\"project_id\":\"${ADMIN_PROJECT_ID}\"}" >/dev/null
bff_get /api/v1/auth/session > "$EVID/23c-session-before-outage.json"
docker stop o3k-araf-demo-idp-1 >/dev/null
sleep 5
docker inspect -f '{{.State.Status}}' o3k-araf-demo-idp-1 > "$EVID/23c-idp-state-outage.txt"
[ "$(cat "$EVID/23c-idp-state-outage.txt")" != running ] || die "demo IdP did not stop"
# (b) O3K stays independent; the console still serves; the pre-established
#     session still reads canonical resources (native tokens, no IdP).
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd must stay ready when the demo IdP is down"
CONSOLE_STATUS="$(pcurl_status https://tenant.o3k.demo/)"
printf 'tenant_console_status_during_idp_outage=%s\n' "$CONSOLE_STATUS" > "$EVID/23c-console-status-outage.txt"
[ "$CONSOLE_STATUS" = 200 ] || die "tenant console did not serve during the IdP outage (status $CONSOLE_STATUS)"
bff_get /api/v1/resources/compute.server > "$EVID/23c-resources-during-outage.json" \
  || die "BFF lost canonical reads during the IdP outage"
python3 - "$EVID/23c-resources-during-outage.json" <<'PY' || die "canonical read during the IdP outage was not a resource collection"
import json, sys
d = json.load(open(sys.argv[1]))
assert isinstance(d.get("items"), list), d
PY
# (c) A NEW login must fail closed. Check the exact HTTP status of a plain
#     curl (no `curl -f`): the BFF returns 401 when it cannot reach the IdP;
#     if it still redirects, the IdP hop itself must answer 5xx. Any 2xx/3xx
#     back to the console would be a fabricated login.
LOGIN_WORK="$(mktemp -d)"
NEW_LOGIN_STATUS="$(curl -s --cacert "$DEMO_CA" -D "$LOGIN_WORK/headers" -o "$LOGIN_WORK/body" \
  -c "$LOGIN_WORK/jar" -w '%{http_code}' https://tenant.o3k.demo/api/v1/auth/login)"
cp "$LOGIN_WORK/body" "$EVID/23c-new-login-body.json" 2>/dev/null || true
NEW_LOGIN_LOCATION="$(sed -n 's/^[Ll]ocation: //p' "$LOGIN_WORK/headers" | tr -d '\r' | head -1)"
printf 'new_login_status=%s\nnew_login_location=%s\n' "$NEW_LOGIN_STATUS" "$NEW_LOGIN_LOCATION" \
  > "$EVID/23c-new-login-status.txt"
grep -q 'araf_tenant_session' "$LOGIN_WORK/jar" \
  && { rm -rf "$LOGIN_WORK"; die "a session cookie was issued while the IdP is down (fabricated login)"; }
rm -rf "$LOGIN_WORK"
case "$NEW_LOGIN_STATUS" in
  401)
    ;;
  502|503)
    ;;
  30*)
    [ -n "$NEW_LOGIN_LOCATION" ] || die "login redirected without a Location during the IdP outage"
    IDP_HOP_STATUS="$(curl -s --cacert "$DEMO_CA" -o /dev/null -w '%{http_code}' "$NEW_LOGIN_LOCATION")"
    printf 'idp_authorize_hop_status=%s\n' "$IDP_HOP_STATUS" >> "$EVID/23c-new-login-status.txt"
    case "$IDP_HOP_STATUS" in
      502|503) ;;
      *) die "the IdP authorize hop answered $IDP_HOP_STATUS during the outage (login not failed closed)" ;;
    esac
    ;;
  *)
    die "unexpected status $NEW_LOGIN_STATUS for a new login during the IdP outage (want 401, or 5xx with the IdP hop failing)"
    ;;
esac
docker start o3k-araf-demo-idp-1 >/dev/null 2>&1 || docker start "$(docker ps -aq --filter name=o3k-araf-demo-idp)" >/dev/null
for i in $(seq 1 120); do
  curl -sf --cacert "$DEMO_CA" https://idp.o3k.demo/demo-healthz >/dev/null 2>&1 && break
  sleep 3
done
curl -sf --cacert "$DEMO_CA" https://idp.o3k.demo/demo-healthz >/dev/null \
  || die "IdP did not recover"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after IdP recovery"
case_ok F3 "IdP outage: O3K independent, console serves, pre-established session reads truth, new login fails closed, full recovery"

log "matrix: interrupted Araf deployment (kill -9 mid-install after purge)"
bash "$DEMO" purge --yes > "$EVID/26-interrupt-purge.log" 2>&1 || die "pre-interrupt purge failed"
bash "$DEMO" install > "$EVID/26-interrupted-install.log" 2>&1 &
INSTALL_PID=$!
sleep 20
kill -9 "$INSTALL_PID" 2>/dev/null || true
pkill -9 -f 'docker (pull|load)' 2>/dev/null || true
sleep 2
docker ps -a --format '{{.Names}} {{.Status}}' > "$EVID/26-interrupted-containers.txt" || true
log "interrupted; re-running install for convergence"
bash "$DEMO" install > "$EVID/26-interrupt-rerun.log" 2>&1 || die "install did not converge after interruption"
bash "$DEMO" verify > "$EVID/26-interrupt-verify.log" 2>&1 || die "verify failed after interrupted deployment recovery"
grep -q 'verify: PASS' "$EVID/26-interrupt-verify.log" || die "interrupted-deployment recovery verify did not report PASS"
# The rerun must have produced the complete stack, not merely found a marker
# file from the interrupted run: the whole compose set is up and every layer
# reports healthy.
assert_demo_container_set "interrupted-deployment recovery"
docker ps --format '{{.Names}} {{.Status}}' | grep '^o3k-araf-demo-' | sort \
  > "$EVID/26-interrupt-rerun-containers.txt"
bash "$DEMO" status > "$EVID/26-interrupt-status.txt" 2>&1 || true
grep -q 'NOT-READY' "$EVID/26-interrupt-status.txt" && die "a layer is NOT-READY after interrupted-deployment recovery"
grep -Eq ' (down|degraded)$' "$EVID/26-interrupt-status.txt" && die "a layer is down/degraded after interrupted-deployment recovery"
assert_demo_federation present "after interrupted-deployment recovery"
assert_o3kd_env_unchanged "after interrupted-deployment recovery"
case_ok F4 "interrupted deployment: rerun rebuilt the full 7-container stack, federation drop-in re-applied, all layers healthy, verify PASS"

# ---- cleanup: uninstall/reinstall, purge/reinstall, foreign canaries -----------------------
# The uninstall assertions are about the DEMO-OWNED federation wiring, never
# about a block inside O3K's own env file (that file must stay byte-identical
# through every cycle — see assert_o3kd_env_unchanged).
assert_o3kd_env_unchanged "before uninstall"
assert_demo_federation present "before uninstall"
log "cleanup: uninstall (state preserved)"
bash "$DEMO" uninstall --yes > "$EVID/27-uninstall.log" 2>&1 || die "uninstall failed"
DOCKER_PS_OUT="$(docker ps --format '{{.Names}}')"
! grep -q 'o3k-araf-demo' <<<"$DOCKER_PS_OUT" || die "demo containers remain after uninstall"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd unhealthy after demo uninstall"
[ -d /var/lib/o3k/araf-demo ] || die "uninstall must preserve the state dir"
[ "$(openstack server show test-vm -c status -f value)" = ACTIVE ] || die "O3K workload broken by demo uninstall"
assert_demo_federation absent "after uninstall"
assert_o3kd_env_unchanged "after uninstall"
CURRENT_CASE=C1 CURRENT_NAME="uninstall: demo runtime + federation drop-in removed, O3K config untouched, state preserved" \
  case_ok C1 "uninstall: demo runtime removed, demo federation env + systemd drop-in gone, O3K + workload untouched, /etc/o3k/o3kd.env byte-identical, state preserved"

log "cleanup: reinstall (convergent)"
bash "$DEMO" install > "$EVID/27-reinstall.log" 2>&1 || die "reinstall after uninstall failed"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after reinstall"
assert_demo_federation present "after reinstall"
assert_o3kd_env_unchanged "after reinstall"
CURRENT_CASE=C2 CURRENT_NAME="reinstall after uninstall converges" \
  case_ok C2 "reinstall after uninstall converges (federation drop-in re-applied, O3K config untouched)"

log "cleanup: purge (all owned demo state removed)"
bash "$DEMO" purge --yes > "$EVID/28-purge.log" 2>&1 || die "purge failed"
DOCKER_PSA_OUT="$(docker ps -a --format '{{.Names}}')"
! grep -q 'o3k-araf-demo' <<<"$DOCKER_PSA_OUT" || die "demo containers remain after purge"
DOCKER_VOL_OUT="$(docker volume ls --format '{{.Name}}')"
! grep -q '^o3k-araf-demo_' <<<"$DOCKER_VOL_OUT" || die "demo volumes remain after purge"
[ ! -e /var/lib/o3k/araf-demo ] || die "state dir remains after purge"
! grep -q 'o3k.demo' /etc/hosts || die "demo hosts entries remain after purge"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd unhealthy after purge"
assert_demo_federation absent "after purge"
assert_o3kd_env_unchanged "after purge"
CURRENT_CASE=C3 CURRENT_NAME="purge: all owned demo state removed" \
  case_ok C3 "purge: all owned demo state removed (containers, volumes, hosts, state dir, federation env + drop-in)"

log "cleanup: purge-reinstall (full recovery)"
bash "$DEMO" install > "$EVID/28-purge-reinstall.log" 2>&1 || die "install after purge failed"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after purge-reinstall"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd not ready at campaign end"
assert_demo_federation present "after purge-reinstall"
assert_o3kd_env_unchanged "after purge-reinstall"
assert_demo_container_set "purge-reinstall"
# `o3k doctor` exits 1 for an advisory "warning" verdict (the installer
# tolerates rc<=1); only rc>=2 means doctor could not produce a report.
doctor_rc=0
o3k doctor --json > "$EVID/29-doctor-final.json" 2>/dev/null || doctor_rc=$?
[ "$doctor_rc" -le 1 ] \
  || die "o3k doctor --json could not produce a report at campaign end (rc $doctor_rc)"
python3 - "$EVID/29-doctor-final.json" <<'PY' || die "o3k doctor --json produced no valid JSON report"
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
assert raw.strip(), "doctor output is empty"
doc = json.loads(raw)
assert isinstance(doc, dict) and "checks" in doc, doc.keys()
assert doc.get("version"), "doctor report carries no version"
assert isinstance(doc["checks"], list) and doc["checks"], "doctor report carries no checks"
PY
case_ok C4 "purge-reinstall: demo fully recovered"
case_ok C7 "final o3k doctor --json report is non-empty valid JSON with checks"
CURRENT_CASE=C8 CURRENT_NAME="O3K config-file ledger converges across uninstall/reinstall/purge cycles" \
  case_ok C8 "/etc/o3k/o3kd.env sha256 identical to the install-ledger baseline across uninstall -> reinstall -> purge cycles (evidence 27b-o3k-o3kd-env-ledger-convergence.txt; the config-ledger regression stays fixed)"

# ---- foreign canaries + final scans --------------------------------------------------------
{
  echo "file-opt: $(sha256sum /opt/o3k-foreign/canary.txt | awk '{print $1}')"
  echo "file-etc: $(sha256sum /etc/o3k-foreign/canary.txt | awk '{print $1}')"
  echo "user: $(grep '^foreigncanary:' /etc/passwd | sha256sum | awk '{print $1}')"
} > "$EVID/31-foreign-canaries-after.txt"
diff "$EVID/09-foreign-canaries-before.txt" "$EVID/31-foreign-canaries-after.txt" \
  || die "foreign canaries changed during the campaign"
case_ok C5 "foreign state preserved (files, user) — no blanket prune"

FAIL=0
for f in "$EVID/25-rerun-install.log" "$EVID/26-interrupted-install.log" "$EVID/26-interrupt-rerun.log" "$EVID/27-reinstall.log" "$EVID/28-purge-reinstall.log"; do
  if [ ! -f "$f" ]; then
    log "SECRET SCAN TARGET MISSING: $f"
    FAIL=1
    continue
  fi
  secret_scan_file "$f" || { log "SECRET SCAN HIT: $f"; FAIL=1; }
done > "$EVID/32-secret-scan-phase2.txt" 2>&1
[ "$FAIL" -eq 0 ] || die "secret scan hits or missing scan targets in phase2 logs"
case_ok C6 "phase2 secret scans clean"

pp4_phase_complete
log "PHASE2-COMPLETE status=passed"
echo "PHASE2-COMPLETE status=passed" > "$EVID/phase2-done"
