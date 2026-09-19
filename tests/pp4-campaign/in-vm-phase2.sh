#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 2 (runs after the host reboot + browser relogin):
#   recovery asserts -> same-version one-liner rerun convergence ->
#   failure/recovery matrix (Araf restart, o3kd restart, IdP outage,
#   interrupted Araf deployment) -> uninstall/reinstall -> purge/reinstall ->
#   foreign canaries + final secret scans.
#
# Usage: sudo bash in-vm-phase2.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/pp4-evidence}"
SOURCE_SHA="${3:-unknown}"
source /home/tester/pp4-campaign/in-vm-lib.sh
DEMO=/usr/local/share/o3k/araf-demo/o3k-araf-demo.sh
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc
BB_ID_BEFORE="$(python3 -c 'import sqlite3; print(sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True).execute("select id from building_blocks limit 1").fetchone()[0])')"

# ---- post-reboot recovery -------------------------------------------------------------
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd not ready after reboot"
curl -sf http://127.0.0.1:9100/readyz >/dev/null || die "o3k-compute not ready after reboot"
bash "$DEMO" status > "$EVID/22-status-post-reboot.txt" 2>&1 || true
for n in idp tenant-bff operator-bff tenant-console operator-console tls-proxy api-relay; do
  docker ps --format '{{.Names}} {{.Status}}' | grep -E "(^|-)${n}\s" | grep -q Up \
    || die "demo container not up after reboot: $n"
done
[ "$(openstack server show test-vm -c status -f value)" = ACTIVE ] || die "test-vm not ACTIVE after reboot"
bash "$DEMO" verify > "$EVID/24-verify-post-reboot.log" 2>&1 || die "post-reboot verify failed"
case_ok R1 "post-reboot recovery: O3K + Araf + workload healthy"

# ---- same-version rerun convergence ----------------------------------------------------
docker ps --format '{{.Names}}' | sort > "$EVID/25-containers-before-rerun.txt"
cp /var/lib/o3k/install-timestamps.env "$EVID/25-timestamps-before-rerun.env"
ONELINER="curl -sfL https://github.com/o3kio/o3k/releases/download/${O3K_CAMPAIGN_VERSION:?}/install.sh | sudo sh -"
log "re-running the one-liner for convergence: $ONELINER"
if eval "$ONELINER" > "$EVID/25-rerun-install.log" 2>&1; then
  log "rerun exit 0"
else
  tail -50 "$EVID/25-rerun-install.log" >&2
  die "one-liner rerun failed"
fi
grep -q 'O3K demo ready' "$EVID/25-rerun-install.log" || die "rerun success output missing"
BB_ID_AFTER="$(python3 -c 'import sqlite3; print(sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True).execute("select id from building_blocks limit 1").fetchone()[0])')"
[ "$BB_ID_BEFORE" = "$BB_ID_AFTER" ] || die "BuildingBlock identity changed across rerun ($BB_ID_BEFORE -> $BB_ID_AFTER)"
python3 - <<'PY' > "$EVID/25-rerun-dupes.txt" || die "duplicate canonical state after rerun"
import sqlite3
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
tables = [r[0] for r in c.execute("select name from sqlite_master where type='table'")]
counts = {}
for t in tables:
    if any(k in t for k in ("building_block", "agent", "provider", "profile")):
        try:
            counts[t] = c.execute(f"select count(*) from {t}").fetchone()[0]
        except Exception:
            pass
print(counts)
assert counts.get("building_blocks") == 1, counts
bad = {k: v for k, v in counts.items() if k != "building_blocks" and v > 1 and "history" not in k and "audit" not in k and "event" not in k}
assert not bad, bad
PY
docker ps --format '{{.Names}}' | sort > "$EVID/25-containers-after-rerun.txt"
sort "$EVID/25-containers-before-rerun.txt" | uniq -d > "$EVID/25-container-dupes.txt"
[ ! -s "$EVID/25-container-dupes.txt" ] || die "duplicate container names after rerun"
diff "$EVID/25-containers-before-rerun.txt" "$EVID/25-containers-after-rerun.txt" \
  || die "container set changed across rerun"
python3 - "$(cat /usr/local/share/o3k/release-manifest.json)" <<'PY' || die "release identity drifted across rerun"
import json, sys
m = json.loads(sys.argv[1])
assert m["version"].lstrip("v") == "$O3K_CAMPAIGN_VERSION".lstrip("v"), m["version"]
PY
[ "$(openstack image list -f json | python3 -c 'import json,sys; print(len([i for i in json.load(sys.stdin) if i["Name"]=="cirros-0.6.3"]))')" = 1 ] \
  || die "duplicate testlab image after rerun"
[ "$(openstack server list -f json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" = 1 ] \
  || die "duplicate servers after rerun"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after rerun"
case_ok R2 "same-version rerun converges: same BuildingBlock, no duplicates, same tuple"

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
docker stop o3k-araf-demo-idp-1 >/dev/null 2>&1 || docker stop "$(docker ps -q --filter name=o3k-araf-demo-idp)" >/dev/null
sleep 5
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd must stay ready when the demo IdP is down"
curl -sf --cacert /var/lib/o3k/araf-demo/tls/ca.crt https://tenant.o3k.demo/ >/dev/null || die "tenant console down during IdP outage"
# authenticated resource reads still serve canonical truth (native tokens, no IdP)
araf_login tenant
bff_post /api/v1/auth/scope "{\"project_id\":\"eba29e2d-53de-461d-ae91-ede7402713cb\"}" >/dev/null
bff_get /api/v1/resources/compute.server > /dev/null || die "BFF lost canonical reads during IdP outage"
# a NEW login must fail truthfully (no silent success, no fixture fallback)
if pcurl -o /dev/null "https://tenant.o3k.demo/api/v1/auth/login" 2>/dev/null; then
  die "new OIDC login succeeded while IdP is down (fabricated success?)"
fi
docker start o3k-araf-demo-idp-1 >/dev/null 2>&1 || docker start "$(docker ps -aq --filter name=o3k-araf-demo-idp)" >/dev/null
for i in $(seq 1 120); do
  curl -sf --cacert /var/lib/o3k/araf-demo/tls/ca.crt https://idp.o3k.demo/demo-healthz >/dev/null 2>&1 && break
  sleep 3
done
curl -sf --cacert /var/lib/o3k/araf-demo/tls/ca.crt https://idp.o3k.demo/demo-healthz >/dev/null \
  || die "IdP did not recover"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after IdP recovery"
case_ok F3 "IdP outage: O3K independent, reads truthful, new login fails closed, full recovery"

log "matrix: interrupted Araf deployment (kill -9 mid-install after purge)"
bash "$DEMO" purge --yes > "$EVID/26-interrupt-purge.log" 2>&1 || die "pre-interrupt purge failed"
bash "$DEMO" install > "$EVID/26-interrupted-install.log" 2>&1 &
INSTALL_PID=$!
sleep 20
kill -9 "$INSTALL_PID" 2>/dev/null || true
pkill -9 -f 'docker (pull|load)' 2>/dev/null || true
sleep 2
log "interrupted; re-running install for convergence"
bash "$DEMO" install > "$EVID/26-interrupt-rerun.log" 2>&1 || die "install did not converge after interruption"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after interrupted deployment recovery"
docker ps --format '{{.Names}}' | grep -c 'o3k-araf-demo' | tee -a "$EVID/26-interrupt-rerun.log"
case_ok F4 "interrupted deployment: rerun converges, no fixture fallback, canonical state intact"

# ---- cleanup: uninstall/reinstall, purge/reinstall, foreign canaries -----------------------
log "cleanup: uninstall (state preserved)"
bash "$DEMO" uninstall --yes > "$EVID/27-uninstall.log" 2>&1 || die "uninstall failed"
! docker ps --format '{{.Names}}' | grep -q 'o3k-araf-demo' || die "demo containers remain after uninstall"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd unhealthy after demo uninstall"
[ -d /var/lib/o3k/araf-demo ] || die "uninstall must preserve the state dir"
[ "$(openstack server show test-vm -c status -f value)" = ACTIVE ] || die "O3K workload broken by demo uninstall"
grep -q 'O3K_OIDC_TRUST_ID' /etc/o3k/o3kd.env && die "federation block survived uninstall"
case_ok C1 "uninstall: demo runtime removed, O3K + workload untouched, state preserved"

log "cleanup: reinstall (convergent)"
bash "$DEMO" install > "$EVID/27-reinstall.log" 2>&1 || die "reinstall after uninstall failed"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after reinstall"
case_ok C2 "reinstall after uninstall converges"

log "cleanup: purge (all owned demo state removed)"
bash "$DEMO" purge --yes > "$EVID/28-purge.log" 2>&1 || die "purge failed"
! docker ps -a --format '{{.Names}}' | grep -q 'o3k-araf-demo' || die "demo containers remain after purge"
! docker volume ls --format '{{.Name}}' | grep -q '^o3k-araf-demo_' || die "demo volumes remain after purge"
[ ! -e /var/lib/o3k/araf-demo ] || die "state dir remains after purge"
! grep -q 'o3k.demo' /etc/hosts || die "demo hosts entries remain after purge"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd unhealthy after purge"
case_ok C3 "purge: all owned demo state removed (containers, volumes, hosts, state dir)"

log "cleanup: purge-reinstall (full recovery)"
bash "$DEMO" install > "$EVID/28-purge-reinstall.log" 2>&1 || die "install after purge failed"
bash "$DEMO" verify > /dev/null 2>&1 || die "verify failed after purge-reinstall"
curl -sf http://127.0.0.1:18080/readyz >/dev/null || die "o3kd not ready at campaign end"
o3k doctor --json > "$EVID/29-doctor-final.json" 2>/dev/null || true
case_ok C4 "purge-reinstall: demo fully recovered"

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
  [ -f "$f" ] || continue
  secret_scan_file "$f" || { log "SECRET SCAN HIT: $f"; FAIL=1; }
done > "$EVID/32-secret-scan-phase2.txt" 2>&1
[ "$FAIL" -eq 0 ] || die "secret scan hits in phase2 logs"
case_ok C6 "phase2 secret scans clean"

log "PHASE2-COMPLETE status=passed"
echo "PHASE2-COMPLETE status=passed" > "$EVID/phase2-done"
