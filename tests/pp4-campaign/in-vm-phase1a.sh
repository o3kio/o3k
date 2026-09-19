#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 1a: foreign canaries -> exact public one-liner ->
# success output + timing stamps -> canonical state -> guest boot proof ->
# curl OIDC verify. Ends by writing the phase1a-done marker (host-run polls).
#
# Usage: sudo bash in-vm-phase1a.sh <ubuntu|debian> <evidence-dir> <source-sha>
set -Eeuo pipefail
DISTRO="${1:-ubuntu}"
EVID="${2:-/tmp/pp4-evidence}"
SOURCE_SHA="${3:-unknown}"
mkdir -p "$EVID"
cd /
# shellcheck source=tests/pp4-campaign/in-vm-lib.sh
source /home/tester/pp4-campaign/in-vm-lib.sh
: > "$EVID/cases.jsonl"

ONELINER="curl -sfL https://github.com/o3kio/o3k/releases/download/${O3K_CAMPAIGN_VERSION:?}/install.sh | sudo sh -"

# ---- host inventory (evidence 00) --------------------------------------------------
{
  echo "distro: $DISTRO"
  cat /etc/os-release
  uname -a
  echo "source_sha: $SOURCE_SHA"
  echo "installer: $ONELINER"
  echo "boot_id: $(cat /proc/sys/kernel/random/boot_id)"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo)"
  echo "svm/vmx flag: $(grep -oE 'svm|vmx' /proc/cpuinfo | sort -u | tr '\n' ' ')"
  echo "kvm device: $(ls -l /dev/kvm 2>&1)"
  free -m
  nproc
  date -u +%FT%TZ
} > "$EVID/00-host-inventory.txt"
case_ok I1 "host inventory captured (OS/kernel/KVM)"

# ---- foreign canaries (checked again after all cleanup in phase2) -------------------
mkdir -p /opt/o3k-foreign /etc/o3k-foreign
printf 'pp4-foreign-canary\n' > /opt/o3k-foreign/canary.txt
printf 'pp4-foreign-canary\n' > /etc/o3k-foreign/canary.txt
id -u foreigncanary >/dev/null 2>&1 || useradd --system --no-create-home foreigncanary
{
  echo "file-opt: $(sha256sum /opt/o3k-foreign/canary.txt | awk '{print $1}')"
  echo "file-etc: $(sha256sum /etc/o3k-foreign/canary.txt | awk '{print $1}')"
  echo "user: $(grep '^foreigncanary:' /etc/passwd | sha256sum | awk '{print $1}')"
} > "$EVID/09-foreign-canaries-before.txt"
if id o3k &>/dev/null || id o3k-compute &>/dev/null; then
  die "pre-check: o3k accounts already exist"
fi
[ ! -e /etc/o3k ] || die "pre-check: /etc/o3k already exists"
case_ok I2 "pre-checks + foreign canaries planted"

# ---- the exact public one-liner (evidence 01) ---------------------------------------
log "running: $ONELINER"
set +e
eval "$ONELINER" 2>&1 | tee "$EVID/01-one-line-install.log"
INSTALL_RC=${PIPESTATUS[0]}
set -e
[ "$INSTALL_RC" -eq 0 ] || die "one-liner exited $INSTALL_RC"
case_ok I3 "one-line installer exit 0 (public release asset $O3K_CAMPAIGN_VERSION)"

# ---- success output (evidence 02) -----------------------------------------------------
grep -A40 'O3K demo ready' "$EVID/01-one-line-install.log" > "$EVID/02-success-output.txt" || true
for token in 'O3K demo ready' 'Tenant Console' 'Operator Console' 'O3K API' \
             'CLI configuration' 'OpenStack compatibility' 'credentials.txt' 'Uninstall'; do
  grep -q "$token" "$EVID/02-success-output.txt" || die "success output missing: $token"
done
case_ok I4 "success output complete (consoles, API, CLI config, uninstall)"

# no raw long-lived secret in the public output
if grep -Eiq 'BEGIN .*PRIVATE KEY|ALICE_PASSWORD=|bootstrap_secret=[a-f0-9]{16,}' "$EVID/01-one-line-install.log"; then
  die "secret material leaked into installer output"
fi
case_ok I5 "no secret material in installer output"

# ---- timing stamps (evidence 03) ------------------------------------------------------
[ -f /var/lib/o3k/install-timestamps.env ] || die "install-timestamps.env missing"
cp /var/lib/o3k/install-timestamps.env "$EVID/03-timestamps.env"
for t in T0 T1 T2 T3 T5; do
  grep -q "^$t=" "$EVID/03-timestamps.env" || die "timestamp $t missing"
done
python3 - "$EVID/03-timestamps.env" <<'PY' || exit 1
import sys
vals = {}
for line in open(sys.argv[1]):
    if "=" in line:
        k, v = line.strip().split("=", 1)
        # numeric epoch stamps only: the ledger also carries T3_ISO (UTC
        # ISO-8601 companion of T3), which is not an epoch integer
        if v.isdigit():
            vals[k] = int(v)
need = ["T0", "T1", "T2", "T3", "T5"]
assert all(k in vals for k in need), vals
PY
case_ok I6 "timing stamps T0-T3,T5 present"

# ---- verified release identity (evidence 06) ------------------------------------------
python3 - <<'PY' > "$EVID/06-release-identity.txt" || die "release identity check failed"
import json
m = json.load(open("/usr/local/share/o3k/release-manifest.json"))
print("installed_version:", m["version"])
print("installed_source_commit:", m["source_commit"])
assert m["version"].lstrip("v") == "$O3K_CAMPAIGN_VERSION".lstrip("v"), m["version"]
PY
case_ok I7 "installed release identity matches campaign version"

# ---- canonical durable state (read-only sqlite, evidence 07) ---------------------------
python3 - <<'PY' > "$EVID/07-canonical-state.txt" || die "canonical state check failed"
import sqlite3
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def one(q):
    return c.execute(q).fetchone()[0]
print("building_blocks_ready:", one("select count(*) from building_blocks where state='ready'"))
print("bootstrap_ready:", one("select count(*) from bootstrap_state where state='ready'"))
print("cloud_profiles:", one("select count(*) from cloud_profiles"))
print("agents:", one("select count(*) from agents"))
print("building_block_id:", one("select id from building_blocks limit 1"))
assert one("select count(*) from building_blocks where state='ready'") == 1
assert one("select count(*) from bootstrap_state where state='ready'") == 1
assert one("select count(*) from cloud_profiles") >= 1
PY
case_ok I8 "canonical state: exactly one ready BuildingBlock/bootstrap, >=1 profile"

# ---- demo IdP federation present ------------------------------------------------------
grep -q 'O3K_OIDC_TRUST_ID' /etc/o3k/o3kd.env || die "o3kd OIDC federation block missing"
case_ok I9 "o3kd OIDC federation enabled"

# ---- OpenStack CLI witness: test-vm truth (evidence 08) --------------------------------
export OS_CLOUD=admin 2>/dev/null || true
# shellcheck disable=SC1091
source /etc/o3k/admin-openrc
openstack token issue >/dev/null || die "openstack CLI token issue failed"
SRV_ID="$(openstack server list -f json | python3 -c 'import json,sys; print([s["ID"] for s in json.load(sys.stdin) if s["Name"]=="test-vm"][0])')"
[ -n "$SRV_ID" ] || die "test-vm not visible via OpenStack CLI"
openstack server show "$SRV_ID" -f json > "$EVID/08-openstack-test-vm.json"
python3 - "$EVID/08-openstack-test-vm.json" <<'PY' || exit 1
import json, sys
s = json.load(open(sys.argv[1]))
assert s["status"] == "ACTIVE", s["status"]
assert s["config_drive"] == "True", s["config_drive"]
PY
case_ok I10 "OpenStack CLI witness: test-vm ACTIVE with config-drive"

# ---- real guest boot proof (evidence 08b) -----------------------------------------------
virsh domstate "$SRV_ID" | grep -q running || virsh domstate test-vm 2>/dev/null | grep -q running \
  || die "no running libvirt domain for test-vm"
virsh list --all > "$EVID/08b-libvirt-domains.txt"
if timeout 120 bash -c "until openstack console log show $SRV_ID 2>/dev/null | grep -Eiq 'cirros|login:'; do sleep 5; done"; then
  openstack console log show "$SRV_ID" | tail -40 > "$EVID/08c-console.log"
else
  die "console boot marker (cirros|login:) not observed for test-vm"
fi
find /var/lib -maxdepth 4 -name '*.leases' -exec grep -h . {} \; 2>/dev/null | grep -E '192\.0\.2\.' > "$EVID/08d-dhcp-leases.txt" || true
[ -s "$EVID/08d-dhcp-leases.txt" ] || log "WARN: no DHCP lease file captured (console marker is the boot proof)"
case_ok I11 "guest boot proof: running libvirt domain + CirrOS console marker"

# ---- Araf container digests (evidence 12) -------------------------------------------------
DEMO=/usr/local/share/o3k/araf-demo/o3k-araf-demo.sh
[ -x "$DEMO" ] || die "demo script not installed to /usr/local/share/o3k/araf-demo"
docker ps --format '{{.Names}}' | sort > "$EVID/11-container-names.txt"
for n in idp tenant-bff operator-bff tenant-console operator-console tls-proxy api-relay; do
  grep -q "o3k-araf-demo-$n" "$EVID/11-container-names.txt" || grep -q "^${n}$" "$EVID/11-container-names.txt" \
    || die "demo container missing: $n"
done
case_ok I12 "Araf demo stack running (7 containers)"

# ---- curl OIDC verify (PP.3 path still green, evidence 04) ---------------------------------
bash "$DEMO" verify > "$EVID/04-verify.log" 2>&1 || die "o3k-araf-demo verify failed"
grep -q 'verify: PASS' "$EVID/04-verify.log" || die "verify PASS marker missing"
case_ok I13 "curl OIDC verify (tenant+operator) PASS"

log "PHASE1A-COMPLETE status=passed"
echo "PHASE1A-COMPLETE status=passed" > "$EVID/phase1a-done"
