#!/usr/bin/env bash
# PP.4 campaign — in-VM PHASE 1a: foreign canaries -> exact public one-liner ->
# success output + timing stamps -> canonical state -> demo capacity + O3K
# config-ledger integrity -> federation drop-in wiring -> guest boot proof ->
# curl OIDC verify -> deployed-production-tuple proof.
# Ends by writing the phase1a-done marker (host-run polls); a crash writes the
# same marker with status=failed so the host fails fast.
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
export PP4_PHASE=phase1a
pp4_install_phase_trap phase1a "$EVID/phase1a-done" PHASE1A
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
# The campaign version and source SHA are passed as argv (not interpolated into
# a quoted heredoc) and both must match the installed release manifest, so a
# stale/wrong campaign revision cannot be reported as accepted evidence.
python3 - "$O3K_CAMPAIGN_VERSION" "$SOURCE_SHA" "$EVID/06-release-identity.txt" <<'PY' || die "release identity check failed"
import json, sys
expected_version, expected_sha, out_path = sys.argv[1:4]
m = json.load(open("/usr/local/share/o3k/release-manifest.json"))
installed_version = m["version"]
installed_commit = m["source_commit"]
assert installed_version.lstrip("v") == expected_version.lstrip("v"), installed_version
if expected_sha not in ("", "unknown"):
    assert installed_commit == expected_sha, (
        f"installed source_commit {installed_commit} != campaign source SHA {expected_sha}"
    )
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(f"installed_version={installed_version}\n")
    handle.write(f"installed_source_commit={installed_commit}\n")
PY
case_ok I7 "installed release identity matches campaign version + source SHA"

# ---- canonical durable state (read-only sqlite, evidence 07) ---------------------------
python3 - "$EVID/07-canonical-state.txt" <<'PY' || die "canonical state check failed"
import sqlite3, sys
out_path = sys.argv[1]
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
def one(q):
    return c.execute(q).fetchone()[0]
ready_blocks = one("select count(*) from building_blocks where state='ready'")
ready_bootstrap = one("select count(*) from bootstrap_state where phase='ready'")
profiles = one("select count(*) from cloud_profiles")
providers = one("select count(*) from placement_providers")
block_id = one("select block_id from building_blocks order by block_id limit 1")
assert ready_blocks == 1, ready_blocks
assert ready_bootstrap == 1, ready_bootstrap
assert profiles >= 1, profiles
assert providers >= 1, providers
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(f"building_blocks_ready={ready_blocks}\n")
    handle.write(f"bootstrap_ready={ready_bootstrap}\n")
    handle.write(f"cloud_profiles={profiles}\n")
    handle.write(f"placement_providers={providers}\n")
    handle.write(f"building_block_id={block_id}\n")
PY
case_ok I8 "canonical state: exactly one ready BuildingBlock/bootstrap, >=1 profile+provider"

# ---- demo disk capacity: evidence, not assumption (evidence 12d) ------------------------
# The "a second VM fits" property of the packaged default must be measured, not
# assumed: the operator declaration in /etc/o3k/o3k-compute.env and the Placement
# DISK_GB inventory the agent published must both leave room for another VM (the
# TestLab flavor needs 10 GB; a 10 GB host total made the second create fail with
# Scheduler(NoValidHost) — found in this campaign).
python3 - "$EVID/12d-demo-disk-capacity.txt" <<'PY' || die "demo disk capacity check failed"
import sqlite3, sys
out_path = sys.argv[1]
# The packaged TestLab flavor (o3k-demo-v1) is a 10 GB disk; the campaign must
# still be able to schedule a second VM of that size after test-vm exists.
REQUIRED_FREE_GB = 10
declared = None
for line in open("/etc/o3k/o3k-compute.env", encoding="utf-8"):
    if line.startswith("O3K_COMPUTE_MAX_DISK_GB="):
        declared = line.split("=", 1)[1].strip()
assert declared, "O3K_COMPUTE_MAX_DISK_GB is not declared in /etc/o3k/o3k-compute.env"
declared = int(declared)
assert declared > 0, declared
c = sqlite3.connect("file:/var/lib/o3k/o3k.sqlite?mode=ro", uri=True)
rows = list(c.execute(
    "select provider_id, resource_class, total, reserved, allocation_ratio, used "
    "from placement_inventories where resource_class = 'DISK_GB' order by provider_id"))
assert rows, "no DISK_GB inventory row was published"
lines = [f"declared_max_disk_gb={declared}", f"required_free_disk_gb={REQUIRED_FREE_GB}"]
free = 0
for provider_id, resource_class, total, reserved, ratio, used in rows:
    # free = total - reserved - used (the allocation ratio is a scheduling
    # multiplier, never a licence to overcommit a bounded declaration)
    row_free = int(total) - int(reserved) - int(used)
    free = max(free, row_free)
    lines.append(
        f"provider={provider_id} resource_class={resource_class} total={total} "
        f"reserved={reserved} allocation_ratio={ratio} used={used} free={row_free}")
lines.append(f"max_free_disk_gb={free}")
lines.append(f"second_vm_fits={'yes' if free >= REQUIRED_FREE_GB else 'no'}")
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
for row in rows:
    assert int(row[2]) == declared, (
        f"Placement DISK_GB total {row[2]} does not equal the declared O3K_COMPUTE_MAX_DISK_GB {declared}")
assert free >= REQUIRED_FREE_GB, (
    f"Placement DISK_GB free {free} cannot schedule another {REQUIRED_FREE_GB} GB VM")
assert declared >= 2 * REQUIRED_FREE_GB, (
    f"declared O3K_COMPUTE_MAX_DISK_GB={declared} leaves no headroom for the TestLab VM "
    f"plus a second {REQUIRED_FREE_GB} GB VM")
PY
case_ok I17 "demo capacity evidence: O3K_COMPUTE_MAX_DISK_GB matches the Placement DISK_GB inventory and still fits a second 10 GB VM"

# ---- O3K config-file ledger: the demo must not mutate O3K-owned config (12b) ------------
# /etc/o3k/o3kd.env is O3K-install-owned: install.sh records its digest in
# /etc/o3k/.o3k-config-files and refuses to re-run when the bytes changed. The
# demo federation used to be appended to that file (PP.3); the PP.4 mechanism
# keeps it in its own drop-in. This records the post-install digest and proves it
# still equals the installer-recorded ledger value — i.e. the demo stage (T3,
# which runs after the ledger is written at T2) did not touch it.
python3 - "$EVID/12b-o3k-o3kd-env-ledger.txt" <<'PY' || die "O3K config-file ledger check failed"
import hashlib, sys
target = "o3kd.env"
path = f"/etc/o3k/{target}"
ledger = "/etc/o3k/.o3k-config-files"
recorded = None
for line in open(ledger, encoding="utf-8"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 3 and parts[0] == "o3k-config-file-v1" and parts[1] == target:
        recorded = parts[2]
assert recorded, f"{ledger} records no digest for {target}"
actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
assert actual == recorded, (
    f"{path} no longer matches the installer-recorded digest "
    f"(current {actual}, ledger {recorded}): something outside the O3K install modified it")
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(f"o3kd_env_path={path}\n")
    handle.write(f"o3kd_env_sha256_after_install={actual}\n")
    handle.write(f"o3kd_env_ledger_recorded_sha256={recorded}\n")
    handle.write("o3kd_env_ledger_match=yes\n")
PY
case_ok I15 "/etc/o3k/o3kd.env matches the O3K install-time content ledger (the demo stage did not mutate an O3K-owned config file)"

# ---- demo IdP federation wiring (verified mechanism, evidence 12c) ----------------------
# VERIFIED: the demo OIDC federation is NOT stored in /etc/o3k/o3kd.env (see I15).
# It lives in the demo-owned 0600 env file pulled in by a systemd drop-in that
# O3K's unit does not own.
DEMO_FED_ENV=/etc/o3k/o3kd-araf-demo.env
DEMO_FED_DROPIN=/etc/systemd/system/o3kd.service.d/araf-demo.conf
{
  echo "demo_federation_env=${DEMO_FED_ENV}"
  echo "demo_federation_env_exists=$([ -f "$DEMO_FED_ENV" ] && echo yes || echo no)"
  echo "demo_federation_env_mode=$(stat -c %a "$DEMO_FED_ENV" 2>/dev/null || echo missing)"
  echo "demo_federation_env_trust_id_lines=$(grep -c '^O3K_OIDC_TRUST_ID=' "$DEMO_FED_ENV" 2>/dev/null || echo 0)"
  echo "demo_federation_dropin=${DEMO_FED_DROPIN}"
  echo "demo_federation_dropin_exists=$([ -f "$DEMO_FED_DROPIN" ] && echo yes || echo no)"
  echo "demo_federation_dropin_environmentfile_lines=$(grep -c "EnvironmentFile=-${DEMO_FED_ENV}" "$DEMO_FED_DROPIN" 2>/dev/null || echo 0)"
  echo "o3kd_env_federation_lines=$(grep -c 'O3K_OIDC_TRUST_ID' /etc/o3k/o3kd.env 2>/dev/null || echo 0)"
  echo "systemctl_cat_dropin_lines=$(systemctl cat o3kd 2>/dev/null | grep -c 'o3kd.service.d/araf-demo.conf' || echo 0)"
  echo "systemctl_cat_environmentfile_lines=$(systemctl cat o3kd 2>/dev/null | grep -c "EnvironmentFile=-${DEMO_FED_ENV}" || echo 0)"
} > "$EVID/12c-demo-federation-wiring.txt"
[ -f "$DEMO_FED_ENV" ] || die "demo federation env file missing: $DEMO_FED_ENV"
[ "$(stat -c %a "$DEMO_FED_ENV")" = 600 ] || die "demo federation env file mode is not 0600: $DEMO_FED_ENV"
grep -q '^O3K_OIDC_TRUST_ID=' "$DEMO_FED_ENV" || die "demo federation env file carries no O3K_OIDC_TRUST_ID"
[ -f "$DEMO_FED_DROPIN" ] || die "demo federation drop-in missing: $DEMO_FED_DROPIN"
grep -q "EnvironmentFile=-${DEMO_FED_ENV}" "$DEMO_FED_DROPIN" || die "drop-in does not pull in $DEMO_FED_ENV"
# NOTE: no `cmd | grep -q` here — pipefail turns grep -q's early exit into a
# SIGPIPE failure of the producer (flaky); capture first, then match.
SYSTEMD_CAT_OUT="$(systemctl cat o3kd 2>/dev/null)" || true
grep -q 'o3kd.service.d/araf-demo.conf' <<<"$SYSTEMD_CAT_OUT" \
  || die "systemctl cat o3kd does not show the demo drop-in applied"
grep -q "EnvironmentFile=-${DEMO_FED_ENV}" <<<"$SYSTEMD_CAT_OUT" \
  || die "systemctl cat o3kd does not apply $DEMO_FED_ENV"
grep -q 'O3K_OIDC_TRUST_ID' /etc/o3k/o3kd.env \
  && die "the demo federation must not live in the O3K-owned /etc/o3k/o3kd.env"
case_ok I9 "o3kd OIDC federation wired via /etc/o3k/o3kd-araf-demo.env (0600) + systemd drop-in; O3K's o3kd.env untouched"

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
assert s["config_drive"] in (True, "True"), s["config_drive"]
PY
case_ok I10 "OpenStack CLI witness: test-vm ACTIVE with config-drive"

# ---- real guest boot proof (evidence 08b/08c/08d) --------------------------------------
# Asserted: a libvirt domain carrying this server's run ownership marker in its
# XML is running, plus the guest console boot marker. The DHCP lease capture is
# opportunistic diagnostic evidence only (dnsmasq lease files are not part of
# the supported contract), never a pass condition.
libvirt_domain_running_for "$SRV_ID" \
  || die "no running libvirt domain carrying server_id=$SRV_ID (managed_by=o3k-compute)"
virsh -c qemu:///system list --all > "$EVID/08b-libvirt-domains.txt"
{
  echo "server_id: $SRV_ID"
  echo "domain: $(libvirt_domain_name_for "$SRV_ID" || true)"
  echo "domstate: $(virsh -c qemu:///system domstate "$(libvirt_domain_name_for "$SRV_ID")" 2>&1)"
  echo "domain_xml_ownership:"
  virsh -c qemu:///system dumpxml "$(libvirt_domain_name_for "$SRV_ID")" 2>/dev/null \
    | grep -Eo 'server_id="[^"]*"|managed_by="[^"]*"' || true
} > "$EVID/08b2-libvirt-domain-ownership.txt"
if timeout 120 bash -c "until openstack console log show $SRV_ID 2>/dev/null | grep -Eiq 'cirros|login:'; do sleep 5; done"; then
  openstack console log show "$SRV_ID" | tail -40 > "$EVID/08c-console.log"
else
  die "console boot marker (cirros|login:) not observed for test-vm"
fi
find /var/lib -maxdepth 4 -name '*.leases' -exec grep -h . {} \; 2>/dev/null | grep -E '192\.0\.2\.' > "$EVID/08d-dhcp-leases.txt" || true
[ -s "$EVID/08d-dhcp-leases.txt" ] || log "WARN: no DHCP lease file captured (console marker is the boot proof)"
case_ok I11 "guest boot proof: running libvirt domain (server_id XML) + CirrOS console marker"

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

# ---- deployed Araf is the pinned production tuple (evidence 10) ----------------------------
# The browser/console claims are only meaningful if the deployment really runs
# the pinned production Araf tuple against the native O3K adapter (never the
# fixture adapter). Capture the deployment-side facts, not just the DOM.
docker inspect -f '{{.Config.Env}}' o3k-araf-demo-tenant-bff-1 \
  > "$EVID/10a-araf-tenant-bff-env.txt" || die "cannot inspect tenant-bff container env"
docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' \
  $(docker ps -q --filter label=com.docker.compose.project=o3k-araf-demo) \
  | sort > "$EVID/10c-araf-compose-services.txt" || die "cannot read compose service labels"
docker inspect -f '{{.Image}}' o3k-araf-demo-tenant-bff-1 o3k-araf-demo-tenant-console-1 \
  o3k-araf-demo-operator-console-1 > "$EVID/10b-araf-image-digests.txt" \
  || die "cannot read deployed image digests"
docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  o3k-araf-demo-tenant-bff-1 o3k-araf-demo-tenant-console-1 \
  o3k-araf-demo-operator-console-1 > "$EVID/10b-araf-image-revisions.txt" \
  || die "cannot read deployed image source revisions"
bash "$DEMO" tuple > "$EVID/10d-araf-tuple-reported.txt" 2>&1 || die "cannot read the pinned demo tuple"
python3 - "$DEMO" "$EVID/10a-araf-tenant-bff-env.txt" "$EVID/10b-araf-image-digests.txt" \
  "$EVID/10b-araf-image-revisions.txt" "$EVID/10c-araf-compose-services.txt" \
  "$EVID/10d-araf-tuple-reported.txt" \
  "$EVID/10-araf-production-tuple.txt" <<'PY' || die "deployed Araf is not the pinned production tuple"
import re, sys

demo_path, env_path, digests_path, revisions_path, services_path, reported_path, out_path = sys.argv[1:8]

demo = open(demo_path, encoding="utf-8").read()
pinned = dict(re.findall(r'^(ARAF_[A-Z0-9_]+)="?([^"\n]+)"?$', demo, re.M))

env = open(env_path, encoding="utf-8").read()
adapter = re.search(r'ARAF_UPSTREAM_ADAPTER=([^\s"]+)', env)
assert adapter, "tenant-bff has no ARAF_UPSTREAM_ADAPTER"
assert adapter.group(1) == "o3k", f"upstream adapter is {adapter.group(1)!r}, not the native o3k adapter"
profile = re.search(r'ARAF_RUNTIME_PROFILE=([^\s"]+)', env)
assert profile and profile.group(1) == "production", (
    f"runtime profile is {profile.group(1) if profile else None!r}, not production"
)
assert "fixture" not in env.lower(), "fixture-mode marker in the deployed tenant-bff environment"

# Observed image identity must equal the pinned config OR index digest of the
# matching component (docker stores either form depending on the image store).
observed = [line.strip() for line in open(digests_path, encoding="utf-8") if line.strip()]
revisions = [line.strip() for line in open(revisions_path, encoding="utf-8")]
components = [
    ("tenant-bff", "ARAF_BFF"),
    ("tenant-console", "ARAF_TENANT_CONSOLE"),
    ("operator-console", "ARAF_OPERATOR_CONSOLE"),
]
assert len(observed) == len(components), observed
assert len(revisions) == len(components), revisions
identity_kinds = []
for (name, prefix), digest, revision in zip(components, observed, revisions):
    allowed = {pinned.get(f"{prefix}_DIGEST"), pinned.get(f"{prefix}_CONFIG_DIGEST")}
    allowed.discard(None)
    assert allowed, f"no pinned digest constants for {prefix}"
    if digest in allowed:
        identity_kinds.append("digest")
    else:
        # Docker/containerd may re-materialize an OCI archive and expose a
        # local image ID that is neither the registry index nor config digest.
        # The archive config was verified before load; require the immutable
        # Araf source revision label as the second independent identity proof.
        assert revision == pinned.get("ARAF_SOURCE_SHA"), (
            f"{name} image {digest} is not pinned and has revision {revision!r}, "
            f"expected {pinned.get('ARAF_SOURCE_SHA')!r}"
        )
        identity_kinds.append("source-revision")

expected_services = {
    "idp", "tenant-bff", "operator-bff", "tenant-console",
    "operator-console", "tls-proxy", "api-relay",
}
observed_services = {line.strip() for line in open(services_path, encoding="utf-8") if line.strip()}
assert observed_services == expected_services, (
    f"compose service set mismatch: {sorted(observed_services)} != {sorted(expected_services)}"
)

reported = {}
for line in open(reported_path, encoding="utf-8"):
    if "=" in line:
        key, _, value = line.strip().partition("=")
        reported[key] = value
araf_version = reported.get("ARAF_VERSION") or pinned.get("ARAF_VERSION", "")
araf_sha = reported.get("ARAF_SOURCE_SHA") or pinned.get("ARAF_SOURCE_SHA", "")
assert araf_version, "cannot resolve the deployed Araf version"
assert araf_sha, "cannot resolve the deployed Araf source SHA"

with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(f"ARAF_VERSION={araf_version}\n")
    handle.write(f"ARAF_SOURCE_SHA={araf_sha}\n")
    handle.write(f"ARAF_UPSTREAM_ADAPTER={adapter.group(1)}\n")
    handle.write(f"ARAF_RUNTIME_PROFILE={profile.group(1)}\n")
    handle.write(f"ARAF_BFF_IMAGE_DIGEST={observed[0]}\n")
    handle.write(f"ARAF_TENANT_CONSOLE_IMAGE_DIGEST={observed[1]}\n")
    handle.write(f"ARAF_OPERATOR_CONSOLE_IMAGE_DIGEST={observed[2]}\n")
    handle.write(f"ARAF_BFF_IMAGE_REVISION={revisions[0]}\n")
    handle.write(f"ARAF_TENANT_CONSOLE_IMAGE_REVISION={revisions[1]}\n")
    handle.write(f"ARAF_OPERATOR_CONSOLE_IMAGE_REVISION={revisions[2]}\n")
    handle.write(f"ARAF_IMAGE_IDENTITY_KINDS={','.join(identity_kinds)}\n")
    handle.write(f"ARAF_COMPOSE_SERVICES={','.join(sorted(observed_services))}\n")
PY
case_ok I14 "deployed Araf is the pinned production tuple (native o3k adapter, pinned digests, 7 services)"

# ---- O3K config-file ledger unchanged after the whole demo stage (evidence 12b2) ----------
# Companion to I15: the demo stage, the curl OIDC verify and every demo
# interaction above must have left O3K's install-owned configuration alone.
{
  echo "o3kd_env_sha256_phase1a_end=$(sha256sum /etc/o3k/o3kd.env | awk '{print $1}')"
  echo "o3kd_env_sha256_after_install=$(awk -F= '$1=="o3kd_env_sha256_after_install"{print $2}' "$EVID/12b-o3k-o3kd-env-ledger.txt")"
} > "$EVID/12b2-o3k-o3kd-env-ledger-after-demo.txt"
python3 - "$EVID/12b-o3k-o3kd-env-ledger.txt" "$EVID/12b2-o3k-o3kd-env-ledger-after-demo.txt" <<'PY' \
  || die "/etc/o3k/o3kd.env changed during the demo stage (O3K config-file ledger broken)"
import sys
after_install = {}
for line in open(sys.argv[1], encoding="utf-8"):
    if "=" in line:
        key, _, value = line.strip().partition("=")
        after_install[key] = value
at_end = {}
for line in open(sys.argv[2], encoding="utf-8"):
    if "=" in line:
        key, _, value = line.strip().partition("=")
        at_end[key] = value
before = after_install.get("o3kd_env_sha256_after_install")
after = at_end.get("o3kd_env_sha256_phase1a_end")
assert before, "12b-o3k-o3kd-env-ledger.txt carries no post-install digest"
assert after, "12b2 evidence carries no end-of-phase digest"
assert before == after, f"/etc/o3k/o3kd.env changed during phase1a: {before} -> {after}"
assert after_install.get("o3kd_env_ledger_match") == "yes", "the ledger match was not recorded"
PY
case_ok I16 "/etc/o3k/o3kd.env sha256 unchanged across the demo stage (byte-identical to the O3K install ledger)"

pp4_phase_complete
log "PHASE1A-COMPLETE status=passed"
echo "PHASE1A-COMPLETE status=passed" > "$EVID/phase1a-done"
