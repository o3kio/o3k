#!/usr/bin/env bash
set -Eeuo pipefail

# Idempotent O3K libvirt TestLab resource bootstrap (issue #613, PP.2 #971).
#
# Speaks ONLY public OpenStack APIs through the `openstack` CLI: no direct
# SQLite writes, no internal service calls, no libvirt shortcuts, no hidden
# admin repair. Re-running converges instead of creating duplicates, and
# `--teardown` removes only the resources this script owns (server, port,
# subnet, network, and the TestLab-spec flavor) — idempotently too, so absent
# resources are fine. Secrets are never printed.
#
# Canonical precondition (PP.2, contracts/installer-v1.yaml): this script
# creates demo workload only AFTER the canonical P15.6 bootstrap
# (`o3k init` + authenticated `o3k join`) has durably reached phase `ready`.
# It verifies the durable canonical state read-only and fails closed when the
# bootstrap is missing — it never fabricates topology, providers,
# BuildingBlocks, CloudProfile state, agent identity, or readiness itself.
#
# Ownership records: the disposable keypair private key (/etc/o3k/testlab-key.pem)
# and the flavor ID of every flavor this script creates
# (/etc/o3k/testlab-flavor-id) are recorded in the install-time configuration
# ledger (/etc/o3k/.o3k-config-files) so uninstall --purge removes them; on
# clients that cannot enumerate flavors (Debian bookworm OSC 6.0.0) the
# flavor NAME is not an ownership marker — teardown and the recreate path
# operate only on the recorded ID and refuse without it.

CONFIG_DIR=/etc/o3k
OPENRC_FILE="$CONFIG_DIR/admin-openrc"
KEY_FILE="$CONFIG_DIR/testlab-key.pem"
FLAVOR_ID_FILE="$CONFIG_DIR/testlab-flavor-id"
LEDGER_FILE="$CONFIG_DIR/.o3k-config-files"

IMAGE_NAME=cirros-0.6.3
NETWORK_NAME=testlab-network
SUBNET_NAME=testlab-subnet
PORT_NAME=testlab-port
FLAVOR_NAME=testlab-flavor
KEYPAIR_NAME=testlab-keypair
SERVER_NAME=test-vm
SUBNET_CIDR=192.0.2.0/29
FIXED_IP=192.0.2.2

# CirrOS 0.6.3 x86_64 disk image. URL and SHA-256 are pinned verbatim from
# the protected real-host workflow (.github/workflows/real-host-validation.yml,
# "Download and verify CirrOS image" step) so the TestLab bootstrap and the
# protected gate exercise the identical artifact from the official site.
CIRROS_URL=https://download.cirros-cloud.net/0.6.3/cirros-0.6.3-x86_64-disk.img
CIRROS_SHA256=7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b
IMAGE_CACHE_DIR="${O3K_TESTLAB_IMAGE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/o3k}"
IMAGE_CACHE_FILE="$IMAGE_CACHE_DIR/cirros-0.6.3-x86_64-disk.img"

TEARDOWN=0
while (($#)); do
  case "$1" in
    --teardown) TEARDOWN=1; shift;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

die() { printf 'TestLab bootstrap failed: %s\n' "$1" >&2; exit 1; }
step() { printf '✓ %s\n' "$1"; }

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-bootstrap.XXXXXX")"
trap 'rm -rf -- "$WORK_DIR"' EXIT

for command in openstack curl sha256sum timeout; do
  command -v "$command" >/dev/null 2>&1 || die "$command is unavailable"
done

# Authenticate from the installed client credentials when present (generated
# 0600 and ledger-owned by packaging/install.sh); otherwise an
# operator-provided OS_* environment governs.
if [[ -f "$OPENRC_FILE" && ! -L "$OPENRC_FILE" ]]; then
  # shellcheck disable=SC1091
  source "$OPENRC_FILE"
fi
export OS_INTERFACE="${OS_INTERFACE:-public}"
export OS_IDENTITY_API_VERSION="${OS_IDENTITY_API_VERSION:-3}"
export OS_USER_DOMAIN_NAME="${OS_USER_DOMAIN_NAME:-Default}"
export OS_PROJECT_DOMAIN_NAME="${OS_PROJECT_DOMAIN_NAME:-Default}"
for var in OS_AUTH_URL OS_USERNAME OS_PASSWORD OS_PROJECT_NAME OS_REGION_NAME; do
  [[ -n "${!var:-}" ]] || die "$var is not configured (source $OPENRC_FILE or export OS_* variables)"
done

# Endpoint overrides for the shared-port demo catalog: the native catalog
# advertises image/network at the bare control-plane root, which serves the
# identity version document, so python-openstackclient reports "does not have
# any supported versions" (recorded as the v0.4.0-rc.1 fresh-host defect on
# BOTH supported distros). Pinning the versioned service roots here matches
# the canonical protected bootstrap (scripts/bootstrap-disposable-testlab.sh)
# and keeps every openstack invocation on one client configuration. The
# password reaches the generator through the process environment (never argv:
# /proc/<pid>/cmdline is world-readable) and the file is created under umask
# 077 so it is never group/world readable, not even transiently.
CLOUDS_FILE="$WORK_DIR/o3k-testlab-clouds.yaml"
export OS_PASSWORD
umask 077
python3 - "$CLOUDS_FILE" "$OS_AUTH_URL" "$OS_USERNAME" \
  "$OS_PROJECT_NAME" "$OS_REGION_NAME" "${OS_INTERFACE:-public}" \
  "${OS_USER_DOMAIN_NAME:-Default}" "${OS_PROJECT_DOMAIN_NAME:-Default}" <<'PY'
import json
import os
import sys

(path, auth_url, username, project, region, interface,
 user_domain, project_domain) = sys.argv[1:9]
password = os.environ["OS_PASSWORD"]
base = auth_url[:-3] if auth_url.endswith("/v3") else auth_url.rstrip("/")
config = {
    "clouds": {
        "o3k-testlab": {
            "auth": {
                "auth_url": auth_url,
                "username": username,
                "password": password,
                "project_name": project,
                "user_domain_name": user_domain,
                "project_domain_name": project_domain,
            },
            "region_name": region,
            "interface": interface,
            "identity_api_version": 3,
            "image_api_version": "2",
            "image_endpoint_override": f"{base}/v2",
            "network_endpoint_override": f"{base}/v2.0",
        }
    }
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
PY
chmod 0600 "$CLOUDS_FILE"
export OS_CLOUD=o3k-testlab OS_CLIENT_CONFIG_FILE="$CLOUDS_FILE"

require_canonical_bootstrap() {
  # Fail closed unless the canonical P15.6 bootstrap is durably ready: one
  # bootstrap_state row at phase ready and at least one enrolled BuildingBlock
  # in the durable store. Read-only access; never mutates runtime state.
  local data_dir="${O3K_DATA_DIR:-/var/lib/o3k}"
  local db="file:$data_dir/o3k.sqlite?mode=ro"
  python3 - "$db" <<'PY'
import sqlite3
import sys

try:
    connection = sqlite3.connect(sys.argv[1], uri=True)
    phases = [row[0] for row in connection.execute(
        "SELECT phase FROM bootstrap_state")]
    blocks = [row[0] for row in connection.execute(
        "SELECT state FROM building_blocks")]
except sqlite3.Error as error:
    raise SystemExit(f"canonical bootstrap state is unreadable: {error}")
if not phases or any(phase != "ready" for phase in phases):
    raise SystemExit(
        "canonical P15.6 bootstrap is not ready "
        f"(bootstrap_state phases: {phases or 'none'})")
if not blocks or any(state != "ready" for state in blocks):
    raise SystemExit(
        f"canonical BuildingBlock is not ready (states: {blocks or 'none'})")
PY
}

wait_for_api() {
  # Bounded readiness wait: authentication is the control-plane liveness gate
  # (issue #613 requires verified service readiness before any mutation).
  local attempts="${O3K_TESTLAB_API_READY_ATTEMPTS:-60}" attempt=1
  while (( attempt <= attempts )); do
    if openstack token issue >/dev/null 2>&1; then
      step "control plane ready (authenticated)"
      return 0
    fi
    sleep "${O3K_TESTLAB_API_READY_INTERVAL_SECONDS:-5}"
    attempt=$((attempt + 1))
  done
  die "control plane did not become ready (openstack token issue failed after ${attempts} attempts)"
}

lookup_id() {
  # Resolve a resource UUID by name through the public CLI (the client
  # resolves names against the list API). Empty output means "absent".
  # Flavors are resolved through `flavor list -f json` matched by Name, not
  # through the value formatter's column layout: `openstack flavor show`
  # follows up with GET /flavors/{id}/os-extra_specs, which O3K does not
  # implement (and does not advertise); the certified harness
  # (tests/openstack-cli-libvirt.sh) resolves flavors the same way.
  # NOTE: on Debian bookworm's python3-openstackclient 6.0.0 the LIST
  # command itself performs that os-extra_specs follow-up for every flavor
  # and fails with the same 404, so on that client this resolver yields
  # empty; the flavor block below converges through the `flavor create`
  # response instead.
  local type="$1" name="$2" json="" value=""
  if [[ "$type" == flavor ]]; then
    json="$(openstack flavor list -f json 2>/dev/null)" || return 0
    value="$(python3 -c '
import json
import sys

flavors = json.load(sys.stdin)
flavor = next((f for f in flavors if f.get("Name") == sys.argv[1]), None)
if flavor is None:
    sys.exit(1)
print(flavor.get("ID", ""))
' "$name" <<<"$json" 2>/dev/null)" || return 0
  else
    value="$(openstack "$type" show "$name" -f value -c id 2>/dev/null || true)"
  fi
  if [[ "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    printf '%s' "$value"
  fi
}
keypair_exists() { openstack keypair show "$KEYPAIR_NAME" >/dev/null 2>&1; }
flavor_spec_ok() {
  local flavor_id="$1" json=""
  json="$(openstack flavor list -f json 2>/dev/null)" || return 1
  python3 -c '
import json
import sys

flavors = json.load(sys.stdin)
flavor = next((f for f in flavors if f.get("ID") == sys.argv[1]), None)
if flavor is None:
    sys.exit(1)
sys.exit(0 if flavor.get("RAM") == 512 and flavor.get("Disk") == 10 and flavor.get("VCPUs") == 1 else 1)
' "$flavor_id" <<<"$json"
}

flavor_list_readable() {
  # 0 when `flavor list -f json` succeeds (python-openstackclient >= 6.2.0,
  # which only follows up to os-extra_specs with --long); 1 when the client
  # cannot list flavors at all (Debian bookworm ships 6.0.0, which follows
  # up for every flavor and 404s against O3K, which does not implement
  # os-extra_specs). Callers use this to pick the resolve-by-list path or
  # the create-response/delete-by-name path.
  openstack flavor list -f json >/dev/null 2>&1
}

flavor_id_and_spec_ok() {
  # Parse the `flavor create -f json` response: the only flavor read that
  # works on every advertised client. Prints the created ID only when the
  # response carries the certified TestLab spec (512 MB / 10 GB / 1 vCPU);
  # any other shape (including unparsable output) exits non-zero.
  python3 -c '
import json
import sys

value = json.load(sys.stdin)
flavor_id = value.get("id")
if not isinstance(flavor_id, str) or not flavor_id:
    sys.exit(1)
if value.get("ram") != 512 or value.get("disk") != 10 or value.get("vcpus") != 1:
    sys.exit(1)
print(flavor_id)
' 2>/dev/null
}

read_flavor_record() {
  # Prints the recorded TestLab flavor ID only when the ownership record is a
  # regular, non-symlink file with a UUID-shaped value; prints nothing
  # otherwise. The flavor NAME is not an ownership marker on the bookworm
  # client (OSC 6.0.0 can read no flavor state at all), so teardown and the
  # 409-recreate path operate ONLY on this recorded ID.
  local value
  [[ -f "$FLAVOR_ID_FILE" && ! -L "$FLAVOR_ID_FILE" ]] || return 0
  value="$(<"$FLAVOR_ID_FILE")"
  if [[ "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    printf '%s' "$value"
  fi
}

write_flavor_record() {
  # Atomically record the ID of a flavor this run created (root-created
  # 0600 o3k:o3k file, tmp-file rename into place) and register it in the
  # configuration ledger so uninstall --purge removes it exactly like
  # testlab-key.pem.
  local flavor_id="$1" tmp
  [[ $EUID -eq 0 ]] || die "root is required to write the flavor ownership record: $FLAVOR_ID_FILE"
  [[ "$flavor_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || die "refusing to record an invalid flavor ID: $flavor_id"
  umask 077
  tmp="$FLAVOR_ID_FILE.tmp-$$"
  printf '%s\n' "$flavor_id" >"$tmp"
  chown o3k:o3k "$tmp" || { rm -f -- "$tmp"; die "could not set ownership of the flavor record: $FLAVOR_ID_FILE"; }
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$FLAVOR_ID_FILE"
  register_file_ledger testlab-flavor-id "$FLAVOR_ID_FILE" 1
}

ensure_image_cache() {
  local actual tmp_file
  if [[ -e "$IMAGE_CACHE_FILE" || -L "$IMAGE_CACHE_FILE" ]]; then
    [[ -f "$IMAGE_CACHE_FILE" && ! -L "$IMAGE_CACHE_FILE" ]] \
      || die "cached CirrOS image is not a regular file: $IMAGE_CACHE_FILE"
    actual="$(sha256sum "$IMAGE_CACHE_FILE" | awk '{print $1}')"
    if [[ "$actual" != "$CIRROS_SHA256" ]]; then
      # Fail closed: never delete or silently replace a cache entry the
      # operator may care about; require explicit operator action instead.
      die "cached CirrOS image failed SHA-256 verification: $IMAGE_CACHE_FILE (remove it manually to force a re-download)"
    fi
    step "CirrOS 0.6.3 cache verified (SHA-256)"
    return 0
  fi
  mkdir -p "$IMAGE_CACHE_DIR"
  tmp_file="$(mktemp "${IMAGE_CACHE_DIR}/cirros-download.XXXXXX")"
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 300 \
    --proto '=https' --tlsv1.2 --output "$tmp_file" "$CIRROS_URL" \
    || { rm -f -- "$tmp_file"; die "CirrOS download failed"; }
  actual="$(sha256sum "$tmp_file" | awk '{print $1}')"
  if [[ "$actual" != "$CIRROS_SHA256" ]]; then
    rm -f -- "$tmp_file"
    die "downloaded CirrOS image failed SHA-256 verification"
  fi
  chmod 0644 "$tmp_file"
  mv -f -- "$tmp_file" "$IMAGE_CACHE_FILE"
  step "CirrOS 0.6.3 downloaded and SHA-256 verified"
}

register_file_ledger() {
  # Record FILE at NAME in the install-time configuration ledger so
  # packaging/uninstall.sh --purge removes it exactly like every other
  # generated /etc/o3k file (same format and digest verification). A
  # non-matching existing entry means the operator changed the file: refuse
  # unless this run itself created the file (created=1). The rewrite path
  # runs under umask 077 so the ledger (and its temp file) stay 0600.
  local name="$1" path="$2" created="$3" digest existing tmp
  [[ -f "$LEDGER_FILE" && ! -L "$LEDGER_FILE" ]] \
    || die "configuration ledger is missing or unsafe: $LEDGER_FILE"
  digest="$(sha256sum "$path" | awk '{print $1}')"
  existing="$(awk -F $'\t' -v key="$name" \
    '$1 == "o3k-config-file-v1" && $2 == key {print $3; exit}' "$LEDGER_FILE")"
  if [[ -z "$existing" ]]; then
    printf 'o3k-config-file-v1\t%s\t%s\n' "$name" "$digest" >>"$LEDGER_FILE"
    return 0
  fi
  [[ "$existing" == "$digest" ]] && return 0
  [[ "$created" == 1 ]] || die "refusing to re-register operator-modified file: $path"
  umask 077
  tmp="$LEDGER_FILE.tmp-$$"
  awk -F $'\t' -v key="$name" '!($1 == "o3k-config-file-v1" && $2 == key)' "$LEDGER_FILE" >"$tmp"
  mv -f -- "$tmp" "$LEDGER_FILE"
  printf 'o3k-config-file-v1\t%s\t%s\n' "$name" "$digest" >>"$LEDGER_FILE"
}

wait_for_server_status() {
  local server_id="$1" wanted="$2" attempts="${3:-30}" status="" attempt
  for attempt in $(seq 1 "$attempts"); do
    status="$(openstack server show "$server_id" -f value -c status 2>/dev/null || true)"
    [[ "$status" == "$wanted" ]] && return 0
    [[ "$status" == "ERROR" ]] && return 1
    sleep 2
  done
  return 1
}

console_poll() {
  local attempts="${O3K_TESTLAB_CONSOLE_ATTEMPTS:-30}" attempt
  for attempt in $(seq 1 "$attempts"); do
    if timeout "${O3K_TESTLAB_CONSOLE_REQUEST_TIMEOUT_SECONDS:-15}" \
        openstack console log show "$SERVER_ID" >"$WORK_DIR/console.log" 2>/dev/null \
      && [[ -s "$WORK_DIR/console.log" ]] \
      && grep -Eiq 'cirros|login:' "$WORK_DIR/console.log"; then
      return 0
    fi
    sleep "${O3K_TESTLAB_CONSOLE_INTERVAL_SECONDS:-2}"
  done
  return 1
}

teardown_server() {
  local id="" attempt
  id="$(lookup_id server "$SERVER_NAME")"
  if [[ -z "$id" ]]; then
    step "server $SERVER_NAME already absent"
    return 0
  fi
  # Delete has an unknown outcome if the request times out or the provider is
  # still converging: observe absence like the certified CLI harness does.
  for attempt in $(seq 1 15); do
    openstack server delete --wait "$id" >/dev/null 2>&1 || true
    [[ -z "$(lookup_id server "$SERVER_NAME")" ]] && break
    sleep 2
  done
  [[ -z "$(lookup_id server "$SERVER_NAME")" ]] \
    || die "server deletion was not verified: $SERVER_NAME"
  step "server $SERVER_NAME deleted"
}

teardown_network_resource() {
  local type="$1" name="$2" id=""
  id="$(lookup_id "$type" "$name")"
  if [[ -z "$id" ]]; then
    step "$type $name already absent"
    return 0
  fi
  openstack "$type" delete "$id" >/dev/null 2>&1 || true
  [[ -z "$(lookup_id "$type" "$name")" ]] \
    || die "$type deletion was not verified: $name"
  step "$type $name deleted"
}

teardown_flavor() {
  local id="" recorded=""
  id="$(lookup_id flavor "$FLAVOR_NAME")"
  if [[ -n "$id" ]]; then
    if flavor_spec_ok "$id"; then
      openstack flavor delete "$id" >/dev/null 2>&1 || true
      [[ -z "$(lookup_id flavor "$FLAVOR_NAME")" ]] \
        || die "flavor deletion was not verified: $FLAVOR_NAME"
      step "flavor $FLAVOR_NAME deleted"
    else
      step "preserving flavor $FLAVOR_NAME (spec is not the TestLab flavor)"
    fi
    return 0
  fi
  if flavor_list_readable; then
    step "flavor $FLAVOR_NAME already absent"
    return 0
  fi
  # Bookworm OSC 6.0.0 cannot list or show flavors at all (os-extra_specs
  # 404), so the spec cannot be verified here and the NAME is not an
  # ownership marker. The bootstrap records the ID of every flavor it
  # creates in the root-owned /etc/o3k/testlab-flavor-id ledger file, and
  # `flavor delete <id>` is the one name-resolution-free flavor mutation
  # that client supports. Delete ONLY by the recorded ID; without a record
  # there is no way to prove the name-holder is ours, so refuse instead of
  # destroying a possibly foreign flavor.
  recorded="$(read_flavor_record)"
  [[ -n "$recorded" ]] \
    || die "refusing to delete flavor $FLAVOR_NAME: no ownership record ($FLAVOR_ID_FILE) and this client cannot verify flavors — remove it manually if it is O3K-owned"
  if openstack flavor delete "$recorded" >/dev/null 2>"$WORK_DIR/flavor-delete.err"; then
    step "flavor $FLAVOR_NAME deleted"
  elif grep -Fq "No Flavor found" "$WORK_DIR/flavor-delete.err"; then
    step "flavor $FLAVOR_NAME already absent"
  else
    die "flavor deletion was not verified: $FLAVOR_NAME"
  fi
}

wait_for_api
if [[ $TEARDOWN -eq 1 ]]; then
  teardown_server
  teardown_network_resource port "$PORT_NAME"
  teardown_network_resource subnet "$SUBNET_NAME"
  teardown_network_resource network "$NETWORK_NAME"
  teardown_flavor
  echo "TestLab resources removed"
  exit 0
fi

require_canonical_bootstrap \
  || die "canonical P15.6 bootstrap (o3k init + authenticated o3k join) is not durably ready — refusing to create demo workload state"
step "canonical bootstrap state verified (phase ready, BuildingBlock ready)"

# Image: upload only when absent; the cache download/verification is then the
# only network-bound step.
IMAGE_ID="$(lookup_id image "$IMAGE_NAME")"
if [[ -n "$IMAGE_ID" ]]; then
  step "image $IMAGE_NAME already present"
else
  ensure_image_cache
  openstack image create "$IMAGE_NAME" --file "$IMAGE_CACHE_FILE" \
    --disk-format qcow2 --container-format bare >/dev/null \
    || die "image creation failed: $IMAGE_NAME"
  IMAGE_ID="$(lookup_id image "$IMAGE_NAME")"
  [[ -n "$IMAGE_ID" ]] || die "created image cannot be resolved: $IMAGE_NAME"
  IMAGE_CREATED=1
  step "image $IMAGE_NAME created (CirrOS SHA-256 verified)"
fi

# Flavor: the certified TestLab shape (tests/openstack-cli-libvirt.sh).
# Name->ID resolution must survive every advertised client:
# - python-openstackclient >= 6.2.0 lists flavors without extra-spec
#   follow-ups, so resolve by Name and verify the spec from `flavor list`.
# - Debian bookworm ships 6.0.0-4, where `flavor list` AND `flavor show`
#   both follow up with GET /flavors/{id}/os-extra_specs for every flavor;
#   O3K does not implement that endpoint, so both fail with 404 and no
#   flavor read exists at all on that client. There the `flavor create`
#   RESPONSE (id/ram/disk/vcpus) is the only spec-verifiable flavor read:
#   capture it, and when the name already exists (HTTP 409) delete the
#   RECORDED flavor by its recorded ID — the one name-resolution-free flavor
#   mutation the client supports — and recreate so the TestLab spec is
#   guaranteed by the fresh response. The name itself is never treated as an
#   ownership marker: without a readable /etc/o3k/testlab-flavor-id record
#   the 409 path refuses to touch the name-holder at all.
# Every flavor this script creates is recorded (ID written to the root-owned
#   /etc/o3k/testlab-flavor-id and ledger-registered like testlab-key.pem),
#   so a later run — and teardown — on any client can prove ownership.
#   When the existing flavor is in use by a server the delete conflicts, so
#   the spec cannot be re-verified by any operation the client offers; the
#   script then proceeds by NAME (the server step resolves it client-side
#   without the extra-spec follow-up) while the record keeps matching the
#   in-use flavor, so teardown still deletes by recorded ID after the server
#   is gone.
FLAVOR_ID="$(lookup_id flavor "$FLAVOR_NAME")"
if [[ -n "$FLAVOR_ID" ]]; then
  flavor_spec_ok "$FLAVOR_ID" || die "flavor $FLAVOR_NAME exists with a different spec"
  step "flavor $FLAVOR_NAME already present (512 MB / 10 GB / 1 vCPU)"
else
  if flavor_create_json="$(openstack flavor create "$FLAVOR_NAME" --ram 512 --disk 10 --vcpus 1 \
    -f json 2>"$WORK_DIR/flavor-create.err")"; then
    FLAVOR_ID="$(flavor_id_and_spec_ok <<<"$flavor_create_json")" \
      || die "created flavor cannot be verified: $FLAVOR_NAME"
    write_flavor_record "$FLAVOR_ID"
    FLAVOR_CREATED=1
    step "flavor $FLAVOR_NAME created (512 MB / 10 GB / 1 vCPU)"
  elif grep -Eqi '409|Conflict' "$WORK_DIR/flavor-create.err"; then
    # The name already exists. Where reads work, re-resolve and verify so
    # the converge-with-verification behavior is unchanged; on the
    # read-broken bookworm client, delete-and-recreate by RECORDED ID only.
    if flavor_list_readable; then
      FLAVOR_ID="$(lookup_id flavor "$FLAVOR_NAME")"
      [[ -n "$FLAVOR_ID" ]] || die "flavor creation failed: $FLAVOR_NAME"
      flavor_spec_ok "$FLAVOR_ID" || die "flavor $FLAVOR_NAME exists with a different spec"
      step "flavor $FLAVOR_NAME already present (512 MB / 10 GB / 1 vCPU)"
    else
      recorded="$(read_flavor_record)"
      [[ -n "$recorded" ]] \
        || die "flavor $FLAVOR_NAME exists but has no ownership record ($FLAVOR_ID_FILE) and this client cannot verify flavors — refusing to delete or recreate it by name (remove it manually if it is O3K-owned)"
      deleted_recorded=0
      if openstack flavor delete "$recorded" >/dev/null 2>"$WORK_DIR/flavor-delete.err"; then
        deleted_recorded=1
      elif grep -Fq 'No Flavor found' "$WORK_DIR/flavor-delete.err"; then
        die "flavor $FLAVOR_NAME exists but the recorded flavor ($recorded) is absent — the name-holder cannot be verified on this client"
      fi
      # A fresh create response is the only spec-verifiable flavor read on
      # this client. When the recorded flavor was deleted and the name was
      # re-taken by someone else in between, recreate 409s and the new
      # name-holder is unverifiable -> fail closed. When the delete itself
      # conflicted (the recorded flavor is in use), the recreate 409 names
      # the same recorded flavor: proceed by name, the record stays valid.
      if flavor_create_json="$(openstack flavor create "$FLAVOR_NAME" --ram 512 --disk 10 --vcpus 1 \
        -f json 2>"$WORK_DIR/flavor-create.err")"; then
        FLAVOR_ID="$(flavor_id_and_spec_ok <<<"$flavor_create_json")" \
          || die "created flavor cannot be verified: $FLAVOR_NAME"
        write_flavor_record "$FLAVOR_ID"
        FLAVOR_CREATED=1
        step "flavor $FLAVOR_NAME created (512 MB / 10 GB / 1 vCPU)"
      elif grep -Eqi '409|Conflict' "$WORK_DIR/flavor-create.err"; then
        [[ "$deleted_recorded" -eq 0 ]] \
          || die "flavor $FLAVOR_NAME exists but is not the recorded flavor — refusing an unverifiable name-holder"
        # The flavor exists and is in use by a server, so it cannot be
        # deleted and recreated, and its spec cannot be read on this client.
        # Proceed by name: the server step resolves the name client-side
        # (the one flavor name-resolution without the extra-spec follow-up).
        step "flavor $FLAVOR_NAME already present (in use; spec verified when it was created)"
      else
        die "flavor creation failed: $FLAVOR_NAME"
      fi
    fi
  else
    die "flavor creation failed: $FLAVOR_NAME"
  fi
fi

NETWORK_ID="$(lookup_id network "$NETWORK_NAME")"
if [[ -n "$NETWORK_ID" ]]; then
  step "network $NETWORK_NAME already present"
else
  openstack network create "$NETWORK_NAME" >/dev/null \
    || die "network creation failed: $NETWORK_NAME"
  NETWORK_ID="$(lookup_id network "$NETWORK_NAME")"
  [[ -n "$NETWORK_ID" ]] || die "created network cannot be resolved: $NETWORK_NAME"
  NETWORK_CREATED=1
  step "network $NETWORK_NAME created"
fi

SUBNET_ID="$(lookup_id subnet "$SUBNET_NAME")"
if [[ -n "$SUBNET_ID" ]]; then
  subnet_cidr="$(openstack subnet show "$SUBNET_ID" -f value -c cidr 2>/dev/null || true)"
  [[ "$subnet_cidr" == "$SUBNET_CIDR" ]] \
    || die "subnet $SUBNET_NAME exists with a different range: $subnet_cidr"
  step "subnet $SUBNET_NAME already present ($SUBNET_CIDR)"
else
  # `openstack subnet create` with the default table formatter crashes on the
  # O3K response ('NoneType' object is not iterable, non-zero exit) even
  # though the subnet is created; use the value formatter like the certified
  # harness (tests/openstack-cli-libvirt.sh).
  openstack subnet create --network "$NETWORK_ID" --subnet-range "$SUBNET_CIDR" \
    "$SUBNET_NAME" -f value -c id >/dev/null || die "subnet creation failed: $SUBNET_NAME"
  SUBNET_ID="$(lookup_id subnet "$SUBNET_NAME")"
  [[ -n "$SUBNET_ID" ]] || die "created subnet cannot be resolved: $SUBNET_NAME"
  SUBNET_CREATED=1
  step "subnet $SUBNET_NAME created ($SUBNET_CIDR)"
fi

# The O3K network adapter does not accept fixed_ips on port create
# (crates/o3k-api/src/network.rs CreatePortRequest) and deterministically
# allocates the first pool address — 192.0.2.2 for a fresh 192.0.2.0/29
# subnet — so the certified harness creates the port without --fixed-ip and
# verifies the allocation (tests/openstack-cli-libvirt.sh). Mirror that here.
PORT_ID="$(lookup_id port "$PORT_NAME")"
if [[ -n "$PORT_ID" ]]; then
  port_network="$(openstack port show "$PORT_ID" -f value -c network_id 2>/dev/null || true)"
  [[ "$port_network" == "$NETWORK_ID" ]] \
    || die "port $PORT_NAME exists on a different network"
  openstack port show "$PORT_ID" -f value -c fixed_ips | grep -Fq "$FIXED_IP" \
    || die "port $PORT_NAME does not carry the expected fixed IP $FIXED_IP"
  step "port $PORT_NAME already present ($FIXED_IP)"
else
  openstack port create --network "$NETWORK_ID" "$PORT_NAME" >/dev/null \
    || die "port creation failed: $PORT_NAME"
  PORT_ID="$(lookup_id port "$PORT_NAME")"
  [[ -n "$PORT_ID" ]] || die "created port cannot be resolved: $PORT_NAME"
  openstack port show "$PORT_ID" -f value -c fixed_ips | grep -Fq "$FIXED_IP" \
    || die "created port did not receive the expected fixed IP $FIXED_IP"
  PORT_CREATED=1
  step "port $PORT_NAME created ($FIXED_IP)"
fi

# Disposable keypair: create only when absent; a pre-existing keypair is
# reused and no new key file is minted. The local private key is ledger-owned
# so uninstall --purge removes it.
if [[ -f "$KEY_FILE" && ! -L "$KEY_FILE" ]]; then
  if keypair_exists; then
    register_file_ledger testlab-key.pem "$KEY_FILE" 0
    step "keypair $KEYPAIR_NAME already present"
  else
    command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is unavailable (install openssh-client)"
    [[ $EUID -eq 0 ]] || die "root is required to re-register the key file"
    ssh-keygen -y -f "$KEY_FILE" >"$WORK_DIR/testlab-key.pub" 2>/dev/null \
      || die "existing key file is unusable: $KEY_FILE"
    openstack keypair create --public-key "$WORK_DIR/testlab-key.pub" \
      "$KEYPAIR_NAME" >/dev/null || die "keypair import failed: $KEYPAIR_NAME"
    register_file_ledger testlab-key.pem "$KEY_FILE" 0
    step "keypair $KEYPAIR_NAME re-imported from the existing key file"
  fi
elif keypair_exists; then
  step "keypair $KEYPAIR_NAME already present (no local key file minted)"
else
  command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is unavailable (install openssh-client)"
  [[ $EUID -eq 0 ]] || die "root is required to create the key file: $KEY_FILE"
  [[ ! -e "$KEY_FILE" && ! -L "$KEY_FILE" ]] \
    || die "refusing to overwrite existing key file: $KEY_FILE"
  ssh-keygen -q -t ed25519 -N '' -C o3k-testlab -f "$WORK_DIR/testlab-key" >/dev/null
  chmod 0600 "$WORK_DIR/testlab-key"
  openstack keypair create --public-key "$WORK_DIR/testlab-key.pub" \
    "$KEYPAIR_NAME" >/dev/null || die "keypair creation failed: $KEYPAIR_NAME"
  umask 077
  install -m 0600 "$WORK_DIR/testlab-key" "$KEY_FILE"
  register_file_ledger testlab-key.pem "$KEY_FILE" 1
  KEYPAIR_CREATED=1
  step "keypair $KEYPAIR_NAME created (private key at $KEY_FILE)"
fi

SERVER_ID="$(lookup_id server "$SERVER_NAME")"
if [[ -n "$SERVER_ID" ]]; then
  step "server $SERVER_NAME already present"
else
  openstack server create --wait --image "$IMAGE_ID" --flavor "${FLAVOR_ID:-$FLAVOR_NAME}" \
    --key-name "$KEYPAIR_NAME" --config-drive true --nic "port-id=$PORT_ID" \
    "$SERVER_NAME" >/dev/null || die "server creation failed: $SERVER_NAME"
  SERVER_ID="$(lookup_id server "$SERVER_NAME")"
  [[ -n "$SERVER_ID" ]] || die "created server cannot be resolved: $SERVER_NAME"
  SERVER_CREATED=1
  step "server $SERVER_NAME created"
fi

wait_for_server_status "$SERVER_ID" ACTIVE "${O3K_TESTLAB_SERVER_ACTIVE_ATTEMPTS:-30}" \
  || die "server $SERVER_NAME did not reach ACTIVE"

openstack server show "$SERVER_ID" -f json >"$WORK_DIR/server-show.json" \
  || die "server show failed: $SERVER_NAME"
python3 - "$WORK_DIR/server-show.json" "$FIXED_IP" <<'PY' \
  || die "server verification failed (ACTIVE, config-drive, fixed IP $FIXED_IP)"
import json
import sys

path, expected_ip = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)
if str(value.get("status", "")).upper() != "ACTIVE":
    raise SystemExit("server is not ACTIVE")
if value.get("config_drive") not in (True, "True", "true", 1):
    raise SystemExit("server config-drive is not enabled")
addresses = []


def collect(node):
    if isinstance(node, dict):
        if "addr" in node:
            addresses.append(str(node["addr"]))
        for child in node.values():
            collect(child)
    elif isinstance(node, list):
        for child in node:
            collect(child)
    elif isinstance(node, str):
        # openstackclient flattens the addresses dict into
        # {network: ["<ip>", ...]}, so plain strings must count.
        addresses.append(node)


collect(value.get("addresses", {}))
if expected_ip not in addresses:
    raise SystemExit("server does not prove the expected fixed IP")
PY
step "server $SERVER_NAME ACTIVE with fixed IP $FIXED_IP and config-drive"

console_poll || die "console log did not show a boot marker (cirros|login:) within the timeout"
step "console boot marker verified (cirros|login:)"

if [[ -z "${IMAGE_CREATED:-}${NETWORK_CREATED:-}${SUBNET_CREATED:-}${PORT_CREATED:-}${FLAVOR_CREATED:-}${KEYPAIR_CREATED:-}${SERVER_CREATED:-}" ]]; then
  echo "TestLab resources already present"
fi
echo "TestLab ready — try: openstack server list ; openstack console log show $SERVER_NAME"
