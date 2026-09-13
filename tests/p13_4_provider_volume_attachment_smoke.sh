#!/usr/bin/env bash
set -euo pipefail

: "${O3K_P13_TOFU:?set O3K_P13_TOFU to OpenTofu 1.12.6}"
: "${O3K_P13_PROVIDER_BINARY:?set O3K_P13_PROVIDER_BINARY to the unmodified provider 3.4.0 binary}"
: "${O3K_LVM_VOLUME_GROUP:?set a disposable LVM volume group}"
: "${O3K_LVM_THIN_POOL:?set a disposable LVM thin pool}"
: "${O3K_LVM_PROVIDER_NAMESPACE:?set a disposable LVM provider namespace}"
root_dir=$(cd "$(dirname "$0")/.." && pwd)
password=${O3K_P13_PASSWORD:-p13-4-provider-password}
project_id=eba29e2d-53de-461d-ae91-ede7402713cb
port=${O3K_P13_PORT:-18993}
work=$(mktemp -d /tmp/o3k-p13-4-attachment.XXXXXX)
pid=
auth_token=
image_id=
run_stage() {
    local stage="$1"; shift; local status
    printf 'RUN %s\n' "$stage" | tee -a "$work/stages.log" >&2
    set +e; "$@" > >(tee -a "$work/stages.log") 2>&1; status=$?; set -e
    if [[ "$status" -ne 0 ]]; then printf 'FAILED: %s exit=%s artifacts=%s\n' "$stage" "$status" "$work" >&2; return "$status"; fi
}
redact_artifacts() {
    sed -i "s/$password/[REDACTED]/g" "$work"/stages.log "$work"/main.tf 2>/dev/null || true
    rm -f "$work/auth.headers"
}
cleanup() {
    local status=$?
    if [[ -n "$image_id" && -n "$auth_token" ]]; then
        curl -fsS -X DELETE -H "X-Auth-Token: $auth_token" "http://127.0.0.1:$port/v2/images/$image_id" >/dev/null 2>&1 || true
    fi
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    if [[ "$status" -ne 0 || "${O3K_P13_KEEP_LOGS:-0}" == 1 ]]; then
        redact_artifacts
        echo "logs: $work" >&2
    else
        rm -rf "$work"
    fi
}
trap cleanup EXIT

O3K_BOOTSTRAP_PASSWORD="$password" \
O3K_TOKEN_SIGNING_KEY="p13-4-attachment-token-signing-key-012345678901234567890123" \
O3K_CINDER_PASSWORD="$password" \
O3K_CINDER_ENDPOINT="http://127.0.0.1:$port" \
O3K_LVM_VOLUME_GROUP="$O3K_LVM_VOLUME_GROUP" \
O3K_LVM_THIN_POOL="$O3K_LVM_THIN_POOL" \
O3K_LVM_PROVIDER_NAMESPACE="$O3K_LVM_PROVIDER_NAMESPACE" \
O3K_COMPATIBILITY_TRACE_PATH="$work/trace.jsonl" \
  "$root_dir/target/debug/o3kd" --listen-addr "127.0.0.1:$port" --data-dir "$work/data" >"$work/o3kd.log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do
    curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS -D "$work/auth.headers" -o /dev/null -H 'Content-Type: application/json' -X POST \
  "http://127.0.0.1:$port/v3/auth/tokens" \
  --data "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"admin\",\"password\":\"$password\"}}},\"scope\":{\"project\":{\"name\":\"admin\"}}}}"
auth_token="$(awk 'tolower($1)=="x-subject-token:" {print $2}' "$work/auth.headers" | tr -d '\r')"
image_id="$(curl -fsS -H "X-Auth-Token: $auth_token" -H 'Content-Type: application/json' -X POST \
  "http://127.0.0.1:$port/v2/images" \
  --data '{"name":"p13-4-provider-attachment-image","visibility":"private","container_format":"bare","disk_format":"raw"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
printf 'p13-4-provider-attachment-image\n' >"$work/image-content"
curl -fsS -H "X-Auth-Token: $auth_token" -H 'Content-Type: application/octet-stream' \
  --data-binary "@$work/image-content" -X PUT "http://127.0.0.1:$port/v2/images/$image_id/file" >/dev/null

mkdir -p "$work/mirror/registry.terraform.io/terraform-provider-openstack/openstack/3.4.0/linux_amd64"
cp "$O3K_P13_PROVIDER_BINARY" "$work/mirror/registry.terraform.io/terraform-provider-openstack/openstack/3.4.0/linux_amd64/terraform-provider-openstack_v3.4.0"
cat >"$work/tofu.tfrc" <<EOF
provider_installation {
  filesystem_mirror {
    path = "$work/mirror"
    include = ["registry.terraform.io/terraform-provider-openstack/openstack"]
  }
  direct { exclude = ["registry.terraform.io/terraform-provider-openstack/openstack"] }
}
EOF
cat >"$work/main.tf" <<EOF
terraform {
  required_version = "= 1.12.6"
  required_providers {
    openstack = {
      source = "terraform-provider-openstack/openstack"
      version = "= 3.4.0"
    }
  }
}
provider "openstack" {
  auth_url = "http://127.0.0.1:$port"
  user_name = "admin"
  password = "$password"
  tenant_id = "$project_id"
  max_retries = 0
}
resource "openstack_blockstorage_volume_v3" "volume" {
  name = "p13-4-provider-attachment-volume"
  size = 1
}
resource "openstack_compute_instance_v2" "server" {
  name = "p13-4-provider-attachment-server"
  image_id = "$image_id"
  flavor_id = "00000000-0000-0000-0000-000000000001"
  network { uuid = openstack_networking_network_v2.network.id }
}
resource "openstack_networking_network_v2" "network" {
  name = "p13-4-provider-attachment-network"
}
resource "openstack_networking_subnet_v2" "subnet" {
  network_id = openstack_networking_network_v2.network.id
  cidr = "198.51.110.0/24"
  ip_version = 4
  enable_dhcp = false
}
resource "openstack_compute_volume_attach_v2" "attachment" {
  instance_id = openstack_compute_instance_v2.server.id
  volume_id = openstack_blockstorage_volume_v3.volume.id
  device = "/dev/vdb"
}
EOF
export TF_CLI_CONFIG_FILE="$work/tofu.tfrc" TF_IN_AUTOMATION=1
(cd "$work" && run_stage "tofu init" "$O3K_P13_TOFU" init -input=false -upgrade=false)
(cd "$work" && run_stage "tofu apply" "$O3K_P13_TOFU" apply -input=false -auto-approve)
(cd "$work" && run_stage "tofu plan" "$O3K_P13_TOFU" plan -detailed-exitcode)
(cd "$work" && run_stage "tofu destroy" "$O3K_P13_TOFU" destroy -input=false -auto-approve)
echo "P13.4 native volume attachment provider lifecycle passed"
