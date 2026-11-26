#!/usr/bin/env bash
# Fresh-host admission for the bounded Early Access installer.
set -Eeuo pipefail
die() { echo "O3K Early Access preflight: $1" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ "$(uname -m)" == x86_64 ]] || die "only x86_64 is supported"
[[ -r /etc/os-release ]] || die "cannot identify the operating system"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] \
  || die "only Ubuntu 24.04 LTS is supported"

for path in \
  /usr/local/share/o3k/release-manifest.json \
  /usr/local/share/o3k/.o3k-installed \
  /usr/local/bin/o3kd /usr/local/bin/o3k \
  /etc/o3k/o3kd.env /etc/o3k/installation-policy.json \
  /etc/o3k/recovery-trust.json /etc/o3k/installation-identity.json \
  /etc/systemd/system/o3kd.service \
  /var/lib/o3k-recovery /var/lib/o3k-recovery-state; do
  [[ ! -e "$path" && ! -L "$path" ]] || die "existing O3K or recovery state blocks a fresh install: $path"
done
if [[ -e /var/lib/o3k ]] && find /var/lib/o3k -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  die "existing O3K data blocks a fresh install"
fi
if id o3k >/dev/null 2>&1 || getent group o3k >/dev/null 2>&1; then
  die "existing O3K service identity blocks a fresh install"
fi

# PostgreSQL packages create a local cluster as a package side effect. Refuse
# any cluster before apt runs; the cluster created by this transaction is
# checked again by install.sh before role or database creation.
if command -v pg_lsclusters >/dev/null 2>&1; then
  clusters="$(pg_lsclusters --no-header 2>/dev/null || true)"
  [[ -z "$clusters" ]] || die "existing PostgreSQL clusters block automatic provisioning"
elif [[ -d /var/lib/postgresql ]] && find /var/lib/postgresql -mindepth 1 -print -quit | grep -q .; then
  die "PostgreSQL data exists but its cluster inventory cannot be verified"
fi

available_kib="$(df -Pk /var/lib 2>/dev/null | awk 'NR == 2 { print $4 }')"
[[ "$available_kib" =~ ^[0-9]+$ && "$available_kib" -ge 1048576 ]] \
  || die "at least 1 GiB free space on /var/lib is required"
[[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die "KVM is unavailable or inaccessible"
echo "Early Access fresh-host preflight: PASS"
