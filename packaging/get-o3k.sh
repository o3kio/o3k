#!/usr/bin/env bash
# get-o3k.sh — thin one-line installer wrapper (issue #613, PP.2 #971, PP.4 #973).
#
# Published as the GitHub Release asset install.sh of every O3K release: the
# release generator exports this file byte-for-byte as dist/install.sh
# (packaging/make-release.sh, 0755, drift-gated by cmp), so the canonical
# alpha invocation is
#   curl -sfL https://github.com/o3kio/o3k/releases/download/<published-version>/install.sh | sudo sh -
# get.o3k.io is only a convenience 302 redirect to that exact asset:
#   curl -sfL https://get.o3k.io | sudo sh -
#
# Canonical bootstrap (PP.2, contracts/installer-v1.yaml): this script is
# orchestration only. After the verified prebuilt runtime is installed it
# invokes the canonical `o3k init` and authenticated `o3k join` (one local
# BuildingBlock, real Placement/topology state), waits for canonical runtime
# readiness (o3kd /readyz, o3k-compute /readyz, `o3k doctor`), and only then
# creates the bounded o3k-demo-v1 workload through the supported public CLI.
# It never fabricates topology, providers, BuildingBlocks, CloudProfile state,
# agent identity, or readiness, and it never compiles on the target host.
#
# The historical/default path then installs the digest-pinned Araf demo
# material and runs packaging/o3k-araf-demo.sh install. PP.4 Core can set
# O3K_SKIP_ARAF=1 to stop after the O3K/TestLab proof; this is an explicit
# product/demo split, not a claim that Araf is no longer required. Araf's
# browser/runtime candidate remains the separately certified PP.4A path.
# A demo-stage failure aborts the installer with a message that O3K itself is
# healthy and the demo stage can be retried from the installed copy — the
# demo never gates O3K readiness. Stage timing is recorded as T0..T5 stamps
# (this file) plus T3 (appended by o3k-araf-demo.sh) in
# /var/lib/o3k/install-timestamps.env.
#
# This file is POSIX-sh compatible on purpose: on Ubuntu 24.04 and Debian 12
# `sudo sh -` is dash, so the piped invocation must not depend on bashisms.
# Fail-fast is `set -eu` plus pipefail where the shell supports it — Ubuntu
# 24.04's dash (0.5.12-6ubuntu5) rejects `set -o pipefail`, so it is enabled
# conditionally (empirically verified on a clean noble VM).
#
# SECURITY CONTRACT — no curl|sh of unauthenticated content:
#   The version to install is BAKED into this file (O3K_INSTALLER_VERSION);
#   the installer never consults a channel service or any other network
#   endpoint to decide which version to install. Every file that is executed
#   (packaging/*.sh, bin/o3kd, bin/o3k-compute, bin/o3k-network) comes from the release
#   tarball AFTER the exact tag, GitHub OIDC identity, Sigstore signature,
#   Rekor checkpoint/inclusion proof, and signed digest manifest are verified;
#   the tarball is never extracted before its digest from that authenticated
#   manifest is verified, and extraction rejects any entry that
#   is absolute, contains a ".." component, does not start with "./", or is
#   not a regular file (symlink, hardlink, device, fifo, socket entries are
#   refused from the `tar -tvzf` listing before anything is written). Any
#   download or verification failure aborts.
#
# An optional endpoint may serve this same file with an added FIRST line
#   O3K_PINNED_VERSION="v0.3.0-alpha.1"
# which is a plain shell assignment when the stream is piped to sh. It is
# kept for optional future /v<version> endpoint paths (packaging/get-o3k-worker)
# and handled by the resolution order below; its absence is not an error.
# There is no fallback to main/latest: resolution failure aborts.
#
# Version resolution precedence:
#   1. O3K_VERSION environment variable (explicit dev/test override);
#   2. O3K_PINNED_VERSION (the endpoint-injected first line, if present);
#   3. the baked O3K_INSTALLER_VERSION release pin (this file's own release).
# The installer NEVER consults a channel service.
#
# Upgrade fence (issue #626, docs/plan/o3k-upgrade.md §12): when an O3K
# release is already installed (parsed from
# /usr/local/share/o3k/release-manifest.json), the resolved TARGET version is
# compared against it BEFORE any mutation:
#   - fresh host (no manifest): the normal install flow, unchanged;
#   - installed == target: the existing idempotent convergence flow;
#   - installed > target: refuse the implicit downgrade (exit 1, no mutation);
#   - installed < target: download + verify the new release bundle (tarball +
#     published .sha256 + install.sh) into /var/lib/o3k/upgrade-download/
#     (mode 0700; the only override knob is O3K_UPGRADE_DOWNLOAD_DIR for
#     test/campaign sandboxes), print the exact next command
#     `sudo /var/lib/o3k/upgrade-download/o3k-<target>/bin/o3k upgrade`, and
#     exit 0. Nothing is extracted or executed here — extraction is the o3k
#     upgrade engine's job — so a noninteractive curl|sh NEVER auto-upgrades
#     an existing installation (safety over convenience).
#
# Supported platforms (strict): Linux x86_64, Ubuntu 24.04 (noble) or
# Debian 12 (bookworm). Anything else fails with a clear message. Root is
# required.
#
# Overrides for testing/campaigns (the only knobs):
#   O3K_RELEASE_BASE  release asset base (default
#                     https://github.com/o3kio/o3k/releases/download)
# Local campaigns serve the release assets from one http server:
# /releases/v<version>/<assets>; HTTP is permitted only for this explicit
# override, production URLs are pinned to HTTPS.
#
# Release asset naming contract (packaging/make-release-archive.sh):
#   o3k-<version>-linux-x86_64.tar.gz + o3k-<version>-linux-x86_64.tar.gz.sha256
#   at <release-base>/v<version>/.
#
# The dependency package list mirrors the exact host set proven by the clean
# Ubuntu 24.04 and Debian 12 VM campaigns
# (target/real-host-workflow-artifacts/asr-021-cd15263/vm-run.sh cloud-init
# package list plus openssl/openssh-client for the bundled bootstrap scripts
# and binutils for readelf in the bundled verify-release-bundle.sh glibc floor
# check).
# This is the one place the OUTER wrapper may apt-install. The bundled
# packaging/install.sh installs nothing, and the PP.4 Araf demo stage
# (packaging/o3k-araf-demo.sh, run after the O3K install) apt-installs only the
# container-engine prerequisites the araf-demo deployment contract allows
# (docker.io + docker-compose-v2 on Ubuntu, iptables + the pinned static
# engine's deps on Debian). It does NOT touch
# netplan, systemd-networkd, sysctl forwarding, or host-wide NAT (goal §11).
set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

# Baked release pin — updated in EVERY release's version-bump commit; the
# published install.sh GitHub Release asset is byte-identical to this file,
# so an installer downloaded from .../releases/download/v<version>/install.sh
# installs exactly <version> by default.
O3K_INSTALLER_VERSION="v0.4.0-rc.24"
O3K_RELEASE_BASE="${O3K_RELEASE_BASE:-https://github.com/o3kio/o3k/releases/download}"
INSTALL_MANIFEST=/usr/local/share/o3k/.o3k-installed

die() { printf 'O3K installer: %s\n' "$1" >&2; exit 1; }
step() { printf '✓ %s\n' "$1"; }

# ---- PP.4 timing ledger -------------------------------------------------------
# Stage stamps for the one-line installer evidence: every stamp prints
# "PP4-TIMESTAMP <name>=<epoch>" and, once /var/lib/o3k exists (created by
# install.sh), durably appends "<name>=<epoch>" to install-timestamps.env
# there. T0 is taken before the data dir exists, so it is additionally kept in
# a variable and persisted right after install.sh runs. o3k-araf-demo.sh
# appends T3 itself (via PP4_TIMESTAMPS_FILE).
PP4_TS_FILE=/var/lib/o3k/install-timestamps.env
pp4_stamp() { # pp4_stamp NAME
  name="$1"
  epoch="$(date +%s)"
  printf 'PP4-TIMESTAMP %s=%s\n' "$name" "$epoch"
  PP4_LAST_STAMP_EPOCH="$epoch"
  if [ -d /var/lib/o3k ]; then
    if [ ! -f "$PP4_TS_FILE" ]; then
      ( umask 077 && : > "$PP4_TS_FILE" ) 2>/dev/null || return 0
    fi
    printf '%s=%s\n' "$name" "$epoch" >> "$PP4_TS_FILE" 2>/dev/null || true
  fi
}

# Platform guard — self-contained so the test matrix can exercise it with
# faked inputs in a subshell.
check_platform() {
  local kernel="$1" machine="$2" distro_id="$3" codename="$4"
  [ "$kernel" = Linux ] || {
    printf 'unsupported kernel: %s — only Linux x86_64 is supported\n' "$kernel" >&2
    exit 1
  }
  [ "$machine" = x86_64 ] || {
    printf 'unsupported architecture: %s — only x86_64 is supported\n' "$machine" >&2
    exit 1
  }
  case "$distro_id:$codename" in
    ubuntu:noble|debian:bookworm) ;;
    *)
      printf 'unsupported distribution: %s %s — only Ubuntu 24.04 (noble) and Debian 12 (bookworm) are supported\n' \
        "${distro_id:-unknown}" "${codename:-unknown}" >&2
      exit 1
      ;;
  esac
}

# Version fence — the ADR-0130 release-version format
# (docs/adr/ADR-0130-release-version-path-fence.md): numeric release version
# with one or two dots and an optional dot-separated alphanumeric prerelease
# suffix, nothing else; an optional leading "v" is accepted and stripped.
# Self-contained so the test matrix can exercise it with faked inputs.
check_version_format() {
  local version="${1#v}"
  printf '%s\n' "$version" \
    | grep -Eq '^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$' \
    || {
      printf 'unsupported version: %s — expected a published release version like v0.3.0-alpha.1; refusing to fall back to main/latest\n' "$1" >&2
      exit 1
    }
}

trim() { # dash-safe: dash does not implement [:space:] in expansion patterns
  printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

fetch() { # fetch URL DESTINATION — fail closed, no silent retry exhaustion
  local url="$1" destination="$2" proto='=https'
  case "$url" in
    http://*) proto='=http,https' ;; # only for the documented local overrides
  esac
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 \
    --max-time 600 --proto "$proto" --output "$destination" "$url" \
    || die "download failed: $url"
}

safe_extract() { # safe_extract TARBALL DESTINATION ENTRIES_FILE
  local tarball="$1" destination="$2" entries="$3" entry
  if ! tar -tzf "$tarball" >"$entries" 2>/dev/null; then
    die "release archive is not a readable gzip tarball: $tarball"
  fi
  while IFS= read -r entry; do
    [ -n "$entry" ] || die "release archive contains an empty entry"
    case "$entry" in
      ./*) ;;
      *) die "unsafe release archive entry (must start with ./): $entry" ;;
    esac
    case "$entry" in
      *'/../'*|*'/..'|'..') die "unsafe release archive entry (.. component): $entry" ;;
    esac
  done <"$entries"
  # Second pass over the verbose listing: refuse any non-regular entry type
  # (symlink, device, fifo, socket) before extraction so an archive cannot
  # plant a link or special file in the extraction tree. The leading listing
  # character is the entry type; ` -> ` is the GNU tar symlink target marker.
  # Checking both is deliberate: a tar implementation that renders a link
  # differently is still caught by the type character.
  if ! tar -tvzf "$tarball" >"$entries.types" 2>/dev/null; then
    die "release archive is not a readable gzip tarball: $tarball"
  fi
  while IFS= read -r entry; do
    case "$entry" in
      *' -> '*) die "unsafe release archive entry (symlink): $entry" ;;
    esac
    case "$(printf '%s' "$entry" | cut -c1)" in
      l|b|c|p|s) die "unsafe release archive entry (device, fifo, or link): $entry" ;;
    esac
  done <"$entries.types"
  tar -xzf "$tarball" -C "$destination" \
    || die "release archive extraction failed: $tarball"
}

# Verify external release metadata before any archive extraction or bundled
# script execution. This uses the system OpenSSL/Python verifier; no verifier
# binary is downloaded from the release channel.
verify_release_metadata() {
  python3 - "$1" "$2" <<'PY'
import base64, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

directory = Path(sys.argv[1])
version = sys.argv[2].removeprefix("v")
tag = "v" + version
identity = f"https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/{tag}"
def fail(message):
    raise SystemExit("O3K installer: release authentication failed: " + message)
def decode(value, name):
    if not isinstance(value, str): fail(name + " is missing")
    try: return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error: fail(name + " is not base64: " + str(error))
def openssl(*args):
    try: return subprocess.check_output(("openssl",) + args, stderr=subprocess.STDOUT, text=True)
    except (OSError, subprocess.CalledProcessError) as error: fail("OpenSSL verification failed: " + str(error))
manifest = directory / "release-digests.txt"
bundle_path = directory / "release-digests.sigstore.json"
provenance_path = directory / "provenance.json"
if not all(path.is_file() for path in (manifest, bundle_path, provenance_path)): fail("required signed metadata is missing")
try: bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as error: fail("malformed Sigstore bundle: " + str(error))
if bundle.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json": fail("unsupported bundle format")
material, message = bundle.get("verificationMaterial"), bundle.get("messageSignature")
if not isinstance(material, dict) or not isinstance(message, dict): fail("bundle has no verification material")
manifest_digest = hashlib.sha256(manifest.read_bytes()).digest()
message_digest = message.get("messageDigest")
if not isinstance(message_digest, dict) or message_digest.get("algorithm") != "SHA2_256" or decode(message_digest.get("digest"), "message digest") != manifest_digest: fail("signed digest does not match release-digests.txt")
certificate = material.get("certificate")
logs = material.get("tlogEntries")
if not isinstance(certificate, dict) or not isinstance(logs, list) or not logs or not isinstance(logs[0], dict): fail("certificate or transparency entry is missing")
try: attime = str(int(logs[0]["integratedTime"]))
except (KeyError, TypeError, ValueError): fail("transparency time is invalid")
root_cert = '''-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----\n'''
intermediate = '''-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----\n'''
with tempfile.TemporaryDirectory(prefix="o3k-installer-sigstore-") as temp:
    work = Path(temp); leaf = work / "leaf.der"; leaf.write_bytes(decode(certificate.get("rawBytes"), "certificate"))
    root = work / "root.pem"; root.write_text(root_cert); chain = work / "intermediate.pem"; chain.write_text(intermediate)
    openssl("verify", "-attime", attime, "-CAfile", str(root), "-untrusted", str(chain), str(leaf))
    public = work / "public.pem"; public.write_text(openssl("x509", "-inform", "DER", "-in", str(leaf), "-pubkey", "-noout"))
    if "URI:" + identity not in openssl("x509", "-inform", "DER", "-in", str(leaf), "-noout", "-ext", "subjectAltName"): fail("certificate identity is not the exact release tag")
    if "https://token.actions.githubusercontent.com" not in openssl("x509", "-inform", "DER", "-in", str(leaf), "-text", "-noout"): fail("GitHub OIDC issuer is not present")
    signature = work / "signature.der"; signature.write_bytes(decode(message.get("signature"), "signature"))
    openssl("dgst", "-sha256", "-verify", str(public), "-signature", str(signature), str(manifest))
entries = {}
for line in manifest.read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]) or fields[1] in entries: fail("malformed or duplicate digest entry")
    if fields[1].startswith("/") or ".." in Path(fields[1]).parts: fail("unsafe digest path")
    entries[fields[1]] = fields[0]
archive = f"o3k-{version}-linux-x86_64.tar.gz"
if archive not in entries or "provenance.json" not in entries or "install.sh" not in entries: fail("required release asset is absent from signed manifest")
try: provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as error: fail("malformed provenance: " + str(error))
if provenance.get("release") != tag or provenance.get("repository") != "o3kio/o3k" or provenance.get("workflow") != ".github/workflows/release.yml" or provenance.get("oidc_issuer") != "https://token.actions.githubusercontent.com": fail("provenance identity binding is wrong")
if provenance.get("self_digest_binding") != "release-digests.txt" or entries["provenance.json"] != hashlib.sha256(provenance_path.read_bytes()).hexdigest(): fail("provenance is not bound by the signed manifest")
entry = logs[0]
try:
    body_bytes = decode(entry.get("canonicalizedBody"), "transparency body")
    body = json.loads(body_bytes)
except (ValueError, TypeError, KeyError) as error: fail("malformed transparency body: " + str(error))
if body.get("spec", {}).get("data", {}).get("hash", {}).get("value") != hashlib.sha256(manifest.read_bytes()).hexdigest(): fail("transparency entry is for a different manifest")
proof = entry.get("inclusionProof")
checkpoint = proof.get("checkpoint") if isinstance(proof, dict) else None
if not isinstance(proof, dict) or not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("envelope"), str): fail("transparency proof is incomplete")
envelope = checkpoint["envelope"]
if "rekor.sigstore.dev" not in envelope: fail("transparency checkpoint is not from the governed Rekor log")
try:
    note, sigline = envelope.rsplit("\n\n", 1)
    _, signer, encoded = sigline.strip().split(" ", 2)
    checkpoint_signature = decode(encoded, "checkpoint signature")
    origin, tree_size_text, checkpoint_root = note.splitlines()[:3]
    tree_size = int(tree_size_text)
    checkpoint_root = decode(checkpoint_root, "checkpoint root hash")
except (ValueError, TypeError) as error: fail("malformed transparency checkpoint: " + str(error))
if signer != "rekor.sigstore.dev" or not origin.startswith("rekor.sigstore.dev - "): fail("checkpoint signer/origin is wrong")
proof_root = decode(proof.get("rootHash"), "inclusion proof root hash")
if tree_size != int(proof.get("treeSize", -1)) or checkpoint_root != proof_root: fail("checkpoint does not bind the inclusion proof root")
with tempfile.TemporaryDirectory(prefix="o3k-rekor-verify-") as rekor_temp:
 rekor_work = Path(rekor_temp)
 rekor_key = rekor_work / "rekor.pub"
 rekor_key.write_text("""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
""")
# Rekor's signed-note signature carries a four-byte public-key hash hint.
 key_der = subprocess.check_output(("openssl", "pkey", "-pubin", "-in", str(rekor_key), "-outform", "DER"), stderr=subprocess.STDOUT)
 if checkpoint_signature[:4] != hashlib.sha256(key_der).digest()[:4]: fail("checkpoint key hint does not match the pinned Rekor key")
 checkpoint_file = rekor_work / "checkpoint"; checkpoint_file.write_text(note + "\n")
 checkpoint_sig = rekor_work / "checkpoint.sig"; checkpoint_sig.write_bytes(checkpoint_signature[4:])
 openssl("dgst", "-sha256", "-verify", str(rekor_key), "-signature", str(checkpoint_sig), str(checkpoint_file))
try:
    index = int(proof.get("logIndex", -1)); hashes = proof.get("hashes")
    if index < 0 or index >= tree_size or not isinstance(hashes, list): raise ValueError("invalid inclusion coordinates")
    node = hashlib.sha256(b"\0" + decode(entry.get("canonicalizedBody"), "transparency body")).digest()
    inner = (index ^ (tree_size - 1)).bit_length(); border = (index >> inner).bit_count()
    if len(hashes) != inner + border: raise ValueError("wrong inclusion proof length")
    for level, encoded_hash in enumerate(hashes[:inner]):
        sibling = decode(encoded_hash, "inclusion proof hash")
        children = node + sibling if ((index >> level) & 1) == 0 else sibling + node
        node = hashlib.sha256(b"\1" + children).digest()
    for encoded_hash in hashes[inner:]: node = hashlib.sha256(b"\1" + decode(encoded_hash, "inclusion proof hash") + node).digest()
    if node != proof_root: raise ValueError("inclusion proof root mismatch")
except (ValueError, TypeError) as error: fail("invalid transparency inclusion proof: " + str(error))
print("release authenticity verified before extraction")
PY
}

wait_http_ok() { # wait_http_ok URL ATTEMPTS
  local url="$1" attempts="$2" attempt=1
  while [ "$attempt" -le "$attempts" ]; do
    if curl --fail --silent --output /dev/null --max-time 5 "$url"; then
      return 0
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
  return 1
}

# Idempotency notice — self-contained so the test matrix can exercise it with
# a faked manifest path in a subshell.
print_installed_notice() {
  if [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ]; then
    printf 'O3K v%s already installed\n' "${VERSION_NO_V:-}"
  fi
}

# ---- upgrade fence helpers (issue #626) ---------------------------------------
# compare_versions LEFT RIGHT — embedded python3 semver-with-prerelease
# comparison (the ADR-0130 release-version format: one or two numeric dots
# plus an optional dot-separated alphanumeric prerelease; a leading "v" is
# accepted and stripped). Exit codes: 0 = LEFT is older, 1 = equal,
# 2 = LEFT is newer, 3 = unparseable input (caller must fail closed).
# Deterministic and unit-tested by tests/installer-negative.sh (extracted via
# sed and driven with faked inputs, same mechanism as check_platform).
compare_versions() {
python3 - "$1" "$2" <<'PY'
import re
import sys


def parse(text):
    text = text.strip()
    if text.startswith("v"):
        text = text[1:]
    match = re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){1,2}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?", text
    )
    if match is None:
        return None
    body, _, prerelease = text.partition("-")
    numeric = [int(part) for part in body.split(".")]
    while len(numeric) < 3:
        numeric.append(0)
    identifiers = tuple(prerelease.split(".")) if prerelease else ()
    return numeric, identifiers


def identifier_key(identifier):
    return (0, int(identifier)) if identifier.isdigit() else (1, identifier)


def precedence(parsed):
    numeric, identifiers = parsed
    return tuple(numeric) + (0 if identifiers else 1,), tuple(
        identifier_key(item) for item in identifiers
    )


left = parse(sys.argv[1])
right = parse(sys.argv[2])
if left is None or right is None:
    sys.exit(3)
if precedence(left) < precedence(right):
    sys.exit(0)
if precedence(left) == precedence(right):
    sys.exit(1)
sys.exit(2)
PY
}

# read_installed_version MANIFEST — prints the installed release version, or
# nothing when the manifest is absent (fresh host). Unreadable/malformed
# manifests fail closed (exit 3). Self-contained for the test matrix.
read_installed_version() {
  local manifest="$1"
  [ -f "$manifest" ] || return 0
  [ ! -L "$manifest" ] || die "installed release manifest must not be a symlink: $manifest"
python3 - "$manifest" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        document = json.load(stream)
except (OSError, ValueError):
    print("O3K installer: installed release manifest is unreadable: %s" % sys.argv[1], file=sys.stderr)
    sys.exit(3)
version = document.get("version") if isinstance(document, dict) else None
if not isinstance(version, str) or not version.strip():
    print("O3K installer: installed release manifest declares no version: %s" % sys.argv[1], file=sys.stderr)
    sys.exit(3)
print(version.strip())
PY
}

# verify_delegation_sha256 DIR ASSET — the same strict published-digest gate
# the install path uses: exactly one `<64-hex>  <asset>` line naming the
# expected asset, then sha256sum --check --strict in DIR.
verify_delegation_sha256() {
  local dir="$1" asset="$2" lines fields digest name
  lines="$(awk 'END{print NR}' "$dir/$asset.sha256")"
  fields="$(awk 'NR==1{print NF}' "$dir/$asset.sha256")"
  digest="$(awk 'NR==1{print $1}' "$dir/$asset.sha256")"
  name="$(awk 'NR==1{print $2}' "$dir/$asset.sha256")"
  [ "$lines" = 1 ] && [ "$fields" = 2 ] \
    || die "published SHA-256 file is malformed: $asset.sha256"
  printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$' \
    || die "published SHA-256 file is malformed: $asset.sha256"
  [ "$name" = "$asset" ] \
    || die "published SHA-256 file names an unexpected asset: $name"
  (cd "$dir" && sha256sum -c --strict -- "$asset.sha256") \
    || die "published SHA-256 verification failed for $asset — refusing to extract or execute anything from the bundle"
}

# delegate_upgrade_download — verified delegation download for the
# installed < target case. Downloads tarball + published .sha256 + install.sh
# into O3K_UPGRADE_DOWNLOAD_DIR (0700), extracts the VERIFIED tarball next to
# them (so the printed `o3k upgrade` entry point exists), and prints the
# exact next command. Extracting a verified archive is not executing a
# downloaded script: the o3k upgrade engine re-downloads and re-verifies
# every asset itself before any mutation, so this copy is only an operator
# entry point, never trusted directly.
# Interrupted-delegation reuse: when the directory already holds the tarball
# and its .sha256, they are re-verified against the published digest and
# reused; a failed re-verification fails closed (remove the directory
# deliberately to force a fresh download).
delegate_upgrade_download() {
  local asset base dest reused=0 bundle_dir
  asset="o3k-${VERSION_NO_V}-linux-x86_64.tar.gz"
  base="$O3K_RELEASE_BASE/v$VERSION_NO_V"
  dest="$O3K_UPGRADE_DOWNLOAD_DIR"
  mkdir -p "$dest"
  chmod 700 "$dest"
  if [ -s "$dest/$asset" ] && [ -s "$dest/$asset.sha256" ]; then
    reused=1
    verify_delegation_sha256 "$dest" "$asset"
  else
    fetch "$base/$asset" "$dest/$asset"
    fetch "$base/$asset.sha256" "$dest/$asset.sha256"
    verify_delegation_sha256 "$dest" "$asset"
  fi
  # install.sh asset copy: a fresh atomic fetch every time (byte-identical to
  # the published GitHub Release asset; never executed by this installer).
  fetch "$base/install.sh" "$dest/install.sh.tmp"
  mv -- "$dest/install.sh.tmp" "$dest/install.sh"
  # Extract the verified tarball so `.../o3k-<target>/bin/o3k upgrade` exists
  # (entry point only; the engine re-verifies everything before mutating).
  # The tarball root is already `o3k-<version>/`, so extraction targets the
  # download directory itself (same convention as the install flow's
  # `safe_extract "$TMP_DIR/$ASSET" "$TMP_DIR" ...`).
  bundle_dir="$dest/o3k-${VERSION_NO_V}"
  if [ ! -x "$bundle_dir/bin/o3k" ]; then
    rm -rf -- "$bundle_dir"
    safe_extract "$dest/$asset" "$dest" "$dest/delegation-entries.txt"
  fi
  chmod 0600 "$dest/$asset" "$dest/$asset.sha256" "$dest/install.sh"
  if [ "$reused" -eq 1 ]; then
    step "upgrade download for O3K v$VERSION_NO_V re-verified ($dest)"
  else
    step "upgrade download for O3K v$VERSION_NO_V verified ($dest)"
  fi
  printf 'O3K v%s is installed; the installer never upgrades an existing installation automatically.\n' "${INSTALLED_VERSION#v}"
  printf 'Run: sudo %s/o3k-%s/bin/o3k upgrade\n' "$dest" "$VERSION_NO_V"
}

# check_upgrade_fence — compares the resolved TARGET version against the
# installed release (parsed from /usr/local/share/o3k/release-manifest.json;
# absent = fresh host). Runs after the platform guard and BEFORE any mutation.
check_upgrade_fence() {
  INSTALLED_VERSION="$(read_installed_version "$INSTALLED_MANIFEST")" \
    || die "installed release manifest is unreadable or declares no version: $INSTALLED_MANIFEST"
  [ -n "$INSTALLED_VERSION" ] || return 0 # fresh host: normal install flow
  set +e
  compare_versions "$INSTALLED_VERSION" "$VERSION"
  fence_status=$?
  set -e
  case "$fence_status" in
    0) # installed < target: verified delegation, then explicit operator action
       delegate_upgrade_download
       exit 0
       ;;
    1) # same version: the existing idempotent convergence flow below
       ;;
    2)
       die "installed v${INSTALLED_VERSION#v} is newer than requested v${VERSION#v}; refusing implicit downgrade"
       ;;
    *)
       die "cannot compare installed v${INSTALLED_VERSION#v} against requested v${VERSION#v}"
       ;;
  esac
}

# ---- platform and privilege guards -------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  printf 'O3K installer: root is required; run: curl -sfL https://get.o3k.io | sudo sh -\n' >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
check_platform "$(uname -s)" "$(uname -m)" "${ID:-}" "${VERSION_CODENAME:-}"

printf 'O3K Cloud OS — TestLab\n'
printf '✓ %s %s\n' "${PRETTY_NAME:-${ID:-unknown} ${VERSION_ID:-unknown}}" "$(uname -m)"

# ---- version resolution -------------------------------------------------------
# The version is baked into this file; the installer never consults a channel
# service. Explicit dev/test overrides take precedence.
VERSION="${O3K_VERSION:-${O3K_PINNED_VERSION:-$O3K_INSTALLER_VERSION}}"
VERSION="$(trim "$VERSION")"
[ -n "$VERSION" ] || die "no installer version resolved"
check_version_format "$VERSION"
VERSION_NO_V="${VERSION#v}"

# ---- upgrade fence (issue #626) — before ANY mutation -------------------------
# Fresh host -> normal install; same version -> idempotent convergence;
# newer installed version -> refuse implicit downgrade (exit 1); older
# installed version -> verified delegation download + printed
# `sudo .../bin/o3k upgrade` command, exit 0. curl|sh never auto-upgrades an
# existing install.
INSTALLED_MANIFEST=/usr/local/share/o3k/release-manifest.json
O3K_UPGRADE_DOWNLOAD_DIR="${O3K_UPGRADE_DOWNLOAD_DIR:-/var/lib/o3k/upgrade-download}"
check_upgrade_fence
print_installed_notice

# T0 marks the start of the real install path: it is stamped only after the
# upgrade fence has decided this run installs (the delegation and downgrade
# branches above exit without touching the timing ledger).
pp4_stamp T0
T0_EPOCH="$PP4_LAST_STAMP_EPOCH"

# ---- private temp dir + cleanup ----------------------------------------------
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/o3k-installer.XXXXXX")"
chmod 700 "$TMP_DIR"
trap 'rm -rf -- "$TMP_DIR"' EXIT
trap 'rm -rf -- "$TMP_DIR"; exit 130' INT
trap 'rm -rf -- "$TMP_DIR"; exit 143' TERM HUP

# Release authenticity is established before apt, libvirt, TLS, or any
# bundled application code is touched.  The digest manifest is downloaded
# separately from the archive and authenticated by the Sigstore bundle.
METADATA_DIR="$TMP_DIR/release-metadata"
mkdir -p -m 700 "$METADATA_DIR"
METADATA_BASE="$O3K_RELEASE_BASE/v$VERSION_NO_V"
fetch "$METADATA_BASE/release-digests.txt" "$METADATA_DIR/release-digests.txt"
fetch "$METADATA_BASE/release-digests.sigstore.json" "$METADATA_DIR/release-digests.sigstore.json"
fetch "$METADATA_BASE/provenance.json" "$METADATA_DIR/provenance.json"
verify_release_metadata "$METADATA_DIR" "$VERSION"
step 'release authenticity verified (Sigstore identity/transparency)'

# ---- host dependencies (the one place apt is allowed) -------------------------
# Mirror the proven clean-VM set (asr-021-cd15263/vm-run.sh cloud-init):
# ca-certificates curl libvirt-daemon-system libvirt-clients qemu-utils
# iproute2 dnsmasq-base polkitd genisoimage python3 python3-openstackclient,
# with the distro-specific QEMU package (Ubuntu 24.04: qemu-kvm; Debian 12:
# qemu-system-x86), plus openssl (bootstrap-certs.sh) and openssh-client
# (ssh-keygen in bootstrap-testlab.sh), plus binutils (readelf for the bundled
# verify-release-bundle.sh glibc floor check). libvirtd is enabled/started
# exactly like the proven VM setup did. No netplan/NAT/sysctl/host-network
# writes.
printf 'installing host dependencies (apt)\n'
APT_PACKAGES="ca-certificates curl openssl openssh-client binutils libvirt-daemon-system libvirt-clients qemu-utils iproute2 dnsmasq-base polkitd genisoimage python3 python3-openstackclient"
case "$ID:$VERSION_CODENAME" in
  ubuntu:noble) APT_PACKAGES="$APT_PACKAGES qemu-kvm" ;;
  debian:bookworm) APT_PACKAGES="$APT_PACKAGES qemu-system-x86" ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
# shellcheck disable=SC2086
apt-get install -y $APT_PACKAGES
systemctl enable --now libvirtd
step 'dependencies ready'

# ---- download the certified release bundle ------------------------------------
ASSET="o3k-${VERSION_NO_V}-linux-x86_64.tar.gz"
ASSET_URL="$O3K_RELEASE_BASE/v$VERSION_NO_V/$ASSET"
printf 'downloading %s\n' "$ASSET"
fetch "$ASSET_URL" "$TMP_DIR/$ASSET"
# SHA-256 remains useful convenience/integrity data, but it is not the
# authenticity root.  Obtain the expected archive digest only from the
# authenticated release-digests.txt and compare the optional .sha256 file to
# that value when present.
ARCHIVE_DIGEST="$(python3 - "$METADATA_DIR/release-digests.txt" "$ASSET" <<'PY'
import re, sys
matches = []
for line in open(sys.argv[1], encoding="utf-8"):
    fields = line.split()
    if len(fields) == 2 and fields[1] == sys.argv[2]: matches.append(fields[0])
if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0]):
    raise SystemExit("authenticated release manifest has no unique archive digest")
print(matches[0])
PY
)" || die 'authenticated release manifest could not provide an archive digest'
printf '%s  %s\n' "$ARCHIVE_DIGEST" "$ASSET" | (cd "$TMP_DIR" && sha256sum -c --strict -) \
  || die "release archive digest mismatch — refusing to extract or execute anything from the bundle"
fetch "$ASSET_URL.sha256" "$TMP_DIR/$ASSET.sha256"
CONVENIENCE_LINE="$(sed -n '1p' "$TMP_DIR/$ASSET.sha256")"
if [ "$CONVENIENCE_LINE" != "$ARCHIVE_DIGEST  $ASSET" ] && [ "$CONVENIENCE_LINE" != "$ARCHIVE_DIGEST *$ASSET" ]; then
  die "convenience SHA-256 file disagrees with authenticated release-digests.txt"
fi
step 'release archive digest verified from authenticated manifest'

# ---- safe extraction ----------------------------------------------------------
safe_extract "$TMP_DIR/$ASSET" "$TMP_DIR" "$TMP_DIR/entries.txt"
BUNDLE_DIR="$TMP_DIR/o3k-$VERSION_NO_V"
[ -d "$BUNDLE_DIR" ] || die "release archive does not contain the expected bundle directory: o3k-$VERSION_NO_V"

# Only now, after the archive bytes are authenticated and safely extracted, use
# internal metadata.  Cross-check it against the already trusted external
# provenance before invoking any script from the bundle.
python3 - "$METADATA_DIR/provenance.json" "$BUNDLE_DIR/manifest.json" "$VERSION_NO_V" <<'PY'
import json, sys
try:
    external = json.load(open(sys.argv[1], encoding="utf-8"))
    internal = json.load(open(sys.argv[2], encoding="utf-8"))
except (OSError, ValueError) as error:
    raise SystemExit("O3K installer: extracted release metadata is unreadable: " + str(error))
if external.get("source_commit") != internal.get("source_commit"):
    raise SystemExit("O3K installer: extracted source_commit disagrees with authenticated provenance")
if internal.get("version") not in (sys.argv[3], "v" + sys.argv[3]):
    raise SystemExit("O3K installer: extracted manifest version disagrees with the authenticated release tag")
PY

# ---- bundled integrity and preflight ------------------------------------------
bash "$BUNDLE_DIR/packaging/verify-release-bundle.sh" "$BUNDLE_DIR" \
  || die "release bundle verification failed for o3k-$VERSION_NO_V"
step "O3K v$VERSION_NO_V verified"
bash "$BUNDLE_DIR/packaging/preflight.sh" --profile libvirt --data-dir /var/lib/o3k \
  || die "preflight failed (--profile libvirt --data-dir /var/lib/o3k): the host does not meet the certified TestLab requirements"
step 'KVM available'

# ---- TLS identities: preserve complete set, bootstrap only when absent --------
TLS_DIR=/etc/o3k/tls
TLS_FILES="ca.pem server.pem server-key.pem agent.pem agent-key.pem agent-id agent-fingerprint"
tls_present=0
for file in $TLS_FILES; do
  if [ -e "$TLS_DIR/$file" ] || [ -L "$TLS_DIR/$file" ]; then
    [ -f "$TLS_DIR/$file" ] && [ ! -L "$TLS_DIR/$file" ] && [ -s "$TLS_DIR/$file" ] \
      || die "TLS identity is not a regular non-empty file: $TLS_DIR/$file"
    tls_present=$((tls_present + 1))
  fi
done
if [ "$tls_present" -eq 7 ]; then
  step 'TLS identities preserved'
elif [ "$tls_present" -eq 0 ]; then
  bash "$BUNDLE_DIR/packaging/bootstrap-certs.sh" \
    --output-dir "$TLS_DIR" --server-name o3k-control-plane --agent-id compute-agent \
    || die 'TLS bootstrap failed'
  step 'mTLS identities ready'
else
  die "partial TLS identity set under $TLS_DIR ($tls_present of 7 files) — refusing to regenerate valid identities; complete the set manually (never use --force)"
fi

# ---- install from the verified bundle -----------------------------------------
# install.sh discovers bin/o3k-network inside the extracted bundle itself and
# installs it (with its unit, not enabled) when present — no extra flag needed.
# --defer-compute-start keeps the compute agent stopped so the canonical join
# below wins the NodeRegistry epoch race (see the canonical bootstrap section).
bash "$BUNDLE_DIR/packaging/install.sh" --profile libvirt --noninteractive \
  --defer-compute-start \
  --binary "$BUNDLE_DIR/bin/o3kd" --compute-binary "$BUNDLE_DIR/bin/o3k-compute" \
  --o3k-binary "$BUNDLE_DIR/bin/o3k" \
  || die 'installation failed; the host holds recoverable O3K-owned state and re-running the installer converges'
step 'o3kd installed'
step 'o3k-compute installed'

# PP.4 timing ledger: /var/lib/o3k exists from here on. Persist T0 (taken
# before the data dir existed); T1/T2/T5 append at their own sites below.
if [ -n "${T0_EPOCH:-}" ]; then
  if [ ! -f "$PP4_TS_FILE" ]; then
    ( umask 077 && : > "$PP4_TS_FILE" ) 2>/dev/null || true
  fi
  printf 'T0=%s\n' "$T0_EPOCH" >> "$PP4_TS_FILE" 2>/dev/null || true
fi

# ---- canonical P15.6 bootstrap (contracts/installer-v1.yaml) -------------------
# The installer is orchestration ONLY: it never fabricates topology, Placement
# providers, BuildingBlocks, CloudProfile state, agent identity, or readiness.
# Canonical init creates the CloudProfile + one-time enrollment grant; the
# authenticated join enrolls this host's agent identity (the mTLS certificate
# minted above) and creates exactly one local BuildingBlock with Placement
# inventory. Idempotent by construction: a repeated init converges on the
# durable profile and issues a fresh grant; a replayed join short-circuits on
# the durable enrolled-agent projection without consuming a second grant.
ENV_FILE=/etc/o3k/o3kd.env
O3K_BIN=/usr/local/bin/o3k
API_URL=http://127.0.0.1:18080/o3k/v1

# Read one shell-quoted scalar from the daemon env file. The generated
# secrets are hex-only, so %q quoting is always plain; anything else fails
# closed instead of misparsing a credential.
read_env_scalar() {
  key="$1"
  value=$(awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$ENV_FILE")
  case "$value" in
    ""|*[!0-9a-fA-F]*) die "$key is missing or not a plain hex value in $ENV_FILE" ;;
  esac
  printf '%s' "$value"
}

wait_http_ok http://127.0.0.1:18080/healthz 30 \
  || die 'o3kd did not become healthy (http://127.0.0.1:18080/healthz)'
step 'control plane ready'

BOOTSTRAP_SECRET=$(read_env_scalar O3K_BOOTSTRAP_SECRET)
AGENT_ID=$(cat "$TLS_DIR/agent-id" 2>/dev/null || true)
case "$AGENT_ID" in *[!A-Za-z0-9._-]*|'') die "agent identity is invalid: $TLS_DIR/agent-id" ;; esac
VCPUS=$(nproc 2>/dev/null || true)
MEMORY_MB=$(awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo)
DISK_GB=$(awk -F= '$1 == "O3K_COMPUTE_MAX_DISK_GB" {sub(/^[^=]*=/, ""); print; exit}' /etc/o3k/o3k-compute.env)
[ -n "$DISK_GB" ] || DISK_GB=10
case "$VCPUS" in ''|*[!0-9]*) die 'host inventory is unavailable (vcpus)' ;; esac
case "$MEMORY_MB" in ''|*[!0-9]*) die 'host inventory is unavailable (memory)' ;; esac
case "$DISK_GB" in ''|*[!0-9]*) die 'host inventory is unavailable (disk)' ;; esac

RUNUSER_BIN=$(command -v runuser || true)
[ -n "$RUNUSER_BIN" ] || RUNUSER_BIN=/usr/sbin/runuser
[ -x "$RUNUSER_BIN" ] || die 'runuser is unavailable; cannot invoke canonical bootstrap as the o3k service account'

# Secret-carrying fragments for the canonical CLI. They live in the o3k-owned
# 0700 data directory as o3k-owned 0600 files and are removed immediately
# after each command: secrets travel via file descriptors and file contents,
# never through argv (world-readable /proc/<pid>/cmdline) or logs. A SIGKILL
# leftover is root/compute-unreadable, o3k-readable only, and the enrollment
# grant it may contain expires after 5 minutes.
SECRET_DIR=/var/lib/o3k
BOOTSTRAP_SECRET_FILE="$SECRET_DIR/.installer-bootstrap-secret"
ENROLLMENT_TOKEN_FILE="$SECRET_DIR/.installer-enrollment-token"
write_secret_file() { # write_secret_file PATH CONTENT — root writes, o3k owns, 0600.
  install -o o3k -g o3k -m 0600 /dev/null "$1" \
    || die "cannot create secret file: $1"
  printf '%s' "$2" >"$1" || die "cannot write secret file: $1"
}

wait_http_ok http://127.0.0.1:18080/healthz 30 \
  || die 'o3kd did not become healthy (http://127.0.0.1:18080/healthz)'
step 'control plane ready'

BOOTSTRAP_SECRET=$(read_env_scalar O3K_BOOTSTRAP_SECRET)
AGENT_ID=$(cat "$TLS_DIR/agent-id" 2>/dev/null || true)
case "$AGENT_ID" in *[!A-Za-z0-9._-]*|'') die "agent identity is invalid: $TLS_DIR/agent-id" ;; esac
VCPUS=$(nproc 2>/dev/null || true)
MEMORY_MB=$(awk '/^MemTotal:/ {print int($2 / 1024); exit}' /proc/meminfo)
DISK_GB=$(awk -F= '$1 == "O3K_COMPUTE_MAX_DISK_GB" {sub(/^[^=]*=/, ""); print; exit}' /etc/o3k/o3k-compute.env)
[ -n "$DISK_GB" ] || DISK_GB=10
case "$VCPUS" in ''|*[!0-9]*) die 'host inventory is unavailable (vcpus)' ;; esac
case "$MEMORY_MB" in ''|*[!0-9]*) die 'host inventory is unavailable (memory)' ;; esac
case "$DISK_GB" in ''|*[!0-9]*) die 'host inventory is unavailable (disk)' ;; esac

# Canonical init, executed as the o3k service account. The response (which
# carries the one-time enrollment token) goes to a root-owned 0600 temporary
# file opened by this shell before privilege drop; it is parsed and destroyed
# immediately and is never printed.
INIT_OUT="$TMP_DIR/o3k-init.json"
( umask 077 && : >"$INIT_OUT" )
write_secret_file "$BOOTSTRAP_SECRET_FILE" "$BOOTSTRAP_SECRET"
"$RUNUSER_BIN" -u o3k -- env O3K_API_URL="$API_URL" \
  O3K_BOOTSTRAP_SECRET_FILE="$BOOTSTRAP_SECRET_FILE" \
  "$O3K_BIN" init --agent-id "$AGENT_ID" \
  >"$INIT_OUT" || { rm -f -- "$BOOTSTRAP_SECRET_FILE"; die 'canonical o3k init failed (see o3kd logs: journalctl -u o3kd)'; }
rm -f -- "$BOOTSTRAP_SECRET_FILE"
ENROLLMENT_TOKEN=$(python3 - "$INIT_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
token = response.get("enrollment_token")
if not isinstance(token, str) or not token:
    raise SystemExit("canonical init did not return an enrollment token")
print(token)
PY
) || die 'canonical init response was invalid'
rm -f -- "$INIT_OUT"
step 'canonical bootstrap initialized (CloudProfile + enrollment grant)'

# Authenticated canonical join. A bounded retry converges across a transient
# store/provider conflict; the grant stays single-use either way. The token
# reaches the CLI through an o3k-owned 0600 file, never argv.
JOIN_OUT="$TMP_DIR/o3k-join.json"
( umask 077 && : >"$JOIN_OUT" "$TMP_DIR/o3k-join.err" )
AGENT_EPOCH=$(openssl rand -hex 16)
write_secret_file "$ENROLLMENT_TOKEN_FILE" "$ENROLLMENT_TOKEN"
join_ok=0
join_attempt=1
while [ "$join_attempt" -le 5 ]; do
  if "$RUNUSER_BIN" -u o3k -- env O3K_API_URL="$API_URL" \
      O3K_ENROLLMENT_TOKEN_FILE="$ENROLLMENT_TOKEN_FILE" "$O3K_BIN" join \
      --agent-id "$AGENT_ID" --agent-epoch "$AGENT_EPOCH" \
      --certificate "$TLS_DIR/agent.pem" \
      --vcpus "$VCPUS" --memory-mb "$MEMORY_MB" --disk-gb "$DISK_GB" \
      >"$JOIN_OUT" 2>"$TMP_DIR/o3k-join.err"; then
    join_ok=1
    break
  fi
  if [ "$join_attempt" -lt 5 ]; then
    printf 'canonical authenticated o3k join attempt %s/5 did not converge; retrying\n' "$join_attempt" >&2
    sleep 2
  fi
  join_attempt=$((join_attempt + 1))
done
rm -f -- "$ENROLLMENT_TOKEN_FILE"
if [ "$join_ok" -ne 1 ]; then
  printf 'O3K installer: canonical authenticated o3k join failed: %s\n' \
    "$(tail -1 "$TMP_DIR/o3k-join.err" 2>/dev/null || echo 'no response')" >&2
  exit 1
fi
BUILDING_BLOCK_ID=$(python3 - "$JOIN_OUT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    response = json.load(stream)
block = response.get("building_block_id")
if not isinstance(block, str) or not block:
    raise SystemExit("canonical join did not return a building block id")
print(block)
PY
) || BUILDING_BLOCK_ID='(unavailable)'
rm -f -- "$JOIN_OUT" "$TMP_DIR/o3k-join.err"
step "canonical authenticated join complete (BuildingBlock $BUILDING_BLOCK_ID)"
pp4_stamp T2

# Only after canonical join does the compute agent start: its first
# registration adopts the join-established identity instead of fencing it.
systemctl start o3k-compute.service \
  || die 'o3k-compute.service failed to start'
wait_http_ok http://127.0.0.1:9100/readyz 90 \
  || die 'o3k-compute did not become ready (http://127.0.0.1:9100/readyz)'
step 'compute agent ready'
wait_http_ok http://127.0.0.1:18080/readyz 120 \
  || die 'o3kd did not reach canonical readiness (http://127.0.0.1:18080/readyz)'
step 'control plane ready (canonical readiness)'
pp4_stamp T1

# Canonical diagnostics gate: `o3k doctor` must report no failing checks.
# A fresh installation legitimately carries advisory WARNs (for example
# "no O3K-created backup exists yet"), which yields overall "warning" and
# exit 1 — that is still a successful diagnostic run. Only "unhealthy"
# (any FAIL) or a doctor invocation error (exit 2) fails the install.
DOCTOR_VERDICT=""
doctor_attempt=1
while [ "$doctor_attempt" -le 30 ]; do
  doctor_rc=0
  DOCTOR_OUT="$("$O3K_BIN" doctor --json 2>/dev/null)" || doctor_rc=$?
  if [ "$doctor_rc" -eq 2 ]; then
    die 'o3k doctor could not produce a report (usage or serialization error)'
  fi
  if [ "$doctor_rc" -le 1 ] && [ -n "$DOCTOR_OUT" ]; then
    DOCTOR_VERDICT="$(printf '%s' "$DOCTOR_OUT" | python3 -c '
import json
import sys

try:
    print(json.load(sys.stdin)["overall_status"])
except Exception:
    print("unknown")
')"
    if [ "$DOCTOR_VERDICT" = healthy ] || [ "$DOCTOR_VERDICT" = warning ]; then
      break
    fi
  fi
  DOCTOR_VERDICT=""
  sleep 5
  doctor_attempt=$((doctor_attempt + 1))
done
if [ -z "$DOCTOR_VERDICT" ]; then
  # Preserve the failing report for the operator before aborting.
  DOCTOR_DIAG=/var/log/o3k/installer-doctor-last.json
  if [ -n "${DOCTOR_OUT:-}" ]; then
    ( umask 077 && printf '%s\n' "$DOCTOR_OUT" >"$DOCTOR_DIAG" ) \
      && printf 'O3K installer: the failing doctor report is preserved at %s (root 0600)\n' "$DOCTOR_DIAG" >&2
  fi
  die 'o3k doctor reported failing checks; the installation is not healthy'
fi
unset DOCTOR_OUT
step 'o3k doctor healthy'

# ---- bounded demo cloud (public APIs only) ------------------------------------
# Creates the frozen o3k-demo-v1 workload (CirrOS image, TestLab flavor,
# bounded flat network, keypair, test-vm) through the supported public CLI
# after canonical bootstrap. The script fails closed unless the canonical
# bootstrap state is durably ready; it fabricates nothing itself.
bash "$BUNDLE_DIR/packaging/bootstrap-testlab.sh" || die 'TestLab bootstrap failed'
pp4_stamp T5
O3K_MANIFEST_SOURCE="$(python3 - "$BUNDLE_DIR/manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    document = json.load(handle)
sha = document.get("source_commit") if isinstance(document, dict) else None
if not isinstance(sha, str) or not sha.strip():
    raise SystemExit("O3K installer: release bundle manifest declares no source_commit")
print(sha.strip())
PY
)" || die 'release bundle manifest is missing source_commit'

# ---- optional Araf demo stage (PP.4A; issue #1029) -----------------------------
# PP.4 Core campaigns may set O3K_SKIP_ARAF=1 to certify the Cloud Kernel and
# bounded OpenStack compatibility without downloading or starting a separately
# versioned dashboard. The default remains the historical demo path so the
# PP.3/PP.4A integration entrypoint and its contracts are preserved.
if [ "${O3K_SKIP_ARAF:-0}" = 1 ]; then
  printf 'Araf demo stage skipped by O3K_SKIP_ARAF=1 (PP.4 Core; PP.4A remains available separately)\n'
  printf '\nO3K Core demo ready\n\n'
  printf 'O3K:\n'
  printf '  version: %s\n' "$VERSION"
  printf '  source: %s\n' "$O3K_MANIFEST_SOURCE"
  printf '  BuildingBlock: %s\n' "$BUILDING_BLOCK_ID"
  printf 'OpenStack compatibility: source /etc/o3k/admin-openrc, then: openstack server list\n'
  printf 'Araf: not deployed (PP.4A #1029)\n'
  exit 0
fi

# ---- Araf demo material and deployment (PP.4A; issue #1029) --------------------
# Install the demo deployment material from the VERIFIED bundle into the O3K
# share dir so post-reboot / convergent reruns work without the bundle
# (o3k-araf-demo.sh resolves its compose material relative to its own path).
# Convergent by content (cmp -s || install), root:root, modes pinned.
DEMO_SHARE_DIR=/usr/local/share/o3k/araf-demo
install -d -m 0755 "$DEMO_SHARE_DIR"
install -d -m 0755 "$DEMO_SHARE_DIR/araf-demo"
install -m 0755 "$BUNDLE_DIR/packaging/o3k-araf-demo.sh" "$DEMO_SHARE_DIR/o3k-araf-demo.sh"
for demo_file in compose.yaml nginx.conf api-relay.conf realm.json README.md; do
  if [ -f "$DEMO_SHARE_DIR/araf-demo/$demo_file" ] \
    && cmp -s "$BUNDLE_DIR/packaging/araf-demo/$demo_file" "$DEMO_SHARE_DIR/araf-demo/$demo_file"; then
    continue # already installed, byte-identical
  fi
  install -m 0644 "$BUNDLE_DIR/packaging/araf-demo/$demo_file" "$DEMO_SHARE_DIR/araf-demo/$demo_file"
done
step 'Araf demo material installed (O3K share dir)'

# Deploy the pinned O3K + Araf demo tuple. Fail closed: a demo-stage failure
# aborts the installer with a retry hint. The message states the O3K readiness
# it actually observed (never a blind "O3K is healthy" claim). The demo script
# appends T3 to the timing ledger via PP4_TIMESTAMPS_FILE.
if ! PP4_TIMESTAMPS_FILE="$PP4_TS_FILE" bash "$BUNDLE_DIR/packaging/o3k-araf-demo.sh" install; then
  if wait_http_ok http://127.0.0.1:18080/readyz 15; then
    die 'Araf demo deployment failed; O3K is installed and its control plane is ready — retry the demo stage with: sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh install'
  fi
  die "Araf demo deployment failed and o3kd is NOT ready (http://127.0.0.1:18080/readyz): inspect 'systemctl status o3kd' and 'journalctl -u o3kd', then retry the demo stage with: sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh install"
fi
step 'Araf demo deployed (pinned tuple)'

# Demo tuple for the success block: Araf values from the demo script (which
# reads the INSTALLED release manifest for the O3K side, so this runs only
# after install.sh above).
ARAF_TUPLE="$(bash "$BUNDLE_DIR/packaging/o3k-araf-demo.sh" tuple)" \
  || die 'could not read the pinned demo tuple from the installed release manifest'
ARAF_TUPLE_VERSION="$(printf '%s\n' "$ARAF_TUPLE" | sed -n 's/^ARAF_VERSION=//p')"
ARAF_TUPLE_SOURCE="$(printf '%s\n' "$ARAF_TUPLE" | sed -n 's/^ARAF_SOURCE_SHA=//p')"
[ -n "$ARAF_TUPLE_VERSION" ] && [ -n "$ARAF_TUPLE_SOURCE" ] \
  || die 'demo tuple output is missing ARAF_VERSION/ARAF_SOURCE_SHA'
printf '\nO3K demo ready\n\n'
printf 'O3K:\n'
printf '  version: %s\n' "$VERSION"
printf '  source: %s\n' "$O3K_MANIFEST_SOURCE"
printf '  BuildingBlock: %s\n' "$BUILDING_BLOCK_ID"
printf 'Araf:\n'
printf '  version: %s\n' "$ARAF_TUPLE_VERSION"
printf '  source: %s\n' "$ARAF_TUPLE_SOURCE"
printf 'Tenant Console:   https://tenant.o3k.demo/   (trust /var/lib/o3k/araf-demo/tls/ca.crt)\n'
printf 'Operator Console: https://operator.o3k.demo/\n'
printf 'O3K API:          https://api.o3k.demo/\n'
printf 'CLI configuration: /etc/o3k/clouds.yaml (+ /etc/o3k/admin-openrc)\n'
printf 'OpenStack compatibility: source /etc/o3k/admin-openrc, then: openstack server list\n'
printf 'Demo login: alice — credentials file /var/lib/o3k/araf-demo/credentials.txt (root 0600, never printed)\n'
printf 'Next:\n'
printf '  openstack server list\n'
printf '  openstack console log show test-vm\n'
printf '  sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh status\n'
printf 'Uninstall:\n'
printf '  sudo /usr/local/share/o3k/araf-demo/o3k-araf-demo.sh uninstall   (Araf demo)\n'
printf '  sudo bash /usr/local/share/o3k/uninstall.sh --yes                (O3K)\n'
