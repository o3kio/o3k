#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/var/tmp}/o3k-p15-7-preflight.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
fake="$work/bin"; mkdir -p "$fake"
for cmd in virsh docker curl; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$fake/$cmd"; chmod +x "$fake/$cmd"
done
cat >"$fake/virsh" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == "-c qemu:///system nodeinfo" ]]; then
  printf 'CPU(s): 8\nMemory size: 16384000 KiB\n'
fi
SH
chmod +x "$fake/virsh"
printf 'kvm\n' >"$work/kvm"
mkdir -p "$work/libvirt-images"
cat >"$work/exchange.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cp "$O3K_P15_7_TEST_ENVELOPE" "$O3K_P15_7_AUTHORITY_OUTPUT_FILE"
SH
chmod +x "$work/exchange.sh"
sha="$(git -C "$root_dir" rev-parse HEAD)"
export O3K_PREFLIGHT_TEST_WORK="$work" O3K_PREFLIGHT_TEST_FAKE="$fake" O3K_PREFLIGHT_TEST_SHA="$sha" O3K_PREFLIGHT_TEST_ROOT="$root_dir"
cat >"$work/run-case.sh" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
case_name="$1"; expected="$2"; shift 2
work="${O3K_PREFLIGHT_TEST_WORK:?}"; fake="${O3K_PREFLIGHT_TEST_FAKE:?}"; sha="${O3K_PREFLIGHT_TEST_SHA:?}"
root_dir="${O3K_PREFLIGHT_TEST_ROOT:?}"
out="$work/$case_name"; mkdir -p "$out"
env \
  PATH="$fake:$PATH" \
  O3K_REAL_HOST_KVM_PATH="$work/kvm" \
  O3K_P15_7_LIBVIRT_IMAGE_ROOT="$work/libvirt-images" \
  RUNNER_TEMP="$out" \
  O3K_REAL_HOST_ARTIFACT_DIR="$out" \
  O3K_P15_7_PREFLIGHT_ARTIFACT="$out/preflight.json" \
  O3K_P15_7_SOURCE_SHA="$sha" GITHUB_SHA="$sha" GITHUB_RUN_ID="$case_name" \
  O3K_P15_7_OIDC_ISSUER=https://issuer.example.test \
  O3K_P15_7_OIDC_AUDIENCE=o3k \
  O3K_P15_7_OIDC_DISCOVERY_URL=https://issuer.example.test/.well-known/openid-configuration \
  ACTIONS_ID_TOKEN_REQUEST_URL=https://token.actions.example.test \
  ACTIONS_ID_TOKEN_REQUEST_TOKEN=oidc-request-token \
  O3K_P15_7_OPERATOR_EXCHANGE_COMMAND="$work/exchange.sh" \
  O3K_P15_7_TEST_ENVELOPE="$work/$case_name.json" \
  "$@" bash "$root_dir/scripts/p15-7-protected-preflight.sh" >/dev/null 2>"$out/stderr" || rc=$?
rc=${rc:-0}
if [[ "$expected" == pass ]]; then [[ "$rc" == 0 ]] || { cat "$out/stderr" >&2; exit 1; }; else [[ "$rc" != 0 ]] || exit 1; fi
python3 - "$out/preflight.json" "$expected" <<'PY'
import json,sys
d=json.load(open(sys.argv[1], encoding='utf-8'))
assert d['redacted'] is True
assert ('passed' if sys.argv[2]=='pass' else 'blocked') == d['status']
assert 'secret-token' not in json.dumps(d)
PY
if [[ "$expected" == pass ]]; then
  token="$out/o3k-p15-7-operator-${case_name}.token"
  marker="${token}.o3k-owned"
  test -f "$token" && test "$(stat -c '%a' "$token")" = 600
  test -f "$marker" && test "$(stat -c '%a' "$marker")" = 600
  ! grep -Fq 'secret-token' "$out/stderr"
  rm -f -- "$token" "$marker"
fi
SH
chmod +x "$work/run-case.sh"
make_envelope() {
  local name="$1" scope="$2" role="$3" iss="$4" aud="$5" exp="$6"
  python3 - "$work/$name.json" "$scope" "$role" "$iss" "$aud" "$exp" <<'PY'
import json,sys
path,scope,role,iss,aud,exp=sys.argv[1:]
json.dump({'token':'secret-token','claims':{'iss':iss,'aud':aud,'scope':scope,'roles':[role],'exp':int(exp)},
           'authority_source':'oidc-federated','signature_verified':True},open(path,'w'))
PY
}
future="$(( $(date +%s) + 3600 ))"
make_envelope valid system operator https://issuer.example.test o3k "$future"
"$work/run-case.sh" valid pass
for spec in \
  "project_scope project operator https://issuer.example.test o3k $future" \
  "non_operator system member https://issuer.example.test o3k $future" \
  "wrong_issuer system operator https://wrong.example.test o3k $future" \
  "wrong_audience system operator https://issuer.example.test other $future" \
  "expired system operator https://issuer.example.test o3k 1" \
  "short_ttl system operator https://issuer.example.test o3k $(( $(date +%s) + 10 ))"; do
  read -r name scope role iss aud exp <<<"$spec"
  make_envelope "$name" "$scope" "$role" "$iss" "$aud" "$exp"
  "$work/run-case.sh" "$name" fail
done
make_envelope unverified system operator https://issuer.example.test o3k "$future"
python3 - "$work/unverified.json" <<'PY'
import json,sys
path=sys.argv[1]
d=json.load(open(path, encoding='utf-8')); d['signature_verified']=False
json.dump(d, open(path, 'w', encoding='utf-8'))
PY
"$work/run-case.sh" unverified fail
rm -f "$work/missing.json"
if env PATH="$fake:$PATH" O3K_REAL_HOST_KVM_PATH="$work/kvm" O3K_P15_7_LIBVIRT_IMAGE_ROOT="$work/libvirt-images" O3K_REAL_HOST_ARTIFACT_DIR="$work/missing" \
  O3K_P15_7_SOURCE_SHA="$sha" GITHUB_SHA="$sha" GITHUB_RUN_ID=missing \
  O3K_P15_7_OIDC_ISSUER=https://issuer.example.test O3K_P15_7_OIDC_AUDIENCE=o3k \
  O3K_P15_7_OIDC_DISCOVERY_URL=https://issuer.example.test/.well-known/openid-configuration \
  bash "$root_dir/scripts/p15-7-protected-preflight.sh"; then
  echo "missing authority was accepted" >&2; exit 1
fi
echo "P15.7 protected preflight tests passed"
