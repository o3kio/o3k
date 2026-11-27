#!/usr/bin/env bash
# Promote the authenticated and qualified draft v0.4.1 assets without rebuilding.
set -Eeuo pipefail

TAG="${1:-}"
OWNER_GO="${O3K_EA_OWNER_GO:-}"
[[ "$TAG" == v0.4.1 ]] || { echo "only v0.4.1 can be promoted by this workflow" >&2; exit 2; }
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$DIST_DIR"' EXIT

release_json="$(gh api "repos/o3kio/o3k/releases/tags/$TAG")"
release_id="$(jq -r '.id' <<<"$release_json")"
[[ "$(jq -r '.draft' <<<"$release_json")" == true ]] || {
  echo "$TAG must exist as a draft before promotion" >&2
  exit 1
}
asset_snapshot="$(jq -S '[.assets[] | {id, name, size, digest}] | sort_by(.name)' <<<"$release_json")"

gh release download "$TAG" --dir "$DIST_DIR"
"$ROOT_DIR/packaging/verify-release-sigstore.sh" "$TAG" "$DIST_DIR"
artifact="$DIST_DIR/o3k-0.4.1-linux-x86_64.tar.gz"
digest="$(sha256sum "$artifact" | awk '{print $1}')"
published_digest="$(awk 'NR == 1 { print $1 }' "$artifact.sha256")"
[[ "$digest" =~ ^[0-9a-f]{64}$ && "$digest" == "$published_digest" ]] || {
  echo "staged v0.4.1 archive digest mismatch" >&2
  exit 1
}

owner_go_prefix="EA-OWNER-GO: sha256:$digest "
[[ "$OWNER_GO" == "$owner_go_prefix"* ]] || {
  echo "promotion requires owner GO bound to the staged archive digest and evidence URL" >&2
  exit 1
}
evidence_url="${OWNER_GO#"$owner_go_prefix"}"
[[ "$evidence_url" =~ ^https://[^[:space:]]+$ ]] || {
  echo "owner GO evidence URL must use HTTPS" >&2
  exit 1
}
gh api repos/o3kio/o3k/issues/1241 --jq '.labels[].name' | grep -Fxq ea-final-go || {
  echo "promotion requires the ea-final-go label on issue #1241" >&2
  exit 1
}
owner_go_comment_count="$(gh api --paginate repos/o3kio/o3k/issues/1241/comments \
  | jq -s --arg digest "$digest" --arg evidence_url "$evidence_url" \
    'add | [.[] | select(.user.login == "senolcolak" and (.body | contains("EA-OWNER-GO")) and (.body | contains("SPEC-0052 acceptance evidence:")) and (.body | contains("sha256:" + $digest)) and (.body | contains($evidence_url)))] | length')"
[[ "$owner_go_comment_count" =~ ^[1-9][0-9]*$ ]] || {
  echo "owner-authored SPEC-0052 evidence comment for the staged digest is missing" >&2
  exit 1
}

# Recheck the same draft and the exact asset identities after verification.
# A delete/re-upload changes asset IDs, while changed bytes fail the signed
# digest verification above. The workflow concurrency group serializes other
# promotion runs; this last snapshot check fails closed on an intervening edit.
latest_release_json="$(gh api "repos/o3kio/o3k/releases/tags/$TAG")"
latest_asset_snapshot="$(jq -S '[.assets[] | {id, name, size, digest}] | sort_by(.name)' <<<"$latest_release_json")"
[[ "$(jq -r '.id' <<<"$latest_release_json")" == "$release_id" \
  && "$(jq -r '.draft' <<<"$latest_release_json")" == true \
  && "$latest_asset_snapshot" == "$asset_snapshot" ]] || {
  echo "staged release or asset identities changed during verification; refusing promotion" >&2
  exit 1
}

gh api --method PATCH "repos/o3kio/o3k/releases/$release_id" \
  --field draft=false --field make_latest=true >/dev/null
echo "Promoted verified draft id=$release_id tag=$TAG sha256=$digest without rebuilding"
