# ADR-0185 — Keyless release signing trust transition

Status: Accepted
Date: 2026-09-20
Review date: 2027-09-20
Responsible maintainer: O3K maintainers
Tracking: PP.4 / #973

## Context

O3K historical releases use `release-digests.txt` signed by an operator-held
Ed25519 key and verified with `packaging/release-verify.pub`. The private
signing material is unavailable for operational use. This is not evidence of
compromise, but it prevents a governed new release without a trust transition.

The historical public key and signatures remain valid and independently
verifiable. Existing releases are never rewritten or re-signed.

## Decision

For `v0.4.0-rc.9` and later, the only supported publication authority is the
protected `.github/workflows/release.yml` workflow running from an exact
release tag. The job uses the `release` GitHub Environment and requests only
`contents: write` and `id-token: write`. GitHub OIDC authenticates the job to
Sigstore Fulcio; Cosign keyless `sign-blob` signs `release-digests.txt` and
emits `release-digests.sigstore.json`, including transparency-log proof.

The verifier requires all of the following, exactly:

- OIDC issuer `https://token.actions.githubusercontent.com`;
- repository `o3kio/o3k`;
- workflow path `.github/workflows/release.yml`;
- the release tag in the certificate identity;
- a valid Sigstore bundle and transparency proof.

The release workflow is protected by repository tag rules and environment
approval. It is not callable by pull requests, branches, or reusable workflow
dispatch. Every third-party action is pinned to a full commit SHA and the
Cosign release is explicitly pinned.

## Contract and compatibility

`contracts/release-bundle-v1.yaml` remains frozen for historical Ed25519
releases. `contracts/release-bundle-v2.yaml` is the successor contract and
defines the keyless bundle. `packaging/trust-policy.yaml` is the machine-readable
policy; its legacy fingerprint is retained permanently. The old
`release-verify.pub` path remains for historical tooling, while the identical
key is also recorded under `packaging/trust/`.

The application/browser OIDC authority (Keycloak in the PP.4 TestLab) is
unrelated to GitHub's workload OIDC and is not changed by this ADR.

## Consequences

No long-lived release private key is required for new releases. Public users
can verify the Sigstore bundle without private infrastructure. A release is
not authentic merely because its checksums match: the exact repository,
workflow, tag identity, issuer, and transparency proof must verify.

The GitHub repository must keep the `release` Environment protected and must
protect release tags. If either protection is absent, the workflow is not
evidence of a governed release and publication is blocked.

## Rollback and migration

Historical Ed25519 verification remains available and is never removed. A
failure in the keyless workflow produces no release. A functional defect in a
published candidate requires a successor tag (`rc.10` or later); assets and
tags are immutable. Returning to the unavailable Ed25519 private key is not a
rollback path.

## Evidence

- `contracts/release-bundle-v2.yaml`
- `packaging/trust-policy.yaml`
- `packaging/make-provenance-sigstore.sh`
- `packaging/verify-release-sigstore.sh`
- `.github/workflows/release.yml`
