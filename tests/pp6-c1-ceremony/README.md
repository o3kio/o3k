# PP.6 C1 ceremony qualification tooling (issue #1225)

Qualification-only tooling for the C1 offline installation ceremony.
**Not production tooling**: `sign.py` stores throwaway private keys
unencrypted on disk and implements no custody controls. It is never shipped
in a release bundle and must never be pointed at production key material.
Production ceremonies follow `docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md`
with custodian-held keys (SPEC-0050 §2).

## Pieces

- `sign.py keygen --out DIR --policy-key-id ID` — generates five throwaway
  Ed25519 keypairs (policy, journal root, evidence root, journal signer,
  evidence signer). The printed policy public key and the given key ID are
  what a qualification release build bakes into the manifest via
  `O3K_C1_INSTALLATION_POLICY_KEY_ID` / `O3K_C1_INSTALLATION_POLICY_PUBLIC_KEY`
  with `O3K_C1_INSTALLATION_POLICY_ENABLED=1`.
- `sign.py sign --descriptor FILE --keys DIR --out DIR` — turns an unsigned
  `o3k-recovery-provisioning-v1` descriptor (stdout of
  `install.sh --c1-prepare-only`) into signed canonical `policy.json`,
  `state.json`, and `trust.json`, self-verifying every signature and the
  canonical round trip.
- `run-guest-ceremony.sh --bundle DIR --keys DIR --evidence DIR` — end-to-end
  driver: creates a disposable Ubuntu 24.04 KVM guest (fixed name prefix
  `o3k-c1qual-`, destroyed on exit), proves the fail-closed refusal of a
  ceremony-less install, runs prepare -> sign -> install, asserts healthy
  `o3kd`/`o3k-compute` services and `/healthz`, and runs the negative
  matrix (tampered policy/state/trust at install time; tampered installed
  policy, missing state high-water, and tampered installed trust after
  install), restoring and re-verifying after each. All output lands in the
  evidence directory with a `SHA256SUMS` manifest; the transient `work/`
  directory is removed after guest teardown (or excluded from the manifest
  with `--keep-guest`). The finalizer does not change ownership or permissions.

The signer is pinned against the canonical Rust verifiers by
`bins/o3k/tests/pp6_c1_ceremony_signer.rs` (`cargo test -p o3k --test
pp6_c1_ceremony_signer`), which verifies the emitted documents with the
same `verify_signed` / `verify_policy` / `verify_initial_state_transition`
/ `verify_trust_bundle` functions the installed startup guard uses.

## Example

```bash
python3 sign.py keygen --out /tmp/c1qual-keys --policy-key-id c1qual-policy-2026-11
# Build a qualification bundle carrying that public key (NOT the protected
# release workflow). Constraints: make-release.sh requires a clean checkout,
# the version must equal the O3K_INSTALLER_VERSION pin in
# packaging/get-o3k.sh, and the binaries must pass the glibc baseline (use
# scripts/build-release-binaries-debian12.sh output):
sudo scripts/build-release-binaries-debian12.sh target/release-debian12
O3K_C1_INSTALLATION_POLICY_ENABLED=1 \
O3K_C1_INSTALLATION_POLICY_KEY_ID=c1qual-policy-2026-11 \
O3K_C1_INSTALLATION_POLICY_PUBLIC_KEY=<from keys.json> \
O3K_UPGRADE_FROM_MIN_VERSION=v0.4.0-rc.5 \
O3K_RELEASE_BINARIES_DIR=target/release-debian12 \
  packaging/make-release.sh 0.4.0-rc.28 libvirt
O3K_RELEASE_SIGNATURE_SCHEME=sigstore packaging/make-release-archive.sh 0.4.0-rc.28
sudo tests/pp6-c1-ceremony/run-guest-ceremony.sh \
  --bundle dist/o3k-0.4.0-rc.28 --keys /tmp/c1qual-keys \
  --evidence /tmp/c1qual-evidence \
  --artifact-sha256 $(awk '{print $1}' dist/o3k-0.4.0-rc.28-linux-x86_64.tar.gz.sha256)
```
