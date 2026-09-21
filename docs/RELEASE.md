# Release verification

Release bundles are built by `packaging/make-release.sh [version] [profile]`.
The bundle contains `o3kd`, optionally `o3k-compute` for the libvirt profile,
an SPDX 2.3 SBOM, a manifest, and `SHA256SUMS`. The SBOM
and manifest record the source commit and workflow name; local path sources are
represented as `NOASSERTION` so private filesystem paths are not published.

## Build baseline

Release binaries are built on the **Debian 12 (bookworm, glibc 2.36) baseline**
so the same artifacts execute on both advertised targets: Ubuntu 24.04 and
Debian 12. A binary built on a newer baseline (for example Ubuntu 24.04's
glibc 2.39) requires `GLIBC_2.38`/`GLIBC_2.39` symbols (`__isoc23_sscanf`,
`pidfd_getpid`, `pidfd_spawnp`) and fails at exec on Debian 12 with
`version 'GLIBC_2.38' not found` (see
`target/real-host-workflow-artifacts/clean-debian/defect-5-glibc-abi.md`).

```bash
bash scripts/build-release-binaries-debian12.sh        # builds in a disposable bookworm rootfs
O3K_RELEASE_BINARIES_DIR=target/release-debian12 \
  packaging/make-release.sh 0.2.0-alpha.2 libvirt
```

The script installs the `rust-toolchain.toml` toolchain with rustup inside the
rootfs, builds `o3kd` and `o3k-compute-bin --features libvirt` with
`cargo build --release --locked`, and records sha256, a glibc-floor proof, and
build provenance in the output directory. `make-release.sh` runs
`packaging/check-glibc-baseline.sh` on the binaries it packages, and
`packaging/verify-release-bundle.sh` re-checks the glibc floor on the finished
bundle, so a binary above the 2.36 baseline blocks the release with a message
naming the offending version and the fix. The check is runnable standalone:
`bash packaging/check-glibc-baseline.sh bin/o3kd`.

Build and verify a candidate locally:

```bash
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD) packaging/make-release.sh 0.2.0-alpha.2 fake
cd dist/o3k-0.2.0-alpha.2
sha256sum --check SHA256SUMS
python3 -m json.tool sbom.spdx.json >/dev/null
# Also checks that SHA256SUMS covers exactly every regular bundle file.
bash packaging/verify-release-bundle.sh .
```

`verify-release-bundle.sh` fails closed on a checksum mismatch, an unlisted or
missing regular file, duplicate or escaping checksum paths, and symlinks in the
bundle. `packaging/make-release.sh` runs this verification after creating the
manifest and checksum file; it does not authenticate the bundle or replace
artifact signing.

## Release manifest

`make-release.sh` writes `dist/o3k-<version>/manifest.json` with these fields:

- `version` — the release version (no `v` prefix);
- `profile` — `fake` or `libvirt`;
- `source_commit`, `workflow` — build provenance;
- `installer_sha256`, `installer_asset` — the `install.sh` release asset
  record (see below);
- `schema_version` — the maximum numeric migration prefix under
  `crates/o3k-store/migrations/` at build time (e.g. `0017_placement.sql` →
  `"17"`). Computed by `make-release.sh`; a build fails closed when the
  migration directory is empty or any file name lacks a numeric prefix. This
  is the single migration authority: the upgrade engine compares the
  installed schema version against this value without embedding any
  migration SQL;
- `upgrade_from.min_version` — the oldest installed release this build
  supports upgrading from. Taken verbatim from the `O3K_UPGRADE_FROM_MIN_VERSION`
  environment variable (with or without a leading `v`); it is deliberately
  **not** hardcoded, so a release build fails with an explicit instruction
  when the operator has not named the previous published release:

  ```bash
  O3K_UPGRADE_FROM_MIN_VERSION=v0.3.0-alpha.1 \
    packaging/make-release.sh 0.4.0-rc.5 libvirt
  ```

The fields are backward-compatible additions: `verify-release-bundle.sh`
accepts bundles with or without them, and older bundle readers ignore unknown
fields.

## install.sh release asset

The one-line installer is a first-class GitHub Release asset named exactly
`install.sh`, exported byte-for-byte from the single installer source
`packaging/get-o3k.sh` (mode 0755) by `packaging/make-release.sh`. Two drift
gates make a second edited copy impossible to miss:

- `make-release.sh` runs `cmp packaging/get-o3k.sh dist/install.sh` right
  after the export and aborts on any mismatch, then records the SHA-256 in
  the bundle manifest as `installer_sha256` (with
  `installer_asset: "install.sh"`);
- `packaging/make-release-archive.sh` re-checks that `dist/install.sh` is
  byte-identical to `packaging/get-o3k.sh` before archiving (aborts on
  drift) and prints its SHA-256.

`install.sh` sits next to the bundle directory in `dist/` — it is a release
asset, not a bundle file, so it is deliberately absent from the bundle
`SHA256SUMS`. The published GitHub Release assets are exactly:
`install.sh`, `o3k-<version>-linux-x86_64.tar.gz`, its `.sha256`, and the
provenance material below (`release-digests.txt`, `provenance.json`, and the
Sigstore bundle). The bundle itself — `o3kd`, `o3k`,
`o3k-compute`, `o3k-network` (libvirt profile), `SHA256SUMS`,
`sbom.spdx.json`, `manifest.json`, packaging, docs, and examples — travels
inside the tarball and is integrity-verified after extraction.

The project does not claim SLSA compliance. Historical releases through the
v1 contract carry Ed25519 provenance generated by
`packaging/make-provenance.sh`: `release-digests.txt`, `release-digests.sig`,
`provenance.json`, and `release-verify.pub`. The historical public key is
permanently retained at `packaging/trust/o3k-release-ed25519-legacy.pub` and
remains independently verifiable:

```bash
openssl pkeyutl -verify -pubin -inkey release-verify.pub -rawin \
  -in release-digests.txt -sigfile release-digests.sig
```

Releases governed by `contracts/release-bundle-v2.yaml` (starting with
`v0.4.0-rc.9`) use the one canonical protected workflow
`.github/workflows/release.yml`. It runs from an exact protected release tag,
requires the `release` Environment approval, and uses GitHub OIDC with no
long-lived signing key. The workflow signs the release-level digest manifest
with the pinned Cosign release and publishes the Sigstore bundle:

```bash
cosign verify-blob \
  --bundle release-digests.sigstore.json \
  --certificate-identity \
  'https://github.com/o3kio/o3k/.github/workflows/release.yml@refs/tags/v0.4.0-rc.9' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  release-digests.txt
```

The verifier requires the exact repository, workflow path, release tag,
issuer, and transparency proof. It rejects another repository, workflow,
branch, issuer, modified digest manifest, or missing bundle. A release must not be described as signed merely because it contains checksums: checksums are integrity, not authenticity, and an artifact is never signed merely because it contains checksums. The application/browser OIDC authority (Keycloak in the PP.4 TestLab) is separate from GitHub's release-workload OIDC.

The public installer performs this verification before downloading or
extracting the archive. Its embedded consumer verifier uses the supported
Ubuntu/Debian OpenSSL and Python runtimes plus pinned Fulcio and Rekor trust
material; it never downloads Cosign or executes archive content to obtain a
verifier. Only after the signed `release-digests.txt` is accepted does it read
the archive digest. The `.sha256` asset remains convenience integrity data,
not the v2 authenticity root. `provenance.json` is generated before the
digest manifest and is included in that signed manifest, avoiding a circular
self-digest.

The libvirt alpha also requires `packaging/release-gate.sh` to report
`status: ready` from real E2E, recovery, clean Ubuntu/Debian installation,
and benchmark artifacts. The invocation must supply `--source-commit`,
`--candidate-evidence-manifest`, and `--human-review`; the manifest must be
generated for the exact candidate and bind every machine artifact to the
candidate binaries and bundle. The latter is checked with
`validate-human-review.sh --require-approved` and its `reviewed_commit` must
match the source commit. Missing, skipped, stale, or unapproved evidence
blocks the gate. This check records a requirement; it does not create or
authenticate a human review.
