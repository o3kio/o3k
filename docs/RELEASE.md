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
    packaging/make-release.sh 0.4.0-rc.1 libvirt
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
provenance material below (`release-digests.txt`, `release-digests.sig`,
`provenance.json`, `release-verify.pub`). The bundle itself — `o3kd`, `o3k`,
`o3k-compute`, `o3k-network` (libvirt profile), `SHA256SUMS`,
`sbom.spdx.json`, `manifest.json`, packaging, docs, and examples — travels
inside the tarball and is integrity-verified after extraction.

The project does not claim SLSA compliance and does not automatically publish
production releases. Since PP.1 (v0.4.0-rc.1), every release additionally
carries ed25519 provenance material generated by
`packaging/make-provenance.sh` and signed with the O3K release key (public
key committed as `packaging/release-verify.pub`; the private key is held by
the release operator and never committed): `release-digests.txt` (SHA-256 of
every published asset), `release-digests.sig` (detached signature),
`provenance.json` (machine-readable binding of release, source commit, and
asset digests), and `release-verify.pub`. Verify with:

```bash
openssl pkeyutl -verify -pubin -inkey release-verify.pub -rawin \
  -in release-digests.txt -sigfile release-digests.sig
```

A future upgrade to keyless Sigstore Cosign from a protected GitHub Actions
release workflow remains possible:

```bash
cosign sign-blob --yes --bundle o3kd.sigstore.json bin/o3kd
cosign verify-blob --bundle o3kd.sigstore.json bin/o3kd \
  --certificate-identity-regexp 'https://github.com/o3kio/o3k/.github/workflows/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

That workflow remains a proposal until a protected workflow, identity
pattern, and maintainer approval are in place. Checksums are integrity, not
authenticity: a release must not be described as signed merely because it contains checksums.

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
