# PostgreSQL restore preflight implementation and evidence

Tracks #1085, #1086, #975 and the #944 recovery runbook. This is PR A's
non-destructive implementation slice. It does not close those issues or change
the accepted technical revision, product profiles, release gate, or proposed
conformance amendments.

## Operator surface

```sh
o3k restore preflight --artifact /absolute/artifact.o3k --target /recovery/target
```

Run on the authorized recovery host as root or the installed `o3k` account.
Install the authenticated release and its trust configuration through the
existing installation process. The existing installed release manifest must
contain the verified release-artifact digest and exact source identity. Never
edit an immutable release tag or fabricate missing installed provenance.

The selected target is an explicitly provisioned, empty directory, owned by
`o3k:o3k`, mode 0700, on block-backed local ext4. Its ancestors must be protected
by root ownership without group/other write permission. An existing controller
startup directory lock excludes preflight; preflight creates no controller lock
file. The independently provisioned PostgreSQL target must already be empty,
owned by the fixed unprivileged `o3k_restore_owner` role and use PostgreSQL 16.
Provisioning is an operator prerequisite; this command never creates a database
or role. PostgreSQL passwords, keys and tokens must not be supplied in arguments
or environment variables.

Provision `<installation-prefix>/etc/o3k/restore.json`, root-owned, mode 0600
or 0640, under root-protected directories:

```json
{
  "format": "o3k-restore-preflight-v1",
  "backend": "postgresql",
  "target_directory": "/recovery/target",
  "recovery_directory": "/recovery/staging",
  "postgres": {
    "database_url": "postgresql://o3k_restore_owner@database.example/o3k_fresh",
    "validation_image": "postgres:16@sha256:REPLACE_WITH_VERIFIED_64_CHARACTER_IMAGE_DIGEST"
  }
}
```

This is local installation policy, not artifact-controlled state or a second
cloud authority. The private recovery directory has the same ext4, owner and
mode requirements, is outside the target and has no existing recovery state.
A procedural exclusive reservation on that directory excludes competing
preflights. Existing files are denied rather than deleted automatically.

The existing root-owned backup trust document pins site, installation, profile,
signing identity, revocations and recovery-key handle. Recovery-key availability
and recipient identity are checked before decryption. Key loss or revocation
fails closed: recover the authorized key through its custody process or choose
an authorized artifact; do not replace trust with values read from the artifact.
Production Option B trust/HSM qualification is still a separate gate.

The host needs PostgreSQL 16 tools and an independently provisioned Docker
runtime with the exact verified PG16 image digest already present. There is no
image pull or fallback runtime. Access to Docker is a privileged recovery-host
authority and must be provisioned accordingly.

## What success proves

Preflight authenticates and boundedly decrypts every member into private staging,
matches exact installed release/site/profile/backend/migration/inventory policy,
and classifies the complete unfiltered archive TOC. It allocates a conservative
9 GiB staging reservation, retaining the unused hold while the bounded plaintext
is written, and checks target capacity without creating target files.

Only disposable PG16 instances execute archive SQL. They have no network, host
mounts, Docker socket or selected-target credentials; root filesystems are read
only, capabilities are dropped, and CPU, memory, process, descriptor, storage
and execution time are bounded. The SQL client has a different OS uid from the
server and cannot rewrite server data/HBA. Bootstrap administrator admission is
closed before untrusted execution. Restore uses the unprivileged role with
`--exit-on-error --no-owner --no-acl` and never imports global roles/passwords.

The clean reference is independently generated from embedded migration files
bound to the committed migration-tree checksums. It undergoes a trusted PG16
dump/reparse cycle: PostgreSQL rewrites certain CHECK casts during round-trip,
so comparing directly to the original parse tree would reject genuine dumps.
The final descriptor comparison remains exact canonical JSON; it does not strip
SQL fragments or normalize away changed permissions. Reference and candidate
instances never coexist and share no storage.

Descriptors cover ordered columns and defaults, indexes, constraints, functions
and security attributes, triggers/enabled states, views, sequences, RLS, schemas,
types, extensions, foreign objects, rules, roles, memberships, ownership, grants,
default ACLs, database ACLs and exact migration IDs/checksums. A discrepancy
rejects before any selected-target connection. Only after D10 passes does a
bounded read-only transaction inspect target emptiness and least-privilege role
policy. Plaintext staging and containers must be removed before success.

Stdout contains one bounded JSON result. Exit 0 means preflight completed;
2 means rejected precondition/artifact; 3 means recoverable host failure;
4 means unknown/quarantined cleanup or identity outcome. Stderr contains only
stable redacted reasons. Success explicitly reports `activation_authorized:
false` and `target_mutated: false`. It is not a restore receipt, reservation
handoff, fencing assertion, or permission to launch a controller.

Interrupted preflight may leave protected staging. A subsequent preflight
rejects existing recovery state. No automatic resume or deletion of ambiguous
state is offered in PR A. Signed D8 disposition/resume belongs to PR B.

## Reproducible evidence

```sh
export O3K_D10_TEST_IMAGE=postgres:16@sha256:YOUR_VERIFIED_IMAGE_DIGEST
tests/pp6_restore_preflight.sh
```

This explicit lane fails if PostgreSQL 16 or containment is unavailable. It
creates a disposable PG16 cluster, authenticates real encrypted/signed test
artifacts, runs the actual validator against executable-definition negatives,
and provisions a separate recovery process container with a local ext4 volume.
Only that orchestrator receives the Docker socket; its SQL-validation children
receive neither the socket nor target connection configuration. It invokes the
actual CLI and checks the selected directory/database and foreign database
catalog remain unchanged on success and artifact/nonempty-target rejection.

The test signer is purpose-isolated software, and the fixture has a synthetic
release digest. This is real PG16/process evidence, not an authenticated
installed-release journey, independent-machine qualification, HSM custody,
cross-host D4 ingress, restore/crash replay, BMC fencing or PKI acceptance.
Those remain explicit evidence gates before operational production claims.

The disposable campaign passed with PostgreSQL 16.15: clean signed preflight,
eleven signed negative cases (major version, function body/security, trigger,
extra function, default, grant, extension, schema, table and missing migration),
plus unchanged-target, foreign-state, pending-state and revocation checks.
The harness emits source SHA, artifact/catalog/migration digests, image pin and
harness digest. An uncommitted run identifies the baseline only; exact-head
evidence must be collected after committing and attached to the PR.

Implementation reference inputs, accessed 2026-10-24:
[PostgreSQL 16 pg_restore](https://www.postgresql.org/docs/16/app-pgrestore.html),
[pg_proc](https://www.postgresql.org/docs/16/catalog-pg-proc.html) and
[privileges](https://www.postgresql.org/docs/16/ddl-priv.html). Repository migration
files and their committed checksum inventory define the independent baseline;
no other implementation's source or private fixtures were used.

## Remaining sequence

PR A requires exact-head security review, `senolcolak` approval, protected checks
and merge-queue integration. PR B then adds inactive SQLite/PostgreSQL mutation,
signed durable D8 journal and resume/crash/replay evidence. PR C supplies Option B
signer/trust lifecycle after genuinely missing normative transport/trust fields
receive exact-revision acceptance; software tests do not satisfy real HSM/mTLS
custody/revocation gates. PR D requires independently controlled database-host
ingress, qualified source fencing and PKI replacement. Until then, no restored
controller activation or provider dispatch is authorized.

Security review additions: release-manifest ancestors must all be root-owned
and protected against replacement; foreign database CREATE grants reject the
selected target. D10 compares RLS command types and PUBLIC roles, view/index
options, sequence ownership/type, role expiry and PostgreSQL 16 membership
options/grantor. Since pg_roles masks passwords, a protected server-uid peer
observer checks only whether any password exists; no password bytes leave
pg_authid. The untrusted SQL uid cannot authenticate as that observer. Failed
validator startup must prove cleanup or return unknown/quarantine, and failed
output readers reap their child process. These checks confer no activation
authority.
