# #1085 PostgreSQL 16 backup and D4 writer-exclusion evidence

Date: 2026-10-24. Branch: `pp6/1085-postgres`. Source base:
`35e049062b6af709141f54522692e8e0c8865661` (protected main). Implementation
commits: `2036b872` (backend, D4 barrier, D10 classification), `bf64a471`
(real PG16 campaign), `9fc51372` (restore role login modes after the barrier).

This document reports executable evidence from a disposable **PostgreSQL 16.15**
cluster (`pg_virtualenv`, Ubuntu `16.15-0ubuntu0.24.04.1`). No managed cluster,
second host, firewall appliance, HSM, or production custody is claimed.

## Campaign

```bash
CARGO_TARGET_DIR=target bash tests/pp6_pg16_backup.sh
```

Recorded on the committed tree:

```text
PASS=22 FAIL=0 NOT-COVERED=5
```

| Row | Result |
| --- | --- |
| `case-n-toc-classifier` | complete TOC classification unit matrix |
| `case-n-barrier-sql` | barrier policy/catalog unit matrix |
| `case-n-contract-prototypes` | accepted D4/D10 decision prototypes |
| `case-n-barrier-sql-live` | real PG16 role/barrier/catalog SQL |
| `case-b-reconnect-denied` | TCP application, Unix-socket and maintenance reconnects denied |
| `case-a-happy` | capture + detached signing + publication `rc=0` |
| `case-e-admission-restored` | admission config, control reconnect and role login modes restored |
| `case-a-verify` | artifact verified with the `database/o3k.dump` member |
| `case-l-replay` | published-operation replay is idempotent |
| `case-l-replay-conflict` | changed published bytes rejected |
| `case-c-retained-writer` | retained writer session terminated |
| `case-d-safe-abort` | staged capture aborted safely; admission restored |
| `case-f-barrier-loss` | changed `pg_hba.conf` aborted before publication |
| `case-g-interrupted-dump` | interrupted dump not published |
| `case-g-admission-crash-recovery` | next invocation restored admission **and** role login modes |
| `case-h-migration-mismatch` | rejected `migration-schema-mismatch` |
| `case-i-unknown-role` / `case-j-unexpected-login` | rejected `unexpected-login-role` |
| `case-j2-writer-privileged` | rejected `writer-role-privileged` |
| `case-k-role-membership` | rejected `o3k-role-membership-rejected` |
| `case-l-wrong-site` | rejected `identity-mismatch` |
| `case-m-invalid-signature` | foreign signature rejected before publication |

## D4 barrier observed on the real cluster

The installed first-match policy was captured while the barrier was active:

```text
# O3K-PP6-D4-ADMISSION-BARRIER-V1 o3k_ev_… 127.0.0.1
host o3k_ev_… o3k_backup_dump 127.0.0.1/32 trust
local all all reject
local replication all reject
host all all 0.0.0.0/0 reject
host all all ::/0 reject
host replication all 0.0.0.0/0 reject
host replication all ::/0 reject
# O3K-PP6-D4-ADMISSION-BARRIER-END-V1
```

The barrier SHA-256 is recorded by the campaign. Application, maintenance and
Unix-socket reconnects were denied before `pg_dump` started; the control session
was closed before the dump probe.

A feature-gated hard process exit at the accepted after-dump boundary left the
barrier and role modes installed (the hook is compiled only for the campaign).
On the next invocation:

```text
role matrix after crash:
o3k_backup_dump|t|f|f|f|f|f
o3k_restore_owner|f|f|f|f|f|f
o3k_runtime|f|f|f|f|f|f

recovery exit: 3 (bounded stop-after-staging)
role matrix after recovery:
o3k_backup_dump|f
o3k_restore_owner|f
o3k_runtime|t
admission leftovers: 0
```

This verifies that the saved admission and the reviewed writer login modes are
restored by the recovery path, not only on the happy path.

## Dump and artifact facts

From the campaign's evidence run:

```text
dump_sha256=c3e10bd0ae5e8808e309c488f45021273459fdd61e761735348b0242899fddb5
dump_bytes=181245
dump_toc_entries=409
```

The artifact uses the existing signed envelope and reports the PostgreSQL
member as `database/o3k.dump`; the campaign also verifies the artifact with the
product verifier. D10 classification rejects unknown/duplicate/forbidden TOC
entries and does not execute archive SQL while listing.

## Gates

- `cargo fmt --all -- --check` — pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — pass.
- `cargo test --workspace --all-features` — pass.
- `python3 scripts/check-maintainability-guards.py` — pass (new argv-only
  `bins/o3k/src/backup_pg_dump.rs` is the only added host-execution path; all
  PostgreSQL SQL remains under `crates/o3k-store/src/postgres/`).

## NOT-COVERED / BLOCKED

- `case-o-reload-incomplete`: injecting a postmaster that silently ignores
  SIGHUP requires a controllable postmaster; the reload timeout is code-path
  asserted only.
- `case-p-disk-full`: a bounded filesystem smaller than the 6 GiB reservation
  was not created; D9 boundaries remain covered by reservation unit tests.
- `case-q-second-host`: a genuinely independent second host and independently
  managed database-host ingress ACL/firewall are not available here.
- `case-r-managed-cluster`: managed PostgreSQL without an enforceable
  database-side admission barrier is unsupported and not claimed.
- `case-s-hsm`: PostgreSQL Option B online signing is blocked on an accepted
  service/transport/trust-schema amendment and an external non-exportable
  PKCS#11 HSM. This slice uses the existing detached-signature seam; **no HSM,
  mTLS signer service, custody, or production-signer acceptance is claimed.**
- No PostgreSQL restore/activation, HA, multi-region, or PP.7 release claim.
- The branch is based on protected main `35e04906` (the merged #1084 artifact
  work); those SQLite artifact changes are included, but protected review and
  any later rebase remain required before merge.
