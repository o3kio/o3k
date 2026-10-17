# PP.6 PostgreSQL 16 size and restore-policy measurement

Status: evidence preparation only; this document does not promote ADR-0189 or
SPEC-0050 and does not certify backup or restore.

## Scope and provenance

The measurements below were run on 2026-10-18 from the working tree associated
with protected-main baseline `a6c4d6d519b974c791d2cb5ea9d83e2eada18807`.
The PostgreSQL server and tools are Ubuntu PostgreSQL 16.15:

```text
PostgreSQL 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)
pg_dump (PostgreSQL) 16.15
```

The server was local and accepting connections. A uniquely named disposable
database (`o3k_pp6_measure_<epoch>_<random>`) owned by the local `postgres` administrator
was created, populated, dumped, and dropped. No existing O3K database was
modified. The PostgreSQL fixture applied all 36 files in
`crates/o3k-store/migrations_postgres/` (77 public tables) with
`psql -v ON_ERROR_STOP=1`; the SQLite fixture applied all 53 files in
`crates/o3k-store/migrations/` (77 non-internal tables). Both are
complete-schema fixtures without production rows, so they are sizing
observations rather than production backup evidence. Direct SQL application does
not create or verify the SQLx `_sqlx_migrations` ledger; this records migration
file inventory, not accepted schema identity.

## Observed sizes

| Backend / operation | Source/database bytes | Native artifact bytes | Elapsed / peak | Available staging at run |
|---|---:|---:|---:|---:|
| SQLite all 53 migrations, checkpoint + `VACUUM INTO` | 1,175,552 | 1,171,456 | not timed | 171,004,874,752 |
| PostgreSQL all 36 migration files | 11,172,887 | 176,867 (`pg_dump -Fc`) | 0.24 s / 14,976 KiB | 153,275,613,184 |

The PostgreSQL result demonstrates custom-format output sizing for the complete
current migration schema, with no production rows. It does not establish a
compression ratio or a production bound. The 9 GiB reservation cap from the
PP.6 decision packet remains an unmodified proposed limit; these small fixtures
cannot justify changing it. A production implementation must measure its
actual database, dump, encrypted outer artifact, and private staging overhead
before reserving space.

## PostgreSQL policy recommendation for human review

The bounded default should remain PostgreSQL 16 custom format (`pg_dump -Fc`)
as one opaque authenticated member, consumed only by the matching PostgreSQL
16 `pg_restore`. The proposed restore invocation is where `--no-owner
--no-acl --exit-on-error` applies; `pg_dump` itself accepts the first two flags
but not `--exit-on-error`. Capture should record server version, dump tool version,
database identity, schema identity, extension inventory, migration identity,
and source SHA. Restore should target a newly created empty O3K-owned database,
run with `--no-owner --no-acl --exit-on-error`, and leave the target inactive
and quarantined on any error or unknown outcome. `--no-owner --no-acl` is a
required defense against artifact-controlled ownership and privilege changes;
it does not make restore atomic or make an untrusted dump safe. TOC review,
extension/schema/function allowlisting, and rejection of injected objects or
security-definer behavior remain pending.

The target role should be provisioned by trusted installation configuration,
outside the dump. The dump must not create cluster roles, passwords,
tablespaces, ownership changes, ACLs, or grants. Based on the current migration
inventory (`crates/o3k-store/migrations_postgres/*.sql`), the role needs database
`CONNECT`, schema `USAGE`, and table/sequence privileges required by the
running O3K store. Exact object grants should be generated from the migration
inventory and checked against the live schema during implementation; a broad
`SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION`, or `BYPASSRLS` grant is
not justified. No non-core extension was observed or required by this fixture;
extensions must be an explicit approved allowlist before restore.

This is a recommendation for ADR-0189/SPEC-0050 review, not an accepted
security policy. Human approval is still required before implementation relies
on it.

## Reproducible measurement

This is a repository evidence harness, not an accepted public backup command.
Run it only against a disposable PostgreSQL 16 service with an administrator
permitted to create and drop its own fixture database. Supply a password-free
PostgreSQL URI in `O3K_ADMIN_URL`; use a protected `PGPASSFILE` or `PGPASSWORD`
for authentication. Do not put passwords in a URI or shell history.

```sh
# O3K_ADMIN_URL and authentication are supplied securely by the environment.
bash tests/pp6_pg_size_measurement.sh /private/new-pp6-measurement
```

The output directory must not exist. The checkout must have no tracked changes,
and both migration directories must contain only committed regular SQL files.
The script verifies server and tool major version 16, creates a uniquely named
database, confirms its owner and connected database before applying migrations,
produces a native dump, measures a SQLite snapshot, and drops its database
before publishing `result.json`. It rejects a query-parameter database override.
The result binds the committed source head/tree and native dump/list digests;
it explicitly excludes the SQLx ledger and encrypted-artifact acceptance.

On failure, `measurement_failed stage=...` identifies the bounded stage without
including SQL, connection URLs or credentials. Raw PostgreSQL stderr is
suppressed; the failure classification is intentionally less detailed than a
server administrator's diagnostics. The private output contains native state
and must be handled and removed as sensitive evidence.

INT/TERM attempt normal cleanup. SIGKILL, host failure or lost infrastructure
can leave a fixture database. An interrupted run has no successful result.
The private `database.name` identifies the generated target for administrator
inspection: verify its owner and that it belongs to this run before removing
it using the normal PostgreSQL administrative process. Never drop databases by
prefix alone. Preserve or remove the output directory explicitly after review.

## Evidence limits and next requirement

The run did not exercise concurrent O3K writers, cross-file quiescence,
encryption/publication, restore failure handling, or a fresh-host activation.
The encrypted full-artifact size is **PENDING**; database and native dump sizes
must not be substituted for it. PostgreSQL production backup/restore therefore remains
`ACCEPTANCE_PENDING`. The next implementation evidence must use a complete
isolated O3K PostgreSQL database and a disposable empty target, while retaining
the exact tool/version and role/object inventory in the manifest.
