# SPEC-0051 — PP.6 bounded redacted support bundle v1

Status: Proposed
Related issue: [#1088](https://github.com/o3kio/o3k/issues/1088)
Parent phase: [#975](https://github.com/o3kio/o3k/issues/975)
Related accepted sources:

- [SPEC-0042 — Durable Cloud Kernel Audit v1](SPEC-0042-durable-audit-v1.md)
- [SPEC-0045 — Native Operator diagnostics v1](SPEC-0045-native-operator-diagnostics-v1.md)
- [`native-diagnostics-v1.schema.json`](../../contracts/native-diagnostics-v1.schema.json)
- [`o3k-doctor-output.schema.json`](../../contracts/o3k-doctor-output.schema.json)

Related authority: [#944](https://github.com/o3kio/o3k/issues/944) owns operator documentation. This proposal does not accept or amend ADR-0189 or SPEC-0050.

This proposal defines the smallest supportability artifact needed by PP.6. It
is a read-only, bounded projection assembled from the existing canonical
diagnostics authority and static process identity. Version 1 carries no Audit
or Operation evidence (§2, §6). It does not create a second health, Operation,
Audit, identity, or persistence authority.

## 1. Proposed access and output surface

The proposed native action is `operator:ReadSupportBundle` against the
`operator/support-bundle` resource type. It requires an authenticated `User`
with the `operator` role and effective System scope. Project-scoped callers,
including project administrators with an `operator` role name, are denied.
Authorization must be resolved before checking source availability.

This proposal selects one transport: a native API response at
`GET /o3k/v1/operator/support-bundle`. It is not a local doctor artifact or
an archive download. The machine-readable response is defined by
`contracts/support-bundle-v1.proposed.schema.json`.

The route must authenticate the bearer token and authorize
`operator:ReadSupportBundle` against `operator/support-bundle` with effective
System scope before reading configuration, opening a store, checking source
availability, or constructing any response. The policy must register the
accepted principal kind (`User`), required `operator` role, and
`require_ownership: false`; a project-scoped caller is denied even when its
role string is `operator`. The route accepts no query parameters. An
unauthorized request has the same `Forbidden`
response regardless of whether any source is configured or healthy.

Generation is read-only. It must not write the canonical store, change
Operation or Audit state, call provider mutation APIs, alter leases/fences,
start or stop services, or create temporary files outside an implementation's
explicitly reserved output path. The route invocation is not mandatory Audit
evidence under SPEC-0042: it is a successful read and does not change
control-plane state. Ordinary tracing may occur after the response is safely
assembled, but bundle contents and source failures must never enter Audit. A
future change to this classification requires an accepted amendment.

## 2. Source authority and allowlist

The bundle may include only these sources:

1. The existing SPEC-0045 diagnostics summary and bounded service, provider,
   and capacity projections. These retain their existing status vocabulary,
   freshness rules, authorization-independent source semantics, and schema
   version.
2. No Audit events in v1. The existing `DurableAuditRepository::page` port
   returns events for one effective scope, in ascending `event_id` order, with
   a single optional outcome filter, so it cannot express a system-wide,
   newest-first view of failures. Audit `reason_category` values are also
   free-form at their call sites, and some carry raw error text. Audit
   evidence is deferred to a later version under the conditions in §6.
3. No Operation rows in v1. System-wide Operation collection is omitted until
   a separate accepted query/action contract exists. The lower-level
   `OperationRecord` is never a source.
4. Static release/profile/backend/schema identity supplied by the running
   process. These are labels, not health authority.

Provider logs, tracing spans, environment/config files, raw SQL, database
diagnostics, filesystem walks, shell output, arbitrary controller output,
tenant payloads, and provider APIs are excluded. A source that cannot produce
the allowlisted projection is represented by a bounded source status and
reason; it is never substituted with raw data.

## 3. Machine-readable payload

The normative shape proposed by this document is
[`support-bundle-v1.proposed.schema.json`](../../contracts/support-bundle-v1.proposed.schema.json).
Its top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Constant `v1`. |
| `generated_at` | RFC3339 time at which collection began. |
| `source` | Object whose `identity` is the immutable source provenance: a 40- or 64-character commit digest, or `release:<name>@<40- or 64-character digest>`. This is informational binding for evidence; transport acceptance does not itself verify the digest. |
| `profile` | Bounded product/deployment profile identifier. |
| `backend` | Backend kind (`sqlite` or `postgresql`) and safe server-version label, if known. |
| `diagnostics` | Existing SPEC-0045 v1 projections, or `null` when unavailable/not configured. |
| `collection` | Per-source status, observation times, partial/error categories, and bounds. |
| `redacted` | Constant `true`. |

Version 1 has no `failure_evidence` member: it carries neither Audit events nor
Operation items. Provider operation IDs, provider error text, and store-level
`error_message` are never included.

The `diagnostics.services` and `diagnostics.providers` lists are bounded to
200 items each. When a list has more entries, or when including every entry
would exceed the 64 KiB source bound, the collector keeps the first entries in
the order of the existing SPEC-0045 projection, sets `has_more: true` and
`omitted_count` to the number of entries left out, and marks the diagnostics
source `partial` with reason category `source_truncated`. `next_cursor` is
always `null`: the bundle is not pageable. When nothing is omitted,
`has_more` is `false` and `omitted_count` is `0`.

## 4. Mixed-time and partial collection semantics

The bundle is not a transactional snapshot. `generated_at` records the start
of collection, while every source projection carries its own source
observation timestamp where that source provides one. `collection.completed_at`
records the end of collection. Consumers must treat fields from different
sources as observations from a bounded interval, not as one consistent instant.

Each source has one of `complete`, `partial`, `unavailable`, or `not_configured`.
An unavailable or truncated diagnostics source does not make the whole artifact
a successful complete bundle: the top-level disposition is `partial` and the
source carries one bounded reason category. The artifact may still be useful
for troubleshooting. Authorization failure occurs before collection and does
not reveal source status.

The collector must fail closed on malformed source data, oversized pages,
unknown schema versions, invalid timestamps, or redaction failure. It may
return a partial artifact only when every included item independently passes
schema validation and redaction checks; the partial disposition must identify
the omitted source by bounded category, never by raw exception text.

The following invariants are mandatory and machine-checkable:

- `collection.sources` contains exactly one entry, named `diagnostics`, which
  maps to the top-level `diagnostics` member;
- `status: complete` requires the mapped payload member to be present and
  valid, with `has_more: false` on both lists; `status: unavailable` or
  `not_configured` requires the mapped member to be `null` and requires a
  non-null bounded `reason_category`;
- `status: partial` requires a non-null, schema-valid mapped payload member
  and a non-null bounded reason category. A null partial payload is invalid;
  null is reserved for `unavailable` and `not_configured`;
- `has_more: true` on either list requires `omitted_count >= 1` and
  `status: partial` with `reason_category: source_truncated`; `has_more:
  false` requires `omitted_count: 0`;
- `collection.disposition: complete` requires the source to be `complete`;
  any other source status requires `partial`;
- `generated_at` equals `collection.started_at`;
- `collection.completed_at` is greater than or equal to
  `collection.started_at`, and every `collection.sources[].observed_at` lies
  within the collection interval unless it is `null`. Observation times
  imported from the diagnostics projection keep their own freshness
  semantics and may predate the collection;
- serialized UTF-8 response size is at most 256 KiB, and the diagnostics
  source payload is at most 64 KiB;
- the response has no cursor or caller-supplied filter fields.

The implementation validator must enforce these invariants after schema
validation and before the response is returned. A schema-valid payload that
violates one is an internal error and is never sent to the caller.

The validator must also apply the `safe_identity` grammar from the schema to
every imported dynamic identity, service, action, resource, and correlation
string in the diagnostics projection. Imported status and reason values must
be members of the fixed SPEC-0045 vocabularies. The external diagnostics
schema remains the structural authority for its fields, while this additional
bundle validator rejects values that are structurally valid there but unsafe
for this transport.

## 5. Secret and privacy exclusions

The payload and any transport metadata must contain no passwords, bearer or
refresh tokens, private keys, certificates or enrollment material, database
URLs or credentials, provider credentials, raw provider payloads, user data,
request/response bodies, arbitrary configuration, environment values, host or
device paths, shell output, stack traces, exception chains, or unbounded
tenant data. The redaction boundary is structural: excluded fields must not
be collected and then filtered from a generic map.

## 6. Deferred failure-evidence sources

Audit and Operation evidence are out of scope for v1. A later amendment may add
an Audit source only after all of the following are accepted:

1. a new system-scoped Audit query port, through the production
   `AuditReader`/adapter boundary, that returns events across scopes newest
   first, accepts a set of failure-relevant outcomes, and keeps the
   repository's integrity-protected cursor semantics, with a fixed 24-hour
   window and at most 50 items;
2. a defined mapping from Audit `reason_category` values to the bundle's
   bounded reason vocabulary, with unmapped values exported as `null`;
3. removal of raw error text from Audit `reason_category` call sites, so no
   Audit field can carry exception or provider text.

A future Operation source must use a new accepted system-scoped query port with
the same route authorization, fixed filter binding, page bound, and cursor
integrity requirements; it may not widen the existing project-scoped
`list_canonical_operations_page` port. The collector must never call
SQLite/PostgreSQL repositories directly, bypass scope checks, issue unbounded
queries, or construct a cursor itself.

## 7. Evidence and acceptance clauses

An implementation is incomplete until it proves, for both SQLite and the
claimed PostgreSQL profile where infrastructure exists:

1. schema validation for complete and partial artifacts;
2. System/operator authorization and denial for tenant/project callers;
3. truncation of the services and providers lists, with `has_more`,
   `omitted_count` and a `partial` source, at both the item and byte bounds;
4. absence of Audit and Operation output;
5. success, unavailable, malformed, oversized, and timeout source behavior;
6. mixed-time metadata and truthful partial disposition;
7. redaction tests seeded with sentinel credentials, tokens, keys, URLs,
   paths, provider payloads, tenant data, and exception text;
8. process or API evidence showing zero canonical/provider mutations, including
   before and after store/audit/operation digests;
9. evidence bound to exact source commit, profile, backend/server version,
   schema version, harness identity, configuration, observed result, cleanup,
   and machine-readable disposition.

No implementation may claim complete metrics/OTLP coverage, backup/restore
state, PKI state, or upgrade state from this contract. Those fields require
their own accepted authorities and must be added as narrow schema amendments.

## 8. Open decisions required before acceptance

The human architecture/security reviewer must explicitly accept:

- `operator:ReadSupportBundle`, System scope, and action/resource naming;
- the non-mandatory invocation-Audit classification and any future change to
  that classification;
- deferring Audit and Operation evidence to a later version (§6), and the
  truncation semantics in §3;
- how backend server versions are normalized into the `safe_version`
  label (for example PostgreSQL's `16.4 (Debian 16.4-1.pgdg120+2)`, whose
  parentheses the label grammar rejects);
- whether source/profile/backend identity may include a release version and
  safe PostgreSQL server-version label.

Until those decisions are recorded, this document and its schema remain
Proposed and do not authorize runtime implementation.
