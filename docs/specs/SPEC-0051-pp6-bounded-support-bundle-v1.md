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
is a read-only, bounded projection assembled from existing canonical
diagnostics, Audit, and public Operation authorities. It does not create a
second health, Operation, Audit, identity, or persistence authority.

## 1. Proposed access and output surface

The proposed native action is `operator:ReadSupportBundle` against the
`operator/support-bundle` resource type. It requires an authenticated `User`
with the `operator` role and effective System scope. Project-scoped callers,
including project administrators with an `operator` role name, are denied.
Authorization must be resolved before checking source availability.

This proposal selects one transport: a native API response at
`GET /o3k/v1/operator/support-bundle`. It is not a local doctor artifact or
an archive download. The machine-readable response is defined by
`contracts/support-bundle-v1.schema.json`.

The route must authenticate the bearer token and authorize
`operator:ReadSupportBundle` against `operator/support-bundle` with effective
System scope before reading configuration, opening a store, checking source
availability, or constructing any response. The policy must register the
accepted principal kind (`User`), required `operator` role, and
`require_ownership: false`; a project-scoped caller is denied even when its
role string is `operator`. Query parameters cannot broaden the fixed
24-hour/50-item bounds. An unauthorized request has the same `Forbidden`
response regardless of whether any source is configured or healthy.

Generation is read-only. It must not write the canonical store, change
Operation or Audit state, call provider mutation APIs, alter leases/fences,
start or stop services, or create temporary files outside an implementation's
explicitly reserved output path. If generation is exposed through a privileged
API. The route invocation is not mandatory Audit evidence under SPEC-0042: it
is a successful read and does not change control-plane state. Ordinary
tracing may occur after the response is safely assembled, but bundle contents
and source failures must never enter Audit. A future change to this
classification requires an accepted amendment.

## 2. Source authority and allowlist

The bundle may include only these sources:

1. The existing SPEC-0045 diagnostics summary and bounded service, provider,
   and capacity projections. These retain their existing status vocabulary,
   freshness rules, authorization-independent source semantics, and schema
   version.
2. SPEC-0042 Audit pages, queried with a bounded System/operator query. Only
   the fields listed in §3 may cross the bundle boundary. Audit remains the
   authority for event identity and correlation.
3. No Operation rows in v1. System-wide Operation collection is omitted until
   a separate accepted query/action contract exists. The lower-level
   `OperationRecord` is never a source.
4. Static release/profile/backend/schema identity supplied by the running
   process. These are labels, not health authority.

Provider logs, tracing spans, environment/config files, raw SQL, database
   diagnostics, filesystem walks, shell output, arbitrary controller output,
   tenant payloads, and provider APIs are excluded. A source that cannot
   produce the allowlisted projection is represented by a bounded source
   status and reason; it is never substituted with raw data.

## 3. Machine-readable payload

The normative shape proposed by this document is
[`support-bundle-v1.schema.json`](../../contracts/support-bundle-v1.schema.json).
Its top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Constant `v1`. |
| `generated_at` | RFC3339 time at which collection began. |
| `source` | Immutable source provenance: a 40/64-character commit digest or `release:<name>@<40/64-character digest>`. This is informational binding for evidence; transport acceptance does not itself verify the digest. |
| `profile` | Bounded product/deployment profile identifier. |
| `backend` | Backend kind (`sqlite` or `postgresql`) and safe server-version label, if known. |
| `diagnostics` | Existing SPEC-0045 v1 projections, or `null` when unavailable/not configured. |
| `failure_evidence` | At most 50 bounded Audit events; Operations are absent in v1. |
| `collection` | Per-source status, observation times, partial/error categories, and bounds. |
| `redacted` | Constant `true`. |

`failure_evidence.audit` contains at most 50 Audit events and no Operation
items in v1, ordered newest first by event timestamp and then stable event ID.
The default and maximum lookback window is 24 hours. A caller cannot request
an unbounded window or increase the bound. Audit events are the only
system-wide failure source in v1. `failure_evidence.audit` is `null` when the
Audit source is unavailable or not configured.

Each Audit item may contain only:

`event_id`, `timestamp`, `request_id`, `audit_id`, `service`, `action`,
`resource_type`, `resource_id`, `operation_id`, `outcome`, and
`reason_category`.

`principal_id`, `principal_kind`, `effective_scope`, and `owner_scope` are
omitted from the exported bundle by default. They require a future accepted
privacy decision. Public resource IDs and correlation IDs remain bounded and
are included only to make an operator failure actionable.

No Operation item is emitted. A future amendment may add Operation summaries
only after it defines a system-scoped query port, action/resource policy,
scope and filter binding, integrity-protected cursor semantics, and a
secret-safe reason-category projection. Provider operation IDs, provider
error text, and store-level `error_message` are never included.

## 4. Mixed-time and partial collection semantics

The bundle is not a transactional snapshot. `generated_at` records the start
of collection, while every source projection carries its own source
observation timestamp where that source provides one. `collection.completed_at`
records the end of collection. Consumers must treat fields from different
sources as observations from a bounded interval, not as one consistent instant.

Each source has one of `complete`, `partial`, `unavailable`, or `not_configured`.
An unavailable Audit or diagnostics source does not make the whole artifact a
successful complete bundle: the top-level disposition is `partial` and the
source carries one bounded reason category. The artifact may still be useful
for troubleshooting. Authorization failure occurs before collection and does
not reveal source status.

The collector must fail closed on malformed source data, oversized pages,
unknown schema versions, invalid timestamps, or redaction failure. It may
return a partial artifact only when every included item independently passes
schema validation and redaction checks; the partial disposition must identify
the omitted source by bounded category, never by raw exception text.

The following invariants are mandatory and machine-checkable:

- `collection.sources` contains each source name at most once;
- `collection.sources` contains only `diagnostics` and `audit`, each at most
  once; `diagnostics` maps to the top-level `diagnostics` member and `audit`
  maps exactly to `failure_evidence.audit`;
- `status: complete` requires the mapped payload member to be present and
  valid; `status: unavailable` or `not_configured` requires the mapped member
  to be `null` and requires a non-null bounded `reason_category`;
- `status: partial` requires a matching payload member and a non-null bounded
  reason category;
- `collection.disposition: complete` requires every listed source to be
  `complete`; any other source status requires `partial`;
- `completed_at` is greater than or equal to `started_at`, and every
  `observed_at` lies within the collection interval unless the source marks
  it `null`;
- serialized UTF-8 response size is at most 256 KiB, each source payload is at
  most 64 KiB, and `failure_evidence.audit` contains at most 50 items;
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

## 6. Authorized query port

The Audit source must call the existing
`DurableAuditRepository::page(&AuditQuery)` port through the production
`AuditReader`/adapter boundary. The route constructs a fixed System/operator
scope query with a fixed 24-hour window, failure-relevant outcome filters,
`limit <= 50`, and the repository's integrity-protected cursor semantics. The
collector must not call SQLite/PostgreSQL repositories directly, bypass scope
checks, issue unbounded queries, or construct a cursor itself.

There is no Operation source in this version. A future Operation source must
use a new accepted system-scoped query port with the same route
authorization, fixed filter binding, page bound, and cursor integrity
requirements; it may not widen the existing project-scoped
`list_canonical_operations_page` port.

## 7. Evidence and acceptance clauses

An implementation is incomplete until it proves, for both SQLite and the
claimed PostgreSQL profile where infrastructure exists:

1. schema validation for complete and partial artifacts;
2. System/operator authorization and denial for tenant/project callers;
3. bounded Audit queries and stable newest-first output;
4. absence of system-wide Operation output until the separate query contract
   is present;
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
- inclusion of public resource and correlation IDs;
- whether any principal/scope identifiers may be exported;
- the bounded Operation query needed for system-wide Operation summaries;
- whether source/profile/backend identity may include a release version and
  safe PostgreSQL server-version label.

Until those decisions are recorded, this document and its schema remain
Proposed and do not authorize runtime implementation.
