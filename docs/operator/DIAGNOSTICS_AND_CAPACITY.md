# Operator diagnostics and capacity

This runbook describes the read-only operator diagnostics projection currently
implemented by `o3kd`. The contract is [SPEC-0045 — Native Operator diagnostics
v1](../specs/SPEC-0045-native-operator-diagnostics-v1.md), with the public
schema in [`contracts/native-diagnostics-v1.schema.json`](../../contracts/native-diagnostics-v1.schema.json).
The endpoints expose canonical O3K observations and Placement capacity; they do
not become a second health, scheduler, provider, or topology authority.

## Access and endpoints

All four routes require a valid O3K identity with the `operator:ReadDiagnostics`
action, effective **System** scope, and the `operator` role. A project-scoped
caller is denied even when its role name is `operator`. Authorization is
evaluated before checking whether the diagnostics reader is configured, so an
unauthorized caller cannot learn deployment configuration. A configured reader
failure returns a bounded Problem Details response with a request correlation
identifier.

Use the native API prefix:

| Method and path | Use |
| --- | --- |
| `GET /o3k/v1/operator/diagnostics` | Aggregate platform status, component counts, control-plane lease status, and location counts. |
| `GET /o3k/v1/operator/diagnostics/services` | Bounded service/controller observations. |
| `GET /o3k/v1/operator/diagnostics/providers` | Bounded provider observations and per-provider Placement dimensions. |
| `GET /o3k/v1/operator/diagnostics/capacity` | Aggregate Placement-authoritative capacity. |

The summary and capacity responses carry `version: "v1"`. The two collection
routes return `items`, `has_more`, and, when applicable, `next_cursor`.
Collection requests accept `limit` and an opaque URL-safe base64 `cursor`.
The default limit is 50, `limit=0` means 50, and the maximum is 200. Invalid
cursors and limits above 200 are client errors. Follow `next_cursor` until
`has_more` is false rather than assuming one response contains the fleet.

Diagnostics are read-only. Do not use these routes as an operator command
surface or as a substitute for the canonical resource, operation, audit, or
governance APIs.

## Interpreting status

Every status uses one of five stable values:

| Status | Meaning and operator response |
| --- | --- |
| `healthy` | The source is observed and meets its readiness/freshness rules. Continue checking dependent classes before declaring the platform healthy. |
| `degraded` | Some source is unhealthy, stale, draining, partially observed, or a capacity invariant is violated. Inspect the service/provider pages and reason values. |
| `unavailable` | The source is explicitly unavailable, disabled, deleted, or every member of a class is unavailable. Restore the dependency or administrative state. |
| `stale` | The last observation is older than its freshness threshold. Re-establish observation and then verify that the fresh state is reflected. |
| `unknown` | No trustworthy observation exists yet, commonly after controller restart or before first heartbeat. Wait for re-observation and investigate if it does not arrive. |

Reason values are bounded categories such as `never_observed`,
`observation_stale`, `heartbeat_lost`, `draining`, `readiness_failed`,
`dependency_unavailable`, `capacity_source_unavailable`, and `unsupported`.
They do not contain provider exception text, credentials, connection strings,
private topology, host paths, node identities, agent epochs, or session IDs.

The aggregate summary is derived from service and provider counts. A partial
fleet, stale source, or unavailable member therefore cannot be hidden by a
healthy member. `unknown` is never treated as healthy. Control-plane liveness
comes from durable controller-session leases; location data is identity/count
data only and has no fabricated region or availability-domain health status.

Provider freshness follows the accepted SPEC-0045 rules. The current agent
lease is 15 seconds. A provider without a fresh observation remains unknown or
stale after restart even when durable Placement rows exist. Disabled, deleted,
draining, unavailable, corrupt, and missing-observation states take precedence
over a healthy-looking durable row.

## Capacity authority and limits

Capacity is sourced from the bounded Placement aggregate. The reported
resource classes are `VCPU`, `MEMORY_MB`, and `DISK_GB`, with units `count`,
`mib`, and `gib`. Aggregate and provider records expose allocatable/total,
reserved, allocated, and available values. `available` is calculated with
saturating arithmetic as allocatable minus reserved minus allocated, so a
drifted value is shown as zero and the status is degraded rather than exposing
a negative or wrapped number.

Placement is authoritative for these dimensions only. Storage, network, Ceph,
quota, tenant health, and provider-specific telemetry are not represented as
capacity claims. An over-reserved or over-allocated durable invariant degrades
capacity, including when another provider has spare capacity. Capacity with no
providers is unknown; durable values without a fresh provider observation are
stale; partial provider failure is degraded.

## Troubleshooting order

1. Confirm the request uses a System-scoped operator identity. A `403` is an
   authorization or scope problem; do not infer backend health from it.
2. Read the summary and record its request identifier, evaluated timestamp,
   aggregate status, control-plane status, and service/provider counts.
3. Read the services page with a bounded limit. Check lifecycle state, status,
   observed time, controller readiness, protocol compatibility, and reason.
4. Read the providers page with a bounded limit. Check provider status,
   availability, administrative state, observed time, draining/unavailable
   reasons, and Placement dimensions.
5. Read capacity and compare allocatable, reserved, allocated, and available
   values. Treat `stale`, `unknown`, and degraded capacity as an observation
   gap or authority problem until fresh evidence says otherwise.
6. If the source is stale or unknown, check the agent/controller heartbeat and
   restart/reconnect path, then query again after a fresh observation. Do not
   retry a mutation merely because a diagnostic read was stale.
7. If the source is unavailable or corrupt, preserve the response request ID
   and use the canonical service, operation, audit, store, and reconciliation
   diagnostics appropriate to the owning subsystem. A diagnostics HTTP 500
   means the durable diagnostic/capacity state was corrupt; it is not proof
   that a provider mutation occurred.
8. If the issue remains, collect bounded, redacted evidence from the same
   timestamp window and include the exact profile, release, schema/backend
   identity, route, status/reason values, and request IDs. Never copy tokens,
   private keys, connection strings, raw provider payloads, or tenant data.

After a controller restart, expect `unknown` or `stale` until each provider has
been observed again. After recovery, re-read the provider and capacity routes
and confirm that statuses and timestamps converge. The projection does not
authorize, fence, reconcile, or mutate external resources.

## Evidence and source links

The production process journey is
[`bins/o3kd/tests/native_diagnostics_process.rs`](../../bins/o3kd/tests/native_diagnostics_process.rs).
It exercises the real router and diagnostics adapter, System-scope
authorization, secret safety, healthy responses, and a provider failure that
transitions stale/degraded and recovers after a fresh observation. The
projection implementation is [`crates/o3k-native-api/src/diagnostics.rs`](../../crates/o3k-native-api/src/diagnostics.rs),
and the production adapter is under
[`bins/o3kd/src/native_adapters/diagnostics.rs`](../../bins/o3kd/src/native_adapters/diagnostics.rs).

Read this runbook with [SPEC-0042 durable audit](../specs/SPEC-0042-durable-audit-v1.md),
[SPEC-0043 native quota](../specs/SPEC-0043-native-quota-v1.md),
[SPEC-0044 native IAM governance](../specs/SPEC-0044-native-iam-governance-v1.md),
and [ADR-0181 canonical location identity](../adr/ADR-0181-canonical-location-identity.md).
The execution boundary remains defined by
[`contracts/execution-boundaries.md`](../../contracts/execution-boundaries.md).

## Explicit limits

The current diagnostics projection does not provide:

- tenant-facing or project-scoped health;
- mutation, provider administration, shell access, or arbitrary RPC/log access;
- a Prometheus `/metrics` endpoint, OTLP export, or a claim of complete metrics
  coverage;
- a support bundle or unbounded infrastructure scan;
- backup/restore, PKI lifecycle, upgrade/rollback, or disaster-recovery status;
- workload, VM, storage, network, Ceph, quota, or external-cloud health claims;
- HA, Kubernetes, multi-region, datacenter-scale, or physical-cluster
  certification.

Control-plane diagnostics describe the bounded O3K projection only. They do not
certify tenant VM/storage recovery or preserve external provider state.
