# PP.4 browser E2E harness

Acceptance evidence for **o3kio/o3k#973** (PP.4 one-line demo with a real
browser): real OIDC login (Keycloak authorization-code + PKCE through the
confidential Araf BFF), Araf tenant + operator consoles backed by the real O3K
native API in the demo profile. **No fixtures, no mocks, no stubs** — every
assertion hits the live deployment.

## Architecture

```
┌─────────────────────────── campaign VM ───────────────────────────┐
│  Chromium (demo CA imported, *.o3k.demo -> 127.0.0.1 in /etc/hosts)│
│  tls-proxy :443 ── tenant-console/operator-console ── Araf BFFs    │
│  Keycloak (idp.o3k.demo)   o3kd native API (api.o3k.demo relay)    │
└────────────────────────────────────────────────────────────────────┘
              ▲ CDP (remote debugging port, e.g. 9223, SSH-forwarded)
┌─────────────┴─────────────── HOST ────────────────────────────────┐
│  Playwright 1.63.0 (this package) — connectOverCDP, no launch     │
└────────────────────────────────────────────────────────────────────┘
```

- The browser runs **inside** the VM so the demo names and CA resolve there.
- The runner connects with `chromium.connectOverCDP(process.env.CDP_URL)`
  (default `http://127.0.0.1:9223`). `playwright.config.ts` deliberately has
  **no webServer and no launch options**.
- Chromium must match the runner: playwright is pinned to exactly `1.63.0`,
  which drives the host-cached `chromium-1243` build.

## Run

```bash
cd tests/pp4-browser-e2e
npm ci
export CDP_URL=http://127.0.0.1:9223
export PP4_ALICE_PASSWORD=...            # demo user's Keycloak password (required)
export PP4_FLAVOR_ID=...                 # uuid of testlab-flavor (see below)
npm test                                 # all three specs, serial
npx playwright test specs/tenant.spec.ts # one journey
```

Validate without a deployment:

```bash
npx tsc --noEmit
npx playwright test --list
```

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `CDP_URL` | `http://127.0.0.1:9223` | CDP endpoint of the in-VM Chromium |
| `TENANT_URL` | `https://tenant.o3k.demo` | tenant console base URL |
| `OPERATOR_URL` | `https://operator.o3k.demo` | operator console base URL |
| `PP4_ALICE_USER` | `alice` | Keycloak user |
| `PP4_ALICE_PASSWORD` | — | **required, fail fast; never logged** |
| `PP4_VM_NAME` | `pp4-native` | deterministic VM name |
| `PP4_IMAGE_NAME` | `cirros-0.6.3` | TestLab image name |
| `PP4_NETWORK_NAME` | `testlab-network` | TestLab network name |
| `PP4_FLAVOR_NAME` | `testlab-flavor` | display name for messages |
| `PP4_FLAVOR_ID` | — | canonical uuid of the flavor (see gaps) |
| `PP4_ADMIN_PROJECT_ID` | — | expected admin project (asserted when set) |
| `PP4_EVIDENCE_DIR` | `./evidence` | screenshots |
| `PP4_OP_TIMEOUT_MS` | `900000` | Operation terminal poll budget (15 min) |
| `PP4_RESOURCE_TIMEOUT_MS` | `600000` | resource-state poll budget |

The campaign bash harness normally bridges
`PP4_ALICE_PASSWORD`/`PP4_FLAVOR_ID` from the VM state
(`/var/lib/o3k/araf-demo` secrets, `/etc/o3k/testlab-flavor-id`).

## stdout protocol (grepped by the campaign harness)

| Line | Emitted when |
| --- | --- |
| `PP4-TIMESTAMPS T4=<unix seconds>` | tenant OIDC login authenticated ("browser login usable") |
| `PP4-NATIVE id=<uuid>` | `pp4-native` created and ACTIVE |
| `PP4-TENANT-OK` | tenant journey finished incl. logout asserts |
| `PP4-OPERATOR-OK` | operator journey finished |
| `PP4-RELOGIN-OK` | post-reboot relogin recovered |

Evidence screenshots: `01-tenant-home-post-login`, `02-create-operation-pending`
(+`02a-create-form-blocked` when the known create-form gap triggers),
`03-pp4-native-active`, `04-operator-overview`, `05-operator-health` in
`PP4_EVIDENCE_DIR`.

## What each spec proves

- `specs/tenant.spec.ts` — steps (a)-(m): OIDC login + storage/DOM security
  scan + cookie audit; admin project scope discovery/selection; service
  catalog from real discovery (no fixture markers); usage/quota truth; home
  context; images → cirros-0.6.3; networks → testlab-network; servers →
  test-vm truthful status; create `pp4-native` (cirros + testlab-flavor +
  testlab-network) → canonical Operation SUCCEEDED → server Ready →
  `PP4-NATIVE id=`; detail shows the canonical uuid; stop action with truthful
  state transition; delete with final absence; logout → session destroyed,
  `/api/v1/context` 401s → `PP4-TENANT-OK`.
- `specs/operator.spec.ts` — login as alice; overview; installed services +
  discovered resource types; provider health; capacity (VCPU totals > 0);
  RegionOne regions; operator operations include the tenant-journey
  compute.server create; logout → `PP4-OPERATOR-OK`.
- `specs/relogin.spec.ts` — post-reboot OIDC/session recovery, read-only →
  `PP4-RELOGIN-OK`.

## Selector/flow provenance (read from source, not guessed)

| Flow | Source |
| --- | --- |
| OIDC: `/api/v1/auth/login` → IdP form → `/api/v1/auth/callback` → home; cookies `araf_<surface>_session` + `araf_csrf` | `araf/backend/console-bff-core/src/auth.rs:393-522`; proven end-to-end by `o3k-rust/tests/p12-iam-8-real-araf-process.sh` and `packaging/o3k-araf-demo.sh` (`browser_login`) |
| Keycloak form fields `username`/`password`/`credentialId`, form action parsed from served HTML | `o3k-rust/packaging/o3k-araf-demo.sh:638-660` (Keycloak 25.0.6 pinned in `packaging/araf-demo/compose.yaml`) |
| Tenant routes (`/`, `/services/catalog`, `/operations/:id`, `/resources/:type[/create|/:id]`, `/usage`) | `araf/apps/tenant-console/src/App.tsx:265-401` |
| Operator routes (`/platform/overview|regions|health|capacity`, `/services/installed`, `/operations`) | `araf/apps/operator-console/src/App.tsx:128-249` |
| Shell identity utility `User/Operator menu for <name>`; nav labels `Tenant navigation`/`Operator navigation` | `araf/packages/shell/src/components/TenantShell.tsx:124-135`, `OperatorShell.tsx:73-90` |
| Create form fields = schema keys (`name`, `image_id`, `flavor_id`, `network_ids`), labels from key, submit `Create <Name>`; submitted screen `Operation <id> is <state>` | `araf/packages/resources/src/components/ResourceCreatePage.tsx:49-108, 298-318, 395`; contract keys from `o3k-rust/crates/o3k-native-api/src/resource_contract.rs:10-22` |
| Action buttons named by lowercase verb (`start`/`stop`/`reboot`/`delete`); destructive confirm modal, `Delete` confirm; `role=status` operation note | `araf/packages/resources/src/components/ResourceActionsPanel.tsx:169-196`; verb descriptors from `araf/backend/console-bff-core/src/o3k_adapter.rs:1270-1287` |
| Collection tables: `role=table` aria-label `<plural> table`, name links to `/resources/<type>/<id>`; columns ID/Name/Status | `araf/packages/resources/src/components/ResourceCollectionPage.tsx:132-147`, `araf/backend/console-bff-core/src/o3k_adapter.rs:1234-1265` |
| Detail header description `ID: <uuid>`; Overview/Operations tabs | `araf/packages/resources/src/components/ResourceDetailPage.tsx:96-101, 52-90` |
| Operation detail `Operation <id>` heading, `Succeeded/Failed` status, Timeline | `araf/packages/operations/src/components/OperationDetailPage.tsx:27-35, 89-92` |
| Status labels Ready/Busy/Error/Unknown (O3K `stopped` → Busy) | `araf/packages/resources/src/status.ts:10-24`, mapping in `o3k_adapter.rs:223-232` |
| BFF endpoints (`/api/v1/auth/session|scopes|scope|logout`, `/api/v1/context`, `/api/v1/resources/...`, `/api/v1/operations`, `/api/v1/operator/...`), CSRF header `x-csrf-token` | `araf/backend/console-bff-core/src/lib.rs:53-179`, `csrf.rs:39-78` |
| Operator pages: overview (`Active operations:`, region/provider summaries), installed services tables, provider health, capacity, regions | `araf/packages/operator-platform/src/pages/*` |
| Demo truth: cirros-0.6.3 / testlab-network / testlab-flavor / test-vm / RegionOne | `o3k-rust/packaging/bootstrap-testlab.sh:34-40`, `bins/o3kd/src/composition/mod.rs:402-406` |

## Known pinned-tuple limitations (measured, worked around loudly)

The harness exercises the UI first and only falls back to the **identical BFF
call with the CSRF header** (the same call Araf's own process evidence makes —
see `tests/p12-iam-8-real-araf-process.sh`) when the UI is blocked. Each
fallback prints a `PP4-NOTE` line and takes a screenshot. No fallback touches
a mock; all traffic hits the live BFF/O3K.

1. **UI mutations 403.** The pinned Araf SPA client never sends
   `x-csrf-token`, but the production BFF requires it for every mutation
   (`araf/backend/console-bff-core/src/csrf.rs:39-78` vs
   `araf/packages/api-client/src/index.ts:691-702`). Affects create, stop,
   delete. → UI click attempted first; fallback adds the header.
2. **Create form blocked client-side.** The O3K create schema is a
   draft 2020-12 document (`crates/o3k-native-api/src/lib.rs:1026-1040`);
   Araf's schema-runtime uses draft-07 Ajv
   (`araf/packages/schema-runtime/src/index.ts:135`), which fails to compile
   it (`no schema with key or ref "https://json-schema.org/draft/2020-12/schema"` —
   verified empirically). Additionally `network_ids` is an array in the
   contract but renders as a text widget
   (`ResourceCreatePage.tsx:73-80`). → Form filled truthfully, submit
   attempted, fallback posts the exact contract payload with
   `network_ids: [<uuid>]`.
3. **No logout UI.** Araf ships no logout button (verified across
   `packages/shell` and `apps/*`). → `POST /api/v1/auth/logout` with the CSRF
   header, as Araf's own evidence does; UI + API asserts follow.
4. **No tenant scope-selection page.** The shell renders only after
   server-side scope selection; rc.12's ProjectSelector is presentation-only.
   → `POST /api/v1/auth/scope` (CSRF), then the shell is asserted in the UI.
5. **Flavor discovery.** `compute.flavor` has no collection in the O3K
   manifest (`crates/o3k-kernel/src/manifest.rs:1907-1930`), so the console
   cannot list flavors. → `PP4_FLAVOR_ID` (VM ledger
   `/etc/o3k/testlab-flavor-id`); the harness additionally tries the
   collection page first in case a future tuple advertises it.

## Notes

- Tests are serial (`workers: 1`, `mode: "serial"`) and share one browser
  context per spec; resource names are deterministic (single-tenant campaign).
- `npm install` was run on the host to produce `package-lock.json`;
  `node_modules/` is gitignored. Playwright browsers are NOT downloaded here
  (`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` is safe): the browser lives in the VM.
