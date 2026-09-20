# PP.4 browser E2E harness

Acceptance evidence for **o3kio/o3k#973** (PP.4 one-line demo with a real
browser): real OIDC login (Keycloak authorization-code + PKCE through the
confidential Araf BFF), Araf tenant + operator consoles backed by the real O3K
native API in the demo profile. **No fixtures, no mocks, no stubs** — every
assertion hits the live deployment.

The journeys are written against **verified** product behaviour: what the demo
profile cannot do is not assumed away, it is performed, observed and recorded
as a **classified gap** (see [Classified gaps](#classified-gaps-verified-product-profile-facts)).
A gap is evidence, not a failure. A fabricated success, a client-side crash
page, or a mutation that bypassed the UI *is* a failure.

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
export PP4_IMAGE_ID=...                  # uuid of the cirros image (compat API)
export PP4_NETWORK_ID=...                # uuid of testlab-network (compat API)
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
| `PP4_VM_NAME` | `pp4-native` | deterministic VM name the console create attempt uses |
| `PP4_UI_TARGET_NAME` | value of `PP4_VM_NAME` | server name the console delete journey targets |
| `PP4_IMAGE_NAME` | `cirros-0.6.3` | TestLab image name (gap detail only) |
| `PP4_NETWORK_NAME` | `testlab-network` | TestLab network name (gap detail only) |
| `PP4_IMAGE_ID` | — | **required**: canonical id `openstack image list` reports (the native `image.image` inventory is empty) |
| `PP4_NETWORK_ID` | — | **required**: canonical id `openstack network list` reports (`testlab-network` is compat-created, not canonical) |
| `PP4_FLAVOR_ID` | — | **required**: canonical uuid of the flavor (see gaps) |
| `PP4_UI_TARGET_ID` | — | supplied only for the post-verification delete run; canonical id created by the browser |
| `PP4_ADMIN_PROJECT_ID` | — | **required**: expected admin project (asserted when set) |
| `PP4_DEPLOYMENT_ENV_FILE` | — | **required**: phase1a production-tuple evidence (`10-araf-production-tuple.txt`) |
| `PP4_EVIDENCE_DIR` | `./evidence` | screenshots |
| `PP4_OP_TIMEOUT_MS` | `900000` | Operation terminal poll budget (15 min) |
| `PP4_RESOURCE_TIMEOUT_MS` | `600000` | resource-state poll budget |

`PP4_IMAGE_ID`/`PP4_NETWORK_ID`/`PP4_FLAVOR_ID` are fail-fast requirements: the
native image/network inventories of this profile are empty and `compute.flavor`
has no collection at all, so there is nothing to fall back on. The campaign bash
harness bridges them from the VM (`/etc/o3k/testlab-flavor-id` and the
unmodified OpenStack CLI). The workload itself is created through Araf's native
schema-driven form; its canonical id is exported as `PP4_UI_TARGET_ID` only
after live provider and guest-boot inspection.

## stdout protocol (grepped by the campaign harness)

| Line | Emitted when |
| --- | --- |
| `PP4-TIMESTAMPS T4=<unix seconds>` | tenant OIDC login authenticated ("browser login usable") |
| `PP4-GAP <id> <detail>` | a verified product-profile gap was observed (a gap, never a failure) |
| `PP4-UI-CREATE id=<uuid> operation=<uuid>` | the schema-driven form created a native server |
| `PP4-UI-DELETE id=<uuid> state=<state>` | the console delete of that native server reached a terminal state |
| `PP4-UI-FALLBACK <step>` | **invalidating**: the mutation did not go through the real UI |
| `PP4-TENANT-OK` | tenant journey finished incl. logout asserts |
| `PP4-OPERATOR-OK` | operator journey finished |
| `PP4-RELOGIN-OK` | post-reboot relogin recovered |

The tenant native-create journey writes its canonical id to
`05-browser-ids.env` as `PP4_UI_CREATE_ID`. Host-side provider and guest-boot
checks run while that resource remains live; only then does the delete journey
receive the same id as `PP4_UI_TARGET_ID`. The operator witness ties its
canonical-operation assertion to that id.

Evidence screenshots: `01-tenant-home-post-login`,
`06-images-native-inventory`, `07-networks-native-inventory`,
`08b-create-form-truthful-error` (or `08b-create-operation` when the create
reached the BFF), `08c-servers-after-failed-create`, `09a-ui-delete-target-detail`,
`09c-ui-delete-operation`, `09d-ui-delete-concealed`, `06-operator-installed-services`
in `PP4_EVIDENCE_DIR`.

## What each spec proves

- `specs/tenant.spec.ts`
  1. OIDC login + storage/DOM security scan + cookie audit.
  2. admin project scope discovery/selection.
  3. service catalog from real discovery (no fixture markers).
  4. usage/quota truth; tenant home context.
  5. **images**: the collection renders truthfully (no fabricated row; every
     row id is cross-checked against the console API) → `PP4-GAP
     images-native-inventory=compat-only`.
  6. **networks**: the same truthfulness proof → `PP4-GAP
     network-compat-created-not-canonical`.
  7. **servers**: `test-vm` is listed and inspected by CANONICAL ID (the
     native list projection carries no spec name).
  8. **console VM create succeeds natively**: the JSON-Schema-driven form is
     filled with the env-provided image/flavor/network ids and submitted
     through the real UI; the canonical Operation succeeds and the resource
     reaches Ready. The host then proves OpenStack visibility, libvirt
     execution, and the CirrOS boot marker.
  9. **console delete on the same native class**: the browser-created server is opened by canonical id and deleted through the
     advertised `delete` action (button + destructive confirmation modal). The
     console must render an operation id with a terminal state (or a
     synchronously completed state — the BFF does not persist pollable
     operations for synchronous mutations), and the resource must then be
     concealed: the detail URL shows the truthful not-found state and the
     canonical live view through the BFF answers 404. Prints
     `PP4-UI-DELETE id=<uuid> state=<state>`.
  10. inspect `test-vm` detail (canonical uuid + name); logout → session
      destroyed, `/api/v1/context` 401s → `PP4-TENANT-OK`.
- `specs/operator.spec.ts` — login as alice; platform overview; installed
  services + discovered resource types (incl. a truthful Storage/volume
  rendering — empty is fine, fabricated is not); provider health; capacity
  (VCPU totals > 0); RegionOne regions; the `/operations` page renders
  truthfully about the upstream global list (the dedicated
  `/api/v1/operator/operations` route is not implemented by O3K on this profile
  → classified gap), and the canonical `/api/v1/operations` list the operator
  surface serves must contain the delete Operation for the resource the tenant
  console deleted (`PP4_UI_TARGET_ID`); logout → `PP4-OPERATOR-OK`.
- `specs/relogin.spec.ts` — post-reboot OIDC/session recovery, read-only, lists
  the TestLab workload by canonical id → `PP4-RELOGIN-OK`.

## Classified gaps (verified product-profile facts)

These are recorded, not worked around. Each is printed as `PP4-GAP <id> <detail>`
and aggregated by the campaign into `35-classified-gaps.txt`.

| Gap id | Observed truth |
| --- | --- |
| `images-native-inventory=compat-only` | The native `image.image` inventory is empty; the demo cirros image exists only through the compatibility (Glance) API. |
| `network-compat-created-not-canonical` | `testlab-network` was created through the compatibility (Neutron) API and lives only in the compat store, so the native `network.network` list does not contain it. |
| `native-vm-create` | No native-create gap is accepted. A campaign that cannot complete the schema-driven create fails. |
| `operator-global-operations-not-exposed` | The operator console's dedicated global operations list (`/api/v1/operator/operations`) is not implemented by upstream O3K, so that page renders an explicit failure/empty state instead of rows. The canonical `/api/v1/operations` list is served on the same surface and carries the operator tie-in. |

## Canonical Operations: synchronous vs. pollable

Native CRUD routes may complete **synchronously**: the BFF then reports the
terminal state in the mutation response itself and does not persist a pollable
history record (`fetch_or_build_operation`, `o3k_adapter.rs`). The harness
therefore reads the Operation id **and** state the console rendered, treats a
terminal console state as authoritative, and only polls
`/api/v1/operations/<id>` while the console reports a non-terminal state.

## UI-mutation rule

Every cloud mutation in this harness goes through the **real console UI**: the
schema-driven create form or advertised action button and its destructive
confirmation modal. Araf rc.15 supplies the production CSRF header itself;
any `PP4-UI-CSRF-BRIDGE` marker or UI fallback fails the campaign. There is
deliberately **no BFF helper for creating or deleting a resource** in
`lib/bff.ts`: a step that cannot be performed through the UI records
`PP4-UI-FALLBACK <step>` (or fails outright) and host-run fails the campaign.

## Selector/flow provenance (read from source, not guessed)

| Flow | Source |
| --- | --- |
| OIDC: `/api/v1/auth/login` → IdP form → `/api/v1/auth/callback` → home; cookies `araf_<surface>_session` + `araf_csrf` | `araf/backend/console-bff-core/src/auth.rs:393-522`; proven end-to-end by `o3k-rust/tests/p12-iam-8-real-araf-process.sh` and `packaging/o3k-araf-demo.sh` (`browser_login`) |
| Keycloak form fields `username`/`password`/`credentialId`, form action parsed from served HTML | `o3k-rust/packaging/o3k-araf-demo.sh:638-660` (Keycloak 25.0.6 pinned in `packaging/araf-demo/compose.yaml`) |
| Tenant routes (`/`, `/services/catalog`, `/operations/:id`, `/resources/:type[/create|/:id]`, `/usage`) | `araf/apps/tenant-console/src/App.tsx:265-401` |
| Operator routes (`/platform/overview|regions|health|capacity`, `/services/installed`, `/operations`) | `araf/apps/operator-console/src/App.tsx:128-249` |
| Shell identity utility `User/Operator menu for <name>`; nav labels `Tenant navigation`/`Operator navigation` | `araf/packages/shell/src/components/TenantShell.tsx:124-135`, `OperatorShell.tsx:73-90` |
| Create form fields = schema keys (`name`, …), labels from key, submit `Create <Name>`; submitted screen `Operation <id> is <state>` | `araf/packages/resources/src/components/ResourceCreatePage.tsx:49-108, 298-318, 395`; contract keys from `o3k-rust/crates/o3k-native-api/src/resource_contract.rs:10-22` (`NetworkCreateSpec` = `{name}`) |
| Contract dialects: `$schema` selects the Ajv 2020-12 entry point | `araf/packages/schema-runtime/src/index.ts:105-135` |
| Submit-time validation summary `Please correct the errors below.` + field-level error slot `<controlId>-error` (Araf passes `controlId=field-<key>`) — how `console-create-schema-dialect` is classified | `araf/packages/resources/src/components/ResourceCreatePage.tsx:245-253, 333-336, 458`; `@cloudscape-design/components` `src/form-field/internal.tsx` (`FormFieldError`) and `src/form-field/util.ts` (`makeSlotId` → `${formFieldId}-error`) |
| Action buttons named by the discovered action (`delete`/`update` for `compute.server`, `delete` for `network.network`); destructive confirm modal, `Delete` confirm; `role=status` operation note | `araf/packages/resources/src/components/ResourceActionsPanel.tsx:169-196`; action names come from O3K discovery `lifecycle_actions` keys (`o3k-rust/crates/o3k-kernel/src/manifest.rs:1870-1905`) |
| Collection tables: `role=table` aria-label `<plural> table`, name links to `/resources/<type>/<id>`, empty state `No resources`; columns ID/Name/Status | `araf/packages/resources/src/components/ResourceCollectionPage.tsx:79-147` |
| Detail header description `ID: <uuid>`; Overview/Operations tabs | `araf/packages/resources/src/components/ResourceDetailPage.tsx:96-101, 52-90` |
| Operation detail `Operation <id>` heading, `Succeeded/Failed` status, Timeline | `araf/packages/operations/src/components/OperationDetailPage.tsx:27-35, 89-92` |
| Status labels Ready/Busy/Error/Unknown | `araf/packages/resources/src/status.ts:10-24` |
| BFF endpoints (`/api/v1/auth/session|scopes|scope|logout`, `/api/v1/context`, `/api/v1/resources/...`, `/api/v1/operations`, `/api/v1/operator/...`), CSRF header `x-csrf-token`; action request body is `{actionId, payload?}` (camelCase) | `araf/backend/console-bff-core/src/lib.rs:53-179`, `csrf.rs:39-78`, `model.rs:364-372` |
| Operator pages: overview (`Active operations:`, region/provider summaries), installed services tables, provider health, capacity, regions | `araf/packages/operator-platform/src/pages/*` |
| Native list projection: `name` falls back to the canonical id when `spec.name` is absent | `araf/backend/console-bff-core/src/o3k_adapter.rs:361-372` |
| Demo truth: cirros-0.6.3 / testlab-network / testlab-flavor / test-vm / RegionOne | `o3k-rust/packaging/bootstrap-testlab.sh:34-40`, `bins/o3kd/src/composition/mod.rs:402-406` |

## Known bounded profile limitations

1. **No logout UI.** Araf ships no logout button (verified across
   `packages/shell` and `apps/*`). → `POST /api/v1/auth/logout` with the CSRF
   header, as Araf's own evidence does; UI + API asserts follow.
2. **No tenant scope-selection page.** The shell renders only after
   server-side scope selection; the ProjectSelector is presentation-only.
   → `POST /api/v1/auth/scope` (CSRF), then the shell is asserted in the UI.
3. **Compatibility-only inventories.** `image.image` and `network.network` have
   no canonical rows on a fresh demo deployment, and `compute.flavor` has no
   collection at all (`crates/o3k-kernel/src/manifest.rs:1907-1930`). → the
   compat ids come from the harness env (`PP4_IMAGE_ID`, `PP4_NETWORK_ID`,
   `PP4_FLAVOR_ID`), and the empty inventories are recorded as gaps. The
   workload itself is created through the native schema-driven form.

## Notes

- Tests are serial (`workers: 1`, `mode: "serial"`) and share one browser
  context per spec; resource names are deterministic (single-tenant campaign).
- The native-create target is supplied to the post-verification delete run by
  the campaign harness (host-run.sh); it is never pre-created through the
  compatibility CLI.
- `npm install` was run on the host to produce `package-lock.json`;
  `node_modules/` is gitignored. Playwright browsers are NOT downloaded here
  (`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` is safe): the browser lives in the VM.
