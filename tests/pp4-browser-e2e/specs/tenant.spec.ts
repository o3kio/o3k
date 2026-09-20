/**
 * PP.4 tenant journey — sequential, one shared browser context.
 *
 * Proves against the live demo deployment (production Araf profile on the real
 * O3K native API, real Keycloak OIDC), and truthfully records what this product
 * profile does NOT support as classified gaps:
 *   a. OIDC login (authorization code + PKCE through the confidential BFF)
 *   b. web-storage/DOM security scan + cookie audit
 *   c. project scope discovery + selection (admin project)
 *   d. service catalog derived from real O3K discovery
 *   e. usage/capacity truth (quotas/meters)
 *   f. deployment topology context on the tenant home
 *   g. image collection renders truthfully — the native `image.image`
 *      inventory is EMPTY while the demo's cirros image exists through the
 *      compatibility (Glance) API -> PP4-GAP images-native-inventory=compat-only
 *   h. network collection renders truthfully — `testlab-network` was created
 *      through the compatibility (Neutron) API and is not a canonical
 *      `network:network` resource -> PP4-GAP network-compat-created-not-canonical
 *   i. server collection lists the CLI-created workload by CANONICAL ID (the
 *      native list projection carries no spec name)
 *   j. a REAL console create of a VM fails truthfully: the native
 *      `compute.server` create cannot be scheduled on this profile (the
 *      network execution agent is inactive by contract), the console shows a
 *      real error, and no server is fabricated. The pinned Araf SPA cannot
 *      submit ANY create form (the create schemas O3K serves declare JSON
 *      Schema 2020-12 while the pinned schema-runtime compiles with draft-07
 *      Ajv; the upstream fix, Araf PR #118, is not in this release tuple), so
 *      the observed console error is classified as well:
 *      -> PP4-GAP native-vm-create=network-provider-inactive
 *      -> PP4-GAP console-create-schema-dialect=<observed error class>
 *   k. a REAL console delete on a supported native resource class: the server
 *      `pp4-ui-target` (created BEFORE the browser phase through the
 *      unmodified OpenStack CLI, so it is a canonical native resource with the
 *      same uuid the console lists) is deleted through its advertised action
 *      and confirmation modal, and the truthful final absence is observed.
 *      Prints PP4-UI-DELETE id=<uuid> state=<observed>.
 *   l. inspect the TestLab workload detail by canonical id
 *   m. logout — session destroyed, follow-up API call 401s
 *
 * stdout protocol lines grepped by the campaign harness:
 *   PP4-TIMESTAMPS T4=<unix seconds>         (after login succeeds)
 *   PP4-UI-CSRF-BRIDGE <METHOD> <path>       (diagnostic: CSRF header added)
 *   PP4-UI-FALLBACK <step>                   (INVALIDATING: a step fell back to
 *                                             the BFF; host-run fails)
 *   PP4-GAP <id> <detail>                    (classified product-profile gap)
 *   PP4-UI-DELETE id=<uuid> state=<state>    (after the console delete)
 *   PP4-TENANT-OK                            (after logout asserts)
 *
 * Security asserts run immediately after login (web storage + DOM scan) plus a
 * deployment-side production-profile check (PP4_DEPLOYMENT_ENV_FILE).
 *
 * Cross-spec handoff: none. The resource the console deletes is the harness's
 * own target, whose canonical id the campaign exports as PP4_UI_TARGET_ID; the
 * operator journey ties its canonical-operations assertion to the same id
 * instead of reading a shared file.
 *
 * Known pinned-tuple limitations exercised here (see ../README.md):
 *   - the pinned Araf SPA never sends x-csrf-token, so UI mutations would 403;
 *     `installCsrfBridge` adds that one header at the network layer, keeping
 *     the click path real. The delete mutation goes through the real UI
 *     (advertised action button + confirmation modal) with no BFF fallback: a
 *     step that cannot be performed through the UI fails the campaign here
 *     rather than bypassing it.
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import {
  bffFetch,
  getResource,
  getSession,
  installCsrfBridge,
  listScopes,
  logCookieNames,
  logout,
} from "../lib/bff";
import {
  assertIdentityVisible,
  connectBrowser,
  loginToSurface,
  selectAdminProject,
  type AuthenticatedSurface,
} from "../lib/login";
import {
  CANONICAL_ID,
  evidence,
  expectNoConsoleCrash,
  expectNoFixtureMarkers,
  expectProductionDeployment,
  findResourceIdByName,
  getResourceOrUndefined,
  openCollection,
  openOperationDetail,
  parseSubmittedOperation,
  resourceRowById,
  resolveTerminalOperation,
  waitForResourceConcealed,
} from "../lib/console";

test.describe.configure({ mode: "serial" });
test.setTimeout(300_000);

const SERVER_TYPE = "compute.server";
const SERVER_PLURAL = "servers";
const NETWORK_TYPE = "network.network";
const NETWORK_PLURAL = "networks";
const IMAGE_TYPE = "image.image";
const IMAGE_PLURAL = "images";

let env: Pp4Env;
let browser: Browser | undefined;
let auth: AuthenticatedSurface;
let projectName = "";
let testVmId = "";

/** Emit a classified product-profile gap: one log line, one evidence line. */
function gap(id: string, detail: string): void {
  // eslint-disable-next-line no-console
  console.log(`PP4-GAP ${id} ${detail}`);
}

/** Read the create page's error banner (or undefined when none is shown). */
async function readErrorBanner(): Promise<string | undefined> {
  const alert = auth.page.getByRole("alert").first();
  if ((await alert.count()) === 0) return undefined;
  const text = (await alert.textContent().catch(() => "")) ?? "";
  return text.trim() === "" ? undefined : text.trim();
}

/** The console create error class plus the raw signal it was decided from. */
interface CreateErrorClassification {
  /** `client-schema-compile` | `client-validation` | `upstream-<status>` | `other`. */
  readonly klass: string;
  /** Rendered field-level error elements (Cloudscape's `<controlId>-error` slot). */
  readonly fieldErrors: number;
}

/**
 * Classify the console create failure from what the page actually rendered.
 *
 * The create page renders the SAME submit-time summary ("Please correct the
 * errors below.") for a schema-runtime compile failure and for contract-field
 * validation, so the banner alone cannot separate the two. The DOM can: the
 * pinned schema-runtime reports a compile failure with an EMPTY instance path
 * (`collectErrors` then maps it to no field), while a real field validation
 * failure renders Cloudscape's error slot `<controlId>-error` (Araf passes
 * `controlId=field-<key>`).
 */
async function classifyCreateError(banner: string): Promise<CreateErrorClassification> {
  if (/correct the errors below/i.test(banner)) {
    const fieldErrors = await auth.page
      .locator('form [id$="-error"]')
      .filter({ hasText: /\S/u })
      .count();
    return { klass: fieldErrors === 0 ? "client-schema-compile" : "client-validation", fieldErrors };
  }
  const upstream = /\((\d{3})\)/u.exec(banner);
  if (upstream?.[1]) return { klass: `upstream-${upstream[1]}`, fieldErrors: 0 };
  return { klass: "other", fieldErrors: 0 };
}

test.beforeAll(async () => {
  env = loadEnv(); // fail fast on missing PP4_ALICE_PASSWORD / PP4_FLAVOR_ID etc.
  // Server-side fixture check: the deployment itself must be the pinned
  // production tuple (phase1a evidence), not merely render without the word.
  expectProductionDeployment(env);
  browser = await connectBrowser(env);
  auth = await loginToSurface(browser, env, "tenant");
  // The pinned SPA sends no CSRF header; bridge it so the UI click path can
  // actually perform its mutations (recorded per request as PP4-UI-CSRF-BRIDGE).
  await installCsrfBridge(auth.context, auth.baseUrl);

  // (a) "browser login usable" measurement for the campaign timestamps.
  // eslint-disable-next-line no-console
  console.log(`PP4-TIMESTAMPS T4=${Math.floor(Date.now() / 1000)}`);

  // SECURITY: no token material may reach web storage or the DOM.
  const storageFindings = await auth.page.evaluate(() => {
    const findings: string[] = [];
    const keyPattern = /access_token|refresh_token|id_token|client_secret/i;
    const jwtPattern = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
    for (const [storeName, store] of [
      ["localStorage", window.localStorage],
      ["sessionStorage", window.sessionStorage],
    ] as const) {
      for (let index = 0; index < store.length; index += 1) {
        const key = store.key(index);
        if (!key) continue;
        const value = store.getItem(key);
        if (keyPattern.test(key)) findings.push(`${storeName}:${key}`);
        if (value && jwtPattern.test(value)) findings.push(`${storeName}:${key}=<jwt>`);
      }
    }
    return findings;
  });
  expect(
    storageFindings,
    "browser web storage must not contain token-like keys or JWT values",
  ).toEqual([]);
  expect(
    await auth.page.content(),
    "document HTML must not contain a client_secret",
  ).not.toContain("client_secret");
  await logCookieNames(auth.context, auth.baseUrl);

  // (b) Scope discovery + selection (required before the shell can render).
  const project = await selectAdminProject(auth, env);
  projectName = project.projectName;

  // Home must render the authenticated shell now.
  await auth.page.goto(`${env.tenantUrl}/`);
  await expect(
    auth.page.getByRole("navigation", { name: "Tenant navigation" }),
    "tenant shell navigation renders after scope selection",
  ).toBeVisible({ timeout: 60_000 });
  await assertIdentityVisible(auth);
  await evidence(auth.page, env, "01-tenant-home-post-login");
});

test.afterAll(async () => {
  try {
    if (auth) await logout(auth.page, auth.baseUrl);
  } catch {
    // already logged out or session gone
  }
  await auth?.context.close().catch(() => undefined);
  await browser?.close().catch(() => undefined);
});

test("project scope is listed and selectable", async () => {
  // The scope discovery endpoint offered the admin project...
  const scopes = await listScopes(auth.page, env.tenantUrl);
  const adminListed = scopes.filter(
    (scope) => scope.kind === "project" && scope.can_request_token !== false,
  );
  expect(adminListed.length, "scope discovery must list projects").toBeGreaterThan(0);
  expect(
    adminListed.some((scope) => scope.id === env.adminProjectId),
    "scope discovery must offer the canonical admin project",
  ).toBe(true);

  // ...and the shell reflects the selection (ProjectSelector in the nav). On a
  // fresh install the navigation drawer starts collapsed, hiding the selector;
  // open it when needed. Cold-start hydration also takes a while, so allow 90s.
  let selector = auth.page.getByLabel("Project");
  if (!(await selector.first().isVisible().catch(() => false))) {
    const drawer = auth.page.getByRole("button", { name: /open navigation drawer/i });
    if ((await drawer.count()) > 0) {
      await drawer.first().click();
    }
    selector = auth.page.getByLabel("Project");
  }
  await expect(selector.first(), "project selector is rendered").toBeVisible({ timeout: 90_000 });
  await expect
    .poll(async () => selector.inputValue(), { timeout: 30_000 })
    .not.toBe("");
  const selectedValue = await selector.inputValue();
  const selectedLabel = await selector.evaluate(
    (element: HTMLSelectElement) => element.selectedOptions[0]?.textContent ?? "",
  );
  // The shell's ProjectSelector renders the canonical project identity (the
  // scope id O3K issued for the admin project); the human name is asserted
  // through scope discovery above. Accept either form and record the label.
  expect(
    selectedValue === env.adminProjectId || selectedLabel.trim() === projectName,
    `project selector must show the canonical admin project (value="${selectedValue}", label="${selectedLabel}")`,
  ).toBe(true);
  // eslint-disable-next-line no-console
  console.log(`[pp4] project scope selected: value="${selectedValue}" label="${selectedLabel.trim()}"`);
});

test("service catalog renders real O3K discovery", async () => {
  await auth.page.goto(`${env.tenantUrl}/services/catalog`);
  await expect(
    auth.page.getByRole("heading", { name: "Service catalog" }),
  ).toBeVisible({ timeout: 30_000 });
  const table = auth.page.getByRole("table", { name: "Service catalog" });
  await expect(table).toBeVisible();
  await expect
    .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1); // header + at least one entry

  // Discovery-derived: the demo advertises the native compute service; the
  // compute.server resource type is rendered as its resource link.
  await expect(auth.page.getByText("Compute", { exact: true }).first()).toBeVisible();
  await expect(
    auth.page.locator('a[href="/resources/compute.server"]').first(),
    "the catalog must link the discovered compute.server resource type",
  ).toBeVisible();
  // Tenant navigation is derived from the same catalog.
  const navigation = auth.page.getByRole("navigation", { name: "Tenant navigation" });
  await expect(navigation.getByRole("link", { name: SERVER_PLURAL })).toBeVisible();
  await expectNoFixtureMarkers(auth.page);
});

test("usage and capacity show real numbers", async () => {
  await auth.page.goto(`${env.tenantUrl}/usage`);
  await expect(
    auth.page.getByRole("heading", { name: /Usage & Cost/i }),
  ).toBeVisible({ timeout: 30_000 });

  // Quota overview: real per-project limits/usage from the O3K quota API.
  const quotaTable = auth.page.getByRole("table", { name: "Quota overview" });
  await expect(quotaTable, "quota overview renders").toBeVisible({ timeout: 30_000 });
  await expect
    .poll(async () => quotaTable.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  // Total vcpus: the compute:vcpus quota row must show real usage, and a real
  // numeric limit or the documented O3K "unlimited" limit kind.
  const vcpusRow = quotaTable.getByRole("row", { name: /compute:vcpus/i });
  if ((await vcpusRow.count()) > 0) {
    const cells = await vcpusRow.first().getByRole("cell").allTextContents();
    const joined = cells.join(" ");
    expect(joined, "compute:vcpus row must carry numeric usage").toMatch(/\d/);
  }

  // Usage: meters or records render when the deployment reports them; an
  // explicit "No usage data" empty state is equally truthful and tolerated.
  // The demo's metering read can also fail truthfully (the console shows the
  // canonical error), which must never be reported as fabricated usage.
  const metered = auth.page.getByRole("table", { name: "Authoritative metering usage" });
  const classic = auth.page.getByRole("table", { name: "Usage by resource type" });
  const emptyState = auth.page.getByText("No usage data");
  const usageError = auth.page.getByText(/Failed to load usage data/i);
  const usageVisible =
    (await metered.count()) > 0 ||
    (await classic.count()) > 0 ||
    (await emptyState.count()) > 0;
  if (!usageVisible) {
    await expect(
      usageError.first(),
      "usage must render data, an explicit empty state, or a truthful error",
    ).toBeVisible({ timeout: 30_000 });
    const detail = (await usageError.first().locator("..").textContent()) ?? "";
    // eslint-disable-next-line no-console
    console.log(
      `PP4-GAP metering-usage-read-error Usage & Cost surfaced a truthful error ` +
        `instead of usage rows: ${detail.trim().slice(0, 200)}`,
    );
  }
  await expectNoFixtureMarkers(auth.page);
});

test("tenant home shows truthful deployment context", async () => {
  await auth.page.goto(`${env.tenantUrl}/`);
  await expect(
    auth.page.getByRole("heading", { name: "Tenant home" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(auth.page.getByText(/Operate .+ in .+/)).toBeVisible();

  // The home page states the truthful deployment context: the canonical
  // project identity and the region (o3k-demo-v1 has no organization concept).
  const banner = auth.page.getByText(/^Operate .+ in .+\./);
  await expect(banner, "tenant home states the deployment context").toBeVisible();
  const bannerText = (await banner.textContent()) ?? "";
  expect(bannerText, "context banner names the canonical project").toContain(env.adminProjectId);
  expect(bannerText, "context banner names the region").toMatch(/\bGlobal\b/);
  const context = auth.page.getByRole("heading", { name: "Current context" }).locator("..");
  await expect(context, "current-context section renders").toBeVisible();
  await expect(
    auth.page.getByText("Current organization"),
    "the context section labels the organization row truthfully",
  ).toBeVisible();
  await expect(
    auth.page.getByText(env.adminProjectId).first(),
    "the context section shows the selected canonical project",
  ).toBeVisible();
  await expect(auth.page.getByText("No project selected")).toHaveCount(0);
});

test("image collection is truthful about the native inventory", async () => {
  const observed = await openCollection(auth.page, env.tenantUrl, IMAGE_TYPE, IMAGE_PLURAL);

  // Whatever is rendered must be a real canonical resource: the console must
  // never invent a row. Every row id is a canonical uuid and is either a live
  // canonical resource of the right type or a concealed canonical tombstone.
  let liveRows = 0;
  let tombstoneRows = 0;
  for (const id of observed.ids) {
    expect(id, "a rendered image row must carry a canonical uuid").toMatch(CANONICAL_ID);
    const resource = await getResourceOrUndefined(auth.page, env.tenantUrl, IMAGE_TYPE, id);
    if (!resource) {
      tombstoneRows += 1;
      continue;
    }
    liveRows += 1;
    expect(resource.id, "the row id must resolve to the same canonical resource").toBe(id);
    expect(resource.resourceType, "a rendered image row must be an image.image resource").toBe(
      IMAGE_TYPE,
    );
  }
  await evidence(auth.page, env, "06-images-native-inventory");

  // VERIFIED profile fact: the demo image exists only through the
  // compatibility (Glance) API, so the native inventory does not carry it.
  const compatListed = observed.ids.includes(env.imageId);
  if (!compatListed) {
    gap(
      "images-native-inventory=compat-only",
      `native_rows=${observed.ids.length} live_rows=${liveRows} tombstone_rows=${tombstoneRows} ` +
        `compat_image_id=${env.imageId} compat_image_name=${env.imageName} ` +
        `empty_state=${String(observed.empty)}`,
    );
  } else {
    // eslint-disable-next-line no-console
    console.log(
      `[pp4] the compat image ${env.imageId} IS a canonical native row ` +
        `(${observed.ids.length} row(s) total): no inventory gap to classify`,
    );
  }
  await expectNoFixtureMarkers(auth.page);
});

test("network collection is truthful about the native inventory", async () => {
  const observed = await openCollection(auth.page, env.tenantUrl, NETWORK_TYPE, NETWORK_PLURAL);

  let liveRows = 0;
  let tombstoneRows = 0;
  for (const id of observed.ids) {
    expect(id, "a rendered network row must carry a canonical uuid").toMatch(CANONICAL_ID);
    const resource = await getResourceOrUndefined(auth.page, env.tenantUrl, NETWORK_TYPE, id);
    if (!resource) {
      tombstoneRows += 1;
      continue;
    }
    liveRows += 1;
    expect(resource.id, "the row id must resolve to the same canonical resource").toBe(id);
    expect(
      resource.resourceType,
      "a rendered network row must be a network.network resource",
    ).toBe(NETWORK_TYPE);
  }
  await evidence(auth.page, env, "07-networks-native-inventory");

  // VERIFIED profile fact: testlab-network was created through the
  // compatibility (Neutron) API and lives only in the compat store, so a fresh
  // demo deployment shows an empty Araf Networks page while
  // `openstack network list` shows it.
  const compatListed = observed.ids.includes(env.networkId);
  if (!compatListed) {
    gap(
      "network-compat-created-not-canonical",
      `native_rows=${observed.ids.length} live_rows=${liveRows} tombstone_rows=${tombstoneRows} ` +
        `compat_network_id=${env.networkId} compat_network_name=${env.networkName} ` +
        `empty_state=${String(observed.empty)}`,
    );
  } else {
    // eslint-disable-next-line no-console
    console.log(
      `[pp4] the compat network ${env.networkId} IS a canonical native row ` +
        `(${observed.ids.length} row(s) total): no inventory gap to classify`,
    );
  }
  await expectNoFixtureMarkers(auth.page);
});

test("server collection lists the TestLab workload by canonical id", async () => {
  // Row identity is the canonical id: VERIFIED, the native list projection
  // does not carry the spec name for every resource (some rows are labelled
  // with their id). The name is asserted on the detail page below.
  testVmId = await findResourceIdByName(auth.page, env.tenantUrl, SERVER_TYPE, "test-vm");
  expect(testVmId, "resolved workload id must be a canonical uuid").toMatch(CANONICAL_ID);

  const observed = await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL);
  expect(observed.ids, `test-vm (${testVmId}) must be listed`).toContain(testVmId);

  const row = resourceRowById(auth.page, SERVER_PLURAL, testVmId);
  await expect(row, `test-vm (${testVmId}) row is listed`).toBeVisible({ timeout: 60_000 });
  // The status cell renders the mapped O3K state (Ready/Busy/Error/Unknown).
  await expect(row.getByText(/Ready|Busy|Error|Unknown/)).toBeVisible();

  // The detail page renders the resource's real name and canonical id.
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(testVmId)}`);
  await expect(
    auth.page.getByRole("heading", { name: "test-vm" }),
    "the detail page renders the TestLab workload name",
  ).toBeVisible({ timeout: 30_000 });
  await expect(auth.page.getByText(`ID: ${testVmId}`)).toBeVisible();
  await expectNoConsoleCrash(auth.page);
  await expectNoFixtureMarkers(auth.page);
});

test("console VM create fails truthfully (classified gap)", async () => {
  test.setTimeout(env.operationTimeoutMs + 6 * 60 * 1000);

  // The pinned demo tuple does not advertise a flavor collection
  // (compute.flavor has no collection in the O3K manifest), so the canonical
  // id must come from the campaign harness (PP4_FLAVOR_ID, read in the VM from
  // /etc/o3k/testlab-flavor-id). loadEnv() already fails when it is missing.
  const flavorId = env.flavorId;

  // Baseline: the server rows that exist BEFORE the create attempt, so the
  // outcome can never pass vacuously on stale state.
  const before = await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL);

  // Schema-driven create form (fields derived from the O3K create contract:
  // name, image_id, flavor_id, network_ids, ...).
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/create`);
  await expect(
    auth.page.getByRole("heading", { name: "Create Server" }),
    "schema-driven create form heading",
  ).toBeVisible({ timeout: 60_000 });

  // exact, because "name" also matches the sibling "key_name" field
  const nameField = auth.page.getByLabel("name", { exact: true });
  const imageField = auth.page.getByLabel("image_id", { exact: true });
  const flavorField = auth.page.getByLabel("flavor_id", { exact: true });
  const networkField = auth.page.getByLabel("network_ids", { exact: true });
  for (const field of [nameField, imageField, flavorField, networkField]) {
    await expect(field, "create form exposes the O3K contract fields").toBeVisible();
  }

  await nameField.fill(env.vmName);
  await imageField.fill(env.imageId);
  await flavorField.fill(flavorId);
  await networkField.fill(env.networkId); // text widget; the array contract needs []

  // The REAL UI submit. No BFF fallback exists for this step: the expected
  // outcome is a truthful failure, so there is nothing to fall back to.
  await auth.page.getByRole("button", { name: "Create Server" }).click();

  const submittedHeading = auth.page.getByRole("heading", { name: /creation submitted/i });
  const alert = auth.page.getByRole("alert").first();
  const outcome = await Promise.race([
    submittedHeading.waitFor({ state: "visible", timeout: 45_000 }).then(() => "submitted" as const),
    alert.waitFor({ state: "visible", timeout: 45_000 }).then(() => "error" as const),
  ]).catch(() => "timeout" as const);

  let detail = "";
  let consoleErrorClass: CreateErrorClassification | undefined;
  let consoleErrorBanner = "";
  if (outcome === "timeout") {
    await evidence(auth.page, env, "08a-create-form-no-outcome");
    throw new Error(
      "[pp4] the console create attempt produced neither a submitted screen nor an error " +
        `banner for ${env.vmName}`,
    );
  }

  if (outcome === "error") {
    const banner = (await readErrorBanner()) ?? "";
    await evidence(auth.page, env, "08b-create-form-truthful-error");
    expect(banner, "the console must surface a real error message").not.toBe("");
    expect(
      await submittedHeading.count(),
      "a truthful error must not leave the create success screen visible",
    ).toBe(0);
    consoleErrorClass = await classifyCreateError(banner);
    consoleErrorBanner = banner;
    detail =
      `console_error_class=${consoleErrorClass.klass} ` +
      `console_error=${JSON.stringify(banner.slice(0, 200))}`;
  } else {
    // The form reached the BFF: the canonical Operation must carry the
    // upstream failure (never a fabricated success). The state is polled
    // directly so "the operation failed" and "the operation never reached a
    // terminal state" are never conflated.
    const bodyText = (await auth.page.textContent("body")) ?? "";
    const submitted = parseSubmittedOperation(bodyText);
    await openOperationDetail(auth.page, env.tenantUrl, submitted.id);
    await evidence(auth.page, env, "08b-create-operation");
    const resolved = await resolveTerminalOperation(
      auth.page,
      env.tenantUrl,
      submitted,
      env.operationTimeoutMs,
    );
    if (resolved.state !== "failed") {
      throw new Error(
        `[pp4] the native compute.server create Operation ${resolved.id} reported ` +
          `${resolved.state}: this profile is documented as unable to create VMs, so a ` +
          "successful create invalidates the harness",
      );
    }
    detail =
      `operation=${resolved.id} state=failed ` +
      `error=${JSON.stringify(`${resolved.errorTitle} ${resolved.errorDetail}`.trim().slice(0, 200))}`;
  }

  // No fabricated resource. Any NEW row is a recorded side effect and must
  // never be Ready (the profile cannot schedule a VM).
  const after = await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL);
  const appeared = after.ids.filter((id) => !before.ids.includes(id));
  const appearedStatuses: string[] = [];
  for (const id of appeared) {
    const resource = await getResourceOrUndefined(auth.page, env.tenantUrl, SERVER_TYPE, id);
    if (!resource) {
      appearedStatuses.push(`${id}=concealed-tombstone`);
      continue;
    }
    appearedStatuses.push(`${id}=${resource.status}`);
    expect(
      resource.status,
      `a server row that appeared from a failed create (${id}) must not be Ready`,
    ).not.toBe("ready");
  }
  await evidence(auth.page, env, "08c-servers-after-failed-create");
  await expectNoConsoleCrash(auth.page);

  gap(
    "native-vm-create=network-provider-inactive",
    `${detail} created_server_rows=${appeared.length} ` +
      `appeared_rows=[${appearedStatuses.join(",")}] requested_network=${env.networkId}`,
  );
  if (consoleErrorClass) {
    // The console refused the create client-side; record WHICH error class the
    // pinned tuple produced, with the verbatim banner it was decided from (the
    // manifest requires this classified gap).
    gap(
      `console-create-schema-dialect=${consoleErrorClass.klass}`,
      `console_error=${JSON.stringify(consoleErrorBanner.slice(0, 200))} ` +
        `field_errors_rendered=${String(consoleErrorClass.fieldErrors)}`,
    );
  }
});

test("console delete of the CLI-created server is observed truthfully", async () => {
  test.setTimeout(env.operationTimeoutMs + 5 * 60 * 1000);
  const targetId = env.uiTargetId;

  // Observe-before-act: the target the campaign created through the unmodified
  // OpenStack CLI must be a LIVE canonical resource (same uuid the console
  // lists) — never a missing or fabricated one.
  const before = await getResource(auth.page, env.tenantUrl, SERVER_TYPE, targetId);
  expect(before.id, "the UI delete target must exist as a canonical resource").toBe(targetId);
  expect(before.resourceType, "the UI delete target must be a compute.server").toBe(SERVER_TYPE);
  const listed = await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL);
  // The collection can render rows progressively after a cold navigation; the
  // target row must actually arrive (never pass vacuously on a partial load).
  await expect
    .poll(
      async () => (await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL)).ids,
      { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toContain(targetId);

  // (1) Open the target's detail page by canonical id.
  await auth.page.goto(
    `${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(targetId)}`,
  );
  await expect(
    auth.page.getByRole("heading", { name: env.uiTargetName }),
    "the target's detail page renders the server name",
  ).toBeVisible({ timeout: 60_000 });
  await expect(auth.page.getByText(`ID: ${targetId}`)).toBeVisible();
  await evidence(auth.page, env, "09a-ui-delete-target-detail");

  // (2) Run the advertised delete action through the REAL UI: the action
  // button opens the destructive confirmation modal, and the modal's confirm
  // performs the mutation. There is deliberately no BFF fallback for this
  // step: a delete that cannot be performed through the UI fails here.
  //
  // The console hides actions while the resource still reads non-ready (the
  // native status projection reports a freshly booted server as busy for a
  // poll or two), so the page is re-opened until the advertised action
  // appears or the bounded wait expires.
  const deleteButton = auth.page.getByRole("button", { name: "delete", exact: true });
  const deadline = Date.now() + 3 * 60 * 1000;
  while ((await deleteButton.count()) === 0 && Date.now() < deadline) {
    await auth.page.waitForTimeout(5_000);
    await auth.page.reload({ waitUntil: "domcontentloaded" });
    await expect(
      auth.page.getByRole("heading", { name: env.uiTargetName }),
      "the target's detail page renders the server name",
    ).toBeVisible({ timeout: 60_000 });
  }
  if ((await deleteButton.count()) === 0) {
    await evidence(auth.page, env, "09b-ui-delete-action-missing");
    const rendered = (await auth.page.getByRole("main").textContent()) ?? "";
    throw new Error(
      `[pp4] the pinned compute.server descriptor offers no delete action for ${targetId} ` +
        `after 3 minutes; page text: ${rendered.replace(/\s+/gu, " ").slice(0, 300)}`,
    );
  }
  await deleteButton.first().click();
  const dialog = auth.page.getByRole("dialog");
  await expect(dialog, "the destructive delete confirmation modal appears").toBeVisible({
    timeout: 20_000,
  });
  await expect(
    dialog.getByText(new RegExp(`delete ${env.uiTargetName}`, "i")),
    "the confirmation names the server being deleted",
  ).toBeVisible({ timeout: 20_000 });
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();

  // (3) The mutation outcome as the console rendered it. Native CRUD routes may
  // complete synchronously and the BFF then reports the terminal state in the
  // mutation response without persisting a pollable history record
  // (`fetch_or_build_operation`), so a state the console already reports as
  // terminal is authoritative and needs no polling.
  const operationNote = auth.page
    .getByRole("status")
    .filter({ hasText: /Operation\s+\S+\s+is\s+\S+/u })
    .first();
  const errorAlert = auth.page.getByRole("alert").first();
  const deleteOutcome = await Promise.race([
    operationNote.waitFor({ state: "visible", timeout: 60_000 }).then(() => "ui" as const),
    errorAlert.waitFor({ state: "visible", timeout: 60_000 }).then(() => "blocked" as const),
  ]).catch(() => "timeout" as const);
  if (deleteOutcome !== "ui") {
    const banner = (await readErrorBanner()) ?? "";
    await evidence(auth.page, env, "09b-ui-delete-blocked");
    throw new Error(
      `[pp4] the console delete of ${targetId} produced no operation state ` +
        `(${deleteOutcome}): ${banner}`,
    );
  }
  const submitted = parseSubmittedOperation((await operationNote.textContent()) ?? "");
  await evidence(auth.page, env, "09c-ui-delete-operation");
  const deleted = await resolveTerminalOperation(
    auth.page,
    env.tenantUrl,
    submitted,
    env.operationTimeoutMs,
  );
  expect(
    deleted.state,
    `the console delete of ${targetId} must reach a truthful terminal state`,
  ).toBe("succeeded");

  // Hand the canonical identity to the campaign harness: this marker is what
  // the bash cross-check asserts the cross-interface absence from.
  // eslint-disable-next-line no-console
  console.log(`PP4-UI-DELETE id=${targetId} state=${deleted.state}`);

  // (4) Truthful final state. The canonical live view through the BFF conceals
  // the resource (404 — the ledger keeps a DELETED tombstone), and the detail
  // URL renders its not-found state instead of a fabricated resource.
  await waitForResourceConcealed(auth.page, env.tenantUrl, SERVER_TYPE, targetId);
  await auth.page.goto(
    `${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(targetId)}`,
  );
  await expect(
    auth.page.getByText(`ID: ${targetId}`),
    "a deleted resource must not be rendered on its detail page",
  ).toHaveCount(0);
  await expect(
    auth.page.getByText(/Could not load resource|not found/i).first(),
    "the detail URL shows a truthful not-found state for the concealed resource",
  ).toBeVisible({ timeout: 30_000 });
  await evidence(auth.page, env, "09d-ui-delete-concealed");
  // eslint-disable-next-line no-console
  console.log(
    `[pp4] ${env.uiTargetName} (${targetId}) after the console delete: ` +
      "detail URL shows the truthful not-found state and the live-resource view is concealed (404)",
  );
});

test("inspect the TestLab workload detail by canonical id", async () => {
  expect(testVmId, "the workload id must have been resolved by the earlier step").not.toBe("");
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(testVmId)}`);
  await expect(
    auth.page.getByRole("heading", { name: "test-vm" }),
    "detail page heading is the server name",
  ).toBeVisible({ timeout: 30_000 });
  // The canonical uuid is displayed in the header description ("ID: <uuid>").
  await expect(
    auth.page.getByText(`ID: ${testVmId}`),
    "canonical uuid must be displayed on the detail page",
  ).toBeVisible();
  await expect(auth.page.getByRole("tab", { name: "Overview" })).toBeVisible();
  await expect(auth.page.getByRole("tab", { name: "Operations" })).toBeVisible();
});

test("logout ends the session", async () => {
  // The pinned Araf console ships no logout UI button (verified across
  // packages/shell and apps); the BFF logout endpoint is exercised exactly as
  // Araf's own process evidence does (POST /api/v1/auth/logout with the CSRF
  // header). This is a read-only session boundary, not a cloud mutation, so it
  // does not invalidate the browser journey.
  await logout(auth.page, env.tenantUrl);

  const session = await getSession(auth.page, env.tenantUrl);
  expect(session.authenticated, "session must be destroyed after logout").toBe(false);

  // The console surfaces the destroyed session on reload.
  await auth.page.reload();
  await expect(
    auth.page.getByRole("heading", { name: "Session unavailable" }),
    "reloading after logout shows the unauthenticated shell state",
  ).toBeVisible({ timeout: 30_000 });

  // Subsequent API call must be rejected.
  const contextResponse = await bffFetch(auth.page, `${env.tenantUrl}/api/v1/context`);
  expect(contextResponse.status, "GET /api/v1/context must 401 after logout").toBe(401);

  // eslint-disable-next-line no-console
  console.log("PP4-TENANT-OK");
});
