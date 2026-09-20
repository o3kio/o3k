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
 *   i. server collection lists the existing TestLab workload by CANONICAL ID (the
 *      native list projection carries no spec name)
 *   j. a REAL console create of a VM from O3K's schema-driven form, with a
 *      successful canonical Operation and ready canonical resource.
 *   k. the same browser-created resource is deleted through its advertised
 *      action and confirmation modal, and truthful absence is observed.
 *      Prints PP4-UI-DELETE id=<uuid> state=<observed>.
 *   l. inspect the TestLab workload detail by canonical id
 *   m. logout — session destroyed, follow-up API call 401s
 *
 * stdout protocol lines grepped by the campaign harness:
 *   PP4-TIMESTAMPS T4=<unix seconds>         (after login succeeds)
 *   PP4-UI-FALLBACK <step>                   (INVALIDATING: a step fell back to
 *                                             the BFF; host-run fails)
 *   PP4-GAP <id> <detail>                    (classified product-profile gap)
 *   PP4-UI-CREATE id=<uuid> operation=<uuid> (after native browser create)
 *   PP4-UI-DELETE id=<uuid> state=<state>    (after the console delete)
 *   PP4-TENANT-OK                            (after logout asserts)
 *
 * Security asserts run immediately after login (web storage + DOM scan) plus a
 * deployment-side production-profile check (PP4_DEPLOYMENT_ENV_FILE).
 *
 * The browser-created canonical id is handed to the campaign through its
 * evidence marker; no compatibility-side precreation is accepted.
 *
 * rc.15 must send x-csrf-token as product behavior. This harness performs no
 * network-layer request repair or hidden fallback.
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import {
  bffFetch,
  getResource,
  getSession,
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
let nativeCreatedId = "";

/** Emit a classified product-profile gap: one log line, one evidence line. */
function gap(id: string, detail: string): void {
  // eslint-disable-next-line no-console
  console.log(`PP4-GAP ${id} ${detail}`);
}

test.beforeAll(async () => {
  env = loadEnv(); // fail fast on missing PP4_ALICE_PASSWORD / PP4_FLAVOR_ID etc.
  nativeCreatedId = env.uiTargetId ?? "";
  // Server-side fixture check: the deployment itself must be the pinned
  // production tuple (phase1a evidence), not merely render without the word.
  expectProductionDeployment(env);
  browser = await connectBrowser(env);
  auth = await loginToSurface(browser, env, "tenant");
  // CSRF is supplied by the rc.15 product client; the harness does not repair
  // requests at the network layer.

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

test("UI creates a native VM through the schema-driven form", async () => {
  test.setTimeout(env.operationTimeoutMs + 6 * 60 * 1000);

  // The pinned demo tuple does not advertise a flavor collection
  // (compute.flavor has no collection in the O3K manifest), so the canonical
  // id must come from the campaign harness (PP4_FLAVOR_ID, read in the VM from
  // /etc/o3k/testlab-flavor-id). loadEnv() already fails when it is missing.
  const flavorId = env.flavorId;

  // Baseline: prove the browser mutation creates a new canonical resource.
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
  // The schema contract is an array of network IDs. The generated text widget
  // accepts JSON, so submit a one-element JSON array rather than a scalar UUID
  // (which the form correctly rejects as invalid input).
  await networkField.fill(JSON.stringify([env.networkId]));

  // The REAL UI submit. No BFF fallback exists for this step.
  await auth.page.getByRole("button", { name: "Create Server" }).click();

  const submittedHeading = auth.page.getByRole("heading", { name: /creation submitted/i });
  const alert = auth.page.getByRole("alert").first();
  await expect(submittedHeading, "UI_CREATE_2 must submit the native create").toBeVisible({ timeout: 60_000 });
  const submitted = parseSubmittedOperation((await auth.page.textContent("body")) ?? "");
  await openOperationDetail(auth.page, env.tenantUrl, submitted.id);
  await evidence(auth.page, env, "08b-create-operation");
  const resolved = await resolveTerminalOperation(auth.page, env.tenantUrl, submitted, env.operationTimeoutMs);
  expect(resolved.state, "UI_CREATE_3 canonical Operation must succeed").toBe("succeeded");
  const after = await openCollection(auth.page, env.tenantUrl, SERVER_TYPE, SERVER_PLURAL);
  const appeared = after.ids.filter((id) => !before.ids.includes(id));
  expect(appeared, "native browser create must create exactly one new canonical server").toHaveLength(1);
  nativeCreatedId = resolved.resourceId ?? appeared[0]!;
  expect(nativeCreatedId).toMatch(CANONICAL_ID);
  const created = await getResource(auth.page, env.tenantUrl, SERVER_TYPE, nativeCreatedId);
  expect(created.id).toBe(nativeCreatedId);
  expect(created.status, "UI_CREATE_4 resource must become ready").toBe("ready");
  await evidence(auth.page, env, "08c-native-created-resource");
  await expectNoConsoleCrash(auth.page);
  console.log(`PP4-UI-CREATE id=${nativeCreatedId} operation=${submitted.id}`);
  console.log("UI_CREATE_1 schema-form-rendered");
  console.log("UI_CREATE_2 browser-submit");
  console.log("UI_CREATE_3 operation-succeeded");
  console.log("UI_CREATE_4 resource-ready");
});

test("console delete is observed truthfully after live native-create inspection", async () => {
  test.skip(!!process.env.PP4_SKIP_DELETE, "delete runs after live provider verification");
  test.setTimeout(env.operationTimeoutMs + 5 * 60 * 1000);
  const targetId = env.uiTargetId ?? nativeCreatedId;
  expect(targetId, "UI_DELETE must delete the browser-created canonical server").toMatch(CANONICAL_ID);

  // Observe-before-act: the target created through the native browser form
  // must remain a LIVE canonical resource (same uuid the console lists).
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
      `[pp4] the compute.server descriptor offers no delete action for ${targetId} ` +
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
    const banner = (await auth.page.getByRole("alert").first().textContent()) ?? "";
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
