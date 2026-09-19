/**
 * PP.4 tenant journey — sequential, one shared browser context.
 *
 * Proves, against the live demo deployment (production Araf profile on the
 * real O3K native API, real Keycloak OIDC):
 *   a. OIDC login (authorization code + PKCE through the confidential BFF)
 *   b. project scope discovery + selection (admin project)
 *   c. service catalog derived from real O3K discovery
 *   d. usage/capacity truth (quotas/meters)
 *   e. deployment topology context on the tenant home
 *   f. image collection contains cirros-0.6.3 (TestLab image)
 *   g. network collection contains testlab-network
 *   h. server collection contains test-vm with truthful status
 *   i. create VM "pp4-native" (cirros + testlab-flavor + testlab-network),
 *      canonical Operation -> SUCCEEDED, server Ready
 *   j. inspect pp4-native detail — canonical uuid displayed
 *   k. stop action — truthful state transition + Operation
 *   l. delete pp4-native — canonical delete Operation + final absence
 *   m. logout — session destroyed, follow-up API call 401s
 *
 * stdout protocol lines grepped by the campaign harness:
 *   PP4-TIMESTAMPS T4=<unix seconds>   (after login succeeds)
 *   PP4-NATIVE id=<uuid>               (after pp4-native is ACTIVE)
 *   PP4-TENANT-OK                      (after logout asserts)
 *
 * Security asserts run immediately after login (web storage + DOM scan).
 *
 * Known pinned-tuple limitations exercised here (see README.md):
 *   - Araf rc.12 SPA never sends x-csrf-token, so UI mutations 403; the
 *     harness attempts the UI click first and falls back to the identical BFF
 *     call with the CSRF header (what Araf's own process evidence uses).
 *   - Araf rc.12 schema-runtime cannot compile the O3K draft 2020-12 create
 *     schema, so the create form blocks client-side; the fallback create uses
 *     the exact payload the form would send (with network_ids as an array).
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import {
  createComputeServer,
  deleteResource,
  getSession,
  listScopes,
  logCookieNames,
  logout,
  submitResourceAction,
} from "../lib/bff";
import {
  assertIdentityVisible,
  connectBrowser,
  loginToSurface,
  selectAdminProject,
  type AuthenticatedSurface,
} from "../lib/login";
import {
  evidence,
  expectNoFixtureMarkers,
  openOperationDetail,
  resourceIdByName,
  resourceRow,
  waitForOperationTerminal,
  waitForResourceStatus,
} from "../lib/console";

test.describe.configure({ mode: "serial" });
test.setTimeout(300_000);

const SERVER_TYPE = "compute.server";
const SERVER_PLURAL = "servers";

let env: Pp4Env;
let browser: Browser | undefined;
let auth: AuthenticatedSurface;
let projectName = "";
let imageId = "";
let networkId = "";
let flavorId = "";
let vmId = "";

async function cleanupVm(): Promise<void> {
  if (!vmId) return;
  try {
    const existing = await resourceRow(auth.page, SERVER_PLURAL, env.vmName).count();
    if (existing > 0) {
      // eslint-disable-next-line no-console
      console.log("[pp4] cleanup: deleting leftover VM");
      await submitResourceAction(auth.page, auth.context, env.tenantUrl, SERVER_TYPE, vmId, "stop").catch(() => undefined);
      await deleteResource(auth.page, auth.context, env.tenantUrl, SERVER_TYPE, vmId).catch(() => undefined);
    }
  } catch {
    // best effort only
  }
}

test.beforeAll(async () => {
  env = loadEnv(); // fail fast on missing PP4_ALICE_PASSWORD etc.
  browser = await connectBrowser(env);
  auth = await loginToSurface(browser, env, "tenant");

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
  await cleanupVm().catch(() => undefined);
  try {
    if (auth) await logout(auth.page, auth.context, auth.baseUrl);
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

  // ...and the shell reflects the selection (ProjectSelector in the nav).
  const selector = auth.page.getByLabel("Project");
  await expect(selector, "project selector is rendered").toBeVisible();
  await expect
    .poll(async () => selector.inputValue(), { timeout: 30_000 })
    .not.toBe("");
  const selectedLabel = await selector.evaluate(
    (element: HTMLSelectElement) => element.selectedOptions[0]?.textContent ?? "",
  );
  expect(selectedLabel, "project selector shows the selected admin project").toBe(projectName);
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

  // Discovery-derived: the demo advertises the native compute service and
  // the compute.server resource type with lifecycle capabilities.
  await expect(auth.page.getByText("Compute", { exact: true }).first()).toBeVisible();
  await expect(auth.page.getByText(/compute\.server:/).first()).toBeVisible();
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
  const metered = auth.page.getByRole("table", { name: "Authoritative metering usage" });
  const classic = auth.page.getByRole("table", { name: "Usage by resource type" });
  const emptyState = auth.page.getByText("No usage data");
  const usageVisible =
    (await metered.count()) > 0 ||
    (await classic.count()) > 0 ||
    (await emptyState.count()) > 0;
  expect(usageVisible, "usage renders data or an explicit empty state").toBe(true);
  await expectNoFixtureMarkers(auth.page);
});

test("tenant home shows truthful deployment context", async () => {
  await auth.page.goto(`${env.tenantUrl}/`);
  await expect(
    auth.page.getByRole("heading", { name: "Tenant home" }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(auth.page.getByText(/Operate .+ in .+/)).toBeVisible();

  const context = auth.page.getByRole("heading", { name: "Current context" }).locator("..");
  await expect(context.getByText("Organization")).toBeVisible();
  await expect(context.getByText("Project")).toBeVisible();
  await expect(context.getByText("Region")).toBeVisible();
  // The selected admin project is the truthfully rendered project context.
  await expect(context.getByText(projectName).first()).toBeVisible();
  await expect(auth.page.getByText("No project selected")).toHaveCount(0);
});

test("image collection contains the TestLab image", async () => {
  imageId = await resourceIdByName(
    auth.page,
    env.tenantUrl,
    "image.image",
    "images",
    env.imageName,
  );
  expect(imageId, "resolved image id must be a canonical uuid").toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  );
});

test("network collection contains the TestLab network", async () => {
  networkId = await resourceIdByName(
    auth.page,
    env.tenantUrl,
    "network.network",
    "networks",
    env.networkName,
  );
  expect(networkId, "resolved network id must be a canonical uuid").toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  );
});

test("server collection contains the TestLab workload with truthful status", async () => {
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}`);
  await expect(
    auth.page.getByRole("heading", { name: new RegExp(SERVER_PLURAL, "i") }).first(),
  ).toBeVisible({ timeout: 30_000 });
  const row = resourceRow(auth.page, SERVER_PLURAL, "test-vm");
  await expect(row, "test-vm row is listed").toBeVisible({ timeout: 60_000 });
  // The status cell renders the mapped O3K state (Ready/Busy/Error/Unknown).
  await expect(row.getByText(/Ready|Busy|Error|Unknown/)).toBeVisible();
  await expectNoFixtureMarkers(auth.page);
});

test("create representative VM pp4-native", async () => {
  test.setTimeout(env.operationTimeoutMs + 6 * 60 * 1000);

  // Resolve the testlab-flavor canonical id. The pinned demo tuple does not
  // advertise a flavor collection (compute.flavor has no collection in the
  // O3K manifest), so the campaign harness normally exports PP4_FLAVOR_ID
  // read from the VM's /etc/o3k/testlab-flavor-id ledger.
  if (env.flavorId) {
    flavorId = env.flavorId;
  } else {
    try {
      flavorId = await resourceIdByName(
        auth.page,
        env.tenantUrl,
        "compute.flavor",
        "flavors",
        env.flavorName,
      );
    } catch (error) {
      throw new Error(
        `[pp4] cannot resolve flavor "${env.flavorName}" through the console ` +
          `(the pinned demo tuple does not advertise a flavor collection): ${String(error)}. ` +
          `Export PP4_FLAVOR_ID=<uuid> (VM ledger: /etc/o3k/testlab-flavor-id).`,
      );
    }
  }

  // Schema-driven create form (fields derived from the O3K create contract:
  // name, image_id, flavor_id, network_ids, ...).
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/create`);
  await expect(
    auth.page.getByRole("heading", { name: "Create Server" }),
    "schema-driven create form heading",
  ).toBeVisible({ timeout: 60_000 });

  const nameField = auth.page.getByLabel("name");
  const imageField = auth.page.getByLabel("image_id");
  const flavorField = auth.page.getByLabel("flavor_id");
  const networkField = auth.page.getByLabel("network_ids");
  for (const field of [nameField, imageField, flavorField, networkField]) {
    await expect(field, "create form exposes the O3K contract fields").toBeVisible();
  }

  await nameField.fill(env.vmName);
  await imageField.fill(imageId);
  await flavorField.fill(flavorId);
  await networkField.fill(networkId); // text widget; array contract needs []

  // Attempt the truthful UI submit first.
  await auth.page.getByRole("button", { name: "Create Server" }).click();

  const submittedHeading = auth.page.getByRole("heading", { name: /creation submitted/i });
  const blockedAlert = auth.page.getByRole("alert").first();
  const outcome = await Promise.race([
    submittedHeading.waitFor({ state: "visible", timeout: 30_000 }).then(() => "submitted" as const),
    blockedAlert.waitFor({ state: "visible", timeout: 30_000 }).then(() => "blocked" as const),
  ]).catch(() => "blocked" as const);

  let createOperationId = "";
  if (outcome === "submitted") {
    // eslint-disable-next-line no-console
    console.log("[pp4] create submitted through the UI form");
    await expect(submittedHeading).toBeVisible();
    const bodyText = (await auth.page.textContent("body")) ?? "";
    const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(bodyText);
    expect(match, "submitted screen must name the canonical Operation").toBeTruthy();
    createOperationId = match![1]!;
  } else {
    // The submit may simply have been slower than the validation alert; do
    // not create a second VM if the form actually went through.
    if (await submittedHeading.isVisible().catch(() => false)) {
      // eslint-disable-next-line no-console
      console.log("[pp4] create submitted through the UI form (slow path)");
      const bodyText = (await auth.page.textContent("body")) ?? "";
      const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(bodyText);
      expect(match, "submitted screen must name the canonical Operation").toBeTruthy();
      createOperationId = match![1]!;
    } else {
      const alertText = (await blockedAlert.first().textContent().catch(() => "")) ?? "";
      // eslint-disable-next-line no-console
      console.log(
        `[pp4] PP4-NOTE create form blocked client-side (pinned Araf schema-runtime ` +
          `cannot compile the O3K draft 2020-12 create schema): ${alertText.trim().slice(0, 200)}`,
      );
      await evidence(auth.page, env, "02a-create-form-blocked");
      // Fallback: the identical BFF call the form would make, with the payload
      // the O3K create contract requires (network_ids as an array).
      const operation = await createComputeServer(auth.page, auth.context, env.tenantUrl, {
        name: env.vmName,
        image_id: imageId,
        flavor_id: flavorId,
        network_ids: [networkId],
      });
      createOperationId = operation.id;
      // eslint-disable-next-line no-console
      console.log(`[pp4] create accepted through the BFF fallback: operation ${createOperationId}`);
    }
  }
  expect(createOperationId).not.toBe("");

  // Canonical Operation observed through the UI.
  await openOperationDetail(auth.page, env.tenantUrl, createOperationId);
  await expect(
    auth.page.getByText(/Pending|Running/).first(),
    "create Operation is observable as pending/running",
  ).toBeVisible({ timeout: 30_000 });
  await evidence(auth.page, env, "02-create-operation-pending");

  // Real-async wait: terminal SUCCEEDED (VM create can take minutes).
  const terminal = await waitForOperationTerminal(
    auth.page,
    env.tenantUrl,
    createOperationId,
    env.operationTimeoutMs,
  );
  expect(terminal.resourceId, "create Operation must reference the new server").toBeTruthy();
  vmId = terminal.resourceId!;

  // The server itself reaches the truthful Ready state.
  await waitForResourceStatus(
    auth.page,
    env.tenantUrl,
    SERVER_TYPE,
    vmId,
    "ready",
    env.resourceTimeoutMs,
  );
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}`);
  const row = resourceRow(auth.page, SERVER_PLURAL, env.vmName);
  await expect(row, "pp4-native is listed after create").toBeVisible({ timeout: 60_000 });
  await expect(row.getByText("Ready")).toBeVisible();
  await evidence(auth.page, env, "03-pp4-native-active");

  // stdout protocol for the bash cross-checks.
  // eslint-disable-next-line no-console
  console.log(`PP4-NATIVE id=${vmId}`);
});

test("inspect pp4-native detail and canonical id", async () => {
  expect(vmId, "VM must have been created by the previous step").not.toBe("");
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(vmId)}`);
  await expect(
    auth.page.getByRole("heading", { name: env.vmName }),
    "detail page heading is the server name",
  ).toBeVisible({ timeout: 30_000 });
  // The canonical uuid is displayed in the header description ("ID: <uuid>").
  await expect(
    auth.page.getByText(`ID: ${vmId}`),
    "canonical uuid must be displayed on the detail page",
  ).toBeVisible();
  await expect(auth.page.getByRole("tab", { name: "Overview" })).toBeVisible();
  await expect(auth.page.getByRole("tab", { name: "Operations" })).toBeVisible();
});

test("stop server action shows truthful transition and Operation", async () => {
  test.setTimeout(env.operationTimeoutMs);
  expect(vmId).not.toBe("");
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(vmId)}`);

  // The descriptor advertises start/stop/reboot/delete/update; the action
  // buttons carry the lowercase action verbs (ResourceActionsPanel).
  const stopButton = auth.page.getByRole("button", { name: "stop", exact: true });
  await expect(stopButton, "stop action is offered for an active server").toBeVisible({
    timeout: 30_000,
  });
  await stopButton.click();

  // UI attempt succeeds (role=status) or 403s (pinned SPA CSRF gap).
  const statusNote = auth.page.getByRole("status").first();
  const errorAlert = auth.page.getByRole("alert").first();
  const stopOutcome = await Promise.race([
    statusNote.waitFor({ state: "visible", timeout: 20_000 }).then(() => "ui" as const),
    errorAlert.waitFor({ state: "visible", timeout: 20_000 }).then(() => "blocked" as const),
  ]).catch(() => "blocked" as const);

  let stopOperationId = "";
  if (stopOutcome === "ui") {
    const text = (await statusNote.textContent()) ?? "";
    const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(text);
    expect(match, "UI action status must name the canonical Operation").toBeTruthy();
    stopOperationId = match![1]!;
  } else {
    // eslint-disable-next-line no-console
    console.log(
      "[pp4] PP4-NOTE UI action blocked (pinned Araf SPA does not send " +
        "x-csrf-token); submitting the identical BFF action with the CSRF header",
    );
    const operation = await submitResourceAction(
      auth.page,
      auth.context,
      env.tenantUrl,
      SERVER_TYPE,
      vmId,
      "stop",
    );
    stopOperationId = operation.id;
  }

  const terminal = await waitForOperationTerminal(
    auth.page,
    env.tenantUrl,
    stopOperationId,
    env.operationTimeoutMs,
  );
  expect(terminal.action, "canonical Operation action is stop").toBe("stop");

  // Truthful state transition: O3K "stopped" maps to the Busy presentation
  // label (packages/resources/src/status.ts), different from Ready.
  await waitForResourceStatus(
    auth.page,
    env.tenantUrl,
    SERVER_TYPE,
    vmId,
    "busy",
    env.resourceTimeoutMs,
  );
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(vmId)}`);
  await expect(
    auth.page.getByText("Busy").first(),
    "server shows the truthful post-stop state",
  ).toBeVisible({ timeout: 30_000 });
});

test("delete pp4-native and observe final absence", async () => {
  test.setTimeout(env.operationTimeoutMs);
  expect(vmId).not.toBe("");
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}/${encodeURIComponent(vmId)}`);

  const deleteButton = auth.page.getByRole("button", { name: "delete", exact: true });
  await expect(deleteButton, "delete action is offered").toBeVisible({ timeout: 30_000 });
  await deleteButton.click();

  // Destructive actions open a confirmation modal.
  const dialog = auth.page.getByRole("dialog");
  await expect(dialog, "delete confirmation modal").toBeVisible({ timeout: 15_000 });
  await expect(dialog.getByText(new RegExp(`delete ${env.vmName}`))).toBeVisible();
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();

  const statusNote = auth.page.getByRole("status").first();
  const errorAlert = auth.page.getByRole("alert").first();
  const deleteOutcome = await Promise.race([
    statusNote.waitFor({ state: "visible", timeout: 20_000 }).then(() => "ui" as const),
    errorAlert.waitFor({ state: "visible", timeout: 20_000 }).then(() => "blocked" as const),
  ]).catch(() => "blocked" as const);

  let deleteOperationId = "";
  if (deleteOutcome === "ui") {
    const text = (await statusNote.textContent()) ?? "";
    const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(text);
    expect(match, "UI delete status must name the canonical Operation").toBeTruthy();
    deleteOperationId = match![1]!;
  } else {
    // eslint-disable-next-line no-console
    console.log(
      "[pp4] PP4-NOTE UI delete blocked (pinned Araf SPA does not send " +
        "x-csrf-token); calling the identical BFF delete with the CSRF header",
    );
    const operation = await deleteResource(
      auth.page,
      auth.context,
      env.tenantUrl,
      SERVER_TYPE,
      vmId,
    );
    deleteOperationId = operation.id;
  }

  const terminal = await waitForOperationTerminal(
    auth.page,
    env.tenantUrl,
    deleteOperationId,
    env.operationTimeoutMs,
  );
  expect(terminal.action, "canonical Operation action is delete").toBe("delete");

  // Truthful final state: pp4-native is absent from the server collection.
  await auth.page.goto(`${env.tenantUrl}/resources/${SERVER_TYPE}`);
  await expect
    .poll(
      async () => resourceRow(auth.page, SERVER_PLURAL, env.vmName).count(),
      { timeout: 60_000, intervals: [1_000, 2_000, 5_000] },
    )
    .toBe(0);
  vmId = ""; // deleted; cleanup guard no longer applies
});

test("logout ends the session", async () => {
  // Araf rc.12 ships no logout UI button (verified across packages/shell and
  // apps); the BFF logout endpoint is exercised exactly as Araf's own
  // process evidence does (POST /api/v1/auth/logout with the CSRF header).
  await logout(auth.page, auth.context, env.tenantUrl);

  const session = await getSession(auth.page, env.tenantUrl);
  expect(session.authenticated, "session must be destroyed after logout").toBe(false);

  // The console surfaces the destroyed session on reload.
  await auth.page.reload();
  await expect(
    auth.page.getByRole("heading", { name: "Session unavailable" }),
    "reloading after logout shows the unauthenticated shell state",
  ).toBeVisible({ timeout: 30_000 });

  // Subsequent API call must be rejected.
  const contextResponse = await auth.page.request.get(`${env.tenantUrl}/api/v1/context`);
  expect(contextResponse.status(), "GET /api/v1/context must 401 after logout").toBe(401);

  // eslint-disable-next-line no-console
  console.log("PP4-TENANT-OK");
});
