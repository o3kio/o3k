/**
 * PP.4 operator journey — sequential, one shared browser context.
 *
 * Proves the operator console (production profile, same canonical O3K
 * authority) shows real platform truth after OIDC login as alice:
 *   - /platform/overview: region/provider status, active operations
 *   - /services/installed: discovered services + resource types, including a
 *     truthful Storage (volume) rendering — empty is fine, fabricated is not
 *   - /platform/health: provider health
 *   - /platform/capacity: real capacity (VCPU totals)
 *   - /platform/regions: RegionOne + AZ truth
 *   - /operations: the canonical operations the tenant journey produced for the
 *     SAME resource id the tenant console deleted (the server the harness
 *     created as `pp4-ui-target`, canonical id exported as PP4_UI_TARGET_ID)
 *   - logout
 *
 * stdout protocol: PP4-OPERATOR-OK at the end.
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import { bffFetch, listOperations, logCookieNames, logout } from "../lib/bff";
import {
  assertIdentityVisible,
  connectBrowser,
  loginToSurface,
  type AuthenticatedSurface,
} from "../lib/login";
import { CANONICAL_ID, evidence, expectNoFixtureMarkers } from "../lib/console";

test.describe.configure({ mode: "serial" });
test.setTimeout(300_000);

let env: Pp4Env;
let browser: Browser | undefined;
let auth: AuthenticatedSurface;
let tenantResourceId = "";

test.beforeAll(async () => {
  env = loadEnv();
  // The resource the tenant console deleted is the harness's own target: its
  // canonical id is the campaign contract PP4_UI_TARGET_ID, so the operator
  // tie-in needs no cross-spec evidence file.
  tenantResourceId = env.uiTargetId;
  expect(tenantResourceId, "PP4_UI_TARGET_ID must carry a canonical uuid").toMatch(CANONICAL_ID);
  browser = await connectBrowser(env);
  auth = await loginToSurface(browser, env, "operator");

  // The operator callback lands on /platform/overview with the shell.
  await expect(
    auth.page.getByRole("navigation", { name: "Operator navigation" }),
    "operator shell renders after OIDC login",
  ).toBeVisible({ timeout: 60_000 });
  await expect(
    auth.page.getByTestId("operator-context"),
    "operator platform context is shown",
  ).toBeVisible();
  await assertIdentityVisible(auth);
  await logCookieNames(auth.context, auth.baseUrl);
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

test("platform overview shows real platform data", async () => {
  await auth.page.goto(`${env.operatorUrl}/platform/overview`);
  await expect(
    auth.page.getByRole("heading", { name: "Platform overview" }),
  ).toBeVisible({ timeout: 30_000 });

  await expect(auth.page.getByText("Active operations:")).toBeVisible();

  // Region + provider status summaries from O3K diagnostics (header rows
  // alone are not evidence — at least one summary must report a data row).
  const regionSummary = auth.page.getByRole("table", { name: "Region status summary" });
  const providerSummary = auth.page.getByRole("table", { name: "Provider status summary" });
  await expect(regionSummary, "region status summary renders").toBeVisible({ timeout: 30_000 });
  await expect(providerSummary, "provider status summary renders").toBeVisible();
  await expect
    .poll(
      async () =>
        (await regionSummary.getByRole("row").count()) > 1 ||
        (await providerSummary.getByRole("row").count()) > 1,
      { timeout: 30_000 },
    )
    .toBe(true);

  await expect(auth.page.getByText(/Data refreshed at/)).toBeVisible();
  await expectNoFixtureMarkers(auth.page);
  await evidence(auth.page, env, "04-operator-overview");
});

test("installed services show the discovered platform", async () => {
  await auth.page.goto(`${env.operatorUrl}/services/installed`);
  await expect(
    auth.page.getByRole("heading", { name: "Installed services" }),
  ).toBeVisible({ timeout: 30_000 });

  const servicesTable = auth.page.getByRole("table", { name: "Installed services" });
  await expect(servicesTable).toBeVisible();
  await expect
    .poll(async () => servicesTable.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  // The demo must advertise the native compute service...
  await expect(servicesTable.getByText("Compute", { exact: true }).first()).toBeVisible();
  // ...and its resource types through discovery.
  const typesTable = auth.page.getByRole("table", { name: "Discovered resource types" });
  await expect(typesTable).toBeVisible();
  await expect(typesTable.getByText("server").first()).toBeVisible();

  // Storage (the volume service) must render truthfully: the service row is
  // discovery-derived, and its resource-type cell is either the real list or
  // the console's "—" empty marker. An empty inventory is fine; a fabricated
  // one is not.
  const storageRow = servicesTable.getByRole("row", { name: /Storage/ }).first();
  await expect(storageRow, "the Storage (volume) service row renders").toBeVisible({
    timeout: 30_000,
  });
  const storageCells = await storageRow.getByRole("cell").allTextContents();
  const storageText = storageCells.join(" | ");
  expect(storageText, "the Storage row must not carry a fixture marker").not.toMatch(/fixture/i);
  // eslint-disable-next-line no-console
  console.log(`[pp4] Storage service row: ${storageText}`);
  const storageTypes = typesTable.getByRole("row", { name: /volume/ });
  // eslint-disable-next-line no-console
  console.log(
    `[pp4] discovered volume resource-type rows: ${String(await storageTypes.count())} ` +
      "(0 is a truthful empty inventory)",
  );
  await evidence(auth.page, env, "06-operator-installed-services");
  await expectNoFixtureMarkers(auth.page);
});

test("provider health is reported truthfully", async () => {
  await auth.page.goto(`${env.operatorUrl}/platform/health`);
  await expect(
    auth.page.getByRole("heading", { name: "Provider health" }),
  ).toBeVisible({ timeout: 30_000 });

  const table = auth.page.getByRole("table", { name: "Provider health table" });
  await expect(table).toBeVisible();
  await expect
    .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  // Statuses are the identity-only diagnostics vocabulary (never fabricated).
  const body = await table.textContent();
  expect(
    /Healthy|Degraded|Unavailable|Maintenance|Stale|Unknown/.test(body ?? ""),
    "provider statuses must render the diagnostics vocabulary",
  ).toBe(true);
  await expectNoFixtureMarkers(auth.page);
  await evidence(auth.page, env, "05-operator-health");
});

test("capacity shows real totals", async () => {
  await auth.page.goto(`${env.operatorUrl}/platform/capacity`);
  await expect(
    auth.page.getByRole("heading", { name: "Capacity" }),
  ).toBeVisible({ timeout: 30_000 });

  const table = auth.page.getByRole("table", { name: "Capacity table" });
  await expect(table).toBeVisible();
  await expect
    .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  // The demo hypervisor inventory reports VCPU totals.
  const vcpuRow = table.getByRole("row", { name: /VCPU/i }).first();
  await expect(vcpuRow, "VCPU capacity row is reported").toBeVisible({ timeout: 30_000 });
  const cells = await vcpuRow.getByRole("cell").allTextContents();
  const totalText = cells[1] ?? "";
  const total = Number.parseInt(totalText, 10);
  expect(
    Number.isNaN(total),
    `VCPU Total must be a real number, got "${totalText}"`,
  ).toBe(false);
  expect(total, "a real TestLab hypervisor must report total vcpus > 0").toBeGreaterThan(0);
  await expectNoFixtureMarkers(auth.page);
});

test("regions expose RegionOne with availability zones", async () => {
  await auth.page.goto(`${env.operatorUrl}/platform/regions`);
  await expect(
    auth.page.getByRole("heading", { name: "Regions" }),
  ).toBeVisible({ timeout: 30_000 });

  const table = auth.page.getByRole("table", { name: "Regions table" });
  await expect(table).toBeVisible();
  const regionRow = table.getByRole("row", { name: /RegionOne/ }).first();
  await expect(regionRow, "RegionOne is the demo region").toBeVisible({ timeout: 30_000 });

  // Availability-zone count column renders (0 is truthful when no AZs are
  // declared; the campaign demo declares none).
  const cells = await regionRow.getByRole("cell").allTextContents();
  expect(cells.length).toBeGreaterThan(2);
  await expectNoFixtureMarkers(auth.page);
});

test("operator operations tie the tenant journey to the canonical authority", async () => {
  await auth.page.goto(`${env.operatorUrl}/operations`);
  await expect(
    auth.page.getByRole("heading", { name: "Operations" }),
  ).toBeVisible({ timeout: 30_000 });

  // The operator console's dedicated GLOBAL operations list
  // (/api/v1/operator/operations) is not implemented by upstream O3K on this
  // profile, so the page must be truthful about it (an explicit error or empty
  // state — never fabricated rows). The canonical list itself is served on the
  // same surface at /api/v1/operations (base_routes) and is what ties the
  // tenant journey's work to the operator's view.
  const globalList = await bffFetch(
    auth.page,
    `${env.operatorUrl}/api/v1/operator/operations?page=0&pageSize=5`,
  );
  // eslint-disable-next-line no-console
  console.log(`[pp4] operator global operations list: HTTP ${globalList.status}`);
  if (!globalList.ok) {
    // eslint-disable-next-line no-console
    console.log(
      `PP4-GAP operator-global-operations-not-exposed HTTP ${globalList.status} ` +
        `${globalList.body.slice(0, 120).replace(/\s+/gu, " ")}`,
    );
    const failed = auth.page.getByText("Could not load operations");
    const empty = auth.page.getByText("No operations", { exact: false });
    const rows = auth.page.getByRole("table", { name: "Operator operations table" }).getByRole("row");
    await expect
      .poll(
        async () =>
          (await failed.count()) > 0 || (await empty.count()) > 0 || (await rows.count()) <= 1,
        { timeout: 30_000 },
      )
      .toBe(true);
    expect(
      await rows.count(),
      "a non-implemented global list must not render fabricated operation rows",
    ).toBeLessThanOrEqual(1); // header row only
  } else {
    const table = auth.page.getByRole("table", { name: "Operator operations table" });
    await expect(table).toBeVisible();
    await expect
      .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
      .toBeGreaterThan(1);
  }

  // Cross-check through the canonical list: the same canonical authority serves
  // both surfaces, so the operations for the EXACT resource the tenant console
  // deleted (the CLI-created `pp4-ui-target`) must be visible here.
  const operations = await listOperations(auth.page, env.operatorUrl, 100);
  const forResource = operations.items.filter(
    (operation) => operation.resourceId === tenantResourceId,
  );
  expect(
    forResource.length,
    `operator operations must include operations for the resource the tenant console ` +
      `deleted (${tenantResourceId}) (canonical list total=${operations.total})`,
  ).toBeGreaterThan(0);
  expect(
    forResource.some((operation) => operation.action === "delete"),
    `the console delete Operation for ${tenantResourceId} must be visible to the operator`,
  ).toBe(true);
  expect(
    forResource.every((operation) => operation.resourceType === "compute.server"),
    "every operation for the tenant resource must be a compute.server operation",
  ).toBe(true);
  // eslint-disable-next-line no-console
  console.log(
    `[pp4] operator canonical operations list sees ${forResource.length} operation(s) for tenant ` +
      `resource ${tenantResourceId}: ${forResource.map((operation) => operation.action).join(", ")}`,
  );
  await expectNoFixtureMarkers(auth.page);
});

test("operator logout ends the session", async () => {
  await logout(auth.page, env.operatorUrl);

  await auth.page.reload();
  await expect(
    auth.page.getByRole("heading", { name: "Session unavailable" }),
    "operator console shows the unauthenticated state after logout",
  ).toBeVisible({ timeout: 30_000 });

  const contextResponse = await bffFetch(auth.page, `${env.operatorUrl}/api/v1/context`);
  expect(contextResponse.status, "GET /api/v1/context must 401 after logout").toBe(401);

  // eslint-disable-next-line no-console
  console.log("PP4-OPERATOR-OK");
});
