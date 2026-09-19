/**
 * PP.4 operator journey — sequential, one shared browser context.
 *
 * Proves the operator console (production profile, same canonical O3K
 * authority) shows real platform truth after OIDC login as alice:
 *   - /platform/overview: region/provider status, active operations
 *   - /services/installed: discovered services + resource types
 *   - /platform/health: provider health
 *   - /platform/capacity: real capacity (VCPU totals)
 *   - /platform/regions: RegionOne + AZ truth
 *   - /operations: the operations created during the tenant journey
 *   - logout
 *
 * stdout protocol: PP4-OPERATOR-OK at the end.
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import { listOperatorOperations, logCookieNames, logout } from "../lib/bff";
import {
  assertIdentityVisible,
  connectBrowser,
  loginToSurface,
  type AuthenticatedSurface,
} from "../lib/login";
import { evidence, expectNoFixtureMarkers } from "../lib/console";

test.describe.configure({ mode: "serial" });
test.setTimeout(300_000);

let env: Pp4Env;
let browser: Browser | undefined;
let auth: AuthenticatedSurface;

test.beforeAll(async () => {
  env = loadEnv();
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
    if (auth) await logout(auth.page, auth.context, auth.baseUrl);
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

test("operator operations include the tenant journey work", async () => {
  await auth.page.goto(`${env.operatorUrl}/operations`);
  await expect(
    auth.page.getByRole("heading", { name: "Operations" }),
  ).toBeVisible({ timeout: 30_000 });

  const table = auth.page.getByRole("table", { name: "Operator operations table" });
  await expect(table).toBeVisible();
  await expect
    .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  // Cross-check through the BFF: the same canonical authority served the
  // tenant journey, so compute.server operations must be visible here.
  const operations = await listOperatorOperations(auth.page, env.operatorUrl, 50);
  const computeOps = operations.items.filter(
    (operation) => operation.resourceType === "compute.server",
  );
  expect(
    computeOps.length,
    "operator operations must include tenant compute.server operations",
  ).toBeGreaterThan(0);
  expect(
    computeOps.some((operation) => operation.action === "create"),
    "the pp4-native create Operation must be visible to the operator",
  ).toBe(true);
  await expectNoFixtureMarkers(auth.page);
});

test("operator logout ends the session", async () => {
  await logout(auth.page, auth.context, env.operatorUrl);

  await auth.page.reload();
  await expect(
    auth.page.getByRole("heading", { name: "Session unavailable" }),
    "operator console shows the unauthenticated state after logout",
  ).toBeVisible({ timeout: 30_000 });

  const contextResponse = await auth.page.request.get(`${env.operatorUrl}/api/v1/context`);
  expect(contextResponse.status(), "GET /api/v1/context must 401 after logout").toBe(401);

  // eslint-disable-next-line no-console
  console.log("PP4-OPERATOR-OK");
});
