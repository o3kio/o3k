/**
 * PP.4 relogin spec — minimal recovery evidence for phase 2.
 *
 * Runs after a host/VM reboot: proves OIDC + sessions recover and the
 * tenant console is usable again. Creates and deletes nothing.
 *
 * stdout protocol: PP4-RELOGIN-OK.
 */
import { expect, test } from "playwright/test";
import type { Browser } from "playwright";
import { loadEnv, type Pp4Env } from "../lib/env";
import { getSession, logout } from "../lib/bff";
import {
  assertIdentityVisible,
  connectBrowser,
  loginToSurface,
  selectAdminProject,
  type AuthenticatedSurface,
} from "../lib/login";

test.setTimeout(300_000);

let env: Pp4Env;
let browser: Browser | undefined;
let auth: AuthenticatedSurface;

test.beforeAll(async () => {
  env = loadEnv();
  browser = await connectBrowser(env);
  // Fresh context: the previous session cookie may or may not have survived
  // the reboot (the demo BFF uses a durable encrypted session store). Both
  // paths are real OIDC behavior: SSO bounce or a fresh authorization form.
  auth = await loginToSurface(browser, env, "tenant");
  await selectAdminProject(auth, env);

  await auth.page.goto(`${env.tenantUrl}/`);
  await expect(
    auth.page.getByRole("navigation", { name: "Tenant navigation" }),
    "tenant console must be usable again after reboot",
  ).toBeVisible({ timeout: 60_000 });
  await assertIdentityVisible(auth);
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

test("relogin recovers OIDC and the read journey", async () => {
  // No create/delete: observe only.
  const session = await getSession(auth.page, env.tenantUrl);
  expect(session.authenticated, "session must be authenticated after relogin").toBe(true);

  await auth.page.goto(`${env.tenantUrl}/services/catalog`);
  await expect(
    auth.page.getByRole("heading", { name: "Service catalog" }),
  ).toBeVisible({ timeout: 30_000 });
  const table = auth.page.getByRole("table", { name: "Service catalog" });
  await expect
    .poll(async () => table.getByRole("row").count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  await auth.page.goto(`${env.tenantUrl}/resources/compute.server`);
  await expect(
    auth.page
      .getByRole("table", { name: "servers table" })
      .getByRole("row", { name: /test-vm/ })
      .first(),
    "the TestLab workload must still be listed after reboot",
  ).toBeVisible({ timeout: 60_000 });

  // eslint-disable-next-line no-console
  console.log("PP4-RELOGIN-OK");
});
