/**
 * Real OIDC login against the demo Keycloak through the confidential-client
 * BFF authorization-code + PKCE flow.
 *
 * Flow (proven by tests/p12-iam-8-real-araf-process.sh and
 * packaging/o3k-araf-demo.sh against the same BFF code):
 *   1. GET <surface>/api/v1/auth/login      -> 302 to the IdP authorize URL
 *   2. Keycloak login form (username/password/credentialId fields, parsed
 *      from the served form in the demo orchestrator's browser_login)
 *   3. IdP redirects to <surface>/api/v1/auth/callback?code=...&state=...
 *   4. BFF exchanges the code server-side and sets the opaque
 *      araf_<surface>_session + araf_csrf cookies, then redirects to the
 *      console home ("/" for tenant, "/platform/overview" for operator).
 *
 * The browser never sees a client secret or any OIDC token; custody stays in
 * the BFF (backend/console-bff-core/src/auth.rs).
 */
import { expect } from "playwright/test";
import type { Browser, BrowserContext, Page } from "playwright";
import { chromium } from "playwright";
import { getContext, getSession, listScopes, selectProjectScope } from "./bff";
import type { Pp4Env } from "./env";

export type Surface = "tenant" | "operator";

export interface AuthenticatedSurface {
  readonly browser: Browser;
  readonly context: BrowserContext;
  readonly page: Page;
  readonly surface: Surface;
  readonly baseUrl: string;
  readonly userName: string;
  readonly userId: string;
}

export function surfaceBaseUrl(env: Pp4Env, surface: Surface): string {
  return surface === "tenant" ? env.tenantUrl : env.operatorUrl;
}

/** Connect to the in-VM Chromium over CDP (see playwright.config.ts). */
export async function connectBrowser(env: Pp4Env): Promise<Browser> {
  const browser = await chromium.connectOverCDP(env.cdpUrl, { timeout: 30_000 });
  return browser;
}

/**
 * Fill the Keycloak login form. Selectors target the stock Keycloak 25 base
 * theme form (the pinned IdP image is Keycloak 25.0.6; the demo
 * orchestrator's browser_login proves the served form carries
 * username/password/credentialId fields and a form action). Fallbacks keep
 * this working if the theme markup drifts slightly.
 */
async function submitKeycloakForm(
  page: Page,
  user: string,
  password: string,
): Promise<void> {
  const form = page
    .locator("form#kc-form-login")
    .or(page.locator("form:has(input[name='password'])"))
    .first();
  await expect(form, "Keycloak login form never appeared").toBeVisible({ timeout: 60_000 });

  const usernameInput = form
    .locator("input[name='username']")
    .or(form.locator("input#username"))
    .or(form.locator("input#email"))
    .or(form.locator("input[name='email']"))
    .first();
  const passwordInput = form
    .locator("input[name='password']")
    .or(form.locator("input#password"))
    .first();
  await usernameInput.fill(user);
  await passwordInput.fill(password);

  const submit = form
    .locator("#kc-login")
    .or(form.locator("input[type='submit']"))
    .or(form.locator("button[type='submit']"))
    .first();
  await submit.click();
}

/**
 * Run the OIDC flow for one console surface and return an authenticated page
 * in a fresh browser context. Tolerates an existing IdP SSO session (the
 * authorize endpoint then bounces straight back to the callback).
 */
export async function loginToSurface(
  browser: Browser,
  env: Pp4Env,
  surface: Surface,
): Promise<AuthenticatedSurface> {
  const baseUrl = surfaceBaseUrl(env, surface);
  const baseOrigin = new URL(baseUrl).origin;
  const context = await browser.newContext();
  const page = await context.newPage();

  // 1. Start the flow at the BFF login endpoint.
  await page.goto(`${baseUrl}/api/v1/auth/login`, {
    waitUntil: "domcontentloaded",
    timeout: 90_000,
  });

  // 2. Either we land on the Keycloak form, or SSO sends us straight home.
  const keycloakForm = page
    .locator("form#kc-form-login")
    .or(page.locator("form:has(input[name='password'])"))
    .first();
  const deadline = Date.now() + 90_000;
  let sawForm = false;
  for (;;) {
    const url = new URL(page.url());
    const backAtConsole =
      url.origin === baseOrigin && !url.pathname.startsWith("/api/v1/auth/");
    if (backAtConsole) break;
    if (await keycloakForm.isVisible().catch(() => false)) {
      sawForm = true;
      break;
    }
    if (Date.now() > deadline) {
      const snippet = (await page.content().catch(() => "")).slice(0, 500);
      throw new Error(
        `[pp4] ${surface}: neither Keycloak form nor console redirect appeared; ` +
          `last URL ${page.url()}; body starts: ${snippet}`,
      );
    }
    await page.waitForTimeout(500);
  }

  if (sawForm) {
    // 3+4. Submit credentials and wait for the callback redirect home.
    await submitKeycloakForm(page, env.aliceUser, env.alicePassword);
    await page.waitForURL(
      (url) => new URL(url.toString()).origin === baseOrigin &&
        !new URL(url.toString()).pathname.startsWith("/api/v1/auth/"),
      { timeout: 90_000 },
    );
  }

  // 5. Authoritative session assertion through the BFF.
  const session = await getSession(page, baseUrl);
  expect(
    session.authenticated,
    `${surface} session must be authenticated after OIDC login`,
  ).toBe(true);
  expect(session.user_name, "session must carry the federated user name").toBeTruthy();

  return {
    browser,
    context,
    page,
    surface,
    baseUrl,
    userName: session.user_name ?? "",
    userId: session.user_id ?? "",
  };
}

/**
 * Tenant-only: the shell cannot render until a project scope is selected
 * server-side (the BFF session needs the exchanged native O3K token before
 * /api/v1/context resolves). Araf rc.12 exposes no scope-selection page in
 * the SPA (ProjectSelector is presentation-only), so selection uses the same
 * BFF endpoint as Araf's own process evidence; the shell then renders the
 * selected project. Asserts the admin project is listed first.
 */
export async function selectAdminProject(
  auth: AuthenticatedSurface,
  env: Pp4Env,
): Promise<{ projectId: string; projectName: string }> {
  const scopes = await listScopes(auth.page, auth.baseUrl);
  expect(scopes.length, "scope discovery must offer at least one scope").toBeGreaterThan(0);
  const projects = scopes.filter(
    (scope) => scope.kind === "project" && scope.can_request_token !== false,
  );
  expect(projects.length, "scope discovery must offer at least one project").toBeGreaterThan(0);

  const chosen =
    (env.adminProjectId
      ? projects.find((scope) => scope.id === env.adminProjectId)
      : undefined) ??
    projects.find((scope) => /admin/i.test(scope.name)) ??
    projects[0];
  expect(chosen, "a project scope must be selectable").toBeTruthy();

  await selectProjectScope(auth.page, auth.baseUrl, chosen!.id);

  // The session context must now carry the selected project.
  const context = await getContext(auth.page, auth.baseUrl);
  expect(context.projectId, "context must reflect the selected project").toBe(chosen!.id);

  return { projectId: chosen!.id, projectName: chosen!.name };
}

/**
 * Assert the authenticated identity is visible in the console shell top
 * navigation (utility "User/Operator menu for <name>" per
 * packages/shell/src/components/TenantShell.tsx / OperatorShell.tsx).
 */
export async function assertIdentityVisible(auth: AuthenticatedSurface): Promise<void> {
  const labelPattern = new RegExp(
    `${auth.surface === "tenant" ? "User" : "Operator"} menu for ${auth.userName}`,
  );
  const utility = auth.page
    .getByRole("link", { name: labelPattern })
    .or(auth.page.getByRole("button", { name: labelPattern }))
    .or(auth.page.getByText(auth.userName, { exact: true }).first());
  await expect(
    utility.first(),
    `identity "${auth.userName}" must be visible in the ${auth.surface} shell`,
  ).toBeVisible({ timeout: 30_000 });
}
