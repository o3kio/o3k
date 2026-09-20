/**
 * Minimal typed access to the Araf BFF API from the browser context.
 *
 * TRANSPORT: the browser runs INSIDE the campaign VM, but this Playwright
 * process runs on the host, where the demo hostnames (tenant.o3k.demo,
 * operator.o3k.demo) do not resolve. `page.request`/`context.request` are
 * Node-side HTTP clients, so every call through them fails with ENOTFOUND.
 * All BFF calls therefore go through `page.evaluate(fetch(...))`: they execute
 * inside the in-VM Chromium, resolve through its /etc/hosts, trust the demo CA
 * and carry the page's real cookie jar (araf_<surface>_session + araf_csrf).
 *
 * The rc.15 SPA supplies the `x-csrf-token` header for product mutations. The
 * harness never rewrites browser requests or installs a network-layer bridge.
 *
 * This module is READ-ONLY apart from the session boundary calls (login scope
 * selection, logout): every cloud mutation in the browser journeys must go
 * through the real console UI. There is deliberately no BFF helper for
 * creating or deleting a resource.
 */
import { expect } from "playwright/test";
import type { BrowserContext, Page } from "playwright";

export interface BffSessionStatus {
  readonly authenticated: boolean;
  /** The BFF serializes camelCase; the snake_case fields are legacy tolerances. */
  readonly userId?: string;
  readonly userName?: string;
  readonly user_id?: string;
  readonly user_name?: string;
  readonly surface?: string;
}

export interface ScopeChoice {
  readonly id: string;
  readonly kind: string;
  readonly name: string;
  readonly domain_id?: string | null;
  readonly can_request_token?: boolean;
}

export interface CanonicalOperation {
  readonly id: string;
  readonly action: string;
  readonly state:
    | "pending"
    | "running"
    | "succeeded"
    | "failed"
    | "retryable"
    | "unknownOutcome";
  readonly resourceId: string | null;
  readonly resourceType: string | null;
  readonly projectId: string | null;
  readonly correlationId: string;
  readonly error: { readonly code: string; readonly title: string; readonly detail: string } | null;
}

export interface CanonicalResource {
  readonly id: string;
  readonly name: string;
  readonly resourceType: string;
  readonly status: "ready" | "busy" | "error" | "unknown";
  readonly properties?: Record<string, unknown>;
}

export interface PaginatedCollection<T> {
  readonly items: readonly T[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
  readonly hasMore: boolean;
}

export interface BffResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly body: string;
}

interface FetchInit {
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

/**
 * Issue a request from INSIDE the browser page (see the module comment).
 * Relative paths are resolved against the page origin; absolute URLs are used
 * as-is (they must share the page origin for cookies to be sent).
 */
export async function bffFetch(
  page: Page,
  url: string,
  init: FetchInit = {},
): Promise<BffResponse> {
  return page.evaluate(
    async ({ url, init }) => {
      const response = await fetch(url, {
        method: init.method ?? "GET",
        headers: init.headers ?? {},
        body: init.body ?? undefined,
        credentials: "same-origin",
      });
      return { status: response.status, ok: response.ok, body: await response.text() };
    },
    { url, init },
  );
}

/** The araf_csrf cookie value as the page itself sees it (not HttpOnly). */
async function browserCsrfToken(page: Page): Promise<string> {
  const value = await page.evaluate(() => {
    const entry = document.cookie.split("; ").find((cookie) => cookie.startsWith("araf_csrf="));
    return entry ? entry.slice("araf_csrf=".length) : "";
  });
  expect(value, "araf_csrf cookie missing; the BFF session was not established").not.toBe("");
  return value;
}

async function expectOk(response: BffResponse, what: string): Promise<BffResponse> {
  expect(response.ok, `${what} failed: HTTP ${response.status} ${response.body.slice(0, 300)}`).toBe(
    true,
  );
  return response;
}

/** Cookie names are logged; values are session secrets and never are. */
const SESSION_COOKIE_NAMES = ["araf_tenant_session", "araf_operator_session", "araf_csrf"] as const;

/**
 * Cookies the demo IdP sets on its OWN host during the OIDC redirect. They are
 * host-scoped to idp.o3k.demo (the console never receives them) and contain a
 * Keycloak session id, not an OAuth token — see the token-name assertion below,
 * which fails on any cookie whose name mentions a token regardless of host.
 */
const IDP_COOKIE_NAMES = [
  "KEYCLOAK_IDENTITY",
  "KEYCLOAK_IDENTITY_LEGACY",
  "KEYCLOAK_SESSION",
  "KEYCLOAK_SESSION_LEGACY",
  "KC_RESTART",
  "AUTH_SESSION_ID",
  "AUTH_SESSION_ID_LEGACY",
  "KC_AUTH_SESSION_HASH",
] as const;

export async function cookieNames(context: BrowserContext): Promise<string[]> {
  const cookies = await context.cookies();
  return cookies.map((cookie) => cookie.name).sort();
}

export async function logCookieNames(context: BrowserContext, baseUrl: string): Promise<void> {
  const host = new URL(baseUrl).host;
  const cookies = await context.cookies();
  const names = cookies.map((cookie) => cookie.name).sort();
  // The console host's own cookies must be exactly the opaque Araf pair.
  const consoleCookies = cookies.filter((cookie) => cookie.domain.replace(/^\./, "") === host);
  const unexpected = consoleCookies
    .map((cookie) => cookie.name)
    .filter((name) => !(SESSION_COOKIE_NAMES as readonly string[]).includes(name));
  // No cookie anywhere in the context may be a cloud/OAuth token, whatever
  // host set it (the demo IdP's session cookies are session ids, not tokens).
  const tokenNamed = names.filter((name) =>
    /(^|_|\b)(access_token|refresh_token|id_token|bearer|authorization)(\b|_|$)/i.test(name),
  );
  // eslint-disable-next-line no-console
  console.log(`[pp4] cookies for ${host}: ${names.join(", ")}${unexpected.length > 0 ? ` (unexpected console cookies: ${unexpected.join(", ")})` : ""}`);
  expect(
    unexpected,
    `only opaque Araf session/CSRF cookies may be present on ${host}, got: ${names.join(", ")}`,
  ).toEqual([]);
  expect(tokenNamed, `no cookie may carry a cloud/OAuth token, got: ${tokenNamed.join(", ")}`).toEqual(
    [],
  );
  const idpOnly = cookies
    .filter((cookie) => !(SESSION_COOKIE_NAMES as readonly string[]).includes(cookie.name))
    .map((cookie) => cookie.name);
  const unknown = idpOnly.filter(
    (name) => !(IDP_COOKIE_NAMES as readonly string[]).includes(name),
  );
  expect(unknown, `unexpected non-Araf cookies: ${unknown.join(", ")}`).toEqual([]);
}

/**
 * Read the araf_csrf cookie value. The BFF sets it without HttpOnly
 * (backend/console-bff-core/src/csrf.rs), so the test can read it exactly as
 * the SPA would.
 */
export async function csrfToken(context: BrowserContext): Promise<string> {
  const cookies = await context.cookies();
  const csrf = cookies.find((cookie) => cookie.name === "araf_csrf");
  if (!csrf) {
    throw new Error("[pp4] araf_csrf cookie missing; login did not complete");
  }
  return csrf.value;
}

export async function getSession(page: Page, baseUrl: string): Promise<BffSessionStatus> {
  const response = await bffFetch(page, `${baseUrl}/api/v1/auth/session`);
  await expectOk(response, "GET /api/v1/auth/session");
  return JSON.parse(response.body) as BffSessionStatus;
}

export async function listScopes(page: Page, baseUrl: string): Promise<ScopeChoice[]> {
  const response = await bffFetch(page, `${baseUrl}/api/v1/auth/scopes`);
  await expectOk(response, "GET /api/v1/auth/scopes");
  return JSON.parse(response.body) as ScopeChoice[];
}

/** POST /api/v1/auth/scope — server-side project selection (CSRF-protected). */
export async function selectProjectScope(page: Page, baseUrl: string, projectId: string): Promise<void> {
  const csrf = await browserCsrfToken(page);
  const response = await bffFetch(page, `${baseUrl}/api/v1/auth/scope`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": csrf },
    body: JSON.stringify({ project_id: projectId }),
  });
  await expectOk(response, "POST /api/v1/auth/scope");
}

export interface SessionContext {
  readonly surface: string;
  readonly userId: string;
  readonly userName: string;
  readonly organizationId: string | null;
  readonly projectId: string | null;
  readonly regionId: string | null;
}

/** GET /api/v1/context — authoritative session context (identity + scope). */
export async function getContext(page: Page, baseUrl: string): Promise<SessionContext> {
  const response = await bffFetch(page, `${baseUrl}/api/v1/context`);
  await expectOk(response, "GET /api/v1/context");
  return JSON.parse(response.body) as SessionContext;
}

export async function getOperation(
  page: Page,
  baseUrl: string,
  operationId: string,
): Promise<CanonicalOperation> {
  const response = await bffFetch(
    page,
    `${baseUrl}/api/v1/operations/${encodeURIComponent(operationId)}`,
  );
  await expectOk(response, `GET /api/v1/operations/${operationId}`);
  return JSON.parse(response.body) as CanonicalOperation;
}

export async function listResources(
  page: Page,
  baseUrl: string,
  resourceType: string,
  pageSize = 100,
): Promise<PaginatedCollection<CanonicalResource>> {
  const response = await bffFetch(
    page,
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}?page=0&pageSize=${pageSize}`,
  );
  await expectOk(response, `GET /api/v1/resources/${resourceType}`);
  return JSON.parse(response.body) as PaginatedCollection<CanonicalResource>;
}

export async function getResource(
  page: Page,
  baseUrl: string,
  resourceType: string,
  id: string,
): Promise<CanonicalResource> {
  const response = await bffFetch(
    page,
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}`,
  );
  await expectOk(response, `GET resource ${id}`);
  return JSON.parse(response.body) as CanonicalResource;
}

export interface OperationList {
  readonly items: readonly CanonicalOperation[];
  readonly total: number;
}

/**
 * GET /api/v1/operations — the canonical operations list the O3K token is
 * scope-bound to (served on both console surfaces; `base_routes`).
 */
/** Like listOperations, but returns null when the route is not mounted (404/501). */
export async function listOperationsOrNull(
  page: Page,
  baseUrl: string,
  pageSize: number,
): Promise<OperationList | null> {
  const response = await bffFetch(
    page,
    `${baseUrl}/api/v1/operations?page=0&pageSize=${String(pageSize)}`,
  );
  if (response.status === 404 || response.status === 501) return null;
  await expectOk(response, "GET /api/v1/operations");
  return JSON.parse(response.body) as OperationList;
}

export async function listOperations(
  page: Page,
  baseUrl: string,
  pageSize = 100,
): Promise<OperationList> {
  const response = await bffFetch(page, `${baseUrl}/api/v1/operations?page=0&pageSize=${pageSize}`);
  await expectOk(response, "GET /api/v1/operations");
  return JSON.parse(response.body) as OperationList;
}

/** POST /api/v1/auth/logout (CSRF-protected). Araf ships no logout UI button. */
export async function logout(page: Page, baseUrl: string): Promise<void> {
  const csrf = await browserCsrfToken(page);
  const response = await bffFetch(page, `${baseUrl}/api/v1/auth/logout`, {
    method: "POST",
    headers: { "x-csrf-token": csrf },
  });
  await expectOk(response, "POST /api/v1/auth/logout");
}
