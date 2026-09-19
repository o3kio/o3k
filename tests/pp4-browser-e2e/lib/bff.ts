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
 * Mutations additionally send the `x-csrf-token` header the BFF CSRF middleware
 * requires (backend/console-bff-core/src/csrf.rs); the pinned Araf release's
 * SPA client does not attach it, which is why the specs install a network-layer
 * CSRF bridge for UI-originated requests (see installCsrfBridge).
 *
 * This module is READ-ONLY apart from the session boundary calls (login scope
 * selection, logout) and `installCsrfBridge`: every cloud mutation in the
 * browser journeys must go through the real console UI. There is deliberately
 * no BFF helper for creating or deleting a resource.
 */
import { expect } from "playwright/test";
import type { BrowserContext, Page } from "playwright";

export interface BffSessionStatus {
  readonly authenticated: boolean;
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

export async function cookieNames(context: BrowserContext): Promise<string[]> {
  const cookies = await context.cookies();
  return cookies.map((cookie) => cookie.name).sort();
}

export async function logCookieNames(context: BrowserContext, baseUrl: string): Promise<void> {
  const names = await cookieNames(context);
  const unexpected = names.filter((name) => !(SESSION_COOKIE_NAMES as readonly string[]).includes(name));
  // eslint-disable-next-line no-console
  console.log(`[pp4] cookies for ${new URL(baseUrl).host}: ${names.join(", ")}${unexpected.length > 0 ? ` (unexpected: ${unexpected.join(", ")})` : ""}`);
  expect(
    unexpected,
    `only opaque Araf session/CSRF cookies may be present, got: ${names.join(", ")}`,
  ).toEqual([]);
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

/**
 * Bridge the pinned console SPA's missing CSRF header at the network layer.
 *
 * The pinned Araf SPA ships no CSRF handling at all, so every POST/DELETE the
 * console UI issues is answered 403 by the BFF double-submit middleware and the
 * UI action can never succeed. This route lets the REAL UI path run (real form,
 * real click, real SPA fetch, real BFF endpoint) by adding only the header the
 * SPA omits. It is not a substitute for the UI: when a step cannot be performed
 * through the UI at all, the spec records PP4-UI-FALLBACK and the campaign
 * fails. Every bridged request is logged for the evidence log.
 */
export async function installCsrfBridge(context: BrowserContext, baseUrl: string): Promise<void> {
  const origin = new URL(baseUrl).origin;
  await context.route("**/api/v1/**", async (route) => {
    const request = route.request();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method())) {
      return route.continue();
    }
    if (new URL(request.url()).origin !== origin) {
      return route.continue();
    }
    const headers = { ...request.headers() };
    if (!headers["x-csrf-token"]) {
      const cookies = await context.cookies();
      const csrf = cookies.find((cookie) => cookie.name === "araf_csrf");
      if (csrf) {
        headers["x-csrf-token"] = csrf.value;
        // eslint-disable-next-line no-console
        console.log(`PP4-UI-CSRF-BRIDGE ${request.method()} ${new URL(request.url()).pathname}`);
      }
    }
    await route.continue({ headers });
  });
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
