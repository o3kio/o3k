/**
 * Minimal typed access to the Araf BFF API from the browser context.
 *
 * All calls go through `page.request`, so they carry the page's real cookie
 * jar (araf_<surface>_session + araf_csrf) and hit the same confidential-BFF
 * endpoints the console UI uses. Mutations additionally send the
 * `x-csrf-token` header the BFF CSRF middleware requires
 * (backend/console-bff-core/src/csrf.rs); the pinned Araf release's SPA
 * client does not attach it, which is why UI mutations fall back here (see
 * README.md "Known upstream limitations").
 */
import { randomUUID } from "node:crypto";
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

/** Cookie names are logged; values are session secrets and never are. */
const SESSION_COOKIE_NAMES = ["araf_tenant_session", "araf_operator_session", "araf_csrf"] as const;

export async function cookieNames(context: BrowserContext, baseUrl: string): Promise<string[]> {
  const cookies = await context.cookies(baseUrl);
  return cookies.map((cookie) => cookie.name).sort();
}

export async function logCookieNames(context: BrowserContext, baseUrl: string): Promise<void> {
  const names = await cookieNames(context, baseUrl);
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
export async function csrfToken(context: BrowserContext, baseUrl: string): Promise<string> {
  const cookies = await context.cookies(baseUrl);
  const csrf = cookies.find((cookie) => cookie.name === "araf_csrf");
  if (!csrf) {
    throw new Error(`[pp4] araf_csrf cookie missing for ${baseUrl}; login did not complete`);
  }
  return csrf.value;
}

export async function getSession(page: Page, baseUrl: string): Promise<BffSessionStatus> {
  const response = await page.request.get(`${baseUrl}/api/v1/auth/session`);
  expect(response.ok(), `GET /api/v1/auth/session failed: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as BffSessionStatus;
}

export async function listScopes(page: Page, baseUrl: string): Promise<ScopeChoice[]> {
  const response = await page.request.get(`${baseUrl}/api/v1/auth/scopes`);
  expect(response.ok(), `GET /api/v1/auth/scopes failed: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as ScopeChoice[];
}

/** POST /api/v1/auth/scope — server-side project selection (CSRF-protected). */
export async function selectProjectScope(
  page: Page,
  context: BrowserContext,
  baseUrl: string,
  projectId: string,
): Promise<void> {
  const csrf = await csrfToken(context, baseUrl);
  const response = await page.request.post(`${baseUrl}/api/v1/auth/scope`, {
    data: { project_id: projectId },
    headers: { "x-csrf-token": csrf },
  });
  expect(response.ok(), `POST /api/v1/auth/scope failed: HTTP ${response.status()}`).toBe(true);
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
  const response = await page.request.get(`${baseUrl}/api/v1/context`);
  expect(response.ok(), `GET /api/v1/context failed: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as SessionContext;
}

async function postMutation<T>(
  page: Page,
  context: BrowserContext,
  baseUrl: string,
  path: string,
  data?: unknown,
): Promise<T> {
  const csrf = await csrfToken(context, baseUrl);
  const response = await page.request.post(`${baseUrl}${path}`, {
    ...(data === undefined ? {} : { data }),
    headers: {
      "x-csrf-token": csrf,
      "Idempotency-Key": randomUUID(),
    },
  });
  expect(
    response.ok(),
    `POST ${path} failed: HTTP ${response.status()} ${(await response.text().catch(() => "")).slice(0, 400)}`,
  ).toBe(true);
  return (await response.json()) as T;
}

/**
 * Create a compute server through the same BFF endpoint the create form
 * posts to. The payload matches the O3K create contract exactly
 * (crates/o3k-native-api/src/resource_contract.rs: ComputeServerCreateSpec).
 */
export async function createComputeServer(
  page: Page,
  context: BrowserContext,
  baseUrl: string,
  payload: { name: string; image_id: string; flavor_id: string; network_ids: string[] },
): Promise<CanonicalOperation> {
  return postMutation<CanonicalOperation>(
    page,
    context,
    baseUrl,
    "/api/v1/resources/compute.server",
    payload,
  );
}

/** Submit a lifecycle action (e.g. "stop") — same payload the UI sends. */
export async function submitResourceAction(
  page: Page,
  context: BrowserContext,
  baseUrl: string,
  resourceType: string,
  id: string,
  actionId: string,
): Promise<CanonicalOperation> {
  return postMutation<CanonicalOperation>(
    page,
    context,
    baseUrl,
    `/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}/actions`,
    { action_id: actionId },
  );
}

/** Delete a resource — same BFF endpoint the UI delete action uses. */
export async function deleteResource(
  page: Page,
  context: BrowserContext,
  baseUrl: string,
  resourceType: string,
  id: string,
): Promise<CanonicalOperation> {
  const csrf = await csrfToken(context, baseUrl);
  const response = await page.request.delete(
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}`,
    {
      headers: {
        "x-csrf-token": csrf,
        "Idempotency-Key": randomUUID(),
      },
    },
  );
  expect(
    response.ok(),
    `DELETE /api/v1/resources/${resourceType}/${id} failed: HTTP ${response.status()}`,
  ).toBe(true);
  return (await response.json()) as CanonicalOperation;
}

export async function getOperation(
  page: Page,
  baseUrl: string,
  operationId: string,
): Promise<CanonicalOperation> {
  const response = await page.request.get(
    `${baseUrl}/api/v1/operations/${encodeURIComponent(operationId)}`,
  );
  expect(response.ok(), `GET /api/v1/operations/${operationId} failed: HTTP ${response.status()}`).toBe(
    true,
  );
  return (await response.json()) as CanonicalOperation;
}

export async function listResources(
  page: Page,
  baseUrl: string,
  resourceType: string,
  pageSize = 100,
): Promise<PaginatedCollection<CanonicalResource>> {
  const response = await page.request.get(
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}?page=0&pageSize=${pageSize}`,
  );
  expect(response.ok(), `GET /api/v1/resources/${resourceType} failed: HTTP ${response.status()}`).toBe(
    true,
  );
  return (await response.json()) as PaginatedCollection<CanonicalResource>;
}

export async function getResource(
  page: Page,
  baseUrl: string,
  resourceType: string,
  id: string,
): Promise<CanonicalResource> {
  const response = await page.request.get(
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}`,
  );
  expect(response.ok(), `GET resource ${id} failed: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as CanonicalResource;
}

export interface OperatorOperationList {
  readonly items: readonly CanonicalOperation[];
  readonly total: number;
}

export async function listOperatorOperations(
  page: Page,
  baseUrl: string,
  pageSize = 25,
): Promise<OperatorOperationList> {
  const response = await page.request.get(
    `${baseUrl}/api/v1/operator/operations?page=0&pageSize=${pageSize}`,
  );
  expect(response.ok(), `GET /api/v1/operator/operations failed: HTTP ${response.status()}`).toBe(true);
  return (await response.json()) as OperatorOperationList;
}

/** POST /api/v1/auth/logout (CSRF-protected). Araf ships no logout UI button. */
export async function logout(page: Page, context: BrowserContext, baseUrl: string): Promise<void> {
  const csrf = await csrfToken(context, baseUrl);
  const response = await page.request.post(`${baseUrl}/api/v1/auth/logout`, {
    headers: { "x-csrf-token": csrf },
  });
  expect(response.ok(), `POST /api/v1/auth/logout failed: HTTP ${response.status()}`).toBe(true);
}
