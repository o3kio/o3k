/**
 * Console-UI helpers shared by the PP.4 journeys. All locators are
 * role/text-based, matching the Araf console sources:
 * - packages/resources/src/components/ResourceCollectionPage.tsx
 * - packages/resources/src/components/ResourceDetailPage.tsx
 * - packages/operations/src/components/OperationDetailPage.tsx
 */
import { existsSync, readFileSync } from "node:fs";
import { expect } from "playwright/test";
import type { Locator, Page } from "playwright";
import { bffFetch, getOperation, getResource, listResources } from "./bff";
import type { CanonicalOperation, CanonicalResource } from "./bff";
import type { Pp4Env } from "./env";
import { ensureEvidenceDir, parseKeyValues } from "./env";

const TERMINAL_STATES = new Set(["succeeded", "failed"]);

/** Save a named evidence screenshot into PP4_EVIDENCE_DIR. */
export async function evidence(page: Page, env: Pp4Env, name: string): Promise<void> {
  const dir = ensureEvidenceDir(env);
  await page.screenshot({ path: `${dir}/${name}.png`, fullPage: true });
  // eslint-disable-next-line no-console
  console.log(`[pp4] evidence screenshot: ${dir}/${name}.png`);
}

/** The pinned production profile must never render fixture markers. */
export async function expectNoFixtureMarkers(page: Page): Promise<void> {
  await expect(
    page.getByText(/fixture/i).first(),
    "production console must not render fixture markers",
  ).toHaveCount(0);
}

/**
 * Server-side companion to the DOM fixture check: re-assert, from the phase1a
 * deployment evidence, that the deployment actually runs the pinned production
 * Araf tuple on the native O3K adapter. The DOM can only show what the server
 * sent; this proves the server itself is not in fixture mode.
 */
export function expectProductionDeployment(env: Pp4Env): void {
  const path = env.deploymentEnvFile;
  expect(
    path,
    "PP4_DEPLOYMENT_ENV_FILE must point at the phase1a Araf production-tuple evidence",
  ).toBeTruthy();
  expect(existsSync(path!), `deployment evidence file ${path} must exist`).toBe(true);
  const raw = readFileSync(path!, "utf8");
  const values = parseKeyValues(raw);
  expect(values["ARAF_UPSTREAM_ADAPTER"], "deployment must use the native o3k adapter").toBe("o3k");
  expect(values["ARAF_RUNTIME_PROFILE"], "deployment must run the production profile").toBe(
    "production",
  );
  expect(
    raw.toLowerCase().includes("fixture"),
    "deployment evidence must not contain a fixture-mode marker",
  ).toBe(false);
  expect(values["ARAF_VERSION"], "deployment evidence must name the Araf version").toBeTruthy();
  // eslint-disable-next-line no-console
  console.log(
    `[pp4] deployment tuple: araf ${values["ARAF_VERSION"]} ` +
      `adapter=${values["ARAF_UPSTREAM_ADAPTER"]} profile=${values["ARAF_RUNTIME_PROFILE"]}`,
  );
}

/**
 * Record that a step could NOT be performed through the browser UI and that the
 * harness therefore used the identical BFF call instead. The marker is
 * machine-checked: host-run fails the campaign when it appears, because the
 * campaign claims a real browser journey.
 */
export function uiFallback(step: string, reason: string): void {
  // eslint-disable-next-line no-console
  console.log(`PP4-UI-FALLBACK ${step}`);
  // eslint-disable-next-line no-console
  console.log(`[pp4] PP4-NOTE step "${step}" not performed through the UI: ${reason}`);
}

/** The canonical Operation identity and state the console rendered. */
export interface SubmittedOperation {
  readonly id: string;
  readonly state: string;
}

/** The resolved terminal outcome of a console-driven mutation. */
export interface TerminalOperation {
  readonly id: string;
  readonly state: string;
  readonly resourceId: string | null;
  readonly errorTitle: string;
  readonly errorDetail: string;
}

/**
 * Parse the console's operation note ("Operation <id> is <state>. Correlation
 * ID: ..."), which is what both the create page and the action panel render.
 */
export function parseSubmittedOperation(text: string): SubmittedOperation {
  const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(text);
  expect(match, "the console must name the canonical Operation and its state").toBeTruthy();
  return { id: match![1]!, state: match![2]!.replace(/[^A-Za-z]/gu, "").toLowerCase() };
}

export function isTerminalState(state: string): boolean {
  return TERMINAL_STATES.has(state);
}

/**
 * Resolve a console-driven mutation to its terminal canonical state.
 *
 * Native CRUD routes may complete synchronously: the BFF then reports the
 * terminal state in the mutation response itself and does **not** persist a
 * pollable history record (see `fetch_or_build_operation` in
 * `araf/backend/console-bff-core/src/o3k_adapter.rs`). A terminal state read
 * from the console is therefore authoritative, and the history route is only
 * polled while the console reports a non-terminal state.
 */
export async function resolveTerminalOperation(
  page: Page,
  baseUrl: string,
  submitted: SubmittedOperation,
  timeoutMs: number,
): Promise<TerminalOperation> {
  if (isTerminalState(submitted.state)) {
    return {
      id: submitted.id,
      state: submitted.state,
      resourceId: null,
      errorTitle: "",
      errorDetail: "",
    };
  }
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const operation: CanonicalOperation = await getOperation(page, baseUrl, submitted.id);
    if (isTerminalState(operation.state)) {
      return {
        id: operation.id,
        state: operation.state,
        resourceId: operation.resourceId,
        errorTitle: operation.error?.title ?? "",
        errorDetail: operation.error?.detail ?? "",
      };
    }
    if (Date.now() > deadline) {
      throw new Error(
        `[pp4] operation ${submitted.id} did not reach a terminal state within ` +
          `${timeoutMs}ms (last state: ${operation.state})`,
      );
    }
    await page.waitForTimeout(5_000);
  }
}

/** Open the operation detail page and assert the canonical header renders. */
export async function openOperationDetail(
  page: Page,
  baseUrl: string,
  operationId: string,
): Promise<void> {
  await page.goto(`${baseUrl}/operations/${encodeURIComponent(operationId)}`);
  await expect(
    page.getByRole("heading", { name: `Operation ${operationId}` }),
    `operation detail heading for ${operationId}`,
  ).toBeVisible({ timeout: 30_000 });
}

/**
 * Locate a collection row by CANONICAL ID.
 *
 * The collection rendering shows whatever label the O3K list projection
 * carries: resources created through the native API carry their spec name,
 * while some resources created through compatibility paths carry only their id
 * in the list projection (their name is still rendered on the detail page).
 * Row identity is therefore the canonical id, not the label.
 */
export function resourceRowById(page: Page, pluralName: string, id: string): Locator {
  const table = page.getByRole("table", { name: `${pluralName} table` });
  return table.getByRole("row").filter({ has: page.locator(`a[href$="${id}"]`) }).first();
}

export const CANONICAL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface CollectionObservation {
  /** Canonical ids linked from the rendered rows (never the row labels). */
  readonly ids: readonly string[];
  /** True when the console rendered its explicit "No resources" empty state. */
  readonly empty: boolean;
}

/**
 * Open a resource collection and observe it TRUTHFULLY:
 * - the page must not render the console error state ("Could not load
 *   resources") and must not crash;
 * - it must either render rows or the explicit "No resources" empty state
 *   (a collection that shows neither is still loading, so this polls).
 *
 * Row identity is the canonical id in each row's detail link: VERIFIED, the
 * native list projection does not carry the spec name for every resource, so
 * the rendered label may be the id itself.
 */
export async function openCollection(
  page: Page,
  baseUrl: string,
  resourceType: string,
  pluralName: string,
): Promise<CollectionObservation> {
  await page.goto(`${baseUrl}/resources/${encodeURIComponent(resourceType)}`);
  await expect(
    page.getByRole("heading", { name: new RegExp(pluralName, "i") }).first(),
    `${pluralName} collection heading`,
  ).toBeVisible({ timeout: 30_000 });
  const table = page.getByRole("table", { name: `${pluralName} table` });
  const crashed = page.getByText("Could not load resources");
  const emptyState = page.getByText("No resources", { exact: true });
  await expect
    .poll(
      async () =>
        (await crashed.count()) > 0 ||
        (await emptyState.count()) > 0 ||
        (await table.getByRole("row").count()) > 1,
      { timeout: 60_000, intervals: [500, 1_000, 2_000, 5_000] },
    )
    .toBe(true);
  expect(
    await crashed.count(),
    `the ${pluralName} collection must not render the console error state`,
  ).toBe(0);
  return {
    ids: await collectionRowIds(page, pluralName),
    empty: (await emptyState.count()) > 0,
  };
}

/** Canonical ids linked from the rows of an already-open collection table. */
export async function collectionRowIds(page: Page, pluralName: string): Promise<string[]> {
  const table = page.getByRole("table", { name: `${pluralName} table` });
  return table.locator('a[href*="/resources/"]').evaluateAll((links) =>
    links
      .map((link) => decodeURIComponent((link.getAttribute("href") ?? "").split("/").pop() ?? ""))
      .filter((id) => id !== ""),
  );
}

/**
 * A console-side crash/fallback page must never be the observed outcome of a
 * truthful failure. Error banners are expected; framework error pages are not.
 */
export async function expectNoConsoleCrash(page: Page): Promise<void> {
  for (const marker of [
    "Could not load resource",
    "Could not load resources",
    "Could not load resource descriptor",
    "Something went wrong",
    "Application error",
  ]) {
    await expect(
      page.getByText(marker, { exact: false }),
      `the console must not render "${marker}"`,
    ).toHaveCount(0);
  }
}

/** Canonical Operation id from an action note ("Operation <id> is <state>. ..."). */
export function operationIdFromNote(text: string): string {
  const match = /Operation\s+(\S+)\s+is\s+(\S+)/.exec(text);
  expect(match, "the console must name the canonical Operation").toBeTruthy();
  return match![1]!;
}

/**
 * Read a resource through the console API, tolerating a concealed tombstone.
 *
 * The canonical ledger keeps a `DELETED` tombstone after a delete, and the
 * native `show` projection deliberately conceals it (404). Returns `undefined`
 * for a concealed resource and throws for any other failure, so "gone" and
 * "the query itself failed" are never conflated.
 */
export async function getResourceOrUndefined(
  page: Page,
  baseUrl: string,
  resourceType: string,
  id: string,
): Promise<CanonicalResource | undefined> {
  const response = await bffFetch(
    page,
    `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}`,
  );
  if (response.status === 404 || response.status === 410) return undefined;
  expect(
    response.ok,
    `GET ${resourceType}/${id} failed: HTTP ${response.status} ${response.body.slice(0, 200)}`,
  ).toBe(true);
  return JSON.parse(response.body) as CanonicalResource;
}

/** Wait until the console API conceals the resource (native `show` is the live view). */
export async function waitForResourceConcealed(
  page: Page,
  baseUrl: string,
  resourceType: string,
  id: string,
  timeoutMs = 120_000,
): Promise<void> {
  let last = 0;
  await expect
    .poll(
      async () => {
        const response = await bffFetch(
          page,
          `${baseUrl}/api/v1/resources/${encodeURIComponent(resourceType)}/${encodeURIComponent(id)}`,
        );
        last = response.status;
        return response.status;
      },
      { timeout: timeoutMs, intervals: [1_000, 2_000, 5_000] },
    )
    .toBe(404);
  expect(last, "the concealed resource must answer 404 on the live-resource view").toBe(404);
}

/**
 * Resolve a resource's canonical id by name through the API: the list
 * projection may omit names, so candidates are confirmed through their detail
 * resource (which always carries the name).
 */
export async function findResourceIdByName(
  page: Page,
  baseUrl: string,
  resourceType: string,
  name: string,
): Promise<string> {
  const listed = await listResources(page, baseUrl, resourceType, 100);
  for (const item of listed.items) {
    if (item.name === name) return item.id;
  }
  for (const item of listed.items) {
    // A listed row can be a soft-deleted tombstone (the native list keeps
    // projecting it): the live view conceals it with 404. Skip those — they
    // are not live resources, and a name lookup must never fail on them.
    const detail = await getResourceOrUndefined(page, baseUrl, resourceType, item.id);
    if (detail?.name === name) return item.id;
  }
  throw new Error(
    `[pp4] no ${resourceType} named "${name}" is visible through the console API ` +
      `(collection total=${listed.total})`,
  );
}
