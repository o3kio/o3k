/**
 * Console-UI helpers shared by the PP.4 journeys. All locators are
 * role/text-based, matching the Araf console sources:
 * - packages/resources/src/components/ResourceCollectionPage.tsx
 * - packages/resources/src/components/ResourceDetailPage.tsx
 * - packages/operations/src/components/OperationDetailPage.tsx
 */
import { expect } from "playwright/test";
import type { Locator, Page } from "playwright";
import { getOperation, getResource } from "./bff";
import type { CanonicalOperation } from "./bff";
import type { Pp4Env } from "./env";
import { ensureEvidenceDir } from "./env";

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
 * Poll the BFF for a canonical Operation until it reaches a terminal state.
 * Returns the terminal operation; throws (with the structured error) on
 * "failed". Up to 15 minutes by default — VM create can take minutes.
 */
export async function waitForOperationTerminal(
  page: Page,
  baseUrl: string,
  operationId: string,
  timeoutMs: number,
): Promise<CanonicalOperation> {
  const deadline = Date.now() + timeoutMs;
  let last: CanonicalOperation | undefined;
  for (;;) {
    last = await getOperation(page, baseUrl, operationId);
    if (TERMINAL_STATES.has(last.state)) break;
    if (Date.now() > deadline) {
      throw new Error(
        `[pp4] operation ${operationId} did not reach a terminal state within ` +
          `${timeoutMs}ms (last state: ${last.state})`,
      );
    }
    await page.waitForTimeout(5_000);
  }
  if (last!.state === "failed") {
    throw new Error(
      `[pp4] operation ${operationId} failed: ` +
        `${last!.error?.code ?? ""} ${last!.error?.title ?? ""} ${last!.error?.detail ?? ""}`,
    );
  }
  return last!;
}

/**
 * Poll the BFF until a resource reaches the wanted status
 * (ready | busy | error | unknown), then return it.
 */
export async function waitForResourceStatus(
  page: Page,
  baseUrl: string,
  resourceType: string,
  id: string,
  want: "ready" | "busy" | "error" | "unknown",
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const resource = await getResource(page, baseUrl, resourceType, id);
    if (resource.status === want) return;
    if (Date.now() > deadline) {
      throw new Error(
        `[pp4] resource ${id} did not reach status "${want}" within ${timeoutMs}ms ` +
          `(last status: ${resource.status})`,
      );
    }
    await page.waitForTimeout(5_000);
  }
}

/**
 * Locate a resource row by name in a generic collection table
 * (aria-label "<plural> table", rows contain the name link).
 */
export function resourceRow(page: Page, pluralName: string, name: string): Locator {
  const table = page.getByRole("table", { name: `${pluralName} table` });
  return table.getByRole("row", { name: new RegExp(name) }).first();
}

/**
 * Open a collection page, wait for the named row, and return the canonical
 * id from the row's Name link href (/resources/<type>/<id>). Asserts the row
 * is truthfully rendered before resolving.
 */
export async function resourceIdByName(
  page: Page,
  baseUrl: string,
  resourceType: string,
  pluralName: string,
  name: string,
): Promise<string> {
  await page.goto(`${baseUrl}/resources/${encodeURIComponent(resourceType)}`);
  await expect(
    page.getByRole("heading", { name: new RegExp(pluralName, "i") }).first(),
    `${pluralName} collection heading`,
  ).toBeVisible({ timeout: 30_000 });
  const row = resourceRow(page, pluralName, name);
  await expect(row, `${pluralName} row for "${name}"`).toBeVisible({ timeout: 60_000 });
  const href = await row.getByRole("link", { name }).getAttribute("href");
  expect(href, `row for "${name}" must link to its detail page`).toBeTruthy();
  const id = decodeURIComponent(href!).split("/").pop();
  expect(id, `detail href for "${name}" must carry the canonical id`).toBeTruthy();
  return id!;
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
