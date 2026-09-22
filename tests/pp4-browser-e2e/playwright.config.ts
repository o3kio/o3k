import { defineConfig } from "playwright/test";

/**
 * PP.4 browser E2E harness.
 *
 * The browser (Chromium) runs INSIDE the campaign VM with the demo CA and
 * /etc/hosts entries; this runner only connects over CDP. Therefore there is
 * deliberately NO webServer and NO launch options here — each spec connects
 * with chromium.connectOverCDP(process.env.CDP_URL) in beforeAll and creates
 * its own BrowserContext. Never add launch options; see README.md.
 */
export default defineConfig({
  testDir: ".",
  testMatch: "**/*.spec.ts",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  // Backstop only; every spec sets explicit per-test timeouts via
  // test.setTimeout() (VM lifecycle polling needs up to 15 minutes).
  timeout: 300_000,
  use: {
    screenshot: "only-on-failure",
  },
  // Serial campaign evidence: the operator journey must observe the
  // operations the tenant journey created, and the relogin check runs last.
  projects: [
    { name: "tenant", testMatch: "specs/tenant.spec.ts" },
    {
      name: "operator",
      testMatch: "specs/operator.spec.ts",
      dependencies: ["tenant"],
    },
    {
      name: "relogin",
      testMatch: "specs/relogin.spec.ts",
      dependencies: ["operator"],
    },
  ],
});
