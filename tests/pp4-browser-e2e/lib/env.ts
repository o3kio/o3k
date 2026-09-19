/**
 * Environment parsing for the PP.4 browser E2E harness.
 *
 * Fail-fast on missing required configuration. Secrets (PP4_ALICE_PASSWORD)
 * are never logged, never defaulted, never hardcoded.
 */
import { mkdirSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export interface Pp4Env {
  /** Base URL of the tenant console (browser-resolvable). */
  readonly tenantUrl: string;
  /** Base URL of the operator console. */
  readonly operatorUrl: string;
  /** CDP endpoint of the in-VM Chromium (SSH-forwarded). */
  readonly cdpUrl: string;
  /** Keycloak user for the whole journey (default "alice"). */
  readonly aliceUser: string;
  /** Keycloak password for alice (REQUIRED, never logged). */
  readonly alicePassword: string;
  /** Canonical VM name created by the tenant journey. */
  readonly vmName: string;
  /** TestLab image name that must exist (default cirros-0.6.3). */
  readonly imageName: string;
  /** TestLab network name that must exist (default testlab-network). */
  readonly networkName: string;
  /** TestLab flavor name (display only; the create contract needs the UUID). */
  readonly flavorName: string;
  /**
   * Canonical UUID of the testlab-flavor. Optional only because the harness
   * additionally attempts UI discovery on /resources/compute.flavor, which the
   * pinned demo tuple does not advertise (the compute.flavor manifest has no
   * collection). The campaign harness must normally provide this, read from
   * the VM's /etc/o3k/testlab-flavor-id ledger.
   */
  readonly flavorId: string | undefined;
  /** Expected admin project id; when set it must be offered by scope discovery. */
  readonly adminProjectId: string | undefined;
  /** Directory for evidence screenshots. */
  readonly evidenceDir: string;
  /** Poll budget for canonical Operations to reach a terminal state. */
  readonly operationTimeoutMs: number;
  /** Poll budget for a server to become Ready after create/start. */
  readonly resourceTimeoutMs: number;
}

function read(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value.trim() === "" ? undefined : value.trim();
}

function required(name: string, hint: string): string {
  const value = read(name);
  if (!value) {
    throw new Error(
      `[pp4] ${name} is required. ${hint}`,
    );
  }
  return value;
}

function withDefault(name: string, fallback: string): string {
  return read(name) ?? fallback;
}

function asPositiveInt(name: string, fallback: number): number {
  const raw = read(name);
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    throw new Error(`[pp4] ${name} must be a positive integer, got "${raw}"`);
  }
  return parsed;
}

function normalizeBaseUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`[pp4] ${name} must be a valid URL, got "${value}"`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`[pp4] ${name} must be http(s), got "${value}"`);
  }
  return url.toString().replace(/\/+$/u, "");
}

let cached: Pp4Env | undefined;

export function loadEnv(): Pp4Env {
  if (cached) return cached;
  const env: Pp4Env = {
    tenantUrl: normalizeBaseUrl(
      "TENANT_URL",
      withDefault("TENANT_URL", "https://tenant.o3k.demo"),
    ),
    operatorUrl: normalizeBaseUrl(
      "OPERATOR_URL",
      withDefault("OPERATOR_URL", "https://operator.o3k.demo"),
    ),
    cdpUrl: withDefault("CDP_URL", "http://127.0.0.1:9223"),
    aliceUser: withDefault("PP4_ALICE_USER", "alice"),
    alicePassword: required(
      "PP4_ALICE_PASSWORD",
      "Export the demo user's Keycloak password (see tests/pp4-browser-e2e/README.md).",
    ),
    vmName: withDefault("PP4_VM_NAME", "pp4-native"),
    imageName: withDefault("PP4_IMAGE_NAME", "cirros-0.6.3"),
    networkName: withDefault("PP4_NETWORK_NAME", "testlab-network"),
    flavorName: withDefault("PP4_FLAVOR_NAME", "testlab-flavor"),
    flavorId: read("PP4_FLAVOR_ID"),
    adminProjectId: read("PP4_ADMIN_PROJECT_ID"),
    evidenceDir: resolve(read("PP4_EVIDENCE_DIR") ?? "./evidence"),
    operationTimeoutMs: asPositiveInt("PP4_OP_TIMEOUT_MS", 15 * 60 * 1000),
    resourceTimeoutMs: asPositiveInt("PP4_RESOURCE_TIMEOUT_MS", 10 * 60 * 1000),
  };
  cached = env;
  return env;
}

/** Create the evidence directory (idempotent) and return its absolute path. */
export function ensureEvidenceDir(env: Pp4Env): string {
  mkdirSync(env.evidenceDir, { recursive: true });
  return isAbsolute(env.evidenceDir) ? env.evidenceDir : resolve(env.evidenceDir);
}
