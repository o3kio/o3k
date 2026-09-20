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
  /** Canonical VM name the tenant journey attempts to create. */
  readonly vmName: string;
  /**
   * Deterministic name of the server the tenant journey deletes through the
   * console. The campaign harness creates it through the unmodified OpenStack
   * CLI BEFORE the browser phase (a CLI-created server is a canonical native
   * resource that the console lists), because the pinned Araf SPA cannot
   * submit any create form.
   */
  readonly uiTargetName: string;
  /**
   * Canonical id of that server (REQUIRED). host-run.sh creates
   * `pp4-ui-target` through the unmodified OpenStack CLI in the VM and exports
   * the id `openstack server show pp4-ui-target -c id -f value` reports.
   */
  readonly uiTargetId: string;
  /** TestLab image name that must exist (default cirros-0.6.3). */
  readonly imageName: string;
  /** TestLab network name that must exist (default testlab-network). */
  readonly networkName: string;
  /**
   * Canonical id of the TestLab image (REQUIRED). VERIFIED: the demo's cirros
   * image exists only through the compatibility (Glance) API — the native
   * `image.image` inventory is empty — so the harness passes the id the
   * unmodified OpenStack CLI reports (`openstack image list`).
   */
  readonly imageId: string;
  /**
   * Canonical id of the TestLab network (REQUIRED). VERIFIED: `testlab-network`
   * was created through the compatibility (Neutron) API and is therefore not a
   * canonical `network:network` resource; the console create form still needs
   * the id `openstack network list` reports.
   */
  readonly networkId: string;
  /** TestLab flavor name (display only; the create contract needs the UUID). */
  readonly flavorName: string;
  /**
   * Canonical UUID of the testlab-flavor (REQUIRED). The pinned demo tuple
   * advertises no flavor collection, so there is nothing to fall back on: the
   * campaign harness reads it from the VM's /etc/o3k/testlab-flavor-id ledger
   * (packaging/bootstrap-testlab.sh) and exports PP4_FLAVOR_ID.
   */
  readonly flavorId: string;
  /** Expected admin project id (REQUIRED; must be offered by scope discovery). */
  readonly adminProjectId: string;
  /**
   * phase1a deployment-tuple evidence (KEY=VALUE) proving the deployed Araf is
   * the pinned production tuple. Required: the console DOM alone is not
   * server-side proof about the deployment.
   */
  readonly deploymentEnvFile: string | undefined;
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
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const env: Pp4Env = {
    tenantUrl: normalizeBaseUrl(
      "TENANT_URL",
      required(
        "TENANT_URL",
        "The campaign must provide the VM-local tenant console URL; refusing public-DNS defaults.",
      ),
    ),
    operatorUrl: normalizeBaseUrl(
      "OPERATOR_URL",
      required(
        "OPERATOR_URL",
        "The campaign must provide the VM-local operator console URL; refusing public-DNS defaults.",
      ),
    ),
    cdpUrl: withDefault("CDP_URL", "http://127.0.0.1:9223"),
    aliceUser: withDefault("PP4_ALICE_USER", "alice"),
    alicePassword: required(
      "PP4_ALICE_PASSWORD",
      "Export the demo user's Keycloak password (see tests/pp4-browser-e2e/README.md).",
    ),
    vmName: withDefault("PP4_VM_NAME", "pp4-native"),
    uiTargetName: withDefault("PP4_UI_TARGET_NAME", "pp4-ui-target"),
    uiTargetId: required(
      "PP4_UI_TARGET_ID",
      "host-run.sh creates `pp4-ui-target` through the unmodified OpenStack CLI in the VM " +
        "before the browser phase; export the id `openstack server show pp4-ui-target -c id -f value` reports.",
    ),
    imageName: withDefault("PP4_IMAGE_NAME", "cirros-0.6.3"),
    networkName: withDefault("PP4_NETWORK_NAME", "testlab-network"),
    imageId: required(
      "PP4_IMAGE_ID",
      "Read it in the VM: sudo sh -c '. /etc/o3k/admin-openrc; openstack image list -f json' " +
        "(the native image.image inventory is empty on this profile).",
    ),
    networkId: required(
      "PP4_NETWORK_ID",
      "Read it in the VM: sudo sh -c '. /etc/o3k/admin-openrc; openstack network list -f json' " +
        "(testlab-network exists only through the compatibility API).",
    ),
    flavorName: withDefault("PP4_FLAVOR_NAME", "testlab-flavor"),
    flavorId: required(
      "PP4_FLAVOR_ID",
      "Read it in the VM: sudo cat /etc/o3k/testlab-flavor-id (the pinned demo " +
        "tuple advertises no flavor collection to fall back on).",
    ),
    adminProjectId: required(
      "PP4_ADMIN_PROJECT_ID",
      "Export the canonical admin project id (eba29e2d-53de-461d-ae91-ede7402713cb).",
    ),
    deploymentEnvFile: read("PP4_DEPLOYMENT_ENV_FILE"),
    evidenceDir: resolve(read("PP4_EVIDENCE_DIR") ?? "./evidence"),
    operationTimeoutMs: asPositiveInt("PP4_OP_TIMEOUT_MS", 15 * 60 * 1000),
    resourceTimeoutMs: asPositiveInt("PP4_RESOURCE_TIMEOUT_MS", 10 * 60 * 1000),
  };
  if (!uuid.test(env.flavorId)) {
    throw new Error(`[pp4] PP4_FLAVOR_ID must be a canonical uuid, got "${env.flavorId}"`);
  }
  if (!uuid.test(env.imageId)) {
    throw new Error(`[pp4] PP4_IMAGE_ID must be a canonical uuid, got "${env.imageId}"`);
  }
  if (!uuid.test(env.networkId)) {
    throw new Error(`[pp4] PP4_NETWORK_ID must be a canonical uuid, got "${env.networkId}"`);
  }
  if (!uuid.test(env.uiTargetId)) {
    throw new Error(`[pp4] PP4_UI_TARGET_ID must be a canonical uuid, got "${env.uiTargetId}"`);
  }
  if (!uuid.test(env.adminProjectId)) {
    throw new Error(`[pp4] PP4_ADMIN_PROJECT_ID must be a canonical uuid, got "${env.adminProjectId}"`);
  }
  cached = env;
  return env;
}

/** Create the evidence directory (idempotent) and return its absolute path. */
export function ensureEvidenceDir(env: Pp4Env): string {
  mkdirSync(env.evidenceDir, { recursive: true });
  return isAbsolute(env.evidenceDir) ? env.evidenceDir : resolve(env.evidenceDir);
}

/** Parse KEY=VALUE lines (the campaign's numbered evidence format). */
export function parseKeyValues(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index <= 0) continue;
    values[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim();
  }
  return values;
}
