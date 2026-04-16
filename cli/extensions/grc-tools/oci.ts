/**
 * OCI GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the oci-sec-inspector spec.
 * The first slice keeps transport/auth aligned with the official OCI CLI while
 * the assessment, normalization, and export logic stay native in grclanker.
 */
import { execFileSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type OciCommandRunner = (args: string[]) => string;

const DEFAULT_REGION = "us-ashburn-1";
const DEFAULT_PROFILE = "DEFAULT";
const DEFAULT_OUTPUT_DIR = "./export/oci";
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_LOOKBACK_DAYS = 7;
const DEFAULT_MAX_KEYS = 200;
const DEFAULT_MAX_POLICIES = 500;
const DEFAULT_COMMAND_TIMEOUT_MS = 15_000;
const SENSITIVE_PORTS = new Set([22, 3389, 1433, 3306, 5432]);

export interface OciResolvedConfig {
  configFile: string;
  profile: string;
  region: string;
  tenancyOcid: string;
  compartmentOcid: string;
  sourceChain: string[];
}

export interface OciAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface OciAccessCheckResult {
  status: "healthy" | "limited";
  tenancyOcid: string;
  compartmentOcid: string;
  surfaces: OciAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface OciFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface OciAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: OciFinding[];
}

export interface OciAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  config_file?: string;
  profile?: string;
  region?: string;
  tenancy_ocid?: string;
  compartment_ocid?: string;
};

type IdentityArgs = CheckAccessArgs & {
  stale_days?: number;
  max_keys?: number;
  max_policies?: number;
};

type LoggingArgs = CheckAccessArgs & {
  lookback_days?: number;
};

type ExportAuditBundleArgs = IdentityArgs & {
  output_dir?: string;
  lookback_days?: number;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return value;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  const object = asObject(value);
  if (!object) return undefined;
  return (
    extractTimestamp(object.timeCreated)
    ?? extractTimestamp(object.timeExpires)
    ?? extractTimestamp(object.timeLastUsed)
    ?? extractTimestamp(object.timeUpdated)
    ?? extractTimestamp(object.createdTime)
  );
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function finding(
  id: string,
  title: string,
  severity: OciFinding["severity"],
  status: OciFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): OciFinding {
  return { id, title, severity, status, summary, evidence, mappings };
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "oci";
}

function ensurePrivateDir(pathname: string): void {
  mkdirSync(pathname, { recursive: true, mode: 0o700 });
  const realPath = realpathSync(pathname);
  const stat = lstatSync(realPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Refusing to use non-directory or symlink path: ${pathname}`);
  }
}

export function resolveSecureOutputPath(baseDir: string, targetDir: string): string {
  ensurePrivateDir(baseDir);
  const realBase = realpathSync(baseDir);
  const resolvedTarget = resolve(realBase, targetDir);
  const relativeTarget = relative(realBase, resolvedTarget);
  if (
    relativeTarget === ".."
    || relativeTarget.startsWith(`..${join("/")}`)
    || relativeTarget.startsWith("..")
  ) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
  }

  const pathSegments = relativeTarget.split(/[\\/]+/).filter(Boolean);
  let currentPath = realBase;
  for (const segment of pathSegments) {
    currentPath = join(currentPath, segment);
    if (!existsSync(currentPath)) break;
    const currentStat = lstatSync(currentPath);
    if (currentStat.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked parent directory: ${currentPath}`);
    }
  }

  const parent = dirname(resolvedTarget);
  ensurePrivateDir(parent);
  const realParent = realpathSync(parent);
  if (lstatSync(realParent).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }
  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return candidate;
    }
  }
  throw new Error(`Unable to allocate output directory under ${root}`);
}

async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, content, { encoding: "utf8", mode: 0o600 });
}

async function createZipArchive(sourceDir: string, zipPath: string): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const output = createWriteStream(zipPath, { mode: 0o600 });
    const archive = archiver("zip", { zlib: { level: 9 } });

    output.on("close", () => resolvePromise());
    output.on("error", rejectPromise);
    archive.on("error", rejectPromise);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    void archive.finalize();
  });
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    if (entry.isDirectory()) count += await countFilesRecursively(fullPath);
    else count += 1;
  }
  return count;
}

function defaultCommandRunner(args: string[]): string {
  return execFileSync("oci", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: DEFAULT_COMMAND_TIMEOUT_MS,
  }).trim();
}

function parseIniSections(contents: string): Record<string, Record<string, string>> {
  const sections: Record<string, Record<string, string>> = {};
  let currentSection = "";
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      sections[currentSection] = sections[currentSection] ?? {};
      continue;
    }
    const eq = line.indexOf("=");
    if (eq === -1 || !currentSection) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    sections[currentSection] = sections[currentSection] ?? {};
    sections[currentSection][key] = value;
  }
  return sections;
}

function expandHome(pathname: string, env: NodeJS.ProcessEnv): string {
  if (pathname.startsWith("~/")) {
    const home = env.HOME ?? env.USERPROFILE;
    return home ? resolve(home, pathname.slice(2)) : pathname;
  }
  return pathname;
}

export function resolveOciConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  configLoader: (pathname: string) => string | undefined = (pathname) => {
    try {
      return readFileSync(pathname, "utf8");
    } catch {
      return undefined;
    }
  },
): OciResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = expandHome(
    asString(input.config_file)
      ?? asString(env.OCI_CONFIG_FILE)
      ?? "~/.oci/config",
    env,
  );
  if (asString(input.config_file)) sourceChain.push("arguments-config-file");
  else if (asString(env.OCI_CONFIG_FILE)) sourceChain.push("environment-config-file");
  else sourceChain.push("default-config-file");

  const profile = asString(input.profile)
    ?? asString(env.OCI_CLI_PROFILE)
    ?? DEFAULT_PROFILE;
  if (asString(input.profile)) sourceChain.push("arguments-profile");
  else if (asString(env.OCI_CLI_PROFILE)) sourceChain.push("environment-profile");
  else sourceChain.push("default-profile");

  const configText = configLoader(configFile);
  const section = configText ? parseIniSections(configText)[profile] ?? {} : {};

  const region = asString(input.region)
    ?? asString(env.OCI_REGION)
    ?? section.region
    ?? DEFAULT_REGION;
  if (asString(input.region)) sourceChain.push("arguments-region");
  else if (asString(env.OCI_REGION)) sourceChain.push("environment-region");
  else if (section.region) sourceChain.push("config-region");
  else sourceChain.push("default-region");

  const tenancyOcid = asString(input.tenancy_ocid)
    ?? asString(env.OCI_TENANCY_OCID)
    ?? section.tenancy;
  if (!tenancyOcid) {
    throw new Error(`Unable to resolve OCI tenancy OCID from arguments, environment, or ${configFile} profile ${profile}.`);
  }
  if (asString(input.tenancy_ocid)) sourceChain.push("arguments-tenancy");
  else if (asString(env.OCI_TENANCY_OCID)) sourceChain.push("environment-tenancy");
  else sourceChain.push("config-tenancy");

  const compartmentOcid = asString(input.compartment_ocid)
    ?? asString(env.OCI_COMPARTMENT_OCID)
    ?? tenancyOcid;
  if (asString(input.compartment_ocid)) sourceChain.push("arguments-compartment");
  else if (asString(env.OCI_COMPARTMENT_OCID)) sourceChain.push("environment-compartment");
  else sourceChain.push("default-compartment-tenancy");

  return {
    configFile,
    profile,
    region,
    tenancyOcid,
    compartmentOcid,
    sourceChain: [...new Set(sourceChain)],
  };
}

function describeSourceChain(config: OciResolvedConfig): string {
  return `OCI profile ${config.profile} in ${config.region}`;
}

function normalizeStatementText(statement: unknown): string {
  return asString(statement)?.toLowerCase() ?? "";
}

function isBroadPolicy(statement: string): boolean {
  return statement.includes("manage all-resources")
    || (statement.includes("manage") && statement.includes(" in tenancy"))
    || statement.includes("all-resources in tenancy");
}

function flattenListResponse(payload: JsonRecord): JsonRecord[] {
  const data = payload.data;
  if (Array.isArray(data)) {
    return data.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  const object = asObject(data);
  return object ? [object] : [];
}

function includesAnySensitivePort(values: unknown): boolean {
  for (const item of asArray(values)) {
    const numeric = asNumber(item);
    if (numeric !== undefined && SENSITIVE_PORTS.has(numeric)) return true;
  }
  return false;
}

function cidrIsWorld(value: unknown): boolean {
  const text = asString(value);
  return text === "0.0.0.0/0" || text === "::/0";
}

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<OciAccessSurface> {
  try {
    const value = await load();
    return {
      name,
      service,
      status: "readable",
      count: countResolver?.(value),
    };
  } catch (error) {
    return {
      name,
      service,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export class OciAuditorClient {
  private readonly now: () => Date;

  constructor(
    private readonly config: OciResolvedConfig,
    private readonly commandRunner: OciCommandRunner = defaultCommandRunner,
    options: { now?: () => Date } = {},
  ) {
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): OciResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private buildBaseArgs(): string[] {
    return [
      "--config-file",
      this.config.configFile,
      "--profile",
      this.config.profile,
      "--region",
      this.config.region,
      "--output",
      "json",
    ];
  }

  private runJson(args: string[]): JsonRecord {
    const output = this.commandRunner([...this.buildBaseArgs(), ...args]);
    return output.trim().length > 0 ? (JSON.parse(output) as JsonRecord) : {};
  }

  async listCompartments(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "compartment", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
      "--access-level", "ACCESSIBLE",
      "--include-root", "true",
    ]));
  }

  async listUsers(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "user", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
    ]));
  }

  async getAuthenticationPolicy(): Promise<JsonRecord | null> {
    return asObject(this.runJson([
      "iam", "authentication-policy", "get",
      "--compartment-id", this.config.tenancyOcid,
    ]).data) ?? null;
  }

  async listMfaTotpDevices(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "mfa-totp-device", "list",
      "--user-id", userOcid,
      "--all",
    ]));
  }

  async listApiKeys(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "user", "api-key", "list",
      "--user-id", userOcid,
      "--all",
    ]));
  }

  async listCustomerSecretKeys(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "customer-secret-key", "list",
      "--user-id", userOcid,
      "--all",
    ]));
  }

  async listAuthTokens(userOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "auth-token", "list",
      "--user-id", userOcid,
      "--all",
    ]));
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "iam", "policy", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
    ]));
  }

  async listCloudGuardTargets(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "target", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
    ]));
  }

  async listCloudGuardProblems(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "problem", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
    ]));
  }

  async listResponderRecipes(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "cloud-guard", "responder-recipe", "list",
      "--compartment-id", this.config.tenancyOcid,
      "--all",
    ]));
  }

  async listAuditEvents(lookbackDays = DEFAULT_LOOKBACK_DAYS): Promise<JsonRecord[]> {
    const end = this.getNow();
    const start = new Date(end.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
    return flattenListResponse(this.runJson([
      "audit", "event", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--start-time", start.toISOString(),
      "--end-time", end.toISOString(),
      "--all",
    ]));
  }

  async listEventRules(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "events", "rule", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
    ]));
  }

  async listSecurityLists(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "security-list", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
    ]));
  }

  async listNetworkSecurityGroups(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "nsg", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
    ]));
  }

  async listNetworkSecurityGroupRules(nsgOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "nsg", "rules", "list",
      "--network-security-group-id", nsgOcid,
      "--all",
    ]));
  }

  async listInternetGateways(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "network", "internet-gateway", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
      "--compartment-id-in-subtree", "true",
    ]));
  }

  async listBastions(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bastion", "bastion", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
    ]));
  }

  async listBastionSessions(bastionOcid: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "bastion", "session", "list",
      "--bastion-id", bastionOcid,
      "--all",
    ]));
  }

  async listVaults(): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "kms", "management", "vault", "list",
      "--compartment-id", this.config.compartmentOcid,
      "--all",
    ]));
  }

  async listKeys(vault: JsonRecord): Promise<JsonRecord[]> {
    const managementEndpoint =
      asString(vault.managementEndpoint) ??
      asString(vault["management-endpoint"]);
    const compartmentId = asString(vault.compartmentId) ?? this.config.compartmentOcid;
    if (!managementEndpoint) return [];
    return flattenListResponse(this.runJson([
      "kms", "management", "key", "list",
      "--management-endpoint", managementEndpoint,
      "--compartment-id", compartmentId,
      "--all",
    ]));
  }

  async getObjectStorageNamespace(): Promise<string> {
    const response = this.runJson(["os", "ns", "get"]);
    return asString(response.data) ?? asString(response.namespace) ?? "";
  }

  async listBuckets(namespaceName: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "os", "bucket", "list",
      "--namespace-name", namespaceName,
      "--compartment-id", this.config.compartmentOcid,
      "--all",
    ]));
  }

  async listPreauthenticatedRequests(namespaceName: string, bucketName: string): Promise<JsonRecord[]> {
    return flattenListResponse(this.runJson([
      "os", "preauth-request", "list",
      "--namespace-name", namespaceName,
      "--bucket-name", bucketName,
      "--all",
    ]));
  }
}

export async function checkOciAccess(
  client: Pick<
    OciAuditorClient,
    "getResolvedConfig" | "listCompartments" | "listUsers" | "getAuthenticationPolicy" | "listAuditEvents" | "listCloudGuardTargets" | "listSecurityLists" | "listVaults" | "getObjectStorageNamespace" | "listBuckets"
  >,
): Promise<OciAccessCheckResult> {
  const config = client.getResolvedConfig();
  const namespaceLoader = async () => {
    const namespace = await client.getObjectStorageNamespace();
    if (!namespace) throw new Error("Object Storage namespace was empty.");
    return client.listBuckets(namespace);
  };
  const surfaces = await Promise.all([
    surface("compartments", "iam", () => client.listCompartments(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("users", "iam", () => client.listUsers(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("authentication_policy", "iam", () => client.getAuthenticationPolicy(), () => 1),
    surface("audit_events", "audit", () => client.listAuditEvents(1), (value) => Array.isArray(value) ? value.length : undefined),
    surface("cloud_guard_targets", "cloud-guard", () => client.listCloudGuardTargets(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("security_lists", "network", () => client.listSecurityLists(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("vaults", "kms", () => client.listVaults(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("object_storage", "os", namespaceLoader, (value) => Array.isArray(value) ? value.length : undefined),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 5 ? "healthy" : "limited";
  const notes = [
    `Authenticated via ${describeSourceChain(config)}.`,
    `Using OCI config ${config.configFile} profile ${config.profile}.`,
    `${readableCount}/${surfaces.length} OCI audit surfaces are readable.`,
  ];

  return {
    status,
    tenancyOcid: config.tenancyOcid,
    compartmentOcid: config.compartmentOcid,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run oci_assess_identity, oci_assess_logging_detection, oci_assess_tenancy_guardrails, or oci_export_audit_bundle."
        : "Install and configure the OCI CLI profile or supply explicit tenancy/profile arguments with read-only inspect permissions.",
  };
}

export async function assessOciIdentity(
  client: Pick<
    OciAuditorClient,
    "getNow" | "getAuthenticationPolicy" | "listUsers" | "listMfaTotpDevices" | "listApiKeys" | "listCustomerSecretKeys" | "listAuthTokens" | "listPolicies" | "listCompartments"
  >,
  options: {
    staleDays?: number;
    maxKeys?: number;
    maxPolicies?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const now = client.getNow();
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const maxKeys = clampNumber(options.maxKeys, DEFAULT_MAX_KEYS, 1, 5000);
  const maxPolicies = clampNumber(options.maxPolicies, DEFAULT_MAX_POLICIES, 1, 5000);

  const [authPolicy, users, policies, compartments] = await Promise.all([
    client.getAuthenticationPolicy(),
    client.listUsers(),
    client.listPolicies(),
    client.listCompartments(),
  ]);

  const passwordPolicy = asObject(authPolicy?.passwordPolicy) ?? {};
  const minLength = asNumber(passwordPolicy.minimumPasswordLength) ?? 0;
  const expirationDays = asNumber(passwordPolicy.passwordExpiresAfterDays) ?? asNumber(passwordPolicy.passwordExpireAfterDays) ?? 0;
  const complexitySatisfied = [
    asBoolean(passwordPolicy.isLowerCaseCharactersRequired),
    asBoolean(passwordPolicy.isUpperCaseCharactersRequired),
    asBoolean(passwordPolicy.isNumericCharactersRequired),
    asBoolean(passwordPolicy.isSpecialCharactersRequired),
  ].every((item) => item === true);

  const consoleUsers = users.filter((user) => {
    const capabilities = asObject(user.capabilities);
    return capabilities?.canUseConsolePassword === true;
  });
  const usersWithoutMfa: string[] = [];
  const staleApiKeys: Array<{ user?: string; fingerprint?: string; ageDays?: number }> = [];
  const staleCustomerSecrets: Array<{ user?: string; id?: string; ageDays?: number }> = [];
  const staleAuthTokens: Array<{ user?: string; id?: string; ageDays?: number }> = [];
  let keyCounter = 0;

  for (const user of users) {
    const userOcid = asString(user.id);
    const userName = asString(user.name) ?? asString(user.description) ?? userOcid ?? "unknown";
    if (!userOcid) continue;
    const capabilities = asObject(user.capabilities);
    if (capabilities?.canUseConsolePassword === true) {
      const devices = await client.listMfaTotpDevices(userOcid);
      if (devices.length === 0) usersWithoutMfa.push(userName);
    }

    const loaders = [
      { items: await client.listApiKeys(userOcid), target: staleApiKeys, idKey: "fingerprint" },
      { items: await client.listCustomerSecretKeys(userOcid), target: staleCustomerSecrets, idKey: "id" },
      { items: await client.listAuthTokens(userOcid), target: staleAuthTokens, idKey: "id" },
    ] as const;
    for (const loader of loaders) {
      for (const item of loader.items) {
        if (keyCounter >= maxKeys) break;
        keyCounter += 1;
        const ageDays = daysBetween(now, extractTimestamp(item.timeCreated));
        if (ageDays !== undefined && ageDays > staleDays) {
          loader.target.push({
            user: userName,
            [loader.idKey]: asString(item[loader.idKey]),
            ageDays: Number(ageDays.toFixed(1)),
          });
        }
      }
    }
  }

  const broadPolicies = policies
    .slice(0, maxPolicies)
    .filter((policy) => asArray(policy.statements).some((statement) => isBroadPolicy(normalizeStatementText(statement))));
  const nonRootCompartments = compartments.filter((compartment) => asString(compartment.id) !== asString(compartment.compartmentId));
  const maxDepth = compartments.reduce((depth, compartment) => {
    const path = asString(compartment.name) ?? "";
    return Math.max(depth, path.split(":").length);
  }, 1);

  const findings = [
    finding(
      "OCI-IAM-01",
      "IAM password policy strength",
      "high",
      minLength >= 14 && complexitySatisfied && expirationDays > 0 && expirationDays <= 90 ? "pass" : "fail",
      `Minimum password length ${minLength}, complexity requirements present=${complexitySatisfied}, expiration=${expirationDays || "unset"} days.`,
      ["FedRAMP IA-5(1)", "CMMC 3.5.7", "SOC 2 CC6.1", "CIS OCI 1.1"],
      { password_policy: passwordPolicy },
    ),
    finding(
      "OCI-IAM-02",
      "Console MFA enforcement",
      "high",
      usersWithoutMfa.length === 0 ? "pass" : "fail",
      usersWithoutMfa.length === 0
        ? "All sampled OCI console users had TOTP MFA devices."
        : `${usersWithoutMfa.length}/${consoleUsers.length} sampled console users lacked MFA devices.`,
      ["FedRAMP IA-2(1)", "FedRAMP IA-2(2)", "CMMC 3.5.3", "CIS OCI 1.2"],
      { console_users: consoleUsers.length, users_without_mfa: usersWithoutMfa.slice(0, 25) },
    ),
    finding(
      "OCI-IAM-03",
      "API and secret key rotation",
      "high",
      staleApiKeys.length + staleCustomerSecrets.length + staleAuthTokens.length === 0 ? "pass" : "fail",
      staleApiKeys.length + staleCustomerSecrets.length + staleAuthTokens.length === 0
        ? `No sampled API keys, customer secret keys, or auth tokens exceeded the ${staleDays}-day threshold.`
        : `${staleApiKeys.length + staleCustomerSecrets.length + staleAuthTokens.length} sampled API or secret credentials exceeded the ${staleDays}-day threshold.`,
      ["FedRAMP IA-5(1)", "FedRAMP AC-2(3)", "CMMC 3.5.8", "CIS OCI 1.3"],
      {
        stale_api_keys: staleApiKeys.slice(0, 25),
        stale_customer_secret_keys: staleCustomerSecrets.slice(0, 25),
        stale_auth_tokens: staleAuthTokens.slice(0, 25),
      },
    ),
    finding(
      "OCI-IAM-04",
      "Broad IAM policies",
      "high",
      broadPolicies.length === 0 ? "pass" : "warn",
      broadPolicies.length === 0
        ? "No sampled policies contained obviously broad manage-all-resources statements."
        : `${broadPolicies.length} sampled policies contained broad tenancy-wide manage statements.`,
      ["FedRAMP AC-3", "FedRAMP AC-6", "CMMC 3.1.5", "CIS OCI 1.4"],
      { broad_policies: broadPolicies.slice(0, 25).map((policy) => ({ name: policy.name, statements: policy.statements })) },
    ),
    finding(
      "OCI-IAM-05",
      "Compartment hierarchy depth",
      "medium",
      nonRootCompartments.length > 0 && maxDepth >= 2 ? "pass" : "warn",
      nonRootCompartments.length > 0 && maxDepth >= 2
        ? `The tenancy exposed ${nonRootCompartments.length} non-root compartments with maximum observed depth ${maxDepth}.`
        : "The tenancy appeared flat or lacked non-root compartment hierarchy in the sampled data.",
      ["FedRAMP CA-3", "FedRAMP CM-2", "CMMC 3.12.1", "CIS OCI 1.5"],
      { non_root_compartments: nonRootCompartments.length, max_depth: maxDepth },
    ),
  ];

  return {
    title: "OCI identity posture",
    summary: {
      console_users: consoleUsers.length,
      users_without_mfa: usersWithoutMfa.length,
      stale_api_keys: staleApiKeys.length,
      stale_customer_secret_keys: staleCustomerSecrets.length,
      stale_auth_tokens: staleAuthTokens.length,
      broad_policies: broadPolicies.length,
      non_root_compartments: nonRootCompartments.length,
      max_compartment_depth: maxDepth,
    },
    findings,
  };
}

export async function assessOciLoggingDetection(
  client: Pick<
    OciAuditorClient,
    "listCloudGuardTargets" | "listCloudGuardProblems" | "listResponderRecipes" | "listAuditEvents" | "listEventRules"
  >,
  options: {
    lookbackDays?: number;
  } = {},
): Promise<OciAssessmentResult> {
  const lookbackDays = clampNumber(options.lookbackDays, DEFAULT_LOOKBACK_DAYS, 1, 90);
  const [targets, problems, responderRecipes, auditEvents, eventRules] = await Promise.all([
    client.listCloudGuardTargets(),
    client.listCloudGuardProblems(),
    client.listResponderRecipes(),
    client.listAuditEvents(lookbackDays),
    client.listEventRules(),
  ]);

  const activeTargets = targets.filter((target) => asString(target.lifecycleState)?.toUpperCase() === "ACTIVE");
  const openProblems = problems.filter((problem) => {
    const lifecycle = asString(problem.lifecycleState)?.toUpperCase();
    return lifecycle !== "RESOLVED" && lifecycle !== "CLOSED";
  });
  const highSeverityProblems = openProblems.filter((problem) => {
    const severity = asString(problem.severity)?.toUpperCase();
    return severity === "CRITICAL" || severity === "HIGH";
  });
  const activeResponders = responderRecipes.filter((recipe) => asString(recipe.lifecycleState)?.toUpperCase() === "ACTIVE");
  const criticalRules = eventRules.filter((rule) => {
    const condition = JSON.stringify(rule.condition ?? rule.actions ?? rule.displayName ?? "").toLowerCase();
    return condition.includes("policy") || condition.includes("network") || condition.includes("identity");
  });

  const findings = [
    finding(
      "OCI-LOG-01",
      "Cloud Guard target coverage",
      "high",
      activeTargets.length > 0 ? "pass" : "fail",
      activeTargets.length > 0
        ? `${activeTargets.length} Cloud Guard targets were active in the sampled scope.`
        : "No active Cloud Guard targets were visible in the sampled scope.",
      ["FedRAMP SI-4", "FedRAMP CA-7", "CMMC 3.14.6", "CIS OCI 2.1"],
      { active_targets: activeTargets.length, total_targets: targets.length },
    ),
    finding(
      "OCI-LOG-02",
      "Open Cloud Guard problems",
      "high",
      highSeverityProblems.length > 0 ? "fail" : openProblems.length > 0 ? "warn" : "pass",
      openProblems.length > 0
        ? `${openProblems.length} open Cloud Guard problems were visible, including ${highSeverityProblems.length} high or critical issues.`
        : "No open Cloud Guard problems were visible in the sampled scope.",
      ["FedRAMP RA-5", "FedRAMP SI-4", "CMMC 3.14.7", "CIS OCI 2.2"],
      { open_problems: openProblems.length, high_severity_problems: highSeverityProblems.length },
    ),
    finding(
      "OCI-LOG-03",
      "Responder recipe activation",
      "medium",
      activeResponders.length > 0 ? "pass" : "warn",
      activeResponders.length > 0
        ? `${activeResponders.length} Cloud Guard responder recipes were active.`
        : "No active Cloud Guard responder recipes were visible in the sampled scope.",
      ["FedRAMP IR-4", "FedRAMP SI-4", "SOC 2 CC7.3", "CIS OCI 2.3"],
      { active_responder_recipes: activeResponders.length, total_responder_recipes: responderRecipes.length },
    ),
    finding(
      "OCI-LOG-04",
      "Audit event visibility",
      "medium",
      auditEvents.length > 0 ? "pass" : "warn",
      auditEvents.length > 0
        ? `${auditEvents.length} audit events were visible over the last ${lookbackDays} days.`
        : `No audit events were visible over the last ${lookbackDays} days in the sampled compartment.`,
      ["FedRAMP AU-2", "FedRAMP AU-6", "CMMC 3.3.1", "CIS OCI 2.4"],
      { audit_events: auditEvents.length, lookback_days: lookbackDays },
    ),
    finding(
      "OCI-LOG-05",
      "Critical event rules",
      "medium",
      criticalRules.length > 0 ? "pass" : "warn",
      criticalRules.length > 0
        ? `${criticalRules.length} event rules appeared to target IAM, policy, or network change paths.`
        : "No obvious event rules targeting IAM, policy, or network changes were visible in the sampled scope.",
      ["FedRAMP AU-12", "FedRAMP SI-4", "SOC 2 CC7.2", "CIS OCI 2.5"],
      { critical_event_rules: criticalRules.length, total_event_rules: eventRules.length },
    ),
  ];

  return {
    title: "OCI logging and detection posture",
    summary: {
      active_cloud_guard_targets: activeTargets.length,
      open_cloud_guard_problems: openProblems.length,
      high_severity_cloud_guard_problems: highSeverityProblems.length,
      active_responder_recipes: activeResponders.length,
      audit_events: auditEvents.length,
      critical_event_rules: criticalRules.length,
    },
    findings,
  };
}

export async function assessOciTenancyGuardrails(
  client: Pick<
    OciAuditorClient,
    "getNow" | "listSecurityLists" | "listNetworkSecurityGroups" | "listNetworkSecurityGroupRules" | "listInternetGateways" | "listBastions" | "listBastionSessions" | "listVaults" | "listKeys" | "getObjectStorageNamespace" | "listBuckets" | "listPreauthenticatedRequests"
  >,
): Promise<OciAssessmentResult> {
  const now = client.getNow();
  const [securityLists, nsgs, internetGateways, bastions, vaults] = await Promise.all([
    client.listSecurityLists(),
    client.listNetworkSecurityGroups(),
    client.listInternetGateways(),
    client.listBastions(),
    client.listVaults(),
  ]);

  const permissiveSecurityLists = securityLists.filter((securityList) => {
    const ingressRules = asArray(securityList.ingressSecurityRules);
    return ingressRules.some((rule) => {
      const item = asObject(rule);
      const source = item?.source ?? item?.cidrBlock;
      const tcpOptions = asObject(item?.tcpOptions);
      const destinationPortRange = asObject(tcpOptions?.destinationPortRange);
      return cidrIsWorld(source) && includesAnySensitivePort(destinationPortRange && [
        destinationPortRange.min,
        destinationPortRange.max,
      ]);
    });
  });

  const permissiveNsgRules: Array<{ nsgId?: string; rule?: JsonRecord }> = [];
  for (const nsg of nsgs) {
    const nsgId = asString(nsg.id);
    if (!nsgId) continue;
    const rules = await client.listNetworkSecurityGroupRules(nsgId);
    for (const rule of rules) {
      const source = rule.source ?? rule.cidrBlock;
      const tcpOptions = asObject(rule.tcpOptions);
      const destinationPortRange = asObject(tcpOptions?.destinationPortRange);
      if (cidrIsWorld(source) && includesAnySensitivePort(destinationPortRange && [
        destinationPortRange.min,
        destinationPortRange.max,
      ])) {
        permissiveNsgRules.push({ nsgId, rule });
      }
    }
  }

  const weakBastions = bastions.filter((bastion) => {
    const ttl = asNumber(bastion.maxSessionTtlInSeconds) ?? 0;
    const clientCidr = asArray(bastion.clientCidrBlockAllowList);
    return ttl === 0 || ttl > 10_800 || clientCidr.length === 0;
  });
  const longRunningSessions: Array<{ bastionId?: string; sessionId?: string; ageHours?: number }> = [];
  for (const bastion of bastions) {
    const bastionId = asString(bastion.id);
    if (!bastionId) continue;
    const sessions = await client.listBastionSessions(bastionId);
    for (const session of sessions) {
      const ageHours = daysBetween(now, extractTimestamp(session.timeCreated));
      if (ageHours !== undefined && ageHours * 24 > 8) {
        longRunningSessions.push({
          bastionId,
          sessionId: asString(session.id),
          ageHours: Number((ageHours * 24).toFixed(1)),
        });
      }
    }
  }

  const weakKeys: Array<{ vault?: string; key?: string; algorithm?: string; daysSinceRotation?: number }> = [];
  for (const vault of vaults) {
    const keys = await client.listKeys(vault);
    for (const key of keys) {
      const keyShape = asObject(key.keyShape);
      const algorithm = asString(keyShape?.algorithm) ?? asString(key.algorithm);
      const rotationDays = daysBetween(now, extractTimestamp(key.timeOfCurrentVersionExpiry ?? key.timeCreated));
      if ((algorithm && !algorithm.includes("AES") && !algorithm.includes("RSA")) || (rotationDays !== undefined && rotationDays > 365)) {
        weakKeys.push({
          vault: asString(vault.displayName) ?? asString(vault.id),
          key: asString(key.displayName) ?? asString(key.id),
          algorithm,
          daysSinceRotation: rotationDays !== undefined ? Number(rotationDays.toFixed(1)) : undefined,
        });
      }
    }
  }

  let publicBuckets: string[] = [];
  let stalePars: Array<{ bucket?: string; id?: string; expires?: string | null }> = [];
  try {
    const namespace = await client.getObjectStorageNamespace();
    const buckets = await client.listBuckets(namespace);
    publicBuckets = buckets
      .filter((bucket) => {
        const access = asString(bucket.publicAccessType)?.toLowerCase();
        return access === "objectread" || access === "objectreadwithoutlist";
      })
      .map((bucket) => asString(bucket.name) ?? "unknown");
    for (const bucket of buckets) {
      const bucketName = asString(bucket.name);
      if (!bucketName) continue;
      const pars = await client.listPreauthenticatedRequests(namespace, bucketName);
      for (const par of pars) {
        const expires = extractTimestamp(par.timeExpires);
        const daysUntilExpiry = expires ? daysBetween(new Date(expires), now.toISOString()) : undefined;
        if (!expires || (daysUntilExpiry !== undefined && daysUntilExpiry > 30)) {
          stalePars.push({
            bucket: bucketName,
            id: asString(par.id),
            expires,
          });
        }
      }
    }
  } catch {
    // Object storage access can be absent without invalidating the whole assessment.
  }

  const findings = [
    finding(
      "OCI-GRD-01",
      "Security list ingress exposure",
      "high",
      permissiveSecurityLists.length > 0 ? "fail" : "pass",
      permissiveSecurityLists.length > 0
        ? `${permissiveSecurityLists.length} security lists exposed sensitive ports to the world.`
        : "No sampled security list exposed sensitive ports to the world.",
      ["FedRAMP SC-7", "FedRAMP AC-4", "CMMC 3.13.1", "CIS OCI 3.1"],
      { security_lists: permissiveSecurityLists.slice(0, 25).map((item) => item.id ?? item.displayName) },
    ),
    finding(
      "OCI-GRD-02",
      "Network security group ingress exposure",
      "high",
      permissiveNsgRules.length > 0 ? "fail" : "pass",
      permissiveNsgRules.length > 0
        ? `${permissiveNsgRules.length} NSG rules exposed sensitive ports to the world.`
        : "No sampled NSG rule exposed sensitive ports to the world.",
      ["FedRAMP SC-7", "FedRAMP AC-4", "CMMC 3.13.1", "CIS OCI 3.2"],
      { nsg_rules: permissiveNsgRules.slice(0, 25) },
    ),
    finding(
      "OCI-GRD-03",
      "Internet gateway exposure",
      "medium",
      internetGateways.length > 0 ? "warn" : "pass",
      internetGateways.length > 0
        ? `${internetGateways.length} internet gateways were visible; confirm attached subnets are tightly filtered.`
        : "No internet gateways were visible in the sampled compartment scope.",
      ["FedRAMP SC-7", "SOC 2 CC6.6", "CIS OCI 3.3", "CMMC 3.13.1"],
      { internet_gateways: internetGateways.length },
    ),
    finding(
      "OCI-GRD-04",
      "Bastion controls and active sessions",
      "medium",
      weakBastions.length > 0 || longRunningSessions.length > 0
        ? (longRunningSessions.length > 0 ? "fail" : "warn")
        : "pass",
      weakBastions.length > 0 || longRunningSessions.length > 0
        ? `${weakBastions.length} bastions had weak TTL/CIDR guardrails and ${longRunningSessions.length} sessions were long-running.`
        : "No sampled bastions had weak TTL/CIDR settings or long-running sessions.",
      ["FedRAMP AC-17", "FedRAMP IA-2", "SOC 2 CC6.6", "CIS OCI 3.4"],
      { weak_bastions: weakBastions.length, long_running_sessions: longRunningSessions.slice(0, 25) },
    ),
    finding(
      "OCI-GRD-05",
      "Vault key hygiene",
      "medium",
      weakKeys.length > 0 ? "warn" : "pass",
      weakKeys.length > 0
        ? `${weakKeys.length} vault keys appeared weak by algorithm or rotation age.`
        : "No sampled vault keys appeared weak by algorithm or rotation age.",
      ["FedRAMP SC-12", "FedRAMP SC-13", "CMMC 3.13.11", "CIS OCI 3.5"],
      { weak_keys: weakKeys.slice(0, 25) },
    ),
    finding(
      "OCI-GRD-06",
      "Object Storage public exposure",
      "high",
      publicBuckets.length > 0 || stalePars.length > 0
        ? (publicBuckets.length > 0 ? "fail" : "warn")
        : "pass",
      publicBuckets.length > 0 || stalePars.length > 0
        ? `${publicBuckets.length} buckets were public and ${stalePars.length} PARs were unbounded or long-lived.`
        : "No sampled public buckets or risky pre-authenticated requests were found.",
      ["FedRAMP AC-3", "FedRAMP SC-7", "PCI-DSS 7.2.1", "CIS OCI 3.6"],
      { public_buckets: publicBuckets.slice(0, 25), stale_pars: stalePars.slice(0, 25) },
    ),
  ];

  return {
    title: "OCI tenancy guardrails",
    summary: {
      permissive_security_lists: permissiveSecurityLists.length,
      permissive_nsg_rules: permissiveNsgRules.length,
      internet_gateways: internetGateways.length,
      weak_bastions: weakBastions.length,
      long_running_sessions: longRunningSessions.length,
      weak_vault_keys: weakKeys.length,
      public_buckets: publicBuckets.length,
      risky_pars: stalePars.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: OciAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `OCI access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: OciAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
  ].join("\n");
}

function buildExecutiveSummary(config: OciResolvedConfig, assessments: OciAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# OCI Audit Bundle",
    "",
    `Region: ${config.region}`,
    `Tenancy: ${config.tenancyOcid}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${failCount}`,
    `- Warning controls: ${warnCount}`,
    `- Passing controls: ${passCount}`,
    `- Critical-severity controls: ${criticalCount}`,
    `- High-severity controls: ${highCount}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status !== "pass")
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
  ].join("\n");
}

function buildControlMatrix(findings: OciFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# OCI Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# OCI Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native OCI tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible OCI audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "The OCI CLI is used for authenticated API transport, but credentials are not written to this bundle.",
  ].join("\n");
}

export async function exportOciAuditBundle(
  client: OciAuditorClient,
  config: OciResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<OciAuditBundleResult> {
  const access = await checkOciAccess(client);
  const identity = await assessOciIdentity(client, {
    staleDays: options.stale_days,
    maxKeys: options.max_keys,
    maxPolicies: options.max_policies,
  });
  const loggingDetection = await assessOciLoggingDetection(client, {
    lookbackDays: options.lookback_days,
  });
  const tenancyGuardrails = await assessOciTenancyGuardrails(client);

  const assessments = [identity, loggingDetection, tenancyGuardrails];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${config.tenancyOcid}-${config.region}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    config_file: config.configFile,
    profile: config.profile,
    region: config.region,
    tenancy_ocid: config.tenancyOcid,
    compartment_ocid: config.compartmentOcid,
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      max_keys: options.max_keys ?? DEFAULT_MAX_KEYS,
      max_policies: options.max_policies ?? DEFAULT_MAX_POLICIES,
      lookback_days: options.lookback_days ?? DEFAULT_LOOKBACK_DAYS,
    },
  }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments));
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", buildControlMatrix(findings));
  await writeSecureTextFile(outputDir, "reports/identity.md", formatAssessmentText(identity));
  await writeSecureTextFile(outputDir, "reports/logging-detection.md", formatAssessmentText(loggingDetection));
  await writeSecureTextFile(outputDir, "reports/tenancy-guardrails.md", formatAssessmentText(tenancyGuardrails));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/logging-detection.json", serializeJson(loggingDetection));
  await writeSecureTextFile(outputDir, "analysis/tenancy-guardrails.json", serializeJson(tenancyGuardrails));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);
  return {
    outputDir,
    zipPath,
    fileCount,
    findingCount: findings.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    config_file: asString(value.config_file),
    profile: asString(value.profile),
    region: asString(value.region),
    tenancy_ocid: asString(value.tenancy_ocid),
    compartment_ocid: asString(value.compartment_ocid),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    stale_days: asNumber(value.stale_days),
    max_keys: asNumber(value.max_keys),
    max_policies: asNumber(value.max_policies),
  };
}

function normalizeLoggingArgs(args: unknown): LoggingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    lookback_days: asNumber(value.lookback_days),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    lookback_days: asNumber(value.lookback_days),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): OciAuditorClient {
  return new OciAuditorClient(resolveOciConfiguration(args));
}

const authParams = {
  config_file: Type.Optional(Type.String({ description: "OCI config file path. Defaults to OCI_CONFIG_FILE or ~/.oci/config." })),
  profile: Type.Optional(Type.String({ description: `OCI config profile. Defaults to OCI_CLI_PROFILE or ${DEFAULT_PROFILE}.` })),
  region: Type.Optional(Type.String({ description: `OCI region override. Defaults to OCI_REGION, config profile region, or ${DEFAULT_REGION}.` })),
  tenancy_ocid: Type.Optional(Type.String({ description: "Explicit OCI tenancy OCID. Defaults to OCI_TENANCY_OCID or config profile tenancy." })),
  compartment_ocid: Type.Optional(Type.String({ description: "Compartment OCID to scope resource inspection. Defaults to OCI_COMPARTMENT_OCID or the tenancy OCID." })),
};

export function registerOciTools(pi: any): void {
  pi.registerTool({
    name: "oci_check_access",
    label: "Check OCI audit access",
    description:
      "Validate OCI CLI-backed read-only access across IAM, Audit, Cloud Guard, Networking, Vault, and Object Storage surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkOciAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "oci_check_access", ...result });
      } catch (error) {
        return errorResult(
          `OCI access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oci_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_identity",
    label: "Assess OCI identity posture",
    description:
      "Assess OCI IAM posture across password policy strength, MFA coverage, API and secret credential rotation, broad policies, and compartment hierarchy depth.",
    parameters: Type.Object({
      ...authParams,
      stale_days: Type.Optional(Type.Number({ description: "Credential staleness threshold in days. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum API/secret credentials to inspect. Defaults to 200.", default: 200 })),
      max_policies: Type.Optional(Type.Number({ description: "Maximum IAM policies to inspect for broad statements. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessOciIdentity(createClient(args), {
          staleDays: args.stale_days,
          maxKeys: args.max_keys,
          maxPolicies: args.max_policies,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `OCI identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oci_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_logging_detection",
    label: "Assess OCI logging and detection",
    description:
      "Assess OCI Cloud Guard targets and problems, responder recipe activation, audit event visibility, and event rule coverage for critical tenancy changes.",
    parameters: Type.Object({
      ...authParams,
      lookback_days: Type.Optional(Type.Number({ description: "Audit event lookback window in days. Defaults to 7.", default: 7 })),
    }),
    prepareArguments: normalizeLoggingArgs,
    async execute(_toolCallId: string, args: LoggingArgs) {
      try {
        const result = await assessOciLoggingDetection(createClient(args), {
          lookbackDays: args.lookback_days,
        });
        return textResult(formatAssessmentText(result), { tool: "oci_assess_logging_detection", ...result });
      } catch (error) {
        return errorResult(
          `OCI logging and detection assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oci_assess_logging_detection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_assess_tenancy_guardrails",
    label: "Assess OCI tenancy guardrails",
    description:
      "Assess OCI network, bastion, vault, and object-storage guardrails, including sensitive-port exposure, bastion controls, vault key hygiene, and public bucket risk.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessOciTenancyGuardrails(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "oci_assess_tenancy_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `OCI tenancy guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oci_assess_tenancy_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oci_export_audit_bundle",
    label: "Export OCI audit bundle",
    description:
      "Export an OCI audit package with access checks, identity findings, logging and detection findings, tenancy guardrails, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      stale_days: Type.Optional(Type.Number({ description: "Credential staleness threshold in days. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum API/secret credentials to inspect. Defaults to 200.", default: 200 })),
      max_policies: Type.Optional(Type.Number({ description: "Maximum IAM policies to inspect for broad statements. Defaults to 500.", default: 500 })),
      lookback_days: Type.Optional(Type.Number({ description: "Audit event lookback window in days. Defaults to 7.", default: 7 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveOciConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportOciAuditBundle(new OciAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "OCI audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "oci_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `OCI audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oci_export_audit_bundle" },
        );
      }
    },
  });
}
