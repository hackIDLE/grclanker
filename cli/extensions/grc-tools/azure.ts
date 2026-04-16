/**
 * Azure GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the azure-sec-inspector spec.
 * The first slice stays read-only and focuses on Entra ID posture, monitoring
 * visibility, and subscription-level guardrails.
 */
import { execFileSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type FetchImpl = typeof fetch;
type AzureCommandRunner = (command: string, args: string[]) => string | undefined;

const DEFAULT_OUTPUT_DIR = "./export/azure";
const DEFAULT_MAX_ASSIGNMENTS = 500;
const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;

export interface AzureResolvedConfig {
  tenantId: string;
  subscriptionId: string;
  graphToken: string;
  managementToken: string;
  sourceChain: string[];
}

export interface AzureAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface AzureAccessCheckResult {
  status: "healthy" | "limited";
  tenantId: string;
  subscriptionId: string;
  surfaces: AzureAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface AzureFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface AzureAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: AzureFinding[];
}

export interface AzureAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  tenant_id?: string;
  subscription_id?: string;
  graph_token?: string;
  management_token?: string;
};

type SubscriptionArgs = CheckAccessArgs & {
  max_assignments?: number;
};

type ExportAuditBundleArgs = SubscriptionArgs & {
  output_dir?: string;
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
    extractTimestamp(object.endDateTime)
    ?? extractTimestamp(object.startDateTime)
    ?? extractTimestamp(object.createdDateTime)
    ?? extractTimestamp(object.lastUpdatedDateTime)
    ?? extractTimestamp(object.created)
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
  severity: AzureFinding["severity"],
  status: AzureFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): AzureFinding {
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
  return normalized || "azure";
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

function defaultCommandRunner(command: string, args: string[]): string | undefined {
  try {
    const output = execFileSync(command, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: DEFAULT_COMMAND_TIMEOUT_MS,
    });
    const trimmed = output.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  } catch {
    return undefined;
  }
}

export function resolveAzureConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  commandRunner: AzureCommandRunner = defaultCommandRunner,
): AzureResolvedConfig {
  const sourceChain: string[] = [];
  const tenantId = asString(input.tenant_id)
    ?? asString(env.AZURE_TENANT_ID)
    ?? commandRunner("az", ["account", "show", "--query", "tenantId", "-o", "tsv"]);
  if (asString(input.tenant_id)) sourceChain.push("arguments-tenant");
  else if (asString(env.AZURE_TENANT_ID)) sourceChain.push("environment-tenant");
  else if (tenantId) sourceChain.push("azure-cli-tenant");

  const subscriptionId = asString(input.subscription_id)
    ?? asString(env.AZURE_SUBSCRIPTION_ID)
    ?? commandRunner("az", ["account", "show", "--query", "id", "-o", "tsv"]);
  if (asString(input.subscription_id)) sourceChain.push("arguments-subscription");
  else if (asString(env.AZURE_SUBSCRIPTION_ID)) sourceChain.push("environment-subscription");
  else if (subscriptionId) sourceChain.push("azure-cli-subscription");

  const graphToken = asString(input.graph_token)
    ?? asString(env.AZURE_GRAPH_TOKEN)
    ?? commandRunner("az", [
      "account",
      "get-access-token",
      "--resource-type",
      "ms-graph",
      "--query",
      "accessToken",
      "-o",
      "tsv",
      ...(tenantId ? ["--tenant", tenantId] : []),
    ]);
  if (asString(input.graph_token)) sourceChain.push("arguments-graph-token");
  else if (asString(env.AZURE_GRAPH_TOKEN)) sourceChain.push("environment-graph-token");
  else if (graphToken) sourceChain.push("azure-cli-graph-token");

  const managementToken = asString(input.management_token)
    ?? asString(env.AZURE_MANAGEMENT_TOKEN)
    ?? asString(env.AZURE_ACCESS_TOKEN)
    ?? commandRunner("az", [
      "account",
      "get-access-token",
      "--resource",
      "https://management.azure.com/",
      "--query",
      "accessToken",
      "-o",
      "tsv",
      ...(tenantId ? ["--tenant", tenantId] : []),
      ...(subscriptionId ? ["--subscription", subscriptionId] : []),
    ]);
  if (asString(input.management_token)) sourceChain.push("arguments-management-token");
  else if (asString(env.AZURE_MANAGEMENT_TOKEN) || asString(env.AZURE_ACCESS_TOKEN)) {
    sourceChain.push("environment-management-token");
  } else if (managementToken) {
    sourceChain.push("azure-cli-management-token");
  }

  if (!tenantId) throw new Error("Unable to resolve an Azure tenant ID from arguments, environment, or az account show.");
  if (!subscriptionId) throw new Error("Unable to resolve an Azure subscription ID from arguments, environment, or az account show.");
  if (!graphToken) throw new Error("Unable to resolve a Microsoft Graph access token from arguments, environment, or az account get-access-token.");
  if (!managementToken) throw new Error("Unable to resolve an Azure management access token from arguments, environment, or az account get-access-token.");

  return {
    tenantId,
    subscriptionId,
    graphToken,
    managementToken,
    sourceChain: [...new Set(sourceChain)],
  };
}

function describeSourceChain(config: AzureResolvedConfig): string {
  return `Azure tenant ${config.tenantId} / subscription ${config.subscriptionId}`;
}

function normalizeRoleName(value: unknown): string | undefined {
  return asString(value)?.toLowerCase();
}

function isPrivilegedDirectoryRole(name?: string): boolean {
  return [
    "global administrator",
    "privileged role administrator",
    "security administrator",
    "conditional access administrator",
  ].includes(name ?? "");
}

function isOwnerRole(name?: string): boolean {
  return name === "owner";
}

function isContributorRole(name?: string): boolean {
  return name === "contributor";
}

function roleDefinitionIdTail(value: string | undefined): string | undefined {
  return value?.split("/").at(-1)?.toLowerCase();
}

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<AzureAccessSurface> {
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

export class AzureAuditorClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    private readonly config: AzureResolvedConfig,
    options: { fetchImpl?: FetchImpl; now?: () => Date } = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): AzureResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private async requestJson(url: string, token: string): Promise<JsonRecord> {
    const response = await this.fetchImpl(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`${response.status} ${response.statusText}${text ? `: ${text.slice(0, 160)}` : ""}`);
    }
    const text = await response.text();
    return text.trim().length > 0 ? (JSON.parse(text) as JsonRecord) : {};
  }

  private async collectGraph(path: string, limit = 500): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = path.startsWith("http") ? path : `https://graph.microsoft.com${path}`;
    while (nextUrl && items.length < limit) {
      const response = await this.requestJson(nextUrl, this.config.graphToken);
      for (const item of asArray(response.value)) {
        const record = asObject(item);
        if (record) items.push(record);
      }
      nextUrl = asString(response["@odata.nextLink"]);
      if (items.length >= limit) break;
    }
    return items.slice(0, limit);
  }

  private async collectArm(path: string, limit = 500): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = path.startsWith("http") ? path : `https://management.azure.com${path}`;
    while (nextUrl && items.length < limit) {
      const response = await this.requestJson(nextUrl, this.config.managementToken);
      for (const item of asArray(response.value)) {
        const record = asObject(item);
        if (record) items.push(record);
      }
      nextUrl = asString(response.nextLink);
      if (items.length >= limit) break;
    }
    return items.slice(0, limit);
  }

  async getOrganization(): Promise<JsonRecord | null> {
    const items = await this.collectGraph("/v1.0/organization?$top=1", 1);
    return items[0] ?? null;
  }

  async listConditionalAccessPolicies(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/identity/conditionalAccess/policies?$top=100", 500);
  }

  async listUserRegistrationDetails(): Promise<JsonRecord[]> {
    return this.collectGraph("/beta/reports/authenticationMethods/userRegistrationDetails?$top=100", 1000);
  }

  async listDirectoryRoles(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/directoryRoles?$top=100", 200);
  }

  async listDirectoryRoleMembers(roleId: string): Promise<JsonRecord[]> {
    return this.collectGraph(`/v1.0/directoryRoles/${roleId}/members?$top=100`, 500);
  }

  async getSecurityDefaultsPolicy(): Promise<JsonRecord | null> {
    return this.requestJson(
      "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
      this.config.graphToken,
    );
  }

  async listServicePrincipals(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/servicePrincipals?$top=100&$select=id,displayName,appId,passwordCredentials,keyCredentials", 1000);
  }

  async listSecureScores(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/security/secureScores?$top=20", 50);
  }

  async listSecurityAlerts(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/security/alerts_v2?$top=50", 200);
  }

  async listDirectoryAudits(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/auditLogs/directoryAudits?$top=50", 200);
  }

  async listSignIns(): Promise<JsonRecord[]> {
    return this.collectGraph("/v1.0/auditLogs/signIns?$top=50", 200);
  }

  async getSubscription(): Promise<JsonRecord | null> {
    return this.requestJson(
      `https://management.azure.com/subscriptions/${this.config.subscriptionId}?api-version=2020-01-01`,
      this.config.managementToken,
    );
  }

  async listDefenderPricings(): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Security/pricings?api-version=2024-01-01`,
      200,
    );
  }

  async listDiagnosticSettings(): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview`,
      200,
    );
  }

  async listSecurityContacts(): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview`,
      50,
    );
  }

  async listRoleAssignments(limit = DEFAULT_MAX_ASSIGNMENTS): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`,
      limit,
    );
  }

  async listRoleDefinitions(): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=atScopeAndBelow()`,
      1000,
    );
  }

  async listNetworkWatchers(): Promise<JsonRecord[]> {
    return this.collectArm(
      `/subscriptions/${this.config.subscriptionId}/providers/Microsoft.Network/networkWatchers?api-version=2024-05-01`,
      200,
    );
  }
}

export async function checkAzureAccess(
  client: Pick<
    AzureAuditorClient,
    "getResolvedConfig" | "getOrganization" | "listConditionalAccessPolicies" | "listDirectoryRoles" | "listSecureScores" | "listDefenderPricings" | "listRoleAssignments" | "listDiagnosticSettings" | "listSecurityContacts"
  >,
): Promise<AzureAccessCheckResult> {
  const config = client.getResolvedConfig();
  const surfaces = await Promise.all([
    surface("organization", "graph", () => client.getOrganization(), () => 1),
    surface("conditional_access", "graph", () => client.listConditionalAccessPolicies(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("directory_roles", "graph", () => client.listDirectoryRoles(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("secure_scores", "graph", () => client.listSecureScores(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("defender_pricings", "arm", () => client.listDefenderPricings(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("role_assignments", "arm", () => client.listRoleAssignments(25), (value) => Array.isArray(value) ? value.length : undefined),
    surface("diagnostic_settings", "arm", () => client.listDiagnosticSettings(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("security_contacts", "arm", () => client.listSecurityContacts(), (value) => Array.isArray(value) ? value.length : undefined),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 6 ? "healthy" : "limited";
  const notes = [
    `Authenticated against ${describeSourceChain(config)}.`,
    `${readableCount}/${surfaces.length} Azure audit surfaces are readable.`,
  ];

  return {
    status,
    tenantId: config.tenantId,
    subscriptionId: config.subscriptionId,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run azure_assess_identity, azure_assess_monitoring, azure_assess_subscription_guardrails, or azure_export_audit_bundle."
        : "Grant Microsoft Graph read permissions and Azure Reader/Security Reader roles for the audit principal.",
  };
}

export async function assessAzureIdentity(
  client: Pick<
    AzureAuditorClient,
    "getNow" | "listConditionalAccessPolicies" | "listUserRegistrationDetails" | "listDirectoryRoles" | "listDirectoryRoleMembers" | "getSecurityDefaultsPolicy" | "listServicePrincipals"
  >,
): Promise<AzureAssessmentResult> {
  const now = client.getNow();
  const [policies, registrations, roles, securityDefaults, servicePrincipals] = await Promise.all([
    client.listConditionalAccessPolicies(),
    client.listUserRegistrationDetails(),
    client.listDirectoryRoles(),
    client.getSecurityDefaultsPolicy(),
    client.listServicePrincipals(),
  ]);

  const enabledPolicies = policies.filter((policy) => asString(policy.state)?.toLowerCase() === "enabled");
  const mfaPolicies = enabledPolicies.filter((policy) => {
    const grantControls = asObject(policy.grantControls);
    const builtInControls = asArray(grantControls?.builtInControls).map((value) => asString(value)?.toLowerCase()).filter(Boolean);
    return builtInControls.includes("mfa");
  });
  const legacyAuthPolicies = enabledPolicies.filter((policy) => {
    const displayName = asString(policy.displayName)?.toLowerCase() ?? "";
    const conditions = asObject(policy.conditions);
    const clientAppTypes = asArray(conditions?.clientAppTypes).map((value) => asString(value)?.toLowerCase()).filter(Boolean);
    return displayName.includes("legacy") || clientAppTypes.includes("exchangeactivesync") || clientAppTypes.includes("other");
  });

  let privilegedAssignments = 0;
  let globalAdmins = 0;
  for (const role of roles) {
    const name = normalizeRoleName(role.displayName);
    const roleId = asString(role.id);
    if (!roleId || !isPrivilegedDirectoryRole(name)) continue;
    const members = await client.listDirectoryRoleMembers(roleId);
    privilegedAssignments += members.length;
    if (name === "global administrator") globalAdmins += members.length;
  }

  const usersWithoutMfa = registrations.filter((item) => item.isMfaRegistered !== true);
  const mfaGapRatio = registrations.length > 0 ? usersWithoutMfa.length / registrations.length : 1;
  const securityDefaultsEnabled = securityDefaults?.isEnabled === true;

  const expiringCredentials: Array<{ servicePrincipal?: string; credentialType: string; endDateTime?: string; daysRemaining?: number }> = [];
  for (const principal of servicePrincipals) {
    const displayName = asString(principal.displayName);
    for (const credential of [
      ...asArray(principal.passwordCredentials),
      ...asArray(principal.keyCredentials),
    ]) {
      const item = asObject(credential);
      const endDateTime = extractTimestamp(item?.endDateTime);
      const daysRemaining = endDateTime
        ? (new Date(endDateTime).getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
        : undefined;
      if (daysRemaining !== undefined && daysRemaining <= 30) {
        expiringCredentials.push({
          servicePrincipal: displayName,
          credentialType: asArray(principal.passwordCredentials).includes(credential) ? "password" : "key",
          endDateTime,
          daysRemaining: Number(daysRemaining.toFixed(1)),
        });
      }
    }
  }

  const findings = [
    finding(
      "AZURE-ID-01",
      "Conditional Access MFA baseline",
      "high",
      mfaPolicies.length > 0 || securityDefaultsEnabled ? "pass" : "fail",
      mfaPolicies.length > 0 || securityDefaultsEnabled
        ? `Strong authentication baseline is present via ${mfaPolicies.length} MFA-focused Conditional Access policies${securityDefaultsEnabled ? " and security defaults" : ""}.`
        : "No MFA-focused Conditional Access policy or security defaults baseline was visible.",
      ["FedRAMP IA-2", "FedRAMP IA-2(1)", "CMMC 3.5.3", "CIS Azure 1.1"],
      { enabled_policies: enabledPolicies.length, mfa_policies: mfaPolicies.length, security_defaults_enabled: securityDefaultsEnabled },
    ),
    finding(
      "AZURE-ID-02",
      "Legacy authentication blocking",
      "high",
      legacyAuthPolicies.length > 0 || securityDefaultsEnabled ? "pass" : "warn",
      legacyAuthPolicies.length > 0 || securityDefaultsEnabled
        ? `Legacy authentication controls were visible via ${legacyAuthPolicies.length} Conditional Access policies${securityDefaultsEnabled ? " and security defaults" : ""}.`
        : "No obvious Conditional Access control targeting legacy authentication was visible.",
      ["FedRAMP AC-7", "FedRAMP IA-2", "CMMC 3.5.3", "CIS Azure 1.2"],
      { legacy_auth_policies: legacyAuthPolicies.length, security_defaults_enabled: securityDefaultsEnabled },
    ),
    finding(
      "AZURE-ID-03",
      "MFA registration coverage",
      "high",
      usersWithoutMfa.length === 0 ? "pass" : mfaGapRatio <= 0.1 ? "warn" : "fail",
      usersWithoutMfa.length === 0
        ? "All sampled users were registered for MFA."
        : `${usersWithoutMfa.length}/${registrations.length} sampled users were not registered for MFA.`,
      ["FedRAMP IA-2(1)", "FedRAMP IA-5", "CMMC 3.5.3", "PCI-DSS 8.4.2"],
      { sampled_users: registrations.length, users_without_mfa: usersWithoutMfa.length },
    ),
    finding(
      "AZURE-ID-04",
      "Privileged directory role sprawl",
      "high",
      globalAdmins > 4 || privilegedAssignments > 10 ? "fail" : privilegedAssignments > 0 ? "warn" : "pass",
      privilegedAssignments > 0
        ? `The sampled tenant exposed ${globalAdmins} Global Administrators and ${privilegedAssignments} privileged role assignments.`
        : "No sampled privileged directory role assignments were returned.",
      ["FedRAMP AC-2", "FedRAMP AC-6", "CMMC 3.1.5", "CIS Azure 1.4"],
      { global_administrators: globalAdmins, privileged_role_assignments: privilegedAssignments },
    ),
    finding(
      "AZURE-ID-05",
      "Service principal credential hygiene",
      "medium",
      expiringCredentials.length === 0 ? "pass" : "warn",
      expiringCredentials.length === 0
        ? "No sampled service principal credentials were expired or expiring within 30 days."
        : `${expiringCredentials.length} sampled service principal credentials were expired or expiring within 30 days.`,
      ["FedRAMP IA-5(1)", "SOC 2 CC6.1", "CIS Azure 1.6", "PCI-DSS 8.6.3"],
      { expiring_credentials: expiringCredentials.slice(0, 25) },
    ),
  ];

  return {
    title: "Azure identity posture",
    summary: {
      enabled_conditional_access_policies: enabledPolicies.length,
      mfa_conditional_access_policies: mfaPolicies.length,
      legacy_auth_policies: legacyAuthPolicies.length,
      sampled_users: registrations.length,
      users_without_mfa: usersWithoutMfa.length,
      global_administrators: globalAdmins,
      privileged_role_assignments: privilegedAssignments,
      expiring_service_principal_credentials: expiringCredentials.length,
      security_defaults_enabled: securityDefaultsEnabled,
    },
    findings,
  };
}

export async function assessAzureMonitoring(
  client: Pick<
    AzureAuditorClient,
    "listSecureScores" | "listSecurityAlerts" | "listDirectoryAudits" | "listSignIns" | "listDefenderPricings" | "listDiagnosticSettings"
  >,
): Promise<AzureAssessmentResult> {
  const [secureScores, alerts, audits, signIns, defenderPricings, diagnosticSettings] = await Promise.all([
    client.listSecureScores(),
    client.listSecurityAlerts(),
    client.listDirectoryAudits(),
    client.listSignIns(),
    client.listDefenderPricings(),
    client.listDiagnosticSettings(),
  ]);

  const currentScore = secureScores[0];
  const currentScoreValue = asNumber(currentScore?.currentScore) ?? 0;
  const maxScoreValue = asNumber(currentScore?.maxScore) ?? 0;
  const secureScoreRatio = maxScoreValue > 0 ? currentScoreValue / maxScoreValue : 0;
  const enabledDefenderPlans = defenderPricings.filter((item) => asString(asObject(item.properties)?.pricingTier)?.toLowerCase() === "standard");
  const requiredDefenderPlans = defenderPricings.length;

  const findings = [
    finding(
      "AZURE-MON-01",
      "Secure Score posture",
      "medium",
      secureScoreRatio >= 0.75 ? "pass" : secureScoreRatio >= 0.5 ? "warn" : "fail",
      maxScoreValue > 0
        ? `Current Secure Score is ${currentScoreValue}/${maxScoreValue} (${Math.round(secureScoreRatio * 100)}%).`
        : "Secure Score data was not visible for the tenant.",
      ["FedRAMP CA-7", "SOC 2 CC7.2", "CIS Azure 2.1", "CMMC 3.12.1"],
      { current_score: currentScoreValue, max_score: maxScoreValue, ratio: Number(secureScoreRatio.toFixed(2)) },
    ),
    finding(
      "AZURE-MON-02",
      "Directory audit visibility",
      "medium",
      audits.length > 0 ? "pass" : "warn",
      audits.length > 0
        ? `${audits.length} recent directory audit events were visible in the sampled window.`
        : "No directory audit events were returned in the sampled window.",
      ["FedRAMP AU-2", "FedRAMP AU-6", "CMMC 3.3.1", "CIS Azure 2.2"],
      { directory_audits: audits.length },
    ),
    finding(
      "AZURE-MON-03",
      "Sign-in telemetry visibility",
      "medium",
      signIns.length > 0 ? "pass" : "warn",
      signIns.length > 0
        ? `${signIns.length} recent sign-in events were visible in the sampled window.`
        : "No sign-in events were returned in the sampled window.",
      ["FedRAMP AU-12", "FedRAMP SI-4", "CMMC 3.3.1", "CIS Azure 2.3"],
      { sign_ins: signIns.length },
    ),
    finding(
      "AZURE-MON-04",
      "Defender for Cloud plan coverage",
      "high",
      enabledDefenderPlans.length === requiredDefenderPlans && requiredDefenderPlans > 0
        ? "pass"
        : enabledDefenderPlans.length > 0
          ? "warn"
          : "fail",
      requiredDefenderPlans > 0
        ? `${enabledDefenderPlans.length}/${requiredDefenderPlans} Defender for Cloud plans were on the Standard tier.`
        : "No Defender pricing records were returned for the subscription.",
      ["FedRAMP SI-4", "FedRAMP RA-5", "CMMC 3.14.6", "CIS Azure 2.4"],
      { enabled_standard_plans: enabledDefenderPlans.length, total_plans: requiredDefenderPlans, alerts: alerts.length },
    ),
    finding(
      "AZURE-MON-05",
      "Subscription diagnostic settings",
      "high",
      diagnosticSettings.length > 0 ? "pass" : "fail",
      diagnosticSettings.length > 0
        ? `${diagnosticSettings.length} subscription diagnostic settings were visible.`
        : "No subscription diagnostic settings were visible.",
      ["FedRAMP AU-4", "FedRAMP AU-9", "SOC 2 CC7.2", "CIS Azure 2.5"],
      { diagnostic_settings: diagnosticSettings.length },
    ),
  ];

  return {
    title: "Azure monitoring posture",
    summary: {
      secure_score_ratio: Number(secureScoreRatio.toFixed(2)),
      directory_audits: audits.length,
      sign_ins: signIns.length,
      defender_standard_plans: enabledDefenderPlans.length,
      defender_total_plans: requiredDefenderPlans,
      security_alerts: alerts.length,
      diagnostic_settings: diagnosticSettings.length,
    },
    findings,
  };
}

export async function assessAzureSubscriptionGuardrails(
  client: Pick<
    AzureAuditorClient,
    "listRoleAssignments" | "listRoleDefinitions" | "listSecurityContacts" | "listNetworkWatchers"
  >,
  options: {
    maxAssignments?: number;
  } = {},
): Promise<AzureAssessmentResult> {
  const maxAssignments = clampNumber(options.maxAssignments, DEFAULT_MAX_ASSIGNMENTS, 1, 5000);
  const [roleAssignments, roleDefinitions, securityContacts, networkWatchers] = await Promise.all([
    client.listRoleAssignments(maxAssignments),
    client.listRoleDefinitions(),
    client.listSecurityContacts(),
    client.listNetworkWatchers(),
  ]);

  const roleMap = new Map<string, string>();
  for (const definition of roleDefinitions) {
    const id = roleDefinitionIdTail(asString(definition.id));
    const name = normalizeRoleName(asObject(definition.properties)?.roleName ?? definition.roleName);
    if (id && name) roleMap.set(id, name);
  }

  const ownerAssignments: JsonRecord[] = [];
  const contributorAssignments: JsonRecord[] = [];
  const privilegedServicePrincipals: JsonRecord[] = [];

  for (const assignment of roleAssignments) {
    const properties = asObject(assignment.properties) ?? {};
    const roleName = roleMap.get(roleDefinitionIdTail(asString(properties.roleDefinitionId)) ?? "");
    const principalType = asString(properties.principalType)?.toLowerCase();
    if (isOwnerRole(roleName)) ownerAssignments.push(assignment);
    if (isContributorRole(roleName)) contributorAssignments.push(assignment);
    if ((isOwnerRole(roleName) || isContributorRole(roleName)) && principalType === "serviceprincipal") {
      privilegedServicePrincipals.push(assignment);
    }
  }

  const configuredContacts = securityContacts.filter((contact) => {
    const properties = asObject(contact.properties);
    return Boolean(asString(properties?.email) ?? asString(properties?.emails));
  });

  const findings = [
    finding(
      "AZURE-SUB-01",
      "Owner assignments at subscription scope",
      "high",
      ownerAssignments.length <= 2 ? (ownerAssignments.length > 0 ? "warn" : "pass") : "fail",
      ownerAssignments.length > 0
        ? `${ownerAssignments.length} Owner assignments were visible at subscription scope.`
        : "No Owner assignments were visible at subscription scope.",
      ["FedRAMP AC-2", "FedRAMP AC-6", "CMMC 3.1.5", "CIS Azure 3.1"],
      { owner_assignments: ownerAssignments.slice(0, 25) },
    ),
    finding(
      "AZURE-SUB-02",
      "Contributor assignments at subscription scope",
      "medium",
      contributorAssignments.length <= 5 ? (contributorAssignments.length > 0 ? "warn" : "pass") : "fail",
      contributorAssignments.length > 0
        ? `${contributorAssignments.length} Contributor assignments were visible at subscription scope.`
        : "No Contributor assignments were visible at subscription scope.",
      ["FedRAMP AC-6", "SOC 2 CC6.2", "CIS Azure 3.2", "CMMC 3.1.6"],
      { contributor_assignments: contributorAssignments.slice(0, 25) },
    ),
    finding(
      "AZURE-SUB-03",
      "Security contacts configured",
      "medium",
      configuredContacts.length > 0 ? "pass" : "fail",
      configuredContacts.length > 0
        ? `${configuredContacts.length} security contacts with email details were visible.`
        : "No Azure security contact with email details was visible.",
      ["FedRAMP IR-6", "FedRAMP CA-7", "CIS Azure 3.3", "CMMC 3.6.1"],
      { security_contacts: configuredContacts.length },
    ),
    finding(
      "AZURE-SUB-04",
      "Network Watcher coverage",
      "medium",
      networkWatchers.length > 0 ? "pass" : "warn",
      networkWatchers.length > 0
        ? `${networkWatchers.length} Network Watcher resources were visible across the subscription.`
        : "No Network Watcher resources were visible for the subscription.",
      ["FedRAMP AU-12", "FedRAMP SC-7", "CIS Azure 3.4", "SOC 2 CC7.2"],
      { network_watchers: networkWatchers.length },
    ),
    finding(
      "AZURE-SUB-05",
      "Privileged service principals at subscription scope",
      "high",
      privilegedServicePrincipals.length > 0 ? "fail" : "pass",
      privilegedServicePrincipals.length > 0
        ? `${privilegedServicePrincipals.length} service principals held Owner or Contributor at subscription scope.`
        : "No service principals held Owner or Contributor at subscription scope in the sampled assignments.",
      ["FedRAMP AC-6", "FedRAMP IA-5", "CMMC 3.1.5", "CIS Azure 3.5"],
      { privileged_service_principals: privilegedServicePrincipals.slice(0, 25) },
    ),
  ];

  return {
    title: "Azure subscription guardrails",
    summary: {
      owner_assignments: ownerAssignments.length,
      contributor_assignments: contributorAssignments.length,
      configured_security_contacts: configuredContacts.length,
      network_watchers: networkWatchers.length,
      privileged_service_principals: privilegedServicePrincipals.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: AzureAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Azure access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AzureAssessmentResult): string {
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

function buildExecutiveSummary(config: AzureResolvedConfig, assessments: AzureAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# Azure Audit Bundle",
    "",
    `Tenant: ${config.tenantId}`,
    `Subscription: ${config.subscriptionId}`,
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

function buildControlMatrix(findings: AzureFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Azure Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Azure Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Azure tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible Azure audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Resolved access tokens are not written to this bundle.",
  ].join("\n");
}

export async function exportAzureAuditBundle(
  client: AzureAuditorClient,
  config: AzureResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AzureAuditBundleResult> {
  const access = await checkAzureAccess(client);
  const identity = await assessAzureIdentity(client);
  const monitoring = await assessAzureMonitoring(client);
  const subscriptionGuardrails = await assessAzureSubscriptionGuardrails(client, {
    maxAssignments: options.max_assignments,
  });

  const assessments = [identity, monitoring, subscriptionGuardrails];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${config.tenantId}-${config.subscriptionId}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    tenant_id: config.tenantId,
    subscription_id: config.subscriptionId,
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      max_assignments: options.max_assignments ?? DEFAULT_MAX_ASSIGNMENTS,
    },
  }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments));
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", buildControlMatrix(findings));
  await writeSecureTextFile(outputDir, "reports/identity.md", formatAssessmentText(identity));
  await writeSecureTextFile(outputDir, "reports/monitoring.md", formatAssessmentText(monitoring));
  await writeSecureTextFile(outputDir, "reports/subscription-guardrails.md", formatAssessmentText(subscriptionGuardrails));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/monitoring.json", serializeJson(monitoring));
  await writeSecureTextFile(outputDir, "analysis/subscription-guardrails.json", serializeJson(subscriptionGuardrails));
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
    tenant_id: asString(value.tenant_id),
    subscription_id: asString(value.subscription_id),
    graph_token: asString(value.graph_token),
    management_token: asString(value.management_token),
  };
}

function normalizeSubscriptionArgs(args: unknown): SubscriptionArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_assignments: asNumber(value.max_assignments),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeSubscriptionArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): AzureAuditorClient {
  return new AzureAuditorClient(resolveAzureConfiguration(args));
}

const authParams = {
  tenant_id: Type.Optional(Type.String({ description: "Azure tenant ID. Defaults to AZURE_TENANT_ID or az account show." })),
  subscription_id: Type.Optional(Type.String({ description: "Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID or az account show." })),
  graph_token: Type.Optional(Type.String({ description: "Explicit Microsoft Graph bearer token. Defaults to AZURE_GRAPH_TOKEN or az account get-access-token." })),
  management_token: Type.Optional(Type.String({ description: "Explicit ARM bearer token. Defaults to AZURE_MANAGEMENT_TOKEN or az account get-access-token." })),
};

export function registerAzureTools(pi: any): void {
  pi.registerTool({
    name: "azure_check_access",
    label: "Check Azure audit access",
    description:
      "Validate read-only Azure audit access across Entra ID, Microsoft Graph security surfaces, and subscription-level ARM posture endpoints.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAzureAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "azure_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Azure access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_identity",
    label: "Assess Azure identity posture",
    description:
      "Assess Azure identity posture across Conditional Access, MFA registration, privileged directory roles, security defaults, and service principal credential hygiene.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessAzureIdentity(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "azure_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Azure identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_monitoring",
    label: "Assess Azure monitoring posture",
    description:
      "Assess Azure Secure Score, directory audit visibility, sign-in telemetry, Defender for Cloud plan coverage, and subscription diagnostic settings.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await assessAzureMonitoring(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "azure_assess_monitoring", ...result });
      } catch (error) {
        return errorResult(
          `Azure monitoring assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_assess_subscription_guardrails",
    label: "Assess Azure subscription guardrails",
    description:
      "Assess Azure subscription guardrails across RBAC sprawl, security contacts, Network Watcher coverage, and privileged service principals.",
    parameters: Type.Object({
      ...authParams,
      max_assignments: Type.Optional(Type.Number({ description: "Maximum ARM role assignments to sample. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeSubscriptionArgs,
    async execute(_toolCallId: string, args: SubscriptionArgs) {
      try {
        const result = await assessAzureSubscriptionGuardrails(createClient(args), {
          maxAssignments: args.max_assignments,
        });
        return textResult(formatAssessmentText(result), { tool: "azure_assess_subscription_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `Azure subscription guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_assess_subscription_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "azure_export_audit_bundle",
    label: "Export Azure audit bundle",
    description:
      "Export an Azure audit package with access checks, identity findings, monitoring findings, subscription guardrails, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_assignments: Type.Optional(Type.Number({ description: "Maximum ARM role assignments to sample. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAzureConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAzureAuditBundle(new AzureAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "Azure audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "azure_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Azure audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "azure_export_audit_bundle" },
        );
      }
    },
  });
}
