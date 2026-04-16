/**
 * GCP GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the gcp-sec-inspector spec.
 * The first slice stays read-only and focuses on IAM hygiene, audit and
 * detection coverage, plus organization-level guardrails.
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

const DEFAULT_OUTPUT_DIR = "./export/gcp";
const DEFAULT_MAX_PROJECTS = 20;
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_MAX_KEYS = 200;
const DEFAULT_MAX_FINDINGS = 200;
const DEFAULT_COMMAND_TIMEOUT_MS = 10_000;

export interface GcpResolvedConfig {
  organizationId?: string;
  projectId?: string;
  accessToken: string;
  sourceChain: string[];
}

export interface GcpAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface GcpAccessCheckResult {
  status: "healthy" | "limited";
  organizationId?: string;
  projectId?: string;
  surfaces: GcpAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface GcpFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface GcpAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: GcpFinding[];
}

export interface GcpAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type GcpCommandRunner = (command: string, args: string[]) => string | undefined;
type FetchImpl = typeof fetch;

type CheckAccessArgs = {
  organization_id?: string;
  project_id?: string;
  access_token?: string;
};

type IdentityArgs = CheckAccessArgs & {
  max_projects?: number;
  stale_days?: number;
  max_keys?: number;
};

type LoggingArgs = CheckAccessArgs & {
  max_projects?: number;
  max_findings?: number;
};

type OrgGuardrailArgs = CheckAccessArgs & {
  max_projects?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  max_projects?: number;
  stale_days?: number;
  max_keys?: number;
  max_findings?: number;
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
    extractTimestamp(object.validAfterTime)
    ?? extractTimestamp(object.createTime)
    ?? extractTimestamp(object.validBeforeTime)
    ?? extractTimestamp(object.updateTime)
    ?? extractTimestamp(object.timestamp)
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
  severity: GcpFinding["severity"],
  status: GcpFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): GcpFinding {
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
  return normalized || "gcp";
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

export function resolveGcpConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
  commandRunner: GcpCommandRunner = defaultCommandRunner,
): GcpResolvedConfig {
  const sourceChain: string[] = [];
  const organizationId = asString(input.organization_id) ?? asString(env.GCP_ORGANIZATION_ID);
  if (organizationId) {
    sourceChain.push(asString(input.organization_id) ? "arguments-organization" : "environment-organization");
  }

  const projectId = asString(input.project_id)
    ?? asString(env.GCP_PROJECT_ID)
    ?? asString(env.GOOGLE_CLOUD_PROJECT)
    ?? asString(env.GCLOUD_PROJECT);
  if (projectId) {
    sourceChain.push(asString(input.project_id) ? "arguments-project" : "environment-project");
  }

  const accessToken = asString(input.access_token)
    ?? asString(env.GCP_ACCESS_TOKEN)
    ?? asString(env.GOOGLE_OAUTH_ACCESS_TOKEN)
    ?? asString(env.GOOGLE_ACCESS_TOKEN)
    ?? commandRunner("gcloud", ["auth", "print-access-token"]);
  if (asString(input.access_token)) sourceChain.push("arguments-access-token");
  else if (asString(env.GCP_ACCESS_TOKEN) || asString(env.GOOGLE_OAUTH_ACCESS_TOKEN) || asString(env.GOOGLE_ACCESS_TOKEN)) {
    sourceChain.push("environment-access-token");
  } else if (accessToken) {
    sourceChain.push("gcloud-access-token");
  }

  if (!accessToken) {
    throw new Error("Unable to resolve a GCP access token from arguments, environment, or gcloud auth print-access-token.");
  }
  if (!organizationId && !projectId) {
    throw new Error("Set organization_id or project_id to scope the GCP audit.");
  }

  return {
    organizationId,
    projectId,
    accessToken,
    sourceChain: [...new Set(sourceChain)],
  };
}

function describeSourceChain(config: GcpResolvedConfig): string {
  if (config.organizationId) {
    return `GCP organization ${config.organizationId}${config.projectId ? ` with project hint ${config.projectId}` : ""}`;
  }
  return `GCP project ${config.projectId ?? "unknown"}`;
}

function inferRootScope(config: GcpResolvedConfig): string {
  if (config.organizationId) return `organizations/${config.organizationId}`;
  if (config.projectId) return `projects/${config.projectId}`;
  throw new Error("A GCP audit scope requires organizationId or projectId.");
}

function parseProjectId(resource: JsonRecord): string | undefined {
  return (
    asString(resource.projectId)
    ?? asString(resource.project)
    ?? asString(resource.projectDisplayName)
    ?? asString(resource.displayName)
    ?? asString(resource.name)?.split("/").at(-1)
  );
}

function parsePolicyBindings(value: unknown): JsonRecord[] {
  const policy = asObject(value);
  if (!policy) return [];
  return asArray(policy.bindings).map(asObject).filter((item): item is JsonRecord => Boolean(item));
}

function isOwnerLikeRole(role?: string): boolean {
  return [
    "roles/owner",
    "roles/editor",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
  ].includes(role ?? "");
}

function isDefaultServiceAccount(member: string): boolean {
  return /compute@developer\.gserviceaccount\.com$/.test(member)
    || /appspot\.gserviceaccount\.com$/.test(member)
    || /cloudbuild\.gserviceaccount\.com$/.test(member);
}

function normalizeMember(member: unknown): string | undefined {
  const value = asString(member);
  return value?.toLowerCase();
}

function interpretOrgPolicyEnabled(policyResponse: JsonRecord | null | undefined): boolean {
  if (!policyResponse) return false;
  const policy = asObject(policyResponse.policy) ?? policyResponse;
  if ((policy.restoreDefault as boolean | undefined) === true) return false;
  const booleanPolicy = asObject(policy.booleanPolicy);
  if (booleanPolicy && booleanPolicy.enforced === true) return true;
  const listPolicy = asObject(policy.listPolicy);
  return asArray(listPolicy?.allowedValues).length > 0 || asArray(listPolicy?.deniedValues).length > 0;
}

async function surface(
  name: string,
  service: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<GcpAccessSurface> {
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

export class GcpAuditorClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    private readonly config: GcpResolvedConfig,
    options: { fetchImpl?: FetchImpl; now?: () => Date } = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): GcpResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private async requestJson(
    url: string,
    init: {
      method?: string;
      body?: unknown;
    } = {},
  ): Promise<JsonRecord> {
    const response = await this.fetchImpl(url, {
      method: init.method ?? "GET",
      headers: {
        Authorization: `Bearer ${this.config.accessToken}`,
        "Content-Type": "application/json",
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`${response.status} ${response.statusText}${text ? `: ${text.slice(0, 160)}` : ""}`);
    }
    const text = await response.text();
    return text.trim().length > 0 ? (JSON.parse(text) as JsonRecord) : {};
  }

  async getOrganization(): Promise<JsonRecord | null> {
    if (!this.config.organizationId) return null;
    return this.requestJson(`https://cloudresourcemanager.googleapis.com/v1/organizations/${this.config.organizationId}`);
  }

  async getProject(projectId = this.config.projectId): Promise<JsonRecord | null> {
    if (!projectId) return null;
    return this.requestJson(`https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}`);
  }

  async listProjects(limit = DEFAULT_MAX_PROJECTS): Promise<JsonRecord[]> {
    if (!this.config.organizationId) {
      return this.config.projectId ? [{ projectId: this.config.projectId, name: this.config.projectId }] : [];
    }

    const resources: JsonRecord[] = [];
    let pageToken: string | undefined;
    const scope = `organizations/${this.config.organizationId}`;
    while (resources.length < limit) {
      const response = await this.requestJson(
        `https://cloudasset.googleapis.com/v1/${scope}:searchAllResources`,
        {
          method: "POST",
          body: {
            assetTypes: ["cloudresourcemanager.googleapis.com/Project"],
            pageSize: Math.min(100, limit - resources.length),
            pageToken,
          },
        },
      );
      for (const item of asArray(response.results)) {
        const resource = asObject(item);
        if (resource) resources.push(resource);
      }
      pageToken = asString(response.nextPageToken);
      if (!pageToken) break;
    }
    return resources;
  }

  async searchAllIamPolicies(limit = 200): Promise<JsonRecord[]> {
    const scope = inferRootScope(this.config);
    const results: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (results.length < limit) {
      const response = await this.requestJson(
        `https://cloudasset.googleapis.com/v1/${scope}:searchAllIamPolicies`,
        {
          method: "POST",
          body: {
            pageSize: Math.min(100, limit - results.length),
            pageToken,
          },
        },
      );
      for (const item of asArray(response.results)) {
        const record = asObject(item);
        if (record) results.push(record);
      }
      pageToken = asString(response.nextPageToken);
      if (!pageToken) break;
    }
    return results;
  }

  async listServiceAccounts(projectId: string): Promise<JsonRecord[]> {
    const accounts: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (true) {
      const response = await this.requestJson(
        `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts${pageToken ? `?pageToken=${encodeURIComponent(pageToken)}` : ""}`,
      );
      for (const item of asArray(response.accounts)) {
        const account = asObject(item);
        if (account) accounts.push(account);
      }
      pageToken = asString(response.nextPageToken);
      if (!pageToken) break;
    }
    return accounts;
  }

  async listServiceAccountKeys(projectId: string, serviceAccountEmail: string): Promise<JsonRecord[]> {
    const encoded = encodeURIComponent(serviceAccountEmail);
    const response = await this.requestJson(
      `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${encoded}/keys?keyTypes=USER_MANAGED`,
    );
    return asArray(response.keys).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async getLoggingSettings(projectId: string): Promise<JsonRecord> {
    return this.requestJson(`https://logging.googleapis.com/v2/projects/${projectId}/settings`);
  }

  async listLogSinks(projectId: string): Promise<JsonRecord[]> {
    const response = await this.requestJson(`https://logging.googleapis.com/v2/projects/${projectId}/sinks`);
    return asArray(response.sinks).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async listLogBuckets(projectId: string): Promise<JsonRecord[]> {
    const response = await this.requestJson(`https://logging.googleapis.com/v2/projects/${projectId}/locations/-/buckets`);
    return asArray(response.buckets).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async listRecentAdminActivity(projectId: string): Promise<JsonRecord[]> {
    const response = await this.requestJson("https://logging.googleapis.com/v2/entries:list", {
      method: "POST",
      body: {
        resourceNames: [`projects/${projectId}`],
        pageSize: 20,
        filter: 'logName:"cloudaudit.googleapis.com%2Factivity"',
      },
    });
    return asArray(response.entries).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async listRecentDataAccess(projectId: string): Promise<JsonRecord[]> {
    const response = await this.requestJson("https://logging.googleapis.com/v2/entries:list", {
      method: "POST",
      body: {
        resourceNames: [`projects/${projectId}`],
        pageSize: 20,
        filter: 'logName:"cloudaudit.googleapis.com%2Fdata_access"',
      },
    });
    return asArray(response.entries).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async listSccSources(): Promise<JsonRecord[]> {
    if (!this.config.organizationId) return [];
    const response = await this.requestJson(
      `https://securitycenter.googleapis.com/v1/organizations/${this.config.organizationId}/sources?pageSize=100`,
    );
    return asArray(response.sources).map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }

  async listSccFindings(limit = DEFAULT_MAX_FINDINGS): Promise<JsonRecord[]> {
    if (!this.config.organizationId) return [];
    const findings: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (findings.length < limit) {
      const query = new URLSearchParams({
        pageSize: String(Math.min(100, limit - findings.length)),
      });
      if (pageToken) query.set("pageToken", pageToken);
      const response = await this.requestJson(
        `https://securitycenter.googleapis.com/v1/organizations/${this.config.organizationId}/sources/-/findings?${query.toString()}`,
      );
      for (const item of asArray(response.listFindingsResults)) {
        const record = asObject(item);
        if (record) findings.push(record);
      }
      pageToken = asString(response.nextPageToken);
      if (!pageToken) break;
    }
    return findings;
  }

  async getEffectiveOrgPolicy(projectId: string, constraint: string): Promise<JsonRecord | null> {
    const response = await this.requestJson(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getEffectiveOrgPolicy`,
      {
        method: "POST",
        body: { constraint },
      },
    );
    return Object.keys(response).length > 0 ? response : null;
  }
}

function summarizeProject(resource: JsonRecord): JsonRecord {
  return {
    projectId: parseProjectId(resource),
    name: asString(resource.displayName) ?? asString(resource.name),
    state: asString(resource.state),
  };
}

export async function checkGcpAccess(
  client: Pick<
    GcpAuditorClient,
    "getResolvedConfig" | "getOrganization" | "listProjects" | "searchAllIamPolicies" | "getLoggingSettings" | "listLogSinks" | "listSccSources" | "getEffectiveOrgPolicy"
  >,
): Promise<GcpAccessCheckResult> {
  const config = client.getResolvedConfig();
  const projects = await client.listProjects(5);
  const targetProject = parseProjectId(projects[0] ?? {}) ?? config.projectId;
  const surfaces = await Promise.all([
    surface("organization", "cloudresourcemanager", () => client.getOrganization(), () => (config.organizationId ? 1 : 0)),
    surface("projects", "cloudasset", async () => projects, (value) => Array.isArray(value) ? value.length : undefined),
    surface("iam_policies", "cloudasset", () => client.searchAllIamPolicies(20), (value) => Array.isArray(value) ? value.length : undefined),
    surface("logging_settings", "logging", async () => {
      if (!targetProject) throw new Error("No project available for logging settings.");
      return client.getLoggingSettings(targetProject);
    }, () => 1),
    surface("log_sinks", "logging", async () => {
      if (!targetProject) throw new Error("No project available for log sinks.");
      return client.listLogSinks(targetProject);
    }, (value) => Array.isArray(value) ? value.length : undefined),
    surface("security_command_center", "securitycenter", () => client.listSccSources(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("org_policy", "cloudresourcemanager", async () => {
      if (!targetProject) throw new Error("No project available for org policy checks.");
      return client.getEffectiveOrgPolicy(targetProject, "constraints/iam.disableServiceAccountKeyCreation");
    }, () => 1),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 5 ? "healthy" : "limited";
  const notes = [
    `Authenticated against ${describeSourceChain(config)}.`,
    `${readableCount}/${surfaces.length} GCP audit surfaces are readable.`,
    targetProject ? `Primary sampled project: ${targetProject}.` : "No project was available for sample queries.",
  ];

  return {
    status,
    organizationId: config.organizationId,
    projectId: targetProject ?? config.projectId,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run gcp_assess_identity, gcp_assess_logging_detection, gcp_assess_org_guardrails, or gcp_export_audit_bundle."
        : "Grant read-only access to Cloud Asset Inventory, IAM, Logging, Cloud Resource Manager, and Security Command Center for the audit principal.",
  };
}

export async function assessGcpIdentity(
  client: Pick<
    GcpAuditorClient,
    "getNow" | "listProjects" | "listServiceAccounts" | "listServiceAccountKeys" | "searchAllIamPolicies"
  >,
  options: {
    maxProjects?: number;
    staleDays?: number;
    maxKeys?: number;
  } = {},
): Promise<GcpAssessmentResult> {
  const now = client.getNow();
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 200);
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const maxKeys = clampNumber(options.maxKeys, DEFAULT_MAX_KEYS, 1, 5000);

  const [projectResources, iamPolicies] = await Promise.all([
    client.listProjects(maxProjects),
    client.searchAllIamPolicies(500),
  ]);
  const projects = projectResources.map(summarizeProject);

  const staleKeys: Array<{ projectId?: string; serviceAccount?: string; key?: string; ageDays?: number }> = [];
  const userManagedKeys: Array<{ projectId?: string; serviceAccount?: string; key?: string }> = [];
  let keyCounter = 0;

  for (const project of projects) {
    const projectId = asString(project.projectId);
    if (!projectId) continue;
    const serviceAccounts = await client.listServiceAccounts(projectId);
    for (const serviceAccount of serviceAccounts) {
      if (keyCounter >= maxKeys) break;
      const email = asString(serviceAccount.email);
      if (!email) continue;
      const keys = await client.listServiceAccountKeys(projectId, email);
      for (const key of keys) {
        if (keyCounter >= maxKeys) break;
        keyCounter += 1;
        const keyName = asString(key.name);
        userManagedKeys.push({ projectId, serviceAccount: email, key: keyName });
        const ageDays = daysBetween(now, extractTimestamp(key.validAfterTime ?? key.createTime));
        if (ageDays !== undefined && ageDays > staleDays) {
          staleKeys.push({ projectId, serviceAccount: email, key: keyName, ageDays: Number(ageDays.toFixed(1)) });
        }
      }
    }
  }

  const privilegedBindings: Array<{ resource?: string; role?: string; member?: string }> = [];
  const crossProjectBindings: Array<{ resource?: string; member?: string; role?: string }> = [];
  const privilegedDefaultServiceAccounts: Array<{ resource?: string; member?: string; role?: string }> = [];

  for (const result of iamPolicies) {
    const resource = asString(result.resource);
    const bindings = parsePolicyBindings(result.policy);
    const resourceProject = resource?.match(/projects\/([^/]+)/)?.[1];
    for (const binding of bindings) {
      const role = asString(binding.role);
      for (const rawMember of asArray(binding.members)) {
        const member = normalizeMember(rawMember);
        if (!member) continue;
        if (isOwnerLikeRole(role)) {
          privilegedBindings.push({ resource, role, member });
        }
        if (member.startsWith("serviceaccount:")) {
          const email = member.replace("serviceaccount:", "");
          const emailProject = email.split("@").at(1)?.split(".").at(0);
          if (resourceProject && emailProject && emailProject !== resourceProject) {
            crossProjectBindings.push({ resource, member, role });
          }
          if (isOwnerLikeRole(role) && isDefaultServiceAccount(email)) {
            privilegedDefaultServiceAccounts.push({ resource, member, role });
          }
        }
      }
    }
  }

  const findings = [
    finding(
      "GCP-IAM-01",
      "Privileged IAM bindings",
      "high",
      privilegedBindings.length > 0 ? "fail" : "pass",
      privilegedBindings.length > 0
        ? `${privilegedBindings.length} owner/editor-style bindings were found across the sampled scope.`
        : "No owner/editor-style bindings were found in the sampled Cloud Asset IAM results.",
      ["FedRAMP AC-2", "FedRAMP AC-6", "CMMC 3.1.5", "CIS GCP 1.5"],
      { bindings: privilegedBindings.slice(0, 25) },
    ),
    finding(
      "GCP-IAM-02",
      "Service account key rotation",
      "high",
      staleKeys.length > 0 ? "fail" : "pass",
      staleKeys.length > 0
        ? `${staleKeys.length} user-managed service account keys exceed the ${staleDays}-day threshold.`
        : `No sampled user-managed service account key exceeded the ${staleDays}-day threshold.`,
      ["FedRAMP IA-5(1)", "FedRAMP SC-12", "CMMC 3.5.8", "CIS GCP 1.4"],
      { stale_keys: staleKeys.slice(0, 25) },
    ),
    finding(
      "GCP-IAM-03",
      "User-managed service account key minimization",
      "medium",
      userManagedKeys.length > 0 ? "warn" : "pass",
      userManagedKeys.length > 0
        ? `${userManagedKeys.length} user-managed service account keys are present; prefer Workload Identity Federation where possible.`
        : "No user-managed service account keys were found in the sampled projects.",
      ["FedRAMP IA-5(1)", "FedRAMP AC-6", "SOC 2 CC6.1", "CIS GCP 1.4"],
      { user_managed_keys: userManagedKeys.slice(0, 25) },
    ),
    finding(
      "GCP-IAM-04",
      "Cross-project service account access",
      "medium",
      crossProjectBindings.length > 0 ? "warn" : "pass",
      crossProjectBindings.length > 0
        ? `${crossProjectBindings.length} cross-project service account bindings were found in the sampled scope.`
        : "No cross-project service account bindings were detected in the sampled IAM policies.",
      ["FedRAMP AC-3", "FedRAMP AC-4", "CMMC 3.1.3", "CIS GCP 1.6"],
      { cross_project_bindings: crossProjectBindings.slice(0, 25) },
    ),
    finding(
      "GCP-IAM-05",
      "Default service account privilege",
      "high",
      privilegedDefaultServiceAccounts.length > 0 ? "fail" : "pass",
      privilegedDefaultServiceAccounts.length > 0
        ? `${privilegedDefaultServiceAccounts.length} default service accounts hold owner/editor-style roles.`
        : "No default service accounts held owner/editor-style roles in the sampled bindings.",
      ["FedRAMP AC-6", "CMMC 3.1.5", "SOC 2 CC6.2", "CIS GCP 1.7"],
      { privileged_default_service_accounts: privilegedDefaultServiceAccounts.slice(0, 25) },
    ),
  ];

  return {
    title: "GCP identity posture",
    summary: {
      sampled_projects: projects.length,
      privileged_bindings: privilegedBindings.length,
      stale_service_account_keys: staleKeys.length,
      user_managed_service_account_keys: userManagedKeys.length,
      cross_project_service_accounts: crossProjectBindings.length,
      privileged_default_service_accounts: privilegedDefaultServiceAccounts.length,
    },
    findings,
  };
}

export async function assessGcpLoggingDetection(
  client: Pick<
    GcpAuditorClient,
    "listProjects" | "getLoggingSettings" | "listLogSinks" | "listLogBuckets" | "listRecentAdminActivity" | "listRecentDataAccess" | "listSccSources" | "listSccFindings"
  >,
  options: {
    maxProjects?: number;
    maxFindings?: number;
  } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 200);
  const maxFindings = clampNumber(options.maxFindings, DEFAULT_MAX_FINDINGS, 1, 5000);
  const projectResources = await client.listProjects(maxProjects);
  const projects = projectResources.map(summarizeProject);

  let adminProjects = 0;
  let dataAccessProjects = 0;
  let sinkProjects = 0;
  let retainedBucketProjects = 0;
  const projectsWithoutSinks: string[] = [];
  const projectsWithoutRetention: string[] = [];

  for (const project of projects) {
    const projectId = asString(project.projectId);
    if (!projectId) continue;
    await client.getLoggingSettings(projectId);
    const [adminEntries, dataAccessEntries, sinks, buckets] = await Promise.all([
      client.listRecentAdminActivity(projectId),
      client.listRecentDataAccess(projectId),
      client.listLogSinks(projectId),
      client.listLogBuckets(projectId),
    ]);
    if (adminEntries.length > 0) adminProjects += 1;
    if (dataAccessEntries.length > 0) dataAccessProjects += 1;
    if (sinks.length > 0) sinkProjects += 1;
    else projectsWithoutSinks.push(projectId);
    const retained = buckets.some((bucket) => (asNumber(bucket.retentionDays) ?? 0) >= 90);
    if (retained) retainedBucketProjects += 1;
    else projectsWithoutRetention.push(projectId);
  }

  const [sccSources, sccFindings] = await Promise.all([
    client.listSccSources(),
    client.listSccFindings(maxFindings),
  ]);

  const findings = [
    finding(
      "GCP-LOG-01",
      "Admin Activity visibility",
      "medium",
      adminProjects === projects.length && projects.length > 0 ? "pass" : adminProjects > 0 ? "warn" : "fail",
      adminProjects === projects.length && projects.length > 0
        ? "Admin Activity log events were visible for every sampled project."
        : `${adminProjects}/${projects.length} sampled projects returned recent Admin Activity events.`,
      ["FedRAMP AU-2", "FedRAMP AU-6", "CMMC 3.3.1", "CIS GCP 2.1"],
      { sampled_projects: projects.length, projects_with_admin_activity: adminProjects },
    ),
    finding(
      "GCP-LOG-02",
      "Data Access logging coverage",
      "high",
      dataAccessProjects === projects.length && projects.length > 0 ? "pass" : dataAccessProjects > 0 ? "warn" : "fail",
      dataAccessProjects === projects.length && projects.length > 0
        ? "Recent Data Access events were visible across every sampled project."
        : `${dataAccessProjects}/${projects.length} sampled projects returned recent Data Access events.`,
      ["FedRAMP AU-12", "FedRAMP AU-3", "CMMC 3.3.1", "CIS GCP 2.3"],
      { sampled_projects: projects.length, projects_with_data_access: dataAccessProjects },
    ),
    finding(
      "GCP-LOG-03",
      "Log sink coverage",
      "high",
      sinkProjects === projects.length && projects.length > 0 ? "pass" : sinkProjects > 0 ? "warn" : "fail",
      sinkProjects === projects.length && projects.length > 0
        ? "Every sampled project had at least one configured log sink."
        : `${projectsWithoutSinks.length} sampled projects lacked a configured log sink.`,
      ["FedRAMP AU-4", "FedRAMP AU-9", "SOC 2 CC7.2", "CIS GCP 2.2"],
      { projects_without_sinks: projectsWithoutSinks.slice(0, 25) },
    ),
    finding(
      "GCP-LOG-04",
      "Log bucket retention",
      "medium",
      retainedBucketProjects === projects.length && projects.length > 0 ? "pass" : retainedBucketProjects > 0 ? "warn" : "fail",
      retainedBucketProjects === projects.length && projects.length > 0
        ? "Every sampled project exposed a log bucket with at least 90 days of retention."
        : `${projectsWithoutRetention.length} sampled projects lacked a log bucket with 90-day retention.`,
      ["FedRAMP AU-11", "FedRAMP AU-9", "CMMC 3.3.8", "CIS GCP 2.4"],
      { projects_without_retention: projectsWithoutRetention.slice(0, 25) },
    ),
    finding(
      "GCP-LOG-05",
      "Security Command Center visibility",
      "medium",
      sccSources.length > 0 ? "pass" : "warn",
      sccSources.length > 0
        ? `Security Command Center returned ${sccSources.length} sources and ${sccFindings.length} findings in the sampled window.`
        : "Security Command Center sources were not visible for the configured scope.",
      ["FedRAMP SI-4", "FedRAMP RA-5", "CMMC 3.14.6", "CIS GCP 3.1"],
      { scc_sources: sccSources.length, scc_findings: sccFindings.length },
    ),
  ];

  return {
    title: "GCP logging and detection posture",
    summary: {
      sampled_projects: projects.length,
      projects_with_admin_activity: adminProjects,
      projects_with_data_access: dataAccessProjects,
      projects_with_log_sinks: sinkProjects,
      projects_with_retained_buckets: retainedBucketProjects,
      scc_sources: sccSources.length,
      scc_findings: sccFindings.length,
    },
    findings,
  };
}

export async function assessGcpOrgGuardrails(
  client: Pick<
    GcpAuditorClient,
    "getResolvedConfig" | "getOrganization" | "listProjects" | "getEffectiveOrgPolicy"
  >,
  options: {
    maxProjects?: number;
  } = {},
): Promise<GcpAssessmentResult> {
  const maxProjects = clampNumber(options.maxProjects, DEFAULT_MAX_PROJECTS, 1, 200);
  const config = client.getResolvedConfig();
  const [organization, projectResources] = await Promise.all([
    client.getOrganization(),
    client.listProjects(maxProjects),
  ]);
  const projects = projectResources.map(summarizeProject);
  const targetProjectId = asString(projects[0]?.projectId) ?? config.projectId;

  const constraints = targetProjectId
    ? await Promise.all([
        client.getEffectiveOrgPolicy(targetProjectId, "constraints/iam.allowedPolicyMemberDomains"),
        client.getEffectiveOrgPolicy(targetProjectId, "constraints/iam.disableServiceAccountKeyCreation"),
        client.getEffectiveOrgPolicy(targetProjectId, "constraints/iam.disableServiceAccountKeyUpload"),
        client.getEffectiveOrgPolicy(targetProjectId, "constraints/compute.disableSerialPortAccess"),
        client.getEffectiveOrgPolicy(targetProjectId, "constraints/compute.requireShieldedVm"),
      ])
    : [null, null, null, null, null];

  const findings = [
    finding(
      "GCP-ORG-01",
      "Organization visibility",
      "medium",
      organization ? "pass" : "warn",
      organization
        ? `Organization ${asString(organization.displayName) ?? asString(organization.name) ?? config.organizationId ?? "visible"} was readable and ${projects.length} projects were sampled.`
        : "Organization metadata was not readable for the configured scope.",
      ["FedRAMP CA-3", "FedRAMP CM-2", "CMMC 3.12.1", "CIS GCP 1.1"],
      { sampled_projects: projects.length, target_project: targetProjectId ?? null },
    ),
    finding(
      "GCP-ORG-02",
      "Domain-restricted sharing",
      "high",
      interpretOrgPolicyEnabled(constraints[0]) ? "pass" : "warn",
      interpretOrgPolicyEnabled(constraints[0])
        ? "A domain-restricted sharing constraint was visible in the effective org policy."
        : "No effective domain-restricted sharing constraint was visible for the sampled project.",
      ["FedRAMP AC-3", "FedRAMP AC-4", "CMMC 3.1.3", "CIS GCP 1.8"],
      { policy: constraints[0] ?? null },
    ),
    finding(
      "GCP-ORG-03",
      "Service account key creation restriction",
      "high",
      interpretOrgPolicyEnabled(constraints[1]) ? "pass" : "fail",
      interpretOrgPolicyEnabled(constraints[1])
        ? "The effective org policy restricts user-managed service account key creation."
        : "The effective org policy does not show service account key creation disabled.",
      ["FedRAMP IA-5(1)", "FedRAMP SC-12", "CMMC 3.5.8", "CIS GCP 1.4"],
      { policy: constraints[1] ?? null },
    ),
    finding(
      "GCP-ORG-04",
      "Service account key upload restriction",
      "high",
      interpretOrgPolicyEnabled(constraints[2]) ? "pass" : "warn",
      interpretOrgPolicyEnabled(constraints[2])
        ? "The effective org policy restricts service account public key upload."
        : "The effective org policy does not show service account public key upload disabled.",
      ["FedRAMP IA-5(1)", "FedRAMP AC-6", "CMMC 3.5.8", "CIS GCP 1.4"],
      { policy: constraints[2] ?? null },
    ),
    finding(
      "GCP-ORG-05",
      "Serial port and Shielded VM guardrails",
      "medium",
      interpretOrgPolicyEnabled(constraints[3]) && interpretOrgPolicyEnabled(constraints[4])
        ? "pass"
        : interpretOrgPolicyEnabled(constraints[3]) || interpretOrgPolicyEnabled(constraints[4])
          ? "warn"
          : "fail",
      interpretOrgPolicyEnabled(constraints[3]) && interpretOrgPolicyEnabled(constraints[4])
        ? "Serial port access is disabled and Shielded VM is required in the sampled effective policy set."
        : "One or more compute hardening guardrails were missing from the sampled effective policy set.",
      ["FedRAMP CM-6", "FedRAMP SI-7", "CMMC 3.4.6", "CIS GCP 4.5"],
      { serial_port_policy: constraints[3] ?? null, shielded_vm_policy: constraints[4] ?? null },
    ),
  ];

  return {
    title: "GCP organization guardrails",
    summary: {
      sampled_projects: projects.length,
      organization_visible: Boolean(organization),
      target_project: targetProjectId ?? null,
      domain_restricted_sharing: interpretOrgPolicyEnabled(constraints[0]),
      service_account_key_creation_disabled: interpretOrgPolicyEnabled(constraints[1]),
      service_account_key_upload_disabled: interpretOrgPolicyEnabled(constraints[2]),
      serial_port_disabled: interpretOrgPolicyEnabled(constraints[3]),
      shielded_vm_required: interpretOrgPolicyEnabled(constraints[4]),
    },
    findings,
  };
}

function formatAccessCheckText(result: GcpAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.service,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `GCP access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: GcpAssessmentResult): string {
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

function buildExecutiveSummary(config: GcpResolvedConfig, assessments: GcpAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# GCP Audit Bundle",
    "",
    `Organization: ${config.organizationId ?? "n/a"}`,
    `Project hint: ${config.projectId ?? "n/a"}`,
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

function buildControlMatrix(findings: GcpFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# GCP Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# GCP Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native GCP tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible GCP audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Resolved access tokens are not written to this bundle.",
  ].join("\n");
}

export async function exportGcpAuditBundle(
  client: GcpAuditorClient,
  config: GcpResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<GcpAuditBundleResult> {
  const access = await checkGcpAccess(client);
  const identity = await assessGcpIdentity(client, {
    maxProjects: options.max_projects,
    staleDays: options.stale_days,
    maxKeys: options.max_keys,
  });
  const loggingDetection = await assessGcpLoggingDetection(client, {
    maxProjects: options.max_projects,
    maxFindings: options.max_findings,
  });
  const orgGuardrails = await assessGcpOrgGuardrails(client, {
    maxProjects: options.max_projects,
  });

  const assessments = [identity, loggingDetection, orgGuardrails];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${config.organizationId ?? config.projectId ?? "gcp-scope"}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    organization_id: config.organizationId ?? null,
    project_id: config.projectId ?? null,
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      max_projects: options.max_projects ?? DEFAULT_MAX_PROJECTS,
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      max_keys: options.max_keys ?? DEFAULT_MAX_KEYS,
      max_findings: options.max_findings ?? DEFAULT_MAX_FINDINGS,
    },
  }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments));
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", buildControlMatrix(findings));
  await writeSecureTextFile(outputDir, "reports/identity.md", formatAssessmentText(identity));
  await writeSecureTextFile(outputDir, "reports/logging-detection.md", formatAssessmentText(loggingDetection));
  await writeSecureTextFile(outputDir, "reports/org-guardrails.md", formatAssessmentText(orgGuardrails));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/logging-detection.json", serializeJson(loggingDetection));
  await writeSecureTextFile(outputDir, "analysis/org-guardrails.json", serializeJson(orgGuardrails));
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
    organization_id: asString(value.organization_id),
    project_id: asString(value.project_id),
    access_token: asString(value.access_token),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_projects: asNumber(value.max_projects),
    stale_days: asNumber(value.stale_days),
    max_keys: asNumber(value.max_keys),
  };
}

function normalizeLoggingArgs(args: unknown): LoggingArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_projects: asNumber(value.max_projects),
    max_findings: asNumber(value.max_findings),
  };
}

function normalizeOrgGuardrailArgs(args: unknown): OrgGuardrailArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_projects: asNumber(value.max_projects),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    max_projects: asNumber(value.max_projects),
    stale_days: asNumber(value.stale_days),
    max_keys: asNumber(value.max_keys),
    max_findings: asNumber(value.max_findings),
  };
}

function createClient(args: CheckAccessArgs): GcpAuditorClient {
  return new GcpAuditorClient(resolveGcpConfiguration(args));
}

const authParams = {
  organization_id: Type.Optional(Type.String({ description: "GCP organization ID to audit. Defaults to GCP_ORGANIZATION_ID." })),
  project_id: Type.Optional(Type.String({ description: "GCP project ID for project-scoped fallback or focused checks. Defaults to GCP_PROJECT_ID or GOOGLE_CLOUD_PROJECT." })),
  access_token: Type.Optional(Type.String({ description: "Explicit OAuth bearer token. Defaults to GCP_ACCESS_TOKEN or gcloud auth print-access-token." })),
};

export function registerGcpTools(pi: any): void {
  pi.registerTool({
    name: "gcp_check_access",
    label: "Check GCP audit access",
    description:
      "Validate read-only GCP audit access across Cloud Resource Manager, Cloud Asset Inventory, IAM, Logging, and Security Command Center surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkGcpAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "gcp_check_access", ...result });
      } catch (error) {
        return errorResult(
          `GCP access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "gcp_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gcp_assess_identity",
    label: "Assess GCP identity posture",
    description:
      "Assess GCP IAM posture across privileged bindings, service account key rotation, user-managed keys, cross-project access, and default service account privilege.",
    parameters: Type.Object({
      ...authParams,
      max_projects: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 20.", default: 20 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for service account keys. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum service account keys to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessGcpIdentity(createClient(args), {
          maxProjects: args.max_projects,
          staleDays: args.stale_days,
          maxKeys: args.max_keys,
        });
        return textResult(formatAssessmentText(result), { tool: "gcp_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `GCP identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "gcp_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gcp_assess_logging_detection",
    label: "Assess GCP logging and detection",
    description:
      "Assess GCP Logging and Security Command Center coverage, including Admin Activity visibility, Data Access signal, log sinks, retained buckets, and SCC findings visibility.",
    parameters: Type.Object({
      ...authParams,
      max_projects: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 20.", default: 20 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Security Command Center findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeLoggingArgs,
    async execute(_toolCallId: string, args: LoggingArgs) {
      try {
        const result = await assessGcpLoggingDetection(createClient(args), {
          maxProjects: args.max_projects,
          maxFindings: args.max_findings,
        });
        return textResult(formatAssessmentText(result), { tool: "gcp_assess_logging_detection", ...result });
      } catch (error) {
        return errorResult(
          `GCP logging and detection assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "gcp_assess_logging_detection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gcp_assess_org_guardrails",
    label: "Assess GCP organization guardrails",
    description:
      "Assess GCP organization-level guardrails including domain-restricted sharing, service account key controls, serial port restrictions, and Shielded VM requirements.",
    parameters: Type.Object({
      ...authParams,
      max_projects: Type.Optional(Type.Number({ description: "Maximum projects to sample when deriving an effective policy target. Defaults to 20.", default: 20 })),
    }),
    prepareArguments: normalizeOrgGuardrailArgs,
    async execute(_toolCallId: string, args: OrgGuardrailArgs) {
      try {
        const result = await assessGcpOrgGuardrails(createClient(args), {
          maxProjects: args.max_projects,
        });
        return textResult(formatAssessmentText(result), { tool: "gcp_assess_org_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `GCP organization guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "gcp_assess_org_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gcp_export_audit_bundle",
    label: "Export GCP audit bundle",
    description:
      "Export a GCP audit package with access checks, identity findings, logging and detection findings, organization guardrails, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_projects: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 20.", default: 20 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for service account keys. Defaults to 90.", default: 90 })),
      max_keys: Type.Optional(Type.Number({ description: "Maximum service account keys to inspect. Defaults to 200.", default: 200 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Security Command Center findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveGcpConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportGcpAuditBundle(new GcpAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "GCP audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "gcp_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `GCP audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "gcp_export_audit_bundle" },
        );
      }
    },
  });
}
