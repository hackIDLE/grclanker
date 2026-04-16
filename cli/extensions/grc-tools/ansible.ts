/**
 * Red Hat Ansible Automation Platform audit tools for grclanker.
 *
 * This native TypeScript surface is grounded in the community
 * ansible-sec-inspector spec and starts with read-only AAP REST API checks.
 */
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

const DEFAULT_LOOKBACK_DAYS = 90;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_JOB_LIMIT = 500;
const DEFAULT_HOST_LIMIT = 1000;
const DEFAULT_TIMEOUT_MS = 30_000;
const TOKEN_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_OUTPUT_DIR = "./export/ansible-aap";

type FetchImpl = typeof fetch;

export interface AnsibleAapConfiguration {
  baseUrl: string;
  username?: string;
  password?: string;
  token?: string;
  timeoutMs: number;
  sourceChain: string[];
}

interface AnsibleAapClientOptions {
  fetchImpl?: FetchImpl;
  now?: () => Date;
}

interface AapListResponse<T> {
  count?: number;
  next?: string | null;
  previous?: string | null;
  results?: T[];
}

export interface AnsibleAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface AnsibleAccessCheckResult {
  status: "healthy" | "limited";
  currentUser?: Record<string, unknown>;
  ping?: Record<string, unknown>;
  surfaces: AnsibleAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface AnsibleFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: Record<string, unknown>;
  mappings: string[];
}

export interface AnsibleAssessmentResult {
  title: string;
  summary: Record<string, unknown>;
  findings: AnsibleFinding[];
}

export interface AnsibleAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  url?: string;
  username?: string;
  token?: string;
  timeout_seconds?: number;
};

type JobHealthArgs = CheckAccessArgs & {
  days?: number;
  job_limit?: number;
  min_success_rate?: number;
  max_manual_rate?: number;
};

type HostCoverageArgs = CheckAccessArgs & {
  stale_host_days?: number;
  critical_stale_host_days?: number;
  host_limit?: number;
  inventory_source_limit?: number;
};

type PlatformSecurityArgs = CheckAccessArgs & {
  max_org_admins?: number;
  stale_credential_days?: number;
  stale_token_days?: number;
  project_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  days?: number;
  job_limit?: number;
  host_limit?: number;
  min_success_rate?: number;
  max_manual_rate?: number;
  stale_host_days?: number;
  critical_stale_host_days?: number;
  max_org_admins?: number;
  stale_credential_days?: number;
  stale_token_days?: number;
};

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

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

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  if (parsed.pathname.endsWith("/api/v2")) {
    parsed.pathname = parsed.pathname.slice(0, -"/api/v2".length) || "/";
  } else if (parsed.pathname.endsWith("/api")) {
    parsed.pathname = parsed.pathname.slice(0, -"/api".length) || "/";
  }
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

export function resolveAnsibleConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
): AnsibleAapConfiguration {
  if (asString(input.password) || asString(input.aap_password)) {
    throw new Error("AAP_PASSWORD must be provided via environment, not tool arguments.");
  }

  const sourceChain: string[] = [];
  const rawUrl = asString(input.url) ?? asString(input.base_url) ?? asString(env.AAP_URL);
  if (!rawUrl) {
    throw new Error("AAP_URL or a url argument is required.");
  }
  sourceChain.push(asString(input.url) || asString(input.base_url) ? "arguments" : "environment");

  const token = asString(input.token) ?? asString(env.AAP_TOKEN);
  const username = asString(input.username) ?? asString(env.AAP_USERNAME);
  const password = asString(env.AAP_PASSWORD);

  if (token) {
    sourceChain.push(asString(input.token) ? "arguments" : "environment");
  } else if (username && password) {
    sourceChain.push(asString(input.username) ? "arguments" : "environment");
    sourceChain.push("environment-password");
  } else {
    throw new Error("AAP_TOKEN or both AAP_USERNAME and AAP_PASSWORD are required.");
  }

  const timeoutSeconds = asNumber(input.timeout_seconds) ?? asNumber(env.AAP_TIMEOUT);

  return {
    baseUrl: normalizeBaseUrl(rawUrl),
    username,
    password,
    token,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    sourceChain: [...new Set(sourceChain)],
  };
}

function splitSetCookieHeader(value: string): string[] {
  return value.split(/,(?=\s*[^;,=\s]+=)/g);
}

function cookieHeaderFromHeaders(headers: Headers): string | undefined {
  const headersWithGetSetCookie = headers as Headers & { getSetCookie?: () => string[] };
  const setCookies =
    typeof headersWithGetSetCookie.getSetCookie === "function"
      ? headersWithGetSetCookie.getSetCookie()
      : headers.get("set-cookie")
        ? splitSetCookieHeader(headers.get("set-cookie") ?? "")
        : [];

  const cookies = setCookies
    .map((cookie) => cookie.split(";")[0]?.trim())
    .filter((cookie): cookie is string => Boolean(cookie));

  return cookies.length > 0 ? cookies.join("; ") : undefined;
}

function csrfTokenFromCookie(cookieHeader?: string): string | undefined {
  const match = cookieHeader?.match(/(?:^|;\s*)csrftoken=([^;]+)/i);
  return match?.[1];
}

function appendQuery(path: string, query: Record<string, string | number | boolean | undefined>): string {
  const base = path.startsWith("http://") || path.startsWith("https://")
    ? new URL(path)
    : new URL(path, "https://aap.local");

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    base.searchParams.set(key, String(value));
  }

  if (path.startsWith("http://") || path.startsWith("https://")) {
    return base.toString();
  }

  return `${base.pathname}${base.search}`;
}

function extractText(value: unknown, fallback = ""): string {
  const text = asString(value);
  return text ?? fallback;
}

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return value;
  const object = asObject(value);
  if (!object) return undefined;
  return (
    extractTimestamp(object.finished)
    ?? extractTimestamp(object.started)
    ?? extractTimestamp(object.created)
    ?? extractTimestamp(object.modified)
  );
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function isFailureStatus(status: unknown): boolean {
  return ["failed", "error", "canceled", "cancelled"].includes(String(status ?? "").toLowerCase());
}

function isSuccessStatus(status: unknown): boolean {
  return String(status ?? "").toLowerCase() === "successful";
}

function finding(
  id: string,
  title: string,
  severity: AnsibleFinding["severity"],
  status: AnsibleFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: Record<string, unknown>,
): AnsibleFinding {
  return { id, title, severity, status, summary, mappings, evidence };
}

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "ansible-aap";
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
  const stat = lstatSync(realParent);
  if (stat.isSymbolicLink()) {
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
    if (entry.isDirectory()) {
      count += await countFilesRecursively(fullPath);
    } else {
      count += 1;
    }
  }
  return count;
}

export class AnsibleAapClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private sessionCookie?: string;
  private csrfToken?: string;
  private sessionPromise?: Promise<void>;
  private sessionExpiresAt?: number;

  constructor(
    private readonly config: AnsibleAapConfiguration,
    options: AnsibleAapClientOptions = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  private resolveUrl(pathOrUrl: string): string {
    if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")) {
      return pathOrUrl;
    }

    const normalizedPath = pathOrUrl.startsWith("/") ? pathOrUrl : `/api/v2/${pathOrUrl}`;
    return `${this.config.baseUrl}${normalizedPath}`;
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }

  private async ensureSession(): Promise<void> {
    if (this.config.token) return;
    if (this.sessionCookie && (this.sessionExpiresAt ?? 0) > Date.now() + TOKEN_SKEW_MS) return;
    if (this.sessionPromise) return this.sessionPromise;

    this.sessionPromise = this.createSession().finally(() => {
      this.sessionPromise = undefined;
    });
    return this.sessionPromise;
  }

  private async createSession(): Promise<void> {
    if (!this.config.username || !this.config.password) {
      throw new Error("AAP session auth requires AAP_USERNAME and AAP_PASSWORD.");
    }

    const loginUrl = this.resolveUrl("/api/login/");
    const initial = await this.fetchWithTimeout(loginUrl, {
      method: "GET",
      headers: { accept: "text/html,application/json" },
    });
    if (!initial.ok) {
      throw new Error(`AAP login bootstrap failed (${initial.status} ${initial.statusText}).`);
    }

    const bootstrapCookie = cookieHeaderFromHeaders(initial.headers);
    const csrfToken = csrfTokenFromCookie(bootstrapCookie);
    const body = new URLSearchParams({
      username: this.config.username,
      password: this.config.password,
    });

    const response = await this.fetchWithTimeout(loginUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        ...(bootstrapCookie ? { cookie: bootstrapCookie } : {}),
        ...(csrfToken ? { "x-csrftoken": csrfToken } : {}),
        referer: loginUrl,
      },
      body,
    });

    if (!response.ok) {
      throw new Error(`AAP session login failed (${response.status} ${response.statusText}).`);
    }

    const loginCookie = cookieHeaderFromHeaders(response.headers);
    this.sessionCookie = [bootstrapCookie, loginCookie].filter(Boolean).join("; ");
    this.csrfToken = csrfTokenFromCookie(this.sessionCookie) ?? csrfToken;
    this.sessionExpiresAt = Date.now() + 60 * 60 * 1000;
  }

  async get<T = unknown>(pathOrUrl: string): Promise<T> {
    await this.ensureSession();
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.config.token) {
      headers.authorization = `Bearer ${this.config.token}`;
    } else {
      if (this.sessionCookie) headers.cookie = this.sessionCookie;
      if (this.csrfToken) headers["x-csrftoken"] = this.csrfToken;
    }

    const response = await this.fetchWithTimeout(this.resolveUrl(pathOrUrl), { method: "GET", headers });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`AAP request failed: ${pathOrUrl} (${response.status} ${response.statusText}) ${text.slice(0, 200)}`);
    }

    return text.length > 0 ? JSON.parse(text) as T : undefined as T;
  }

  async list<T = Record<string, unknown>>(
    path: string,
    query: Record<string, string | number | boolean | undefined> = {},
    options: { limit?: number } = {},
  ): Promise<T[]> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    let next: string | null = appendQuery(path, { page_size: DEFAULT_PAGE_SIZE, ...query });
    const items: T[] = [];

    while (next && items.length < limit) {
      const page: AapListResponse<T> | T[] = await this.get<AapListResponse<T> | T[]>(next);
      const results = Array.isArray(page) ? page : page.results ?? [];
      items.push(...results.slice(0, limit - items.length));
      next = Array.isArray(page) ? null : page.next ?? null;
    }

    return items;
  }

  async count(path: string): Promise<number> {
    const page = await this.get<AapListResponse<unknown>>(appendQuery(path, { page_size: 1 }));
    return typeof page.count === "number" ? page.count : page.results?.length ?? 0;
  }

  getNow(): Date {
    return this.now();
  }
}

function currentUserFromMe(value: unknown): Record<string, unknown> | undefined {
  const object = asObject(value);
  if (!object) return undefined;
  if (Array.isArray(object.results)) return asObject(object.results[0]);
  return object;
}

async function readableSurface(client: AnsibleAapClient, name: string, endpoint: string): Promise<AnsibleAccessSurface> {
  try {
    return {
      name,
      endpoint,
      status: "readable",
      count: await client.count(endpoint),
    };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function checkAnsibleAccess(client: AnsibleAapClient): Promise<AnsibleAccessCheckResult> {
  const me = await client.get("/api/v2/me/");
  const currentUser = currentUserFromMe(me);
  const ping = await client.get<Record<string, unknown>>("/api/v2/ping/").catch(() => undefined);

  const surfaces = await Promise.all([
    readableSurface(client, "organizations", "/api/v2/organizations/"),
    readableSurface(client, "users", "/api/v2/users/"),
    readableSurface(client, "teams", "/api/v2/teams/"),
    readableSurface(client, "inventories", "/api/v2/inventories/"),
    readableSurface(client, "hosts", "/api/v2/hosts/"),
    readableSurface(client, "job_templates", "/api/v2/job_templates/"),
    readableSurface(client, "jobs", "/api/v2/jobs/"),
    readableSurface(client, "credentials", "/api/v2/credentials/"),
    readableSurface(client, "schedules", "/api/v2/schedules/"),
    readableSurface(client, "projects", "/api/v2/projects/"),
    readableSurface(client, "activity_stream", "/api/v2/activity_stream/"),
    readableSurface(client, "auth_settings", "/api/v2/settings/authentication/"),
  ]);

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = currentUser && readableCount >= 6 ? "healthy" : "limited";
  const notes = [
    currentUser
      ? `Authenticated as ${extractText(currentUser.username, extractText(currentUser.email, "current AAP user"))}.`
      : "Authentication succeeded but /api/v2/me/ did not return a recognizable user.",
    `${readableCount}/${surfaces.length} audit surfaces are readable.`,
  ];

  return {
    status,
    currentUser,
    ping,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run ansible_assess_job_health, ansible_assess_host_coverage, and ansible_assess_platform_security."
        : "Grant read-only auditor access to jobs, hosts, credentials, projects, organizations, activity stream, and settings.",
  };
}

export async function assessAnsibleJobHealth(
  client: Pick<AnsibleAapClient, "list" | "getNow">,
  options: {
    days?: number;
    jobLimit?: number;
    minSuccessRate?: number;
    maxManualRate?: number;
  } = {},
): Promise<AnsibleAssessmentResult> {
  const now = client.getNow();
  const days = clampNumber(options.days, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const since = new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
  const jobs = await client.list<Record<string, unknown>>(
    "/api/v2/jobs/",
    { type: "job", started__gt: since, order_by: "-started" },
    { limit: clampNumber(options.jobLimit, DEFAULT_JOB_LIMIT, 1, 5000) },
  );

  const total = jobs.length;
  const successful = jobs.filter((job) => isSuccessStatus(job.status)).length;
  const failed = jobs.filter((job) => isFailureStatus(job.status)).length;
  const manual = jobs.filter((job) => String(job.launch_type ?? "").toLowerCase() === "manual").length;
  const runningOrPending = jobs.filter((job) => ["running", "pending"].includes(String(job.status ?? "").toLowerCase())).length;
  const successRate = total === 0 ? 0 : (successful / total) * 100;
  const manualRate = total === 0 ? 0 : (manual / total) * 100;
  const minSuccessRate = options.minSuccessRate ?? 90;
  const maxManualRate = options.maxManualRate ?? 25;

  const byTemplate = new Map<string, { name: string; total: number; failed: number; recentFailures: number }>();
  for (const job of jobs) {
    const key = String(job.unified_job_template ?? job.job_template ?? job.name ?? "unknown");
    const name = extractText(job.name, key);
    const current = byTemplate.get(key) ?? { name, total: 0, failed: 0, recentFailures: 0 };
    current.total += 1;
    if (isFailureStatus(job.status)) {
      current.failed += 1;
      if (current.recentFailures === current.total - 1) current.recentFailures += 1;
    }
    byTemplate.set(key, current);
  }

  const chronicFailures = [...byTemplate.values()]
    .filter((template) => template.total >= 3 && (template.failed / template.total > 0.2 || template.recentFailures > 3))
    .sort((left, right) => right.failed / right.total - left.failed / left.total)
    .slice(0, 10);

  const findings = [
    finding(
      "AAP-JOB-01",
      "Job success rate",
      "high",
      total === 0 || successRate < minSuccessRate ? "fail" : "pass",
      total === 0
        ? `No job executions were visible in the last ${days} days.`
        : `${successful}/${total} jobs succeeded (${formatPercent(successRate)}).`,
      ["FedRAMP CA-7", "FedRAMP SI-2", "SOC 2 CC7.1", "CIS 16.12"],
      { total, successful, failed, success_rate: successRate, min_success_rate: minSuccessRate },
    ),
    finding(
      "AAP-JOB-02",
      "Chronic playbook failures",
      "high",
      chronicFailures.length > 0 ? "fail" : "pass",
      chronicFailures.length > 0
        ? `${chronicFailures.length} templates show repeated or high-rate failures.`
        : "No chronic job template failure pattern was detected in the sampled job history.",
      ["FedRAMP SI-2", "FedRAMP CA-5", "SOC 2 CC7.4", "CIS 7.4"],
      { templates: chronicFailures },
    ),
    finding(
      "AAP-JOB-03",
      "Manual launch rate",
      "medium",
      manualRate > maxManualRate ? "warn" : "pass",
      `${manual}/${total} jobs were launched manually (${formatPercent(manualRate)}).`,
      ["FedRAMP CM-3", "FedRAMP CM-5", "SOC 2 CC8.1", "CIS 4.1"],
      { manual, total, manual_rate: manualRate, max_manual_rate: maxManualRate },
    ),
    finding(
      "AAP-JOB-04",
      "Running or pending jobs",
      "medium",
      runningOrPending > 0 ? "warn" : "pass",
      runningOrPending > 0
        ? `${runningOrPending} jobs are currently running or pending in the sampled window.`
        : "No running or pending jobs appeared in the sampled history.",
      ["FedRAMP CA-7", "FedRAMP SI-4", "SOC 2 CC7.1"],
      { running_or_pending: runningOrPending },
    ),
  ];

  return {
    title: "Ansible AAP job execution health",
    summary: { days, total_jobs: total, successful, failed, success_rate: successRate, manual_rate: manualRate },
    findings,
  };
}

export async function assessAnsibleHostCoverage(
  client: Pick<AnsibleAapClient, "list" | "getNow">,
  options: {
    staleHostDays?: number;
    criticalStaleHostDays?: number;
    hostLimit?: number;
    inventorySourceLimit?: number;
  } = {},
): Promise<AnsibleAssessmentResult> {
  const now = client.getNow();
  const staleDays = clampNumber(options.staleHostDays, 30, 1, 365);
  const criticalDays = clampNumber(options.criticalStaleHostDays, 60, staleDays, 730);
  const hosts = await client.list<Record<string, unknown>>("/api/v2/hosts/", { order_by: "name" }, {
    limit: clampNumber(options.hostLimit, DEFAULT_HOST_LIMIT, 1, 10_000),
  });
  const inventorySources = await client.list<Record<string, unknown>>("/api/v2/inventory_sources/", {}, {
    limit: clampNumber(options.inventorySourceLimit, 200, 1, 5000),
  }).catch(() => []);

  const unmanaged = hosts.filter((host) => !host.last_job && !host.last_job_host_summary);
  const disabled = hosts.filter((host) => host.enabled === false);
  const stale = hosts.filter((host) => {
    const age = daysBetween(now, extractTimestamp(host.last_job_host_summary) ?? extractTimestamp(host.last_job));
    return age !== undefined && age > staleDays;
  });
  const criticalStale = hosts.filter((host) => {
    const age = daysBetween(now, extractTimestamp(host.last_job_host_summary) ?? extractTimestamp(host.last_job));
    return age !== undefined && age > criticalDays;
  });
  const unhealthySources = inventorySources.filter((source) => {
    const status = String(source.status ?? "").toLowerCase();
    const age = daysBetween(now, extractTimestamp(source.last_updated) ?? extractTimestamp(source.modified));
    return ["failed", "error"].includes(status) || (age !== undefined && age > staleDays);
  });
  const disabledRate = hosts.length === 0 ? 0 : (disabled.length / hosts.length) * 100;

  const findings = [
    finding(
      "AAP-HOST-01",
      "Unmanaged hosts",
      "critical",
      unmanaged.length > 0 ? "fail" : "pass",
      unmanaged.length > 0
        ? `${unmanaged.length}/${hosts.length} hosts have no visible job history.`
        : "Every sampled host has visible job history.",
      ["FedRAMP CM-8", "FedRAMP CM-8(1)", "SOC 2 CC6.1", "CIS 1.1"],
      { count: unmanaged.length, sample: unmanaged.slice(0, 10).map((host) => host.name ?? host.id) },
    ),
    finding(
      "AAP-HOST-02",
      "Stale host coverage",
      criticalStale.length > 0 ? "critical" : "high",
      stale.length > 0 ? "fail" : "pass",
      stale.length > 0
        ? `${stale.length}/${hosts.length} hosts have no run in more than ${staleDays} days; ${criticalStale.length} exceed ${criticalDays} days.`
        : `No sampled host exceeded the ${staleDays}-day stale coverage threshold.`,
      ["FedRAMP CM-8", "FedRAMP SI-2", "SOC 2 CC6.1", "CIS 7.4"],
      { stale_count: stale.length, critical_stale_count: criticalStale.length },
    ),
    finding(
      "AAP-HOST-03",
      "Inventory source sync health",
      "medium",
      unhealthySources.length > 0 ? "warn" : "pass",
      unhealthySources.length > 0
        ? `${unhealthySources.length}/${inventorySources.length} inventory sources are failed or stale.`
        : "No failed or stale inventory sources were detected.",
      ["FedRAMP CM-8(2)", "SOC 2 CC6.1", "CIS 1.1"],
      { count: unhealthySources.length, sample: unhealthySources.slice(0, 10).map((source) => source.name ?? source.id) },
    ),
    finding(
      "AAP-HOST-04",
      "Disabled hosts",
      "low",
      disabledRate > 5 ? "warn" : "pass",
      `${disabled.length}/${hosts.length} hosts are disabled (${formatPercent(disabledRate)}).`,
      ["FedRAMP CM-8", "SOC 2 CC6.1", "CIS 1.1"],
      { disabled_count: disabled.length, disabled_rate: disabledRate },
    ),
  ];

  return {
    title: "Ansible AAP host coverage",
    summary: {
      total_hosts: hosts.length,
      unmanaged_hosts: unmanaged.length,
      stale_hosts: stale.length,
      critical_stale_hosts: criticalStale.length,
      inventory_sources: inventorySources.length,
    },
    findings,
  };
}

function hasExternalAuth(settings: Record<string, unknown>): boolean {
  return Object.entries(settings).some(([key, value]) => {
    const normalizedKey = key.toLowerCase();
    if (!normalizedKey.includes("ldap") && !normalizedKey.includes("saml") && !normalizedKey.includes("oidc")) {
      return false;
    }
    if (typeof value === "string") return value.trim().length > 0;
    if (typeof value === "boolean") return value;
    if (Array.isArray(value)) return value.length > 0;
    const object = asObject(value);
    if (object) return Object.values(object).some((entry) => Boolean(entry));
    return Boolean(value);
  });
}

export async function assessAnsiblePlatformSecurity(
  client: Pick<AnsibleAapClient, "list" | "get" | "getNow">,
  options: {
    maxOrgAdmins?: number;
    staleCredentialDays?: number;
    staleTokenDays?: number;
    projectLimit?: number;
  } = {},
): Promise<AnsibleAssessmentResult> {
  const now = client.getNow();
  const maxOrgAdmins = clampNumber(options.maxOrgAdmins, 3, 1, 50);
  const staleCredentialDays = clampNumber(options.staleCredentialDays, 90, 1, 730);
  const staleTokenDays = clampNumber(options.staleTokenDays, 90, 1, 730);
  const organizations = await client.list<Record<string, unknown>>("/api/v2/organizations/");
  const credentials = await client.list<Record<string, unknown>>("/api/v2/credentials/").catch(() => []);
  const tokens = await client.list<Record<string, unknown>>("/api/v2/tokens/").catch(() => []);
  const projects = await client.list<Record<string, unknown>>("/api/v2/projects/", {}, {
    limit: clampNumber(options.projectLimit, 500, 1, 5000),
  }).catch(() => []);
  const notificationTemplates = await client.list<Record<string, unknown>>("/api/v2/notification_templates/").catch(() => []);
  const activity = await client.list<Record<string, unknown>>("/api/v2/activity_stream/", { order_by: "-timestamp" }, { limit: 10 }).catch(() => []);
  const authSettings = await client.get<Record<string, unknown>>("/api/v2/settings/authentication/").catch(() => ({}));

  const orgAdminCounts = [];
  for (const org of organizations) {
    const id = org.id;
    if (id === undefined || id === null) continue;
    const admins = await client.list<Record<string, unknown>>(`/api/v2/organizations/${id}/admins/`, {}, {
      limit: maxOrgAdmins + 20,
    }).catch(() => []);
    orgAdminCounts.push({ id, name: org.name ?? org.summary_fields, count: admins.length });
  }
  const excessiveAdmins = orgAdminCounts.filter((org) => org.count > maxOrgAdmins);
  const staleCredentials = credentials.filter((credential) => {
    const age = daysBetween(now, extractTimestamp(credential.modified) ?? extractTimestamp(credential.created));
    return age !== undefined && age > staleCredentialDays;
  });
  const riskyTokens = tokens.filter((token) => {
    const expires = extractTimestamp(token.expires);
    const createdAge = daysBetween(now, extractTimestamp(token.created));
    return !expires || (createdAge !== undefined && createdAge > staleTokenDays);
  });
  const manualOrFailedProjects = projects.filter((project) => {
    const scmType = String(project.scm_type ?? "").toLowerCase();
    return scmType === "" || scmType === "manual" || project.last_update_failed === true;
  });
  const latestActivityAge = daysBetween(now, extractTimestamp(activity[0]?.timestamp) ?? extractTimestamp(activity[0]?.created));
  const externalAuth = hasExternalAuth(authSettings);

  const findings = [
    finding(
      "AAP-RBAC-01",
      "Organization admin count",
      "high",
      excessiveAdmins.length > 0 ? "fail" : "pass",
      excessiveAdmins.length > 0
        ? `${excessiveAdmins.length} organizations exceed ${maxOrgAdmins} admins.`
        : `No organization exceeded ${maxOrgAdmins} admins in the sampled data.`,
      ["FedRAMP AC-6(5)", "SOC 2 CC6.3", "CIS 5.4"],
      { organizations: orgAdminCounts },
    ),
    finding(
      "AAP-RBAC-02",
      "External authentication enforcement",
      "critical",
      externalAuth ? "pass" : "fail",
      externalAuth
        ? "LDAP, SAML, or OIDC-related authentication settings are present."
        : "No LDAP, SAML, or OIDC authentication setting was detected.",
      ["FedRAMP IA-2", "FedRAMP IA-8", "SOC 2 CC6.1", "CIS 5.6"],
      { detected_keys: Object.keys(authSettings).filter((key) => /ldap|saml|oidc/i.test(key)) },
    ),
    finding(
      "AAP-AUDIT-01",
      "Activity stream retention",
      "high",
      activity.length === 0 || (latestActivityAge !== undefined && latestActivityAge > 1) ? "fail" : "pass",
      activity.length === 0
        ? "No activity stream records were visible."
        : `Latest activity stream record is ${latestActivityAge?.toFixed(1) ?? "unknown"} days old.`,
      ["FedRAMP AU-2", "FedRAMP AU-9", "SOC 2 CC7.2", "CIS 8.2"],
      { visible_activity_records: activity.length, latest_activity_age_days: latestActivityAge },
    ),
    finding(
      "AAP-CRED-01",
      "Stale credentials",
      "high",
      staleCredentials.length > 0 ? "fail" : "pass",
      staleCredentials.length > 0
        ? `${staleCredentials.length}/${credentials.length} credentials are older than ${staleCredentialDays} days.`
        : `No visible credentials exceeded ${staleCredentialDays} days since modification.`,
      ["FedRAMP IA-5", "FedRAMP IA-5(1)", "SOC 2 CC6.1", "CIS 5.2"],
      { count: staleCredentials.length, sample: staleCredentials.slice(0, 10).map((credential) => credential.name ?? credential.id) },
    ),
    finding(
      "AAP-CRED-02",
      "OAuth2 token hygiene",
      "medium",
      riskyTokens.length > 0 ? "warn" : "pass",
      riskyTokens.length > 0
        ? `${riskyTokens.length}/${tokens.length} tokens are missing expiration or older than ${staleTokenDays} days.`
        : "No missing-expiration or stale OAuth2 tokens were visible.",
      ["FedRAMP IA-5(13)", "FedRAMP AC-2(3)", "SOC 2 CC6.1"],
      { count: riskyTokens.length },
    ),
    finding(
      "AAP-PROJ-01",
      "Project SCM health",
      "medium",
      manualOrFailedProjects.length > 0 ? "warn" : "pass",
      manualOrFailedProjects.length > 0
        ? `${manualOrFailedProjects.length}/${projects.length} projects use manual SCM or have failed updates.`
        : "Visible projects have SCM configuration without failed latest updates.",
      ["FedRAMP CM-2", "FedRAMP SA-10", "SOC 2 CC8.1", "CIS 4.8"],
      { count: manualOrFailedProjects.length, sample: manualOrFailedProjects.slice(0, 10).map((project) => project.name ?? project.id) },
    ),
    finding(
      "AAP-AUDIT-02",
      "Notification coverage",
      "medium",
      notificationTemplates.length === 0 ? "warn" : "pass",
      notificationTemplates.length === 0
        ? "No notification templates were visible for failure or operational alerting."
        : `${notificationTemplates.length} notification templates were visible.`,
      ["FedRAMP SI-4", "FedRAMP IR-5", "SOC 2 CC7.2", "CIS 8.11"],
      { notification_template_count: notificationTemplates.length },
    ),
  ];

  return {
    title: "Ansible AAP platform security",
    summary: {
      organizations: organizations.length,
      credentials: credentials.length,
      tokens: tokens.length,
      projects: projects.length,
      notification_templates: notificationTemplates.length,
      external_auth: externalAuth,
    },
    findings,
  };
}

function formatAccessCheckText(result: AnsibleAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Ansible AAP access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AnsibleAssessmentResult): string {
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

function buildExecutiveSummary(
  config: AnsibleAapConfiguration,
  assessments: AnsibleAssessmentResult[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# Ansible AAP Audit Bundle",
    "",
    `Target: ${config.baseUrl}`,
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

function buildControlMatrix(findings: AnsibleFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Ansible AAP Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Ansible AAP Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Ansible Automation Platform tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible AAP audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Secrets are not written to this bundle. AAP passwords must come from `AAP_PASSWORD` and are never accepted as tool arguments.",
  ].join("\n");
}

export async function exportAnsibleAuditBundle(
  client: AnsibleAapClient,
  config: AnsibleAapConfiguration,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AnsibleAuditBundleResult> {
  const access = await checkAnsibleAccess(client);
  const jobHealth = await assessAnsibleJobHealth(client, {
    days: options.days,
    jobLimit: options.job_limit,
    minSuccessRate: options.min_success_rate,
    maxManualRate: options.max_manual_rate,
  });
  const hostCoverage = await assessAnsibleHostCoverage(client, {
    staleHostDays: options.stale_host_days,
    criticalStaleHostDays: options.critical_stale_host_days,
    hostLimit: options.host_limit,
  });
  const platformSecurity = await assessAnsiblePlatformSecurity(client, {
    maxOrgAdmins: options.max_org_admins,
    staleCredentialDays: options.stale_credential_days,
    staleTokenDays: options.stale_token_days,
  });

  const assessments = [jobHealth, hostCoverage, platformSecurity];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${new URL(config.baseUrl).host}-ansible-aap-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    target: config.baseUrl,
    auth_mode: config.token ? "token" : "session",
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      days: options.days ?? DEFAULT_LOOKBACK_DAYS,
      job_limit: options.job_limit ?? DEFAULT_JOB_LIMIT,
      host_limit: options.host_limit ?? DEFAULT_HOST_LIMIT,
      min_success_rate: options.min_success_rate ?? 90,
      max_manual_rate: options.max_manual_rate ?? 25,
      stale_host_days: options.stale_host_days ?? 30,
      critical_stale_host_days: options.critical_stale_host_days ?? 60,
      max_org_admins: options.max_org_admins ?? 3,
      stale_credential_days: options.stale_credential_days ?? 90,
      stale_token_days: options.stale_token_days ?? 90,
    },
  }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments));
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", buildControlMatrix(findings));
  await writeSecureTextFile(outputDir, "reports/job-health.md", formatAssessmentText(jobHealth));
  await writeSecureTextFile(outputDir, "reports/host-coverage.md", formatAssessmentText(hostCoverage));
  await writeSecureTextFile(outputDir, "reports/platform-security.md", formatAssessmentText(platformSecurity));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/job-health.json", serializeJson(jobHealth));
  await writeSecureTextFile(outputDir, "analysis/host-coverage.json", serializeJson(hostCoverage));
  await writeSecureTextFile(outputDir, "analysis/platform-security.json", serializeJson(platformSecurity));
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
    url: asString(value.url) ?? asString(value.base_url),
    username: asString(value.username),
    token: asString(value.token),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeJobHealthArgs(args: unknown): JobHealthArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    days: asNumber(value.days),
    job_limit: asNumber(value.job_limit),
    min_success_rate: asNumber(value.min_success_rate),
    max_manual_rate: asNumber(value.max_manual_rate),
  };
}

function normalizeHostCoverageArgs(args: unknown): HostCoverageArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    stale_host_days: asNumber(value.stale_host_days),
    critical_stale_host_days: asNumber(value.critical_stale_host_days),
    host_limit: asNumber(value.host_limit),
    inventory_source_limit: asNumber(value.inventory_source_limit),
  };
}

function normalizePlatformSecurityArgs(args: unknown): PlatformSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_org_admins: asNumber(value.max_org_admins),
    stale_credential_days: asNumber(value.stale_credential_days),
    stale_token_days: asNumber(value.stale_token_days),
    project_limit: asNumber(value.project_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    days: asNumber(value.days),
    job_limit: asNumber(value.job_limit),
    host_limit: asNumber(value.host_limit),
    min_success_rate: asNumber(value.min_success_rate),
    max_manual_rate: asNumber(value.max_manual_rate),
    stale_host_days: asNumber(value.stale_host_days),
    critical_stale_host_days: asNumber(value.critical_stale_host_days),
    max_org_admins: asNumber(value.max_org_admins),
    stale_credential_days: asNumber(value.stale_credential_days),
    stale_token_days: asNumber(value.stale_token_days),
  };
}

function createClient(args: CheckAccessArgs): AnsibleAapClient {
  return new AnsibleAapClient(
    resolveAnsibleConfiguration({
      url: args.url,
      username: args.username,
      token: args.token,
      timeout_seconds: args.timeout_seconds,
    }),
  );
}

const authParams = {
  url: Type.Optional(Type.String({ description: "AAP base URL. Defaults to AAP_URL." })),
  username: Type.Optional(Type.String({ description: "AAP username for session auth. Defaults to AAP_USERNAME. Password must come from AAP_PASSWORD." })),
  token: Type.Optional(Type.String({ description: "AAP OAuth2 bearer token. Defaults to AAP_TOKEN." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "Request timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerAnsibleTools(pi: any): void {
  pi.registerTool({
    name: "ansible_check_access",
    label: "Check Ansible AAP audit access",
    description:
      "Validate read-only Ansible Automation Platform API access and show which job, host, credential, RBAC, and audit surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAnsibleAccess(createClient(args));
        return textResult(formatAccessCheckText(result), {
          tool: "ansible_check_access",
          ...result,
        });
      } catch (error) {
        return errorResult(
          `Ansible AAP access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "ansible_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_job_health",
    label: "Assess Ansible AAP job health",
    description:
      "Assess Ansible Automation Platform job execution health, including success rate, chronic template failures, manual launch rate, and running or pending jobs.",
    parameters: Type.Object({
      ...authParams,
      days: Type.Optional(Type.Number({ description: "Lookback window in days. Defaults to 90.", default: 90 })),
      job_limit: Type.Optional(Type.Number({ description: "Maximum jobs to sample. Defaults to 500.", default: 500 })),
      min_success_rate: Type.Optional(Type.Number({ description: "Minimum acceptable job success percentage. Defaults to 90.", default: 90 })),
      max_manual_rate: Type.Optional(Type.Number({ description: "Maximum acceptable manual launch percentage. Defaults to 25.", default: 25 })),
    }),
    prepareArguments: normalizeJobHealthArgs,
    async execute(_toolCallId: string, args: JobHealthArgs) {
      try {
        const result = await assessAnsibleJobHealth(createClient(args), {
          days: args.days,
          jobLimit: args.job_limit,
          minSuccessRate: args.min_success_rate,
          maxManualRate: args.max_manual_rate,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_job_health", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP job health assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "ansible_assess_job_health" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_host_coverage",
    label: "Assess Ansible AAP host coverage",
    description:
      "Assess Ansible Automation Platform host coverage, unmanaged hosts, stale automation coverage, inventory source sync health, and disabled host rate.",
    parameters: Type.Object({
      ...authParams,
      stale_host_days: Type.Optional(Type.Number({ description: "High stale-host threshold in days. Defaults to 30.", default: 30 })),
      critical_stale_host_days: Type.Optional(Type.Number({ description: "Critical stale-host threshold in days. Defaults to 60.", default: 60 })),
      host_limit: Type.Optional(Type.Number({ description: "Maximum hosts to sample. Defaults to 1000.", default: 1000 })),
      inventory_source_limit: Type.Optional(Type.Number({ description: "Maximum inventory sources to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeHostCoverageArgs,
    async execute(_toolCallId: string, args: HostCoverageArgs) {
      try {
        const result = await assessAnsibleHostCoverage(createClient(args), {
          staleHostDays: args.stale_host_days,
          criticalStaleHostDays: args.critical_stale_host_days,
          hostLimit: args.host_limit,
          inventorySourceLimit: args.inventory_source_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_host_coverage", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP host coverage assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "ansible_assess_host_coverage" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_platform_security",
    label: "Assess Ansible AAP platform security",
    description:
      "Assess Ansible Automation Platform RBAC, external auth, activity stream, credential age, OAuth2 token hygiene, project SCM health, and notification coverage.",
    parameters: Type.Object({
      ...authParams,
      max_org_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per organization. Defaults to 3.", default: 3 })),
      stale_credential_days: Type.Optional(Type.Number({ description: "Credential age threshold in days. Defaults to 90.", default: 90 })),
      stale_token_days: Type.Optional(Type.Number({ description: "OAuth2 token age threshold in days. Defaults to 90.", default: 90 })),
      project_limit: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizePlatformSecurityArgs,
    async execute(_toolCallId: string, args: PlatformSecurityArgs) {
      try {
        const result = await assessAnsiblePlatformSecurity(createClient(args), {
          maxOrgAdmins: args.max_org_admins,
          staleCredentialDays: args.stale_credential_days,
          staleTokenDays: args.stale_token_days,
          projectLimit: args.project_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_platform_security", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP platform security assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "ansible_assess_platform_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_export_audit_bundle",
    label: "Export Ansible AAP audit bundle",
    description:
      "Export an Ansible Automation Platform audit package with access checks, job health, host coverage, platform-security findings, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      days: Type.Optional(Type.Number({ description: "Lookback window in days. Defaults to 90.", default: 90 })),
      job_limit: Type.Optional(Type.Number({ description: "Maximum jobs to sample. Defaults to 500.", default: 500 })),
      host_limit: Type.Optional(Type.Number({ description: "Maximum hosts to sample. Defaults to 1000.", default: 1000 })),
      min_success_rate: Type.Optional(Type.Number({ description: "Minimum acceptable job success percentage. Defaults to 90.", default: 90 })),
      max_manual_rate: Type.Optional(Type.Number({ description: "Maximum acceptable manual launch percentage. Defaults to 25.", default: 25 })),
      stale_host_days: Type.Optional(Type.Number({ description: "High stale-host threshold in days. Defaults to 30.", default: 30 })),
      critical_stale_host_days: Type.Optional(Type.Number({ description: "Critical stale-host threshold in days. Defaults to 60.", default: 60 })),
      max_org_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per organization. Defaults to 3.", default: 3 })),
      stale_credential_days: Type.Optional(Type.Number({ description: "Credential age threshold in days. Defaults to 90.", default: 90 })),
      stale_token_days: Type.Optional(Type.Number({ description: "OAuth2 token age threshold in days. Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAnsibleConfiguration({
          url: args.url,
          username: args.username,
          token: args.token,
          timeout_seconds: args.timeout_seconds,
        });
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAnsibleAuditBundle(
          new AnsibleAapClient(config),
          config,
          outputRoot,
          args,
        );
        return textResult(
          [
            "Ansible AAP audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "ansible_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Ansible AAP audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "ansible_export_audit_bundle" },
        );
      }
    },
  });
}
