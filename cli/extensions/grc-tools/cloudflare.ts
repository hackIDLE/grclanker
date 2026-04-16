/**
 * Cloudflare security posture tools for grclanker.
 *
 * This first slice stays read-only and focuses on token access validation,
 * account and Zero Trust identity posture, zone TLS and DNS security, traffic
 * controls, and exportable evidence bundles.
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

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/cloudflare";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_ZONE_LIMIT = 20;
const DEFAULT_MEMBER_LIMIT = 200;
const DEFAULT_TOKEN_LIMIT = 200;
const DEFAULT_AUDIT_LIMIT = 200;
const DEFAULT_PAGE_SIZE = 50;
const DEFAULT_MAX_SUPER_ADMINS = 2;

export interface CloudflareResolvedConfig {
  apiToken?: string;
  apiKey?: string;
  email?: string;
  accountId?: string;
  baseUrl: string;
  timeoutMs: number;
  authMethod: "token" | "global_key";
  sourceChain: string[];
}

export interface CloudflareAccessSurface {
  name: string;
  scope: "user" | "account" | "zone";
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface CloudflareAccessCheckResult {
  status: "healthy" | "limited";
  authMethod: CloudflareResolvedConfig["authMethod"];
  accountId?: string;
  surfaces: CloudflareAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface CloudflareFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface CloudflareAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: CloudflareFinding[];
}

export interface CloudflareAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  api_token?: string;
  api_key?: string;
  email?: string;
  account_id?: string;
  base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  max_super_admins?: number;
  member_limit?: number;
  token_limit?: number;
  zone_limit?: number;
};

type ZoneSecurityArgs = CheckAccessArgs & {
  zone_limit?: number;
};

type TrafficArgs = CheckAccessArgs & {
  zone_limit?: number;
  audit_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  max_super_admins?: number;
  member_limit?: number;
  token_limit?: number;
  zone_limit?: number;
  audit_limit?: number;
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
    if (/^(true|1|yes|on|enabled|active)$/i.test(value.trim())) return true;
    if (/^(false|0|no|off|disabled|inactive)$/i.test(value.trim())) return false;
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
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
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
  return normalized || "cloudflare";
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
  await chmod(zipPath, 0o600);
}

async function countFilesRecursively(rootDir: string): Promise<number> {
  let total = 0;
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      total += await countFilesRecursively(pathname);
    } else if (entry.isFile()) {
      total += 1;
    }
  }
  return total;
}

export function resolveCloudflareConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): CloudflareResolvedConfig {
  const sourceChain: string[] = [];
  const apiToken = asString(input.api_token)
    ?? asString(input.token)
    ?? asString(env.CLOUDFLARE_API_TOKEN);
  if (apiToken) {
    sourceChain.push(asString(input.api_token) || asString(input.token) ? "arguments-api-token" : "environment-api-token");
  }

  const apiKey = asString(input.api_key)
    ?? asString(env.CLOUDFLARE_API_KEY);
  const email = asString(input.email)
    ?? asString(env.CLOUDFLARE_EMAIL);

  if (!apiToken && !(apiKey && email)) {
    throw new Error("Provide CLOUDFLARE_API_TOKEN or the CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY pair.");
  }

  if (!apiToken) {
    sourceChain.push(asString(input.api_key) ? "arguments-api-key" : "environment-api-key");
    sourceChain.push(asString(input.email) ? "arguments-email" : "environment-email");
  }

  const accountId = asString(input.account_id)
    ?? asString(env.CLOUDFLARE_ACCOUNT_ID);
  if (accountId) sourceChain.push(asString(input.account_id) ? "arguments-account-id" : "environment-account-id");

  const baseUrl = normalizeBaseUrl(
    asString(input.base_url) ?? asString(env.CLOUDFLARE_API_BASE_URL) ?? "https://api.cloudflare.com/client/v4",
  );
  if (asString(input.base_url)) sourceChain.push("arguments-base-url");
  else if (asString(env.CLOUDFLARE_API_BASE_URL)) sourceChain.push("environment-base-url");
  else sourceChain.push("default-base-url");

  return {
    apiToken,
    apiKey,
    email,
    accountId,
    baseUrl,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.CLOUDFLARE_TIMEOUT)),
    authMethod: apiToken ? "token" : "global_key",
    sourceChain: [...new Set(sourceChain)],
  };
}

function buildHeaders(config: CloudflareResolvedConfig): Record<string, string> {
  if (config.authMethod === "token" && config.apiToken) {
    return {
      accept: "application/json",
      authorization: `Bearer ${config.apiToken}`,
    };
  }

  return {
    accept: "application/json",
    "x-auth-email": config.email ?? "",
    "x-auth-key": config.apiKey ?? "",
  };
}

function extractResultArray(payload: unknown): JsonRecord[] {
  const object = asObject(payload);
  const result = asObject(object?.result);
  if (Array.isArray(object?.result)) {
    return object.result.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  if (Array.isArray(result?.items)) {
    return result.items.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  if (Array.isArray(result?.records)) {
    return result.records.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  return [];
}

function extractResultObject(payload: unknown): JsonRecord | undefined {
  const object = asObject(payload);
  return asObject(object?.result) ?? object;
}

function cloudflareErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  const errors = asArray(object?.errors)
    .map((item) => {
      const record = asObject(item);
      return asString(record?.message) ?? asString(record?.error);
    })
    .filter((item): item is string => Boolean(item));
  return errors.length > 0 ? errors.join("; ") : undefined;
}

export class CloudflareApiClient {
  private readonly config: CloudflareResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    config: CloudflareResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): CloudflareResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(`${this.config.baseUrl}${normalizedPath}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async requestJson(
    path: string,
    options: {
      query?: JsonRecord;
      allow404?: boolean;
    } = {},
  ): Promise<JsonRecord | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await this.fetchImpl(this.buildUrl(path, options.query), {
        method: "GET",
        headers: buildHeaders(this.config),
        signal: controller.signal,
      });

      const rawText = await response.text();
      const payload = rawText.length > 0 ? JSON.parse(rawText) as JsonRecord : {};

      if (response.status === 404 && options.allow404) {
        return null;
      }

      if (!response.ok) {
        const detail = cloudflareErrorSummary(payload) ?? rawText.slice(0, 240);
        throw new Error(`Cloudflare request failed for ${path} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`);
      }

      if (payload.success === false) {
        throw new Error(cloudflareErrorSummary(payload) ?? `Cloudflare API reported failure for ${path}.`);
      }

      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async listPaginated(
    path: string,
    options: {
      query?: JsonRecord;
      allow404?: boolean;
      limit?: number;
      perPage?: number;
    } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_PAGE_SIZE, 1, 5000);
    const perPage = clampNumber(options.perPage, DEFAULT_PAGE_SIZE, 1, 100);
    const results: JsonRecord[] = [];

    for (let page = 1; results.length < limit; page += 1) {
      const payload = await this.requestJson(path, {
        query: {
          page,
          per_page: perPage,
          ...options.query,
        },
        allow404: options.allow404,
      });

      if (payload === null) return [];
      const pageItems = extractResultArray(payload);
      results.push(...pageItems.slice(0, limit - results.length));

      const resultInfo = asObject(payload.result_info);
      const totalPages = asNumber(resultInfo?.total_pages);
      if (pageItems.length === 0 || (totalPages !== undefined && page >= totalPages) || pageItems.length < perPage) {
        break;
      }
    }

    return results;
  }

  async verifyCurrentToken(): Promise<JsonRecord | null> {
    return this.requestJson("/user/tokens/verify", { allow404: true });
  }

  async listAccounts(limit = DEFAULT_PAGE_SIZE): Promise<JsonRecord[]> {
    return this.listPaginated("/accounts", { limit });
  }

  async listZones(limit = DEFAULT_ZONE_LIMIT): Promise<JsonRecord[]> {
    return this.listPaginated("/zones", {
      limit,
      query: this.config.accountId ? { "account.id": this.config.accountId } : {},
    });
  }

  async listUserTokens(limit = DEFAULT_TOKEN_LIMIT): Promise<JsonRecord[]> {
    return this.listPaginated("/user/tokens", { limit, allow404: true });
  }

  async getZoneSettings(zoneId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/zones/${encodeURIComponent(zoneId)}/settings`, { allow404: true, perPage: 100, limit: 100 });
  }

  async listFirewallRules(zoneId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/zones/${encodeURIComponent(zoneId)}/firewall/rules`, { allow404: true, limit: 200 });
  }

  async listZoneRulesets(zoneId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/zones/${encodeURIComponent(zoneId)}/rulesets`, { allow404: true, limit: 200 });
  }

  async getDnssec(zoneId: string): Promise<JsonRecord | null> {
    return this.requestJson(`/zones/${encodeURIComponent(zoneId)}/dnssec`, { allow404: true }).then((payload) => extractResultObject(payload) ?? null);
  }

  async listRateLimits(zoneId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/zones/${encodeURIComponent(zoneId)}/rate_limits`, { allow404: true, limit: 200 });
  }

  async listPageRules(zoneId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/zones/${encodeURIComponent(zoneId)}/pagerules`, { allow404: true, limit: 200 });
  }

  async getBotManagement(zoneId: string): Promise<JsonRecord | null> {
    return this.requestJson(`/zones/${encodeURIComponent(zoneId)}/bot_management`, { allow404: true }).then((payload) => extractResultObject(payload) ?? null);
  }

  async getUniversalSslSettings(zoneId: string): Promise<JsonRecord | null> {
    return this.requestJson(`/zones/${encodeURIComponent(zoneId)}/ssl/universal/settings`, { allow404: true }).then((payload) => extractResultObject(payload) ?? null);
  }

  async listAccessApplications(accountId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/access/apps`, { allow404: true, limit: 200 });
  }

  async listAccessPolicies(accountId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/access/policies`, { allow404: true, limit: 200 });
  }

  async listIdentityProviders(accountId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/access/identity_providers`, { allow404: true, limit: 100 });
  }

  async listGatewayRules(accountId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/gateway/rules`, { allow404: true, limit: 200 });
  }

  async listAuditLogs(accountId: string, limit = DEFAULT_AUDIT_LIMIT): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/audit_logs`, { allow404: true, limit });
  }

  async listMembers(accountId: string, limit = DEFAULT_MEMBER_LIMIT): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/members`, { allow404: true, limit });
  }

  async listIpAccessRules(accountId: string): Promise<JsonRecord[]> {
    return this.listPaginated(`/accounts/${encodeURIComponent(accountId)}/firewall/access_rules/rules`, { allow404: true, limit: 200 });
  }
}

function finding(
  id: string,
  title: string,
  severity: CloudflareFinding["severity"],
  status: CloudflareFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): CloudflareFinding {
  return { id, title, severity, status, summary, evidence, mappings };
}

function deriveAccountContext(
  config: CloudflareResolvedConfig,
  accounts: JsonRecord[],
): { accountId?: string; note: string } {
  if (config.accountId) {
    return { accountId: config.accountId, note: `Using configured account ${config.accountId}.` };
  }

  const soleId = asString(accounts[0]?.id);
  if (accounts.length === 1 && soleId) {
    return { accountId: soleId, note: `Using the only visible Cloudflare account ${soleId}.` };
  }

  if (accounts.length === 0) {
    return { accountId: undefined, note: "No Cloudflare account context was visible; account-scoped checks will stay limited." };
  }

  return {
    accountId: undefined,
    note: "Multiple Cloudflare accounts were visible with no account_id selected; account-scoped checks will stay limited.",
  };
}

async function readableSurface(
  name: string,
  scope: CloudflareAccessSurface["scope"],
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<CloudflareAccessSurface> {
  try {
    const value = await load();
    return {
      name,
      scope,
      endpoint,
      status: "readable",
      count: countResolver?.(value),
    };
  } catch (error) {
    return {
      name,
      scope,
      endpoint,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function notConfiguredSurface(
  name: string,
  scope: CloudflareAccessSurface["scope"],
  endpoint: string,
  error: string,
): CloudflareAccessSurface {
  return {
    name,
    scope,
    endpoint,
    status: "not_configured",
    error,
  };
}

function zoneName(zone: JsonRecord): string {
  return asString(zone.name) ?? asString(zone.id) ?? "unknown-zone";
}

function settingMap(settings: JsonRecord[]): Map<string, unknown> {
  return new Map(
    settings
      .map((item) => {
        const id = asString(item.id);
        return id ? [id, item.value] as const : undefined;
      })
      .filter((item): item is readonly [string, unknown] => Boolean(item)),
  );
}

function isEnabled(value: unknown): boolean {
  return asBoolean(value) === true || /^(on|active|enabled|strict)$/i.test(asString(value) ?? "");
}

function isStrictSsl(value: unknown): boolean {
  return /strict/i.test(asString(value) ?? "");
}

function minTlsAtLeast12(value: unknown): boolean {
  const numeric = asNumber(value);
  if (numeric !== undefined) return numeric >= 1.2;
  const text = asString(value);
  return text ? Number(text) >= 1.2 : false;
}

function hstsEnabled(value: unknown): boolean {
  const object = asObject(value);
  const nested = asObject(object?.strict_transport_security);
  return isEnabled(nested?.enabled ?? nested?.value ?? object?.enabled ?? value);
}

function extractPolicies(value: unknown): unknown[] {
  const object = asObject(value);
  if (Array.isArray(object?.policies)) return object.policies;
  const result = asObject(object?.result);
  if (Array.isArray(result?.policies)) return result.policies;
  return [];
}

function extractTokenStatus(value: unknown): string | undefined {
  const object = asObject(value);
  return asString(object?.status) ?? asString(asObject(object?.result)?.status);
}

function collectMemberRoleNames(member: JsonRecord): string[] {
  const values = [
    asString(member.role),
    asString(member.access_role),
    ...asArray(member.roles).map((item) => asString(asObject(item)?.name) ?? asString(item)),
  ];
  return values.filter((item): item is string => Boolean(item));
}

function pageRuleIsRisky(rule: JsonRecord): boolean {
  const targets = JSON.stringify(rule.targets ?? rule.target ?? rule.priority ?? "").toLowerCase();
  const actions = asArray(rule.actions)
    .map((item) => {
      const action = asObject(item);
      const id = asString(action?.id);
      const value = asString(action?.value);
      return id && value ? `${id}:${value}`.toLowerCase() : id?.toLowerCase();
    })
    .filter((item): item is string => Boolean(item));

  return actions.some((item) =>
    item.includes("disable_security")
    || item.includes("security_level:essentially_off")
    || item.includes("always_use_https:off")
    || ((targets.includes("login") || targets.includes("auth") || targets.includes("admin") || targets.includes("api"))
      && item.includes("cache_level:cache_everything"))
  );
}

function rulesetsProvideManagedProtection(rulesets: JsonRecord[]): boolean {
  return rulesets.some((ruleset) => {
    const phase = asString(ruleset.phase)?.toLowerCase() ?? "";
    const kind = asString(ruleset.kind)?.toLowerCase() ?? "";
    return phase.includes("firewall") || kind.includes("managed");
  });
}

export async function checkCloudflareAccess(
  client: Pick<
    CloudflareApiClient,
    "getResolvedConfig" | "verifyCurrentToken" | "listAccounts" | "listZones" | "getZoneSettings" | "getDnssec" | "listMembers" | "listAccessApplications" | "listAuditLogs"
  >,
): Promise<CloudflareAccessCheckResult> {
  const config = client.getResolvedConfig();
  const [verify, accounts, zones] = await Promise.all([
    client.verifyCurrentToken().catch(() => null),
    client.listAccounts(),
    client.listZones(),
  ]);
  const { accountId, note } = deriveAccountContext(config, accounts);
  const firstZoneId = asString(zones[0]?.id);

  const surfaces: CloudflareAccessSurface[] = [
    await readableSurface("token_verify", "user", "/user/tokens/verify", () => client.verifyCurrentToken(), () => verify ? 1 : 0),
    await readableSurface("accounts", "account", "/accounts", () => client.listAccounts(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("zones", "zone", "/zones", () => client.listZones(), (value) => Array.isArray(value) ? value.length : undefined),
  ];

  if (firstZoneId) {
    surfaces.push(
      await readableSurface(
        "zone_settings",
        "zone",
        `/zones/${firstZoneId}/settings`,
        () => client.getZoneSettings(firstZoneId),
        (value) => Array.isArray(value) ? value.length : undefined,
      ),
      await readableSurface(
        "dnssec",
        "zone",
        `/zones/${firstZoneId}/dnssec`,
        () => client.getDnssec(firstZoneId),
        () => 1,
      ),
    );
  } else {
    surfaces.push(
      notConfiguredSurface("zone_settings", "zone", "/zones/{zone_id}/settings", "No visible zones were available."),
      notConfiguredSurface("dnssec", "zone", "/zones/{zone_id}/dnssec", "No visible zones were available."),
    );
  }

  if (accountId) {
    surfaces.push(
      await readableSurface(
        "members",
        "account",
        `/accounts/${accountId}/members`,
        () => client.listMembers(accountId),
        (value) => Array.isArray(value) ? value.length : undefined,
      ),
      await readableSurface(
        "zero_trust_apps",
        "account",
        `/accounts/${accountId}/access/apps`,
        () => client.listAccessApplications(accountId),
        (value) => Array.isArray(value) ? value.length : undefined,
      ),
      await readableSurface(
        "audit_logs",
        "account",
        `/accounts/${accountId}/audit_logs`,
        () => client.listAuditLogs(accountId),
        (value) => Array.isArray(value) ? value.length : undefined,
      ),
    );
  } else {
    surfaces.push(
      notConfiguredSurface("members", "account", "/accounts/{account_id}/members", note),
      notConfiguredSurface("zero_trust_apps", "account", "/accounts/{account_id}/access/apps", note),
      notConfiguredSurface("audit_logs", "account", "/accounts/{account_id}/audit_logs", note),
    );
  }

  const readableCount = surfaces.filter((surfaceItem) => surfaceItem.status === "readable").length;
  const status = readableCount >= 5 ? "healthy" : "limited";

  return {
    status,
    authMethod: config.authMethod,
    accountId,
    surfaces,
    notes: [
      `Authenticated with ${config.authMethod === "token" ? "an API token" : "a Global API Key"}.`,
      note,
      `${readableCount}/${surfaces.length} Cloudflare audit surfaces are readable.`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run cloudflare_assess_identity, cloudflare_assess_zone_security, cloudflare_assess_traffic_controls, or cloudflare_export_audit_bundle."
        : "Provide a read-only API token and, when multiple accounts exist, set account_id to unlock account-scoped Cloudflare checks.",
  };
}

export async function assessCloudflareIdentity(
  client: Pick<
    CloudflareApiClient,
    "getResolvedConfig" | "verifyCurrentToken" | "listAccounts" | "listMembers" | "listAccessApplications" | "listAccessPolicies" | "listIdentityProviders" | "listUserTokens" | "listZones"
  >,
  options: {
    maxSuperAdmins?: number;
    memberLimit?: number;
    tokenLimit?: number;
    zoneLimit?: number;
  } = {},
): Promise<CloudflareAssessmentResult> {
  const config = client.getResolvedConfig();
  const maxSuperAdmins = clampNumber(options.maxSuperAdmins, DEFAULT_MAX_SUPER_ADMINS, 0, 100);
  const memberLimit = clampNumber(options.memberLimit, DEFAULT_MEMBER_LIMIT, 1, 5000);
  const tokenLimit = clampNumber(options.tokenLimit, DEFAULT_TOKEN_LIMIT, 1, 5000);
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);

  const [verify, accounts, zones, tokens] = await Promise.all([
    client.verifyCurrentToken().catch(() => null),
    client.listAccounts(),
    client.listZones(zoneLimit),
    client.listUserTokens(tokenLimit).catch(() => []),
  ]);
  const { accountId, note } = deriveAccountContext(config, accounts);

  const [members, accessApps, accessPolicies, identityProviders] = accountId
    ? await Promise.all([
      client.listMembers(accountId, memberLimit).catch(() => []),
      client.listAccessApplications(accountId).catch(() => []),
      client.listAccessPolicies(accountId).catch(() => []),
      client.listIdentityProviders(accountId).catch(() => []),
    ])
    : [[], [], [], []];

  const verifiedPolicies = extractPolicies(verify);
  const verifiedStatus = extractTokenStatus(verify)?.toLowerCase();
  const superAdmins = members.filter((member) =>
    collectMemberRoleNames(member).some((role) => /super/i.test(role) && /admin/i.test(role)),
  );
  const tokensWithoutExpiry = tokens.filter((token) => !asString(token.expires_on) && !asString(token.expires_at));
  const tokenCoverageSufficient =
    config.authMethod === "token"
    && verifiedStatus === "active"
    && (verifiedPolicies.length > 0 || tokens.length > 0);
  const accessCoverageGood = accessApps.length > 0 && accessPolicies.length > 0;

  const findings = [
    finding(
      "CF-IAM-01",
      "API credential type",
      "high",
      config.authMethod === "token" ? "pass" : "fail",
      config.authMethod === "token"
        ? "Cloudflare access is using an API token rather than a legacy Global API Key."
        : "Cloudflare access is using a legacy Global API Key; move to a scoped API token.",
      ["FedRAMP AC-6", "SOC 2 CC6.1", "PCI-DSS 7.2.1", "CIS 5.1"],
      { auth_method: config.authMethod },
    ),
    finding(
      "CF-IAM-02",
      "Current token verification and scoping",
      "high",
      tokenCoverageSufficient ? "pass" : config.authMethod === "global_key" ? "warn" : "fail",
      tokenCoverageSufficient
        ? `The active API token verified successfully with ${verifiedPolicies.length || tokens.length} visible policy entries.`
        : config.authMethod === "global_key"
          ? "Global API Key auth bypasses token verification; a scoped token is preferred."
          : "The active API token could not be verified as active and scoped from the available Cloudflare metadata.",
      ["FedRAMP AC-3", "FedRAMP IA-5", "SOC 2 CC6.2", "CIS 5.2"],
      { verified_status: verifiedStatus ?? null, verified_policies: verifiedPolicies.length, tokens_without_expiry: tokensWithoutExpiry.length },
    ),
    finding(
      "CF-IAM-03",
      "Account member privilege concentration",
      "medium",
      !accountId ? "warn" : superAdmins.length <= maxSuperAdmins ? "pass" : "warn",
      !accountId
        ? note
        : superAdmins.length <= maxSuperAdmins
          ? `${superAdmins.length} Super Administrator assignments were visible, within the configured threshold of ${maxSuperAdmins}.`
          : `${superAdmins.length} Super Administrator assignments exceeded the configured threshold of ${maxSuperAdmins}.`,
      ["FedRAMP AC-2", "FedRAMP AC-6", "SOC 2 CC6.3", "CIS 6.1"],
      { account_id: accountId ?? null, super_admins: superAdmins.length, member_count: members.length },
    ),
    finding(
      "CF-IAM-04",
      "Zero Trust Access app and policy coverage",
      "high",
      !accountId ? "warn" : accessCoverageGood ? "pass" : "warn",
      !accountId
        ? note
        : accessCoverageGood
          ? `${accessApps.length} Access apps and ${accessPolicies.length} Access policies were visible for the sampled account.`
          : `Zero Trust Access coverage looked thin with ${accessApps.length} apps and ${accessPolicies.length} policies across ${zones.length} sampled zones.`,
      ["FedRAMP AC-3", "SOC 2 CC6.1", "CMMC 3.1.2", "CIS 1.1"],
      { access_apps: accessApps.length, access_policies: accessPolicies.length, sampled_zones: zones.length },
    ),
    finding(
      "CF-IAM-05",
      "Zero Trust identity provider coverage",
      "medium",
      !accountId ? "warn" : identityProviders.length > 0 ? "pass" : "warn",
      !accountId
        ? note
        : identityProviders.length > 0
          ? `${identityProviders.length} Zero Trust identity providers were visible for the sampled account.`
          : "No Zero Trust identity providers were visible for the sampled account.",
      ["FedRAMP IA-2", "SOC 2 CC6.1", "PCI-DSS 8.3.1", "CIS 1.2"],
      { identity_providers: identityProviders.length },
    ),
  ];

  return {
    title: "Cloudflare identity posture",
    summary: {
      auth_method: config.authMethod,
      account_id: accountId ?? null,
      visible_accounts: accounts.length,
      sampled_zones: zones.length,
      super_admins: superAdmins.length,
      access_apps: accessApps.length,
      access_policies: accessPolicies.length,
      identity_providers: identityProviders.length,
      tokens_without_expiry: tokensWithoutExpiry.length,
    },
    findings,
  };
}

export async function assessCloudflareZoneSecurity(
  client: Pick<
    CloudflareApiClient,
    "listZones" | "getZoneSettings" | "getDnssec" | "listFirewallRules" | "listZoneRulesets" | "getUniversalSslSettings"
  >,
  options: {
    zoneLimit?: number;
  } = {},
): Promise<CloudflareAssessmentResult> {
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);
  const zones = await client.listZones(zoneLimit);

  const strictSslGaps: string[] = [];
  const minTlsGaps: string[] = [];
  const httpsHstsGaps: string[] = [];
  const dnssecSslGaps: string[] = [];
  const managedProtectionGaps: string[] = [];

  for (const zone of zones) {
    const zoneId = asString(zone.id);
    if (!zoneId) continue;
    const [settings, dnssec, firewallRules, rulesets, universalSsl] = await Promise.all([
      client.getZoneSettings(zoneId).catch(() => []),
      client.getDnssec(zoneId).catch(() => null),
      client.listFirewallRules(zoneId).catch(() => []),
      client.listZoneRulesets(zoneId).catch(() => []),
      client.getUniversalSslSettings(zoneId).catch(() => null),
    ]);
    const settingsById = settingMap(settings);
    const name = zoneName(zone);

    if (!isStrictSsl(settingsById.get("ssl"))) {
      strictSslGaps.push(name);
    }
    if (!minTlsAtLeast12(settingsById.get("min_tls_version"))) {
      minTlsGaps.push(name);
    }

    const httpsOkay = isEnabled(settingsById.get("always_use_https")) && isEnabled(settingsById.get("automatic_https_rewrites"));
    const hstsOkay = hstsEnabled(settingsById.get("security_header"));
    if (!(httpsOkay && hstsOkay)) {
      httpsHstsGaps.push(name);
    }

    const dnssecActive = /active/i.test(asString(dnssec?.status) ?? "");
    const universalSslEnabled = isEnabled(universalSsl?.enabled ?? universalSsl?.value ?? universalSsl?.certificate_status);
    if (!(dnssecActive && universalSslEnabled)) {
      dnssecSslGaps.push(name);
    }

    if (!(firewallRules.length > 0 || rulesetsProvideManagedProtection(rulesets))) {
      managedProtectionGaps.push(name);
    }
  }

  const findings = [
    finding(
      "CF-ZONE-01",
      "Managed edge protection coverage",
      "high",
      managedProtectionGaps.length === 0 ? "pass" : "warn",
      managedProtectionGaps.length === 0
        ? "All sampled zones showed Cloudflare firewall rules or managed rulesets."
        : `${managedProtectionGaps.length} sampled zones lacked visible firewall rules or managed rulesets.`,
      ["FedRAMP SC-7", "SOC 2 CC6.6", "PCI-DSS 6.6", "CIS 9.1"],
      { zones_without_managed_protection: managedProtectionGaps.slice(0, 25) },
    ),
    finding(
      "CF-ZONE-02",
      "SSL mode Full (Strict)",
      "high",
      strictSslGaps.length === 0 ? "pass" : "fail",
      strictSslGaps.length === 0
        ? "All sampled zones enforced Full (Strict) SSL mode."
        : `${strictSslGaps.length} sampled zones were not enforcing Full (Strict) SSL mode.`,
      ["FedRAMP SC-8", "SOC 2 CC6.7", "PCI-DSS 4.1", "CIS 3.1"],
      { zones_without_strict_ssl: strictSslGaps.slice(0, 25) },
    ),
    finding(
      "CF-ZONE-03",
      "Minimum TLS version",
      "medium",
      minTlsGaps.length === 0 ? "pass" : "fail",
      minTlsGaps.length === 0
        ? "All sampled zones required TLS 1.2 or newer."
        : `${minTlsGaps.length} sampled zones allowed a minimum TLS version below 1.2 or did not expose the setting.`,
      ["FedRAMP SC-8(1)", "SOC 2 CC6.7", "PCI-DSS 4.1", "CIS 3.2"],
      { zones_below_tls12: minTlsGaps.slice(0, 25) },
    ),
    finding(
      "CF-ZONE-04",
      "HTTPS and HSTS enforcement",
      "medium",
      httpsHstsGaps.length === 0 ? "pass" : "warn",
      httpsHstsGaps.length === 0
        ? "All sampled zones enforced Always Use HTTPS, HTTPS rewrites, and HSTS."
        : `${httpsHstsGaps.length} sampled zones lacked full HTTPS and HSTS enforcement.`,
      ["FedRAMP SC-8", "SOC 2 CC6.7", "PCI-DSS 4.1", "CIS 3.3"],
      { zones_missing_https_hsts: httpsHstsGaps.slice(0, 25) },
    ),
    finding(
      "CF-ZONE-05",
      "DNSSEC and Universal SSL coverage",
      "medium",
      dnssecSslGaps.length === 0 ? "pass" : "warn",
      dnssecSslGaps.length === 0
        ? "All sampled zones had DNSSEC active and Universal SSL enabled."
        : `${dnssecSslGaps.length} sampled zones were missing DNSSEC or Universal SSL coverage.`,
      ["FedRAMP SC-20", "SOC 2 CC6.7", "CMMC 3.13.15", "CIS 3.4"],
      { zones_missing_dnssec_or_universal_ssl: dnssecSslGaps.slice(0, 25) },
    ),
  ];

  return {
    title: "Cloudflare zone security posture",
    summary: {
      sampled_zones: zones.length,
      zones_without_managed_protection: managedProtectionGaps.length,
      zones_without_strict_ssl: strictSslGaps.length,
      zones_below_tls12: minTlsGaps.length,
      zones_missing_https_hsts: httpsHstsGaps.length,
      zones_missing_dnssec_or_universal_ssl: dnssecSslGaps.length,
    },
    findings,
  };
}

export async function assessCloudflareTrafficControls(
  client: Pick<
    CloudflareApiClient,
    "getResolvedConfig" | "listAccounts" | "listZones" | "listRateLimits" | "listPageRules" | "getBotManagement" | "listAuditLogs" | "listGatewayRules" | "listIpAccessRules"
  >,
  options: {
    zoneLimit?: number;
    auditLimit?: number;
  } = {},
): Promise<CloudflareAssessmentResult> {
  const config = client.getResolvedConfig();
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);
  const auditLimit = clampNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT, 1, 5000);

  const [accounts, zones] = await Promise.all([
    client.listAccounts(),
    client.listZones(zoneLimit),
  ]);
  const { accountId, note } = deriveAccountContext(config, accounts);

  const zonesWithoutRateLimits: string[] = [];
  const riskyPageRuleZones: string[] = [];
  const zonesWithoutBotControls: string[] = [];

  for (const zone of zones) {
    const zoneId = asString(zone.id);
    if (!zoneId) continue;
    const [rateLimits, pageRules, botManagement] = await Promise.all([
      client.listRateLimits(zoneId).catch(() => []),
      client.listPageRules(zoneId).catch(() => []),
      client.getBotManagement(zoneId).catch(() => null),
    ]);
    const name = zoneName(zone);

    if (rateLimits.length === 0) {
      zonesWithoutRateLimits.push(name);
    }
    if (pageRules.some(pageRuleIsRisky)) {
      riskyPageRuleZones.push(name);
    }
    if (!botManagement || !Object.values(botManagement).some((value) => isEnabled(value))) {
      zonesWithoutBotControls.push(name);
    }
  }

  const [auditLogs, gatewayRules, ipAccessRules] = accountId
    ? await Promise.all([
      client.listAuditLogs(accountId, auditLimit).catch(() => []),
      client.listGatewayRules(accountId).catch(() => []),
      client.listIpAccessRules(accountId).catch(() => []),
    ])
    : [[], [], []];

  const findings = [
    finding(
      "CF-TRF-01",
      "Rate limiting coverage",
      "medium",
      zonesWithoutRateLimits.length === 0 ? "pass" : "warn",
      zonesWithoutRateLimits.length === 0
        ? "All sampled zones exposed at least one rate limiting rule."
        : `${zonesWithoutRateLimits.length} sampled zones did not expose rate limiting rules.`,
      ["FedRAMP SC-5", "SOC 2 CC6.6", "PCI-DSS 6.5.10", "CIS 9.5"],
      { zones_without_rate_limits: zonesWithoutRateLimits.slice(0, 25) },
    ),
    finding(
      "CF-TRF-02",
      "Page rule security regressions",
      "medium",
      riskyPageRuleZones.length === 0 ? "pass" : "warn",
      riskyPageRuleZones.length === 0
        ? "No risky page-rule patterns were visible in the sampled zones."
        : `${riskyPageRuleZones.length} sampled zones had page rules that appeared to weaken security controls.`,
      ["FedRAMP CM-6", "SOC 2 CC8.1", "PCI-DSS 2.2", "CIS 10.1"],
      { zones_with_risky_page_rules: riskyPageRuleZones.slice(0, 25) },
    ),
    finding(
      "CF-TRF-03",
      "Bot and automated traffic controls",
      "medium",
      zonesWithoutBotControls.length === 0 ? "pass" : "warn",
      zonesWithoutBotControls.length === 0
        ? "All sampled zones exposed bot-management or comparable automated traffic controls."
        : `${zonesWithoutBotControls.length} sampled zones did not expose bot-management style controls.`,
      ["FedRAMP SC-7", "SOC 2 CC6.6", "PCI-DSS 6.6", "CIS 9.4"],
      { zones_without_bot_controls: zonesWithoutBotControls.slice(0, 25) },
    ),
    finding(
      "CF-TRF-04",
      "Account audit log visibility",
      "high",
      !accountId ? "warn" : auditLogs.length > 0 ? "pass" : "warn",
      !accountId
        ? note
        : auditLogs.length > 0
          ? `${auditLogs.length} audit log events were visible for the sampled account.`
          : "No account audit log events were visible for the sampled account.",
      ["FedRAMP AU-2", "FedRAMP AU-6", "SOC 2 CC7.2", "PCI-DSS 10.2.1"],
      { account_id: accountId ?? null, audit_logs: auditLogs.length },
    ),
    finding(
      "CF-TRF-05",
      "Gateway and IP access controls",
      "medium",
      !accountId ? "warn" : gatewayRules.length > 0 || ipAccessRules.length > 0 ? "pass" : "warn",
      !accountId
        ? note
        : gatewayRules.length > 0 || ipAccessRules.length > 0
          ? `${gatewayRules.length} Gateway rules and ${ipAccessRules.length} IP access rules were visible for the sampled account.`
          : "No Gateway rules or IP access rules were visible for the sampled account.",
      ["FedRAMP SC-7", "SOC 2 CC6.6", "PCI-DSS 1.3.2", "CIS 9.6"],
      { gateway_rules: gatewayRules.length, ip_access_rules: ipAccessRules.length },
    ),
  ];

  return {
    title: "Cloudflare traffic controls posture",
    summary: {
      account_id: accountId ?? null,
      sampled_zones: zones.length,
      zones_without_rate_limits: zonesWithoutRateLimits.length,
      zones_with_risky_page_rules: riskyPageRuleZones.length,
      zones_without_bot_controls: zonesWithoutBotControls.length,
      audit_logs: auditLogs.length,
      gateway_rules: gatewayRules.length,
      ip_access_rules: ipAccessRules.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: CloudflareAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.scope,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Cloudflare access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Scope", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: CloudflareAssessmentResult): string {
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

function buildExecutiveSummary(config: CloudflareResolvedConfig, assessments: CloudflareAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;

  return [
    "# Cloudflare Audit Bundle",
    "",
    `Auth method: ${config.authMethod}`,
    `Account: ${config.accountId ?? "auto / unspecified"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${failCount}`,
    `- Warning controls: ${warnCount}`,
    `- Passing controls: ${passCount}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status !== "pass")
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
  ].join("\n");
}

function buildControlMatrix(findings: CloudflareFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Cloudflare Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Cloudflare Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Cloudflare tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible Cloudflare audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

export async function exportCloudflareAuditBundle(
  client: Pick<
    CloudflareApiClient,
    | "getResolvedConfig"
    | "verifyCurrentToken"
    | "listAccounts"
    | "listZones"
    | "getZoneSettings"
    | "getDnssec"
    | "listMembers"
    | "listAccessApplications"
    | "listAuditLogs"
    | "listAccessPolicies"
    | "listIdentityProviders"
    | "listUserTokens"
    | "listFirewallRules"
    | "listZoneRulesets"
    | "getUniversalSslSettings"
    | "listRateLimits"
    | "listPageRules"
    | "getBotManagement"
    | "listGatewayRules"
    | "listIpAccessRules"
  >,
  config: CloudflareResolvedConfig,
  outputRoot: string,
  options: {
    maxSuperAdmins?: number;
    memberLimit?: number;
    tokenLimit?: number;
    zoneLimit?: number;
    auditLimit?: number;
  } = {},
): Promise<CloudflareAuditBundleResult> {
  const access = await checkCloudflareAccess(client);
  const identity = await assessCloudflareIdentity(client, options);
  const zoneSecurity = await assessCloudflareZoneSecurity(client, options);
  const trafficControls = await assessCloudflareTrafficControls(client, options);
  const assessments = [identity, zoneSecurity, trafficControls];
  const findings = assessments.flatMap((assessment) => assessment.findings);

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(config.accountId ?? "cloudflare-account")}-audit-bundle`,
  );

  await writeSecureTextFile(outputDir, "README.md", `${buildBundleReadme()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    auth_method: config.authMethod,
    account_id: config.accountId ?? null,
    source_chain: config.sourceChain,
  }));
  await writeSecureTextFile(
    outputDir,
    "summary.md",
    [
      formatAccessCheckText(access),
      "",
      formatAssessmentText(identity),
      "",
      formatAssessmentText(zoneSecurity),
      "",
      formatAssessmentText(trafficControls),
    ].join("\n"),
  );
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", `${buildControlMatrix(findings)}\n`);
  await writeSecureTextFile(outputDir, "reports/identity.md", `${formatAssessmentText(identity)}\n`);
  await writeSecureTextFile(outputDir, "reports/zone-security.md", `${formatAssessmentText(zoneSecurity)}\n`);
  await writeSecureTextFile(outputDir, "reports/traffic-controls.md", `${formatAssessmentText(trafficControls)}\n`);
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/zone-security.json", serializeJson(zoneSecurity));
  await writeSecureTextFile(outputDir, "analysis/traffic-controls.json", serializeJson(trafficControls));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));

  const zipPath = resolveSecureOutputPath(outputRoot, `${safeDirName(config.accountId ?? "cloudflare-account")}-audit-bundle.zip`);
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    api_token: asString(value.api_token) ?? asString(value.token),
    api_key: asString(value.api_key),
    email: asString(value.email),
    account_id: asString(value.account_id),
    base_url: asString(value.base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_super_admins: asNumber(value.max_super_admins),
    member_limit: asNumber(value.member_limit),
    token_limit: asNumber(value.token_limit),
    zone_limit: asNumber(value.zone_limit),
  };
}

function normalizeZoneSecurityArgs(args: unknown): ZoneSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    zone_limit: asNumber(value.zone_limit),
  };
}

function normalizeTrafficArgs(args: unknown): TrafficArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    zone_limit: asNumber(value.zone_limit),
    audit_limit: asNumber(value.audit_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    audit_limit: asNumber(value.audit_limit),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): CloudflareApiClient {
  return new CloudflareApiClient(resolveCloudflareConfiguration(args));
}

const authParams = {
  api_token: Type.Optional(Type.String({ description: "Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN." })),
  api_key: Type.Optional(Type.String({ description: "Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY." })),
  email: Type.Optional(Type.String({ description: "Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL." })),
  account_id: Type.Optional(Type.String({ description: "Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID." })),
  base_url: Type.Optional(Type.String({ description: "Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerCloudflareTools(pi: any): void {
  pi.registerTool({
    name: "cloudflare_check_access",
    label: "Check Cloudflare audit access",
    description:
      "Validate read-only Cloudflare access across token verification, accounts, zones, zone settings, DNSSEC, members, Zero Trust apps, and audit logs.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkCloudflareAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "cloudflare_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "cloudflare_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_identity",
    label: "Assess Cloudflare identity posture",
    description:
      "Assess Cloudflare authentication method, token verification, member privilege concentration, Zero Trust Access coverage, and identity provider posture.",
    parameters: Type.Object({
      ...authParams,
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Administrator assignments before warning. Defaults to 2.", default: 2 })),
      member_limit: Type.Optional(Type.Number({ description: "Maximum account members to inspect. Defaults to 200.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum API tokens to inspect. Defaults to 200.", default: 200 })),
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessCloudflareIdentity(createClient(args), {
          maxSuperAdmins: args.max_super_admins,
          memberLimit: args.member_limit,
          tokenLimit: args.token_limit,
          zoneLimit: args.zone_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "cloudflare_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_zone_security",
    label: "Assess Cloudflare zone security",
    description:
      "Assess Cloudflare zone security posture across firewall and managed rulesets, strict SSL, minimum TLS, HTTPS and HSTS enforcement, DNSSEC, and Universal SSL.",
    parameters: Type.Object({
      ...authParams,
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
    }),
    prepareArguments: normalizeZoneSecurityArgs,
    async execute(_toolCallId: string, args: ZoneSecurityArgs) {
      try {
        const result = await assessCloudflareZoneSecurity(createClient(args), {
          zoneLimit: args.zone_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_zone_security", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare zone security assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "cloudflare_assess_zone_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_traffic_controls",
    label: "Assess Cloudflare traffic controls",
    description:
      "Assess Cloudflare traffic and edge control posture across rate limiting, page rules, bot management, account audit logs, Gateway rules, and IP access controls.",
    parameters: Type.Object({
      ...authParams,
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit log entries to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeTrafficArgs,
    async execute(_toolCallId: string, args: TrafficArgs) {
      try {
        const result = await assessCloudflareTrafficControls(createClient(args), {
          zoneLimit: args.zone_limit,
          auditLimit: args.audit_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_traffic_controls", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare traffic control assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "cloudflare_assess_traffic_controls" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_export_audit_bundle",
    label: "Export Cloudflare audit bundle",
    description:
      "Export a Cloudflare audit package with access checks, identity findings, zone security, traffic-control findings, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Administrator assignments before warning. Defaults to 2.", default: 2 })),
      member_limit: Type.Optional(Type.Number({ description: "Maximum account members to inspect. Defaults to 200.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum API tokens to inspect. Defaults to 200.", default: 200 })),
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit log entries to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveCloudflareConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportCloudflareAuditBundle(new CloudflareApiClient(config), config, outputRoot, {
          maxSuperAdmins: args.max_super_admins,
          memberLimit: args.member_limit,
          tokenLimit: args.token_limit,
          zoneLimit: args.zone_limit,
          auditLimit: args.audit_limit,
        });
        return textResult(
          [
            "Cloudflare audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "cloudflare_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Cloudflare audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "cloudflare_export_audit_bundle" },
        );
      }
    },
  });
}
