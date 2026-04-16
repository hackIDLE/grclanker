/**
 * Zoom organization audit tools for grclanker.
 *
 * This native TypeScript surface starts with read-only Zoom account access
 * across identity posture, collaboration governance, and meeting security.
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

const DEFAULT_OUTPUT_DIR = "./export/zoom";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_LIMIT = 300;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_GROUP_LIMIT = 50;
const DEFAULT_ROLE_LIMIT = 100;
const DEFAULT_OPERATION_LOG_LIMIT = 200;
const DEFAULT_MAX_ADMINS = 10;
const DEFAULT_MAX_ADMIN_SAMPLES = 20;
const DEFAULT_MAX_RECORDING_RETENTION_DAYS = 365;

export interface ZoomResolvedConfig {
  accountId: string;
  token?: string;
  clientId?: string;
  clientSecret?: string;
  baseUrl: string;
  oauthBaseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
}

export interface ZoomAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface ZoomAccessCheckResult {
  status: "healthy" | "limited";
  accountId: string;
  surfaces: ZoomAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface ZoomFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface ZoomAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: ZoomFinding[];
}

export interface ZoomAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  account_id?: string;
  token?: string;
  client_id?: string;
  client_secret?: string;
  base_url?: string;
  oauth_base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  max_admins?: number;
};

type CollaborationArgs = CheckAccessArgs & {
  group_limit?: number;
  operation_log_limit?: number;
  max_recording_retention_days?: number;
};

type MeetingSecurityArgs = CheckAccessArgs & {
  group_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  user_limit?: number;
  max_admins?: number;
  group_limit?: number;
  operation_log_limit?: number;
  max_recording_retention_days?: number;
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
    if (/^(true|1|yes|enabled|on|active|required|locked|verified)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled|off|inactive|optional|unverified)$/i.test(value.trim())) return false;
  }
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
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
  return normalized || "zoom";
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

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
}

function firstDefined(value: unknown, paths: string[][]): unknown {
  for (const path of paths) {
    const candidate = getNestedValue(value, path);
    if (candidate !== undefined) return candidate;
  }
  return undefined;
}

function hasObjectData(value: unknown): boolean {
  const object = asObject(value);
  return Boolean(object && Object.keys(object).length > 0);
}

function objectHasAnySignal(value: unknown): boolean {
  const object = asObject(value);
  if (!object) return false;
  for (const entry of Object.values(object)) {
    if (isExplicitlyEnabled(entry) || isExplicitlyDisabled(entry)) return true;
    if (asObject(entry) && objectHasAnySignal(entry)) return true;
  }
  return false;
}

function isExplicitlyEnabled(value: unknown): boolean {
  return asBoolean(value) === true || /^(enabled|active|required|strict|host|on|yes|verified|locked)$/i.test(asString(value) ?? "");
}

function isExplicitlyDisabled(value: unknown): boolean {
  return asBoolean(value) === false || /^(disabled|inactive|off|none|optional|personal|all|everyone|unverified)$/i.test(asString(value) ?? "");
}

function encodeBasicAuth(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
}

function deriveDefaultOauthBaseUrl(baseUrl: string): string {
  return /zoomgov/i.test(baseUrl) ? "https://zoomgov.com" : "https://zoom.us";
}

function zoomErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  return [
    asString(object.message),
    asString(object.error),
    asString(object.reason),
    ...asArray(object.errors).map((item) =>
      asString(asObject(item)?.message) ?? asString(asObject(item)?.detail) ?? asString(item),
    ),
  ].filter((item): item is string => Boolean(item)).join("; ") || undefined;
}

function extractCollection(payload: unknown, keys: string[]): JsonRecord[] {
  const object = asObject(payload);
  if (!object) return [];
  for (const key of keys) {
    const value = object[key];
    if (Array.isArray(value)) {
      return value.map(asObject).filter((item): item is JsonRecord => Boolean(item));
    }
  }
  return [];
}

function userId(user: JsonRecord): string | undefined {
  return asString(user.id) ?? asString(user.userId) ?? asString(user.email);
}

function groupName(group: JsonRecord): string {
  return asString(group.name) ?? asString(group.display_name) ?? asString(group.id) ?? "group";
}

function domainName(domain: JsonRecord): string {
  return asString(domain.domain) ?? asString(domain.name) ?? asString(domain.id) ?? "domain";
}

function roleName(role: JsonRecord): string {
  return asString(role.name) ?? asString(role.role_name) ?? asString(role.id) ?? "role";
}

function loginTypesForUser(user: JsonRecord): string[] {
  const directValues = [
    user.login_type,
    user.loginType,
    user.sign_in_type,
    user.signInType,
  ];
  const listValues = [
    ...asArray(user.login_types),
    ...asArray(user.loginTypes),
    ...asArray(firstDefined(user, [["security", "login_types"], ["security", "loginTypes"]])),
  ];
  return [...directValues, ...listValues]
    .map((value) => asString(value))
    .filter((value): value is string => Boolean(value));
}

function isSsoLike(value: string): boolean {
  return /sso|saml/i.test(value) || value === "101";
}

function isSsoOnlyUser(user: JsonRecord): boolean | undefined {
  const loginTypes = loginTypesForUser(user);
  if (loginTypes.length === 0) return undefined;
  return loginTypes.every(isSsoLike);
}

function userLooksLikeAdmin(user: JsonRecord): boolean {
  const values = [
    asString(user.role_name),
    asString(user.roleName),
    asString(user.type),
    asString(user.user_type),
    asString(firstDefined(user, [["permissions", "role"], ["role", "name"]])),
  ].filter((value): value is string => Boolean(value));
  return values.some((value) => /admin|owner|security/i.test(value));
}

function isAdminRole(role: JsonRecord): boolean {
  return /admin|owner|security/i.test(roleName(role));
}

function isVerifiedDomain(domain: JsonRecord): boolean {
  return asBoolean(firstDefined(domain, [
    ["verified"],
    ["is_verified"],
    ["verification_verified"],
  ])) === true || /verified/i.test(asString(firstDefined(domain, [
    ["status"],
    ["verification_state"],
    ["verificationStatus"],
  ])) ?? "");
}

function isPermissiveDomain(domain: JsonRecord): boolean {
  const name = domainName(domain);
  return name.includes("*") || asBoolean(firstDefined(domain, [
    ["allow_all"],
    ["allowAll"],
    ["trust_all"],
  ])) === true;
}

function boolAtPaths(value: unknown, candidatePaths: string[][]): boolean {
  return candidatePaths.some((path) => isExplicitlyEnabled(getNestedValue(value, path)));
}

function disabledAtPaths(value: unknown, candidatePaths: string[][]): boolean {
  return candidatePaths.some((path) => isExplicitlyDisabled(getNestedValue(value, path)));
}

function meetingPasswordRequired(settings: unknown): boolean {
  return boolAtPaths(settings, [
    ["schedule_meeting", "require_password_for_scheduling_new_meetings"],
    ["schedule_meeting", "default_password_for_scheduled_meetings"],
    ["meeting_security", "password_required"],
  ]);
}

function meetingPasswordLocked(lockSettings: unknown): boolean {
  return boolAtPaths(lockSettings, [
    ["schedule_meeting", "require_password_for_scheduling_new_meetings"],
    ["schedule_meeting", "default_password_for_scheduled_meetings"],
  ]);
}

function waitingRoomEnabled(settings: unknown): boolean {
  return boolAtPaths(settings, [
    ["in_meeting", "waiting_room"],
    ["security", "waiting_room"],
  ]);
}

function authenticatedUsersRequired(settings: unknown): boolean {
  return boolAtPaths(settings, [
    ["schedule_meeting", "meeting_authentication"],
    ["schedule_meeting", "only_authenticated_users_can_join"],
    ["security", "meeting_authentication"],
  ]);
}

function screenSharingHostOnly(settings: unknown): boolean {
  const value = asString(firstDefined(settings, [
    ["in_meeting", "screen_sharing"],
    ["security", "screen_sharing"],
  ]));
  return /host/i.test(value ?? "");
}

function fileTransferRestricted(settings: unknown): boolean {
  return disabledAtPaths(settings, [
    ["in_meeting", "file_transfer"],
    ["security", "file_transfer"],
    ["chat", "file_transfer"],
  ]);
}

function localRecordingDisabled(settings: unknown): boolean {
  return disabledAtPaths(settings, [
    ["recording", "local_recording"],
    ["recording", "allow_local_recording"],
  ]);
}

function embedPasswordDisabled(settings: unknown): boolean {
  return disabledAtPaths(settings, [
    ["schedule_meeting", "embed_password_in_join_link"],
  ]);
}

function pmiRestricted(settings: unknown): boolean {
  return disabledAtPaths(settings, [
    ["schedule_meeting", "use_pmi_for_scheduled_meetings"],
    ["schedule_meeting", "use_pmi_for_instant_meetings"],
  ]);
}

function e2eeEnabled(settings: unknown): boolean {
  return boolAtPaths(settings, [
    ["in_meeting", "e2e_encryption"],
    ["in_meeting", "e2ee_encryption"],
    ["security", "e2ee_encryption"],
  ]);
}

function dataResidencyEnabled(settings: unknown): boolean {
  const value = firstDefined(settings, [
    ["in_meeting", "data_center_regions"],
    ["security", "data_center_regions"],
  ]);
  return asArray(value).length > 0;
}

function recordingAutoDeleteEnabled(settings: unknown): boolean {
  return boolAtPaths(settings, [
    ["recording", "auto_delete_cmr"],
    ["recording", "auto_delete"],
  ]);
}

function recordingRetentionDays(settings: unknown): number | undefined {
  return asNumber(firstDefined(settings, [
    ["recording", "auto_delete_cmr_days"],
    ["recording", "auto_delete_days"],
  ]));
}

function phoneRecordingEnabled(value: unknown): boolean {
  return boolAtPaths(value, [
    ["automatic_recording"],
    ["auto_recording"],
    ["recording_enabled"],
    ["recording", "enabled"],
    ["policy", "recording_enabled"],
  ]);
}

function phoneRecordingDisabled(value: unknown): boolean {
  return disabledAtPaths(value, [
    ["automatic_recording"],
    ["auto_recording"],
    ["recording_enabled"],
    ["recording", "enabled"],
    ["policy", "recording_enabled"],
  ]);
}

export function resolveZoomConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): ZoomResolvedConfig {
  const sourceChain: string[] = [];
  const accountId = asString(input.account_id)
    ?? asString(env.ZOOM_ACCOUNT_ID);
  if (!accountId) {
    throw new Error("ZOOM_ACCOUNT_ID or an account_id argument is required.");
  }
  sourceChain.push(asString(input.account_id) ? "arguments-account" : "environment-account");

  const token = asString(input.token)
    ?? asString(env.ZOOM_TOKEN)
    ?? asString(env.ZOOM_ACCESS_TOKEN);
  const clientId = asString(input.client_id) ?? asString(env.ZOOM_CLIENT_ID);
  const clientSecret = asString(input.client_secret) ?? asString(env.ZOOM_CLIENT_SECRET);
  if (!token && (!clientId || !clientSecret)) {
    throw new Error("Provide ZOOM_TOKEN or Zoom Server-to-Server OAuth credentials (ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET).");
  }

  if (token) {
    sourceChain.push(asString(input.token) ? "arguments-token" : "environment-token");
  } else {
    sourceChain.push(asString(input.client_id) ? "arguments-client-id" : "environment-client-id");
    sourceChain.push(asString(input.client_secret) ? "arguments-client-secret" : "environment-client-secret");
  }

  const baseUrl = normalizeBaseUrl(
    asString(input.base_url) ?? asString(env.ZOOM_BASE_URL) ?? asString(env.ZOOM_API_BASE_URL) ?? "https://api.zoom.us/v2",
  );
  const oauthBaseUrl = normalizeBaseUrl(
    asString(input.oauth_base_url) ?? asString(env.ZOOM_OAUTH_BASE_URL) ?? deriveDefaultOauthBaseUrl(baseUrl),
  );

  return {
    accountId,
    token,
    clientId,
    clientSecret,
    baseUrl,
    oauthBaseUrl,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.ZOOM_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class ZoomApiClient {
  private readonly config: ZoomResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private accessToken?: string;
  private accessTokenExpiresAt = 0;
  private accessTokenPromise?: Promise<string>;

  constructor(
    config: ZoomResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    if (config.token) {
      this.accessToken = config.token;
      this.accessTokenExpiresAt = Number.MAX_SAFE_INTEGER;
    }
  }

  getResolvedConfig(): ZoomResolvedConfig {
    return this.config;
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async fetchJson(
    url: string,
    init: RequestInit = {},
    options: { skipAuth?: boolean } = {},
  ): Promise<JsonRecord> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const headers = new Headers(init.headers ?? {});
      if (!headers.has("accept")) headers.set("accept", "application/json");
      if (!options.skipAuth) {
        headers.set("authorization", `Bearer ${await this.getAccessToken()}`);
      }

      const response = await this.fetchImpl(url, {
        ...init,
        headers,
        signal: controller.signal,
      });

      const rawText = await response.text();
      const payload = rawText.length > 0 ? JSON.parse(rawText) as JsonRecord : {};
      if (!response.ok) {
        const detail = zoomErrorSummary(payload) ?? rawText.slice(0, 240);
        throw new Error(`Zoom request failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`);
      }
      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async fetchAccessToken(): Promise<string> {
    if (!this.config.clientId || !this.config.clientSecret) {
      throw new Error("Zoom Server-to-Server OAuth credentials are missing.");
    }

    const tokenUrl = new URL(`${this.config.oauthBaseUrl}/oauth/token`);
    tokenUrl.searchParams.set("grant_type", "account_credentials");
    tokenUrl.searchParams.set("account_id", this.config.accountId);

    const payload = await this.fetchJson(tokenUrl.toString(), {
      method: "POST",
      headers: {
        authorization: `Basic ${encodeBasicAuth(this.config.clientId, this.config.clientSecret)}`,
      },
    }, { skipAuth: true });

    const accessToken = asString(payload.access_token);
    if (!accessToken) {
      throw new Error("Zoom OAuth token response did not include access_token.");
    }

    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    this.accessToken = accessToken;
    this.accessTokenExpiresAt = Date.now() + Math.max((expiresIn - 60) * 1000, 60_000);
    return accessToken;
  }

  private async getAccessToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.accessTokenExpiresAt) {
      return this.accessToken;
    }
    if (!this.accessTokenPromise) {
      this.accessTokenPromise = this.fetchAccessToken();
    }
    try {
      return await this.accessTokenPromise;
    } finally {
      this.accessTokenPromise = undefined;
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    return this.fetchJson(this.buildUrl(path, query));
  }

  async list(
    path: string,
    collectionKeys: string[],
    query: JsonRecord = {},
    options: { limit?: number; pageSize?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_PAGE_LIMIT, 1, 10000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_PAGE_LIMIT, 1, 300);
    const items: JsonRecord[] = [];
    let nextPageToken: string | undefined;

    while (items.length < limit) {
      const payload = await this.get(path, {
        ...query,
        page_size: pageSize,
        next_page_token: nextPageToken,
      });
      const pageItems = extractCollection(payload, collectionKeys);
      items.push(...pageItems.slice(0, limit - items.length));
      nextPageToken = asString(payload.next_page_token);
      if (!nextPageToken || pageItems.length === 0) break;
    }

    return items;
  }

  async getCurrentUser(): Promise<JsonRecord> {
    return this.get("/users/me");
  }

  async getAccountSettings(): Promise<JsonRecord> {
    return this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/settings`);
  }

  async getAccountLockSettings(): Promise<JsonRecord> {
    return this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/lock_settings`);
  }

  async listUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    return this.list("/users", ["users"], {}, { limit });
  }

  async getUserSettings(userIdValue: string): Promise<JsonRecord> {
    return this.get(`/users/${encodeURIComponent(userIdValue)}/settings`);
  }

  async listRoles(limit = DEFAULT_ROLE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/roles", ["roles"], {}, { limit });
  }

  async getRoleDetail(roleId: string): Promise<JsonRecord> {
    return this.get(`/roles/${encodeURIComponent(roleId)}`);
  }

  async listRoleMembers(roleId: string, limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list(`/roles/${encodeURIComponent(roleId)}/members`, ["members"], {}, { limit });
  }

  async listGroups(limit = DEFAULT_GROUP_LIMIT): Promise<JsonRecord[]> {
    return this.list("/groups", ["groups"], {}, { limit });
  }

  async getGroupSettings(groupId: string): Promise<JsonRecord> {
    return this.get(`/groups/${encodeURIComponent(groupId)}/settings`);
  }

  async getGroupLockSettings(groupId: string): Promise<JsonRecord> {
    return this.get(`/groups/${encodeURIComponent(groupId)}/lock_settings`);
  }

  async listOperationLogs(limit = DEFAULT_OPERATION_LOG_LIMIT): Promise<JsonRecord[]> {
    return this.list("/report/operationlogs", ["operation_logs", "activity_logs", "logs"], {}, { limit, pageSize: 100 });
  }

  async listImGroups(limit = DEFAULT_GROUP_LIMIT): Promise<JsonRecord[]> {
    return this.list("/im/groups", ["groups", "im_groups"], {}, { limit });
  }

  async getManagedDomains(): Promise<JsonRecord[]> {
    const payload = await this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/managed_domains`);
    return extractCollection(payload, ["domains", "managed_domains"]);
  }

  async listTrustedDomains(): Promise<JsonRecord[]> {
    const payload = await this.get(`/accounts/${encodeURIComponent(this.config.accountId)}/trusted_domains`);
    return extractCollection(payload, ["domains", "trusted_domains"]);
  }

  async getPhoneCallHandlingSettings(): Promise<JsonRecord> {
    return this.get("/phone/call_handling/settings");
  }

  async getPhoneRecordingPolicies(): Promise<JsonRecord> {
    return this.get("/phone/recording");
  }
}

async function readableSurface(
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<ZoomAccessSurface> {
  try {
    const value = await load();
    return {
      name,
      endpoint,
      status: "readable",
      count: countResolver?.(value),
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

function finding(
  id: string,
  title: string,
  severity: ZoomFinding["severity"],
  status: ZoomFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): ZoomFinding {
  return { id, title, severity, status, summary, mappings, evidence };
}

async function collectGroupPolicySnapshots(
  client: Pick<ZoomApiClient, "listGroups" | "getGroupSettings" | "getGroupLockSettings">,
  groupLimit: number,
): Promise<{
  sampledGroups: number;
  lockVisibleCount: number;
  relaxedMeetingSecurityGroups: string[];
  relaxedFileControlGroups: string[];
}> {
  const groups = await client.listGroups(groupLimit).catch(() => []);
  const sampledGroups = groups
    .map((group) => ({ id: asString(group.id), name: groupName(group) }))
    .filter((group): group is { id: string; name: string } => Boolean(group.id))
    .slice(0, groupLimit);

  const snapshots = await Promise.all(sampledGroups.map(async (group) => {
    const [settings, locks] = await Promise.all([
      client.getGroupSettings(group.id).catch(() => ({})),
      client.getGroupLockSettings(group.id).catch(() => ({})),
    ]);
    const settingsVisible = hasObjectData(settings);
    return {
      name: group.name,
      lockVisible: hasObjectData(locks) || objectHasAnySignal(locks),
      relaxedMeetingSecurity:
        settingsVisible
        && (!meetingPasswordRequired(settings) || !waitingRoomEnabled(settings) || !authenticatedUsersRequired(settings)),
      relaxedFileControls:
        settingsVisible
        && (!fileTransferRestricted(settings) || !localRecordingDisabled(settings)),
    };
  }));

  return {
    sampledGroups: sampledGroups.length,
    lockVisibleCount: snapshots.filter((item) => item.lockVisible).length,
    relaxedMeetingSecurityGroups: snapshots.filter((item) => item.relaxedMeetingSecurity).map((item) => item.name),
    relaxedFileControlGroups: snapshots.filter((item) => item.relaxedFileControls).map((item) => item.name),
  };
}

export async function checkZoomAccess(
  client: Pick<
    ZoomApiClient,
    | "getResolvedConfig"
    | "getCurrentUser"
    | "getAccountSettings"
    | "getAccountLockSettings"
    | "listUsers"
    | "listRoles"
    | "listGroups"
    | "listOperationLogs"
    | "listImGroups"
    | "getManagedDomains"
    | "listTrustedDomains"
    | "getPhoneRecordingPolicies"
  >,
): Promise<ZoomAccessCheckResult> {
  const config = client.getResolvedConfig();
  const currentUserSurface = await readableSurface("current_user", "/users/me", () => client.getCurrentUser(), () => 1);
  const currentUser = asObject(currentUserSurface.status === "readable"
    ? await client.getCurrentUser().catch(() => ({}))
    : {}) ?? {};

  const surfaces: ZoomAccessSurface[] = [
    currentUserSurface,
    await readableSurface("account_settings", `/accounts/${config.accountId}/settings`, () => client.getAccountSettings(), () => 1),
    await readableSurface("account_lock_settings", `/accounts/${config.accountId}/lock_settings`, () => client.getAccountLockSettings(), () => 1),
    await readableSurface("users", "/users", () => client.listUsers(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("roles", "/roles", () => client.listRoles(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("groups", "/groups", () => client.listGroups(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("operation_logs", "/report/operationlogs", () => client.listOperationLogs(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("im_groups", "/im/groups", () => client.listImGroups(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("managed_domains", `/accounts/${config.accountId}/managed_domains`, () => client.getManagedDomains(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("trusted_domains", `/accounts/${config.accountId}/trusted_domains`, () => client.listTrustedDomains(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("phone_recording", "/phone/recording", () => client.getPhoneRecordingPolicies(), () => 1),
  ];

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = readableCount >= 8 ? "healthy" : "limited";

  return {
    status,
    accountId: config.accountId,
    surfaces,
    notes: [
      `Using Zoom account ${config.accountId}.`,
      `Authenticated as ${asString(currentUser.email) ?? asString(currentUser.first_name) ?? asString(currentUser.id) ?? "current Zoom admin context"}.`,
      `${readableCount}/${surfaces.length} Zoom audit surfaces are readable.`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run zoom_assess_identity, zoom_assess_collaboration_governance, zoom_assess_meeting_security, or zoom_export_audit_bundle."
        : "Provide a Zoom Server-to-Server OAuth app with account, user, group, role, report, IM, and phone read scopes.",
  };
}

export async function assessZoomIdentity(
  client: Pick<
    ZoomApiClient,
    "getResolvedConfig" | "listUsers" | "listRoles" | "listRoleMembers" | "getUserSettings" | "getManagedDomains"
  >,
  options: {
    userLimit?: number;
    maxAdmins?: number;
  } = {},
): Promise<ZoomAssessmentResult> {
  const config = client.getResolvedConfig();
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 10000);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 5000);

  const [users, roles, managedDomains] = await Promise.all([
    client.listUsers(userLimit).catch(() => []),
    client.listRoles().catch(() => []),
    client.getManagedDomains().catch(() => []),
  ]);

  const adminRoles = roles.filter(isAdminRole).slice(0, 20);
  const adminMemberSets = await Promise.all(adminRoles.map(async (role) =>
    client.listRoleMembers(asString(role.id) ?? "").catch(() => []),
  ));

  const adminIds = new Set<string>();
  for (const members of adminMemberSets) {
    for (const member of members) {
      const id = userId(member);
      if (id) adminIds.add(id);
    }
  }
  for (const user of users) {
    const id = userId(user);
    if (id && userLooksLikeAdmin(user)) adminIds.add(id);
  }

  const adminUsers = users.filter((user) => {
    const id = userId(user);
    return Boolean(id && adminIds.has(id));
  });
  const sampledAdminIds = [...adminIds].slice(0, DEFAULT_MAX_ADMIN_SAMPLES);
  const sampledAdminSettings = await Promise.all(sampledAdminIds.map(async (id) => ({
    id,
    settings: await client.getUserSettings(id).catch(() => ({})),
  })));
  const adminsWithoutMfa = sampledAdminSettings.filter((item) => !boolAtPaths(item.settings, [
    ["feature", "two_factor_auth"],
    ["feature", "two_factor_authentication"],
    ["security", "two_factor_auth"],
  ]));

  const nonSsoUsers = users.filter((user) => isSsoOnlyUser(user) === false);
  const unknownLoginUsers = users.filter((user) => isSsoOnlyUser(user) === undefined);
  const unverifiedDomains = managedDomains.filter((domain) => !isVerifiedDomain(domain));

  const findings = [
    finding(
      "ZOOM-ID-01",
      "Enterprise sign-in restrictions",
      "critical",
      nonSsoUsers.length > 0 ? "fail" : unknownLoginUsers.length > 0 ? "warn" : "pass",
      nonSsoUsers.length > 0
        ? `${nonSsoUsers.length}/${users.length} sampled users exposed non-SSO sign-in types.`
        : unknownLoginUsers.length > 0
          ? `${unknownLoginUsers.length}/${users.length} sampled users did not expose a clear login_type, so SSO enforcement could not be fully confirmed.`
          : "All sampled users exposed SSO-style sign-in types.",
      ["FedRAMP IA-2", "SOC 2 CC6.1", "PCI-DSS 8.3.1", "CIS 4.1"],
      {
        sampled_users: users.length,
        non_sso_users: nonSsoUsers.slice(0, 25).map((user) => asString(user.email) ?? userId(user)),
        unknown_login_users: unknownLoginUsers.length,
      },
    ),
    finding(
      "ZOOM-ID-02",
      "Admin MFA coverage",
      "critical",
      sampledAdminIds.length === 0 ? "warn" : adminsWithoutMfa.length === 0 ? "pass" : "fail",
      sampledAdminIds.length === 0
        ? "No admin users were sampled from role membership or user metadata."
        : adminsWithoutMfa.length === 0
          ? `Sampled ${sampledAdminIds.length} admin users and all exposed two-factor auth settings as enabled.`
          : `${adminsWithoutMfa.length}/${sampledAdminIds.length} sampled admin users did not expose admin MFA as enabled.`,
      ["FedRAMP IA-2(1)", "SOC 2 CC6.1", "PCI-DSS 8.4.2", "CIS 4.5"],
      {
        sampled_admin_users: sampledAdminIds.length,
        admins_without_mfa: adminsWithoutMfa.map((item) => item.id),
      },
    ),
    finding(
      "ZOOM-ID-03",
      "Managed domains verified",
      "high",
      managedDomains.length === 0 ? "warn" : unverifiedDomains.length === 0 ? "pass" : "fail",
      managedDomains.length === 0
        ? "No managed domains were visible for the Zoom account."
        : unverifiedDomains.length === 0
          ? `All ${managedDomains.length} visible managed domains were verified.`
          : `${unverifiedDomains.length}/${managedDomains.length} visible managed domains were not verified.`,
      ["FedRAMP IA-8", "SOC 2 CC6.1", "PCI-DSS 8.2.1", "CIS 4.1"],
      {
        managed_domains: managedDomains.length,
        unverified_domains: unverifiedDomains.slice(0, 25).map(domainName),
      },
    ),
    finding(
      "ZOOM-ID-04",
      "Administrative privilege concentration",
      "medium",
      adminIds.size <= maxAdmins ? "pass" : "warn",
      adminIds.size <= maxAdmins
        ? `${adminIds.size} sampled admin users fell within the configured threshold of ${maxAdmins}.`
        : `${adminIds.size} sampled admin users exceeded the configured threshold of ${maxAdmins}.`,
      ["FedRAMP AC-2", "FedRAMP AC-6", "SOC 2 CC6.3", "PCI-DSS 7.2.2"],
      {
        sampled_admin_users: adminIds.size,
        max_admins: maxAdmins,
        admin_roles: adminRoles.map(roleName),
      },
    ),
  ];

  return {
    title: "Zoom identity posture",
    summary: {
      account_id: config.accountId,
      sampled_users: users.length,
      sampled_admin_users: adminIds.size,
      admins_without_mfa: adminsWithoutMfa.length,
      managed_domains: managedDomains.length,
      unverified_domains: unverifiedDomains.length,
      non_sso_users: nonSsoUsers.length,
      unknown_login_users: unknownLoginUsers.length,
    },
    findings,
  };
}

export async function assessZoomCollaborationGovernance(
  client: Pick<
    ZoomApiClient,
    | "getResolvedConfig"
    | "getAccountSettings"
    | "listTrustedDomains"
    | "listImGroups"
    | "listGroups"
    | "getGroupSettings"
    | "getGroupLockSettings"
    | "listOperationLogs"
    | "getPhoneCallHandlingSettings"
    | "getPhoneRecordingPolicies"
  >,
  options: {
    groupLimit?: number;
    operationLogLimit?: number;
    maxRecordingRetentionDays?: number;
  } = {},
): Promise<ZoomAssessmentResult> {
  const config = client.getResolvedConfig();
  const groupLimit = clampNumber(options.groupLimit, DEFAULT_GROUP_LIMIT, 1, 500);
  const operationLogLimit = clampNumber(options.operationLogLimit, DEFAULT_OPERATION_LOG_LIMIT, 1, 1000);
  const maxRecordingRetentionDays = clampNumber(
    options.maxRecordingRetentionDays,
    DEFAULT_MAX_RECORDING_RETENTION_DAYS,
    1,
    3650,
  );

  const [
    accountSettings,
    trustedDomains,
    imGroups,
    groupSnapshots,
    operationLogs,
    phoneCallHandling,
    phoneRecording,
  ] = await Promise.all([
    client.getAccountSettings().catch(() => ({})),
    client.listTrustedDomains().catch(() => []),
    client.listImGroups().catch(() => []),
    collectGroupPolicySnapshots(client, groupLimit).catch(() => ({
      sampledGroups: 0,
      lockVisibleCount: 0,
      relaxedMeetingSecurityGroups: [],
      relaxedFileControlGroups: [],
    })),
    client.listOperationLogs(operationLogLimit).catch(() => []),
    client.getPhoneCallHandlingSettings().catch(() => ({})),
    client.getPhoneRecordingPolicies().catch(() => ({})),
  ]);

  const permissiveDomains = trustedDomains.filter(isPermissiveDomain);
  const chatGoverned = imGroups.length > 0;
  const fileTransferLockedDown = fileTransferRestricted(accountSettings) && groupSnapshots.relaxedFileControlGroups.length === 0;
  const autoDeleteEnabled = recordingAutoDeleteEnabled(accountSettings);
  const retentionDays = recordingRetentionDays(accountSettings);
  const localRecordingOff = localRecordingDisabled(accountSettings);
  const phoneRecordingGoverned = phoneRecordingEnabled(phoneRecording) || phoneRecordingEnabled(phoneCallHandling);
  const phoneRecordingExplicitlyOff = phoneRecordingDisabled(phoneRecording) || phoneRecordingDisabled(phoneCallHandling);
  const auditVisible = operationLogs.length > 0;

  const findings = [
    finding(
      "ZOOM-COLLAB-01",
      "Trusted domain restrictions",
      "high",
      trustedDomains.length === 0 ? "warn" : permissiveDomains.length === 0 ? "pass" : "fail",
      trustedDomains.length === 0
        ? "No trusted domain restrictions were visible."
        : permissiveDomains.length === 0
          ? `Sampled ${trustedDomains.length} trusted domains without wildcard-style trust.`
          : `${permissiveDomains.length}/${trustedDomains.length} trusted domains appeared overly permissive.`,
      ["FedRAMP AC-4", "SOC 2 CC6.6", "PCI-DSS 1.3.4", "CIS 13.4"],
      {
        trusted_domains: trustedDomains.length,
        permissive_domains: permissiveDomains.slice(0, 25).map(domainName),
      },
    ),
    finding(
      "ZOOM-COLLAB-02",
      "Chat and file transfer governance",
      "high",
      fileTransferLockedDown && chatGoverned ? "pass" : fileTransferLockedDown || chatGoverned ? "warn" : "fail",
      fileTransferLockedDown && chatGoverned
        ? "File transfer was restricted and IM groups exposed scoped collaboration boundaries."
        : fileTransferLockedDown || chatGoverned
          ? "Only part of the collaboration governance picture was visible: either file transfer restrictions or IM group scoping."
          : "File transfer restrictions and IM group boundaries were not clearly visible.",
      ["FedRAMP SC-7", "SOC 2 CC6.6", "PCI-DSS 1.3.1", "CIS 13.1"],
      {
        file_transfer_restricted: fileTransferLockedDown,
        im_groups: imGroups.length,
        relaxed_group_file_controls: groupSnapshots.relaxedFileControlGroups.slice(0, 25),
      },
    ),
    finding(
      "ZOOM-COLLAB-03",
      "Recording retention and local recording governance",
      "high",
      !autoDeleteEnabled || !localRecordingOff
        ? "fail"
        : retentionDays === undefined || retentionDays > maxRecordingRetentionDays
          ? "warn"
          : "pass",
      !autoDeleteEnabled || !localRecordingOff
        ? "Cloud recording auto-delete was not enabled or local recording remained enabled."
        : retentionDays === undefined || retentionDays > maxRecordingRetentionDays
          ? `Recording retention was visible but exceeded the ${maxRecordingRetentionDays}-day review threshold or did not expose a day count.`
          : `Cloud recording auto-delete was enabled with retention set to ${retentionDays} days and local recording disabled.`,
      ["FedRAMP SI-12", "SOC 2 CC6.7", "PCI-DSS 3.1", "CIS 3.1"],
      {
        auto_delete_enabled: autoDeleteEnabled,
        retention_days: retentionDays ?? null,
        local_recording_disabled: localRecordingOff,
      },
    ),
    finding(
      "ZOOM-COLLAB-04",
      "Zoom Phone recording governance",
      "medium",
      phoneRecordingGoverned ? "pass" : phoneRecordingExplicitlyOff ? "fail" : "warn",
      phoneRecordingGoverned
        ? "Zoom Phone recording controls exposed active recording governance."
        : phoneRecordingExplicitlyOff
          ? "Zoom Phone recording controls appeared explicitly disabled."
          : "Zoom Phone recording governance was not clearly visible.",
      ["FedRAMP AU-14", "SOC 2 CC7.2", "PCI-DSS 10.1", "CIS 8.1"],
      {
        phone_recording_governed: phoneRecordingGoverned,
        phone_recording_explicitly_off: phoneRecordingExplicitlyOff,
        phone_call_handling_visible: hasObjectData(phoneCallHandling),
      },
    ),
    finding(
      "ZOOM-COLLAB-05",
      "Audit log visibility and group lock coverage",
      "medium",
      auditVisible && groupSnapshots.lockVisibleCount > 0 ? "pass" : auditVisible || groupSnapshots.lockVisibleCount > 0 ? "warn" : "fail",
      auditVisible && groupSnapshots.lockVisibleCount > 0
        ? `Admin operation logs were visible and ${groupSnapshots.lockVisibleCount}/${groupSnapshots.sampledGroups} sampled groups exposed lock settings.`
        : auditVisible || groupSnapshots.lockVisibleCount > 0
          ? "Either admin operation logs or group lock settings were visible, but not both."
          : "Neither admin operation logs nor group lock settings were clearly visible.",
      ["FedRAMP AU-12", "FedRAMP AC-3", "SOC 2 CC7.2", "PCI-DSS 10.2"],
      {
        operation_logs: operationLogs.length,
        sampled_groups: groupSnapshots.sampledGroups,
        groups_with_locks: groupSnapshots.lockVisibleCount,
      },
    ),
  ];

  return {
    title: "Zoom collaboration governance",
    summary: {
      account_id: config.accountId,
      trusted_domains: trustedDomains.length,
      permissive_domains: permissiveDomains.length,
      im_groups: imGroups.length,
      operation_logs: operationLogs.length,
      sampled_groups: groupSnapshots.sampledGroups,
      groups_with_locks: groupSnapshots.lockVisibleCount,
      auto_delete_enabled: autoDeleteEnabled,
      retention_days: retentionDays ?? null,
      local_recording_disabled: localRecordingOff,
      phone_recording_governed: phoneRecordingGoverned,
    },
    findings,
  };
}

export async function assessZoomMeetingSecurity(
  client: Pick<
    ZoomApiClient,
    "getResolvedConfig" | "getAccountSettings" | "getAccountLockSettings" | "listGroups" | "getGroupSettings" | "getGroupLockSettings"
  >,
  options: {
    groupLimit?: number;
  } = {},
): Promise<ZoomAssessmentResult> {
  const config = client.getResolvedConfig();
  const groupLimit = clampNumber(options.groupLimit, DEFAULT_GROUP_LIMIT, 1, 500);

  const [accountSettings, accountLockSettings, groupSnapshots] = await Promise.all([
    client.getAccountSettings().catch(() => ({})),
    client.getAccountLockSettings().catch(() => ({})),
    collectGroupPolicySnapshots(client, groupLimit).catch(() => ({
      sampledGroups: 0,
      lockVisibleCount: 0,
      relaxedMeetingSecurityGroups: [],
      relaxedFileControlGroups: [],
    })),
  ]);

  const passwordRequired = meetingPasswordRequired(accountSettings);
  const passwordLocked = meetingPasswordLocked(accountLockSettings);
  const waitingRoom = waitingRoomEnabled(accountSettings);
  const authRequired = authenticatedUsersRequired(accountSettings);
  const hostOnlySharing = screenSharingHostOnly(accountSettings);
  const transferRestricted = fileTransferRestricted(accountSettings);
  const localRecordingOff = localRecordingDisabled(accountSettings);
  const joinLinkHygiene = embedPasswordDisabled(accountSettings);
  const pmiOff = pmiRestricted(accountSettings);
  const encryptionOn = e2eeEnabled(accountSettings);
  const dataResidencyOn = dataResidencyEnabled(accountSettings);

  const findings = [
    finding(
      "ZOOM-MTG-01",
      "Meeting password enforcement and lock coverage",
      "critical",
      passwordRequired && passwordLocked ? "pass" : passwordRequired ? "warn" : "fail",
      passwordRequired && passwordLocked
        ? "Meeting password defaults were enabled and locked at account scope."
        : passwordRequired
          ? "Meeting password defaults were enabled but account lock coverage was not visible."
          : "Meeting password defaults were not clearly enforced.",
      ["FedRAMP AC-3", "SOC 2 CC6.1", "PCI-DSS 8.3.1", "CIS 5.2"],
      {
        password_required: passwordRequired,
        password_locked: passwordLocked,
      },
    ),
    finding(
      "ZOOM-MTG-02",
      "Waiting room and authenticated joins",
      "critical",
      !waitingRoom || !authRequired
        ? "fail"
        : groupSnapshots.relaxedMeetingSecurityGroups.length > 0
          ? "warn"
          : "pass",
      !waitingRoom || !authRequired
        ? "Waiting room defaults or authenticated-join requirements were not clearly enabled."
        : groupSnapshots.relaxedMeetingSecurityGroups.length > 0
          ? `${groupSnapshots.relaxedMeetingSecurityGroups.length} sampled groups appeared to weaken waiting room, password, or authentication controls.`
          : "Waiting room and authenticated join defaults were visible with no sampled group overrides weakening them.",
      ["FedRAMP AC-3", "FedRAMP IA-2", "SOC 2 CC6.1", "PCI-DSS 8.3.1"],
      {
        waiting_room: waitingRoom,
        authenticated_joins: authRequired,
        relaxed_groups: groupSnapshots.relaxedMeetingSecurityGroups.slice(0, 25),
      },
    ),
    finding(
      "ZOOM-MTG-03",
      "Screen sharing and file transfer restrictions",
      "high",
      hostOnlySharing && transferRestricted ? "pass" : hostOnlySharing || transferRestricted ? "warn" : "fail",
      hostOnlySharing && transferRestricted
        ? "Screen sharing was limited to host-only and file transfer was restricted."
        : hostOnlySharing || transferRestricted
          ? "Only one of the expected meeting content controls was clearly visible: host-only screen sharing or file transfer restriction."
          : "Screen sharing and file transfer restrictions were not clearly visible.",
      ["FedRAMP SC-7", "SOC 2 CC6.6", "PCI-DSS 1.3.1", "CIS 5.3"],
      {
        host_only_sharing: hostOnlySharing,
        file_transfer_restricted: transferRestricted,
      },
    ),
    finding(
      "ZOOM-MTG-04",
      "Recording and join-link hygiene",
      "high",
      !localRecordingOff ? "fail" : joinLinkHygiene && pmiOff ? "pass" : "warn",
      !localRecordingOff
        ? "Local recording remained enabled."
        : joinLinkHygiene && pmiOff
          ? "Local recording was disabled, passwords were not embedded in join links, and PMI usage was restricted."
          : "Local recording was disabled, but join-link password embedding or PMI restrictions were not fully visible.",
      ["FedRAMP MP-5", "SOC 2 CC6.1", "PCI-DSS 3.4.1", "CIS 3.1"],
      {
        local_recording_disabled: localRecordingOff,
        embed_password_disabled: joinLinkHygiene,
        pmi_restricted: pmiOff,
      },
    ),
    finding(
      "ZOOM-MTG-05",
      "Encryption and data residency controls",
      "high",
      encryptionOn && dataResidencyOn ? "pass" : encryptionOn || dataResidencyOn ? "warn" : "fail",
      encryptionOn && dataResidencyOn
        ? "E2EE availability and data center residency controls were visible."
        : encryptionOn || dataResidencyOn
          ? "Only one of the expected meeting protection controls was clearly visible: E2EE or data residency."
          : "E2EE and data residency controls were not clearly visible.",
      ["FedRAMP SC-8(1)", "SOC 2 CC6.7", "PCI-DSS 4.1", "CIS 14.4"],
      {
        e2ee_enabled: encryptionOn,
        data_residency_enabled: dataResidencyOn,
      },
    ),
  ];

  return {
    title: "Zoom meeting security",
    summary: {
      account_id: config.accountId,
      password_required: passwordRequired,
      password_locked: passwordLocked,
      waiting_room: waitingRoom,
      authenticated_joins: authRequired,
      host_only_sharing: hostOnlySharing,
      file_transfer_restricted: transferRestricted,
      local_recording_disabled: localRecordingOff,
      embed_password_disabled: joinLinkHygiene,
      pmi_restricted: pmiOff,
      e2ee_enabled: encryptionOn,
      data_residency_enabled: dataResidencyOn,
      sampled_groups: groupSnapshots.sampledGroups,
      relaxed_groups: groupSnapshots.relaxedMeetingSecurityGroups.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: ZoomAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 90) : "",
  ]);

  return [
    `Zoom access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: ZoomAssessmentResult): string {
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

function buildExecutiveSummary(config: ZoomResolvedConfig, assessments: ZoomAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;

  return [
    "# Zoom Audit Bundle",
    "",
    `Account: ${config.accountId}`,
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

function buildControlMatrix(findings: ZoomFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Zoom Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Zoom Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Zoom tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible Zoom audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

export async function exportZoomAuditBundle(
  client: Pick<
    ZoomApiClient,
    | "getResolvedConfig"
    | "getCurrentUser"
    | "getAccountSettings"
    | "getAccountLockSettings"
    | "listUsers"
    | "listRoles"
    | "listRoleMembers"
    | "getUserSettings"
    | "listGroups"
    | "getGroupSettings"
    | "getGroupLockSettings"
    | "listOperationLogs"
    | "listImGroups"
    | "getManagedDomains"
    | "listTrustedDomains"
    | "getPhoneCallHandlingSettings"
    | "getPhoneRecordingPolicies"
  >,
  config: ZoomResolvedConfig,
  outputRoot: string,
  options: {
    userLimit?: number;
    maxAdmins?: number;
    groupLimit?: number;
    operationLogLimit?: number;
    maxRecordingRetentionDays?: number;
  } = {},
): Promise<ZoomAuditBundleResult> {
  const access = await checkZoomAccess(client);
  const identity = await assessZoomIdentity(client, options);
  const collaboration = await assessZoomCollaborationGovernance(client, options);
  const meetingSecurity = await assessZoomMeetingSecurity(client, options);
  const assessments = [identity, collaboration, meetingSecurity];
  const findings = assessments.flatMap((assessment) => assessment.findings);

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(config.accountId)}-audit-bundle`,
  );

  await writeSecureTextFile(outputDir, "README.md", `${buildBundleReadme()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    account_id: config.accountId,
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
      formatAssessmentText(collaboration),
      "",
      formatAssessmentText(meetingSecurity),
    ].join("\n"),
  );
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", `${buildControlMatrix(findings)}\n`);
  await writeSecureTextFile(outputDir, "reports/identity.md", `${formatAssessmentText(identity)}\n`);
  await writeSecureTextFile(outputDir, "reports/collaboration-governance.md", `${formatAssessmentText(collaboration)}\n`);
  await writeSecureTextFile(outputDir, "reports/meeting-security.md", `${formatAssessmentText(meetingSecurity)}\n`);
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/collaboration-governance.json", serializeJson(collaboration));
  await writeSecureTextFile(outputDir, "analysis/meeting-security.json", serializeJson(meetingSecurity));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));

  const zipPath = resolveSecureOutputPath(outputRoot, `${safeDirName(config.accountId)}-audit-bundle.zip`);
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
    account_id: asString(value.account_id),
    token: asString(value.token),
    client_id: asString(value.client_id),
    client_secret: asString(value.client_secret),
    base_url: asString(value.base_url),
    oauth_base_url: asString(value.oauth_base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    max_admins: asNumber(value.max_admins),
  };
}

function normalizeCollaborationArgs(args: unknown): CollaborationArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    group_limit: asNumber(value.group_limit),
    operation_log_limit: asNumber(value.operation_log_limit),
    max_recording_retention_days: asNumber(value.max_recording_retention_days),
  };
}

function normalizeMeetingSecurityArgs(args: unknown): MeetingSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    group_limit: asNumber(value.group_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    group_limit: asNumber(value.group_limit),
    operation_log_limit: asNumber(value.operation_log_limit),
    max_recording_retention_days: asNumber(value.max_recording_retention_days),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): ZoomApiClient {
  return new ZoomApiClient(resolveZoomConfiguration(args));
}

const authParams = {
  account_id: Type.Optional(Type.String({ description: "Zoom account ID. Defaults to ZOOM_ACCOUNT_ID." })),
  token: Type.Optional(Type.String({ description: "Pre-issued Zoom OAuth access token. Defaults to ZOOM_TOKEN." })),
  client_id: Type.Optional(Type.String({ description: "Zoom Server-to-Server OAuth client ID. Defaults to ZOOM_CLIENT_ID." })),
  client_secret: Type.Optional(Type.String({ description: "Zoom Server-to-Server OAuth client secret. Defaults to ZOOM_CLIENT_SECRET." })),
  base_url: Type.Optional(Type.String({ description: "Zoom REST API base URL. Defaults to https://api.zoom.us/v2." })),
  oauth_base_url: Type.Optional(Type.String({ description: "Zoom OAuth base URL. Defaults to https://zoom.us or https://zoomgov.com based on base_url." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerZoomTools(pi: any): void {
  pi.registerTool({
    name: "zoom_check_access",
    label: "Check Zoom audit access",
    description:
      "Validate Zoom read-only access across account settings, users, roles, groups, operation logs, IM groups, trusted domains, and phone recording policy surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkZoomAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "zoom_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Zoom access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "zoom_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_identity",
    label: "Assess Zoom identity posture",
    description:
      "Assess Zoom identity posture across SSO sign-in restrictions, admin MFA coverage, managed domain verification, and admin privilege concentration.",
    parameters: Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessZoomIdentity(createClient(args), {
          userLimit: args.user_limit,
          maxAdmins: args.max_admins,
        });
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Zoom identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "zoom_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_collaboration_governance",
    label: "Assess Zoom collaboration governance",
    description:
      "Assess Zoom collaboration governance across trusted domain restrictions, chat and file transfer governance, recording retention, phone recording policy, and audit-log plus group-lock coverage.",
    parameters: Type.Object({
      ...authParams,
      group_limit: Type.Optional(Type.Number({ description: "Maximum groups to inspect. Defaults to 50.", default: 50 })),
      operation_log_limit: Type.Optional(Type.Number({ description: "Maximum admin operation log entries to inspect. Defaults to 200.", default: 200 })),
      max_recording_retention_days: Type.Optional(Type.Number({ description: "Maximum acceptable cloud recording retention in days before warning. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeCollaborationArgs,
    async execute(_toolCallId: string, args: CollaborationArgs) {
      try {
        const result = await assessZoomCollaborationGovernance(createClient(args), {
          groupLimit: args.group_limit,
          operationLogLimit: args.operation_log_limit,
          maxRecordingRetentionDays: args.max_recording_retention_days,
        });
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_collaboration_governance", ...result });
      } catch (error) {
        return errorResult(
          `Zoom collaboration governance assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "zoom_assess_collaboration_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_assess_meeting_security",
    label: "Assess Zoom meeting security",
    description:
      "Assess Zoom meeting security across password defaults and locks, waiting room and authenticated joins, host-only sharing, recording hygiene, and encryption plus data residency controls.",
    parameters: Type.Object({
      ...authParams,
      group_limit: Type.Optional(Type.Number({ description: "Maximum groups to inspect for override drift. Defaults to 50.", default: 50 })),
    }),
    prepareArguments: normalizeMeetingSecurityArgs,
    async execute(_toolCallId: string, args: MeetingSecurityArgs) {
      try {
        const result = await assessZoomMeetingSecurity(createClient(args), {
          groupLimit: args.group_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "zoom_assess_meeting_security", ...result });
      } catch (error) {
        return errorResult(
          `Zoom meeting security assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "zoom_assess_meeting_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "zoom_export_audit_bundle",
    label: "Export Zoom audit bundle",
    description:
      "Export a Zoom audit package with access checks, identity findings, collaboration governance, meeting security findings, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
      group_limit: Type.Optional(Type.Number({ description: "Maximum groups to inspect. Defaults to 50.", default: 50 })),
      operation_log_limit: Type.Optional(Type.Number({ description: "Maximum admin operation log entries to inspect. Defaults to 200.", default: 200 })),
      max_recording_retention_days: Type.Optional(Type.Number({ description: "Maximum acceptable cloud recording retention in days before warning. Defaults to 365.", default: 365 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveZoomConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportZoomAuditBundle(new ZoomApiClient(config), config, outputRoot, {
          userLimit: args.user_limit,
          maxAdmins: args.max_admins,
          groupLimit: args.group_limit,
          operationLogLimit: args.operation_log_limit,
          maxRecordingRetentionDays: args.max_recording_retention_days,
        });
        return textResult(
          [
            "Zoom audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "zoom_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Zoom audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "zoom_export_audit_bundle" },
        );
      }
    },
  });
}
