/**
 * Google Workspace GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the official Admin SDK
 * Directory API, Reports API, and Alert Center API. The first slice stays
 * read-only and focuses on service-account-backed domain-wide delegated access
 * so GRC engineers can assess a tenant with one audit principal.
 */
import { createPrivateKey, sign as signData } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type GwsAuthMode = "service_account" | "access_token";
type GwsFindingStatus = "Pass" | "Partial" | "Fail" | "Manual" | "Info";
type GwsSeverity = "critical" | "high" | "medium" | "low" | "info";
type FrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap"
  | "general";

const DEFAULT_OUTPUT_DIR = "./export/gws";
const DEFAULT_LOOKBACK_DAYS = 30;
const PAGE_SIZE = 200;
const MAX_USERS = 500;
const MAX_ACTIVITY_RECORDS = 200;
const MAX_ALERTS = 100;
const MAX_TOKEN_USERS = 25;
const MAX_RETRIES = 4;
const TOKEN_SKEW_MS = 60 * 1000;
const DORMANT_DAYS = 90;
const USERS_FIELDS = [
  "users(id,primaryEmail,isAdmin,isDelegatedAdmin,suspended,archived,lastLoginTime,isEnrolledIn2Sv,isEnforcedIn2Sv,orgUnitPath)",
  "nextPageToken",
].join(",");
const GWS_READ_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
  "https://www.googleapis.com/auth/admin.directory.user.security",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
  "https://www.googleapis.com/auth/apps.alerts",
];
const SUSPICIOUS_LOGIN_NAMES = new Set([
  "suspicious_login",
  "suspicious_login_less_secure_app",
  "suspicious_programmatic_login",
  "gov_attack_warning",
  "risky_sensitive_action_blocked",
  "user_signed_out_due_to_suspicious_session_cookie",
  "account_disabled_hijacked",
  "account_disabled_password_leak",
]);
const HIGH_RISK_SCOPE_PATTERN = /(admin|gmail|drive|cloud-platform|apps\.groups|directory|classroom|vault|spreadsheets|docs)/i;

type RawConfigArgs = {
  auth_mode?: string;
  credentials_file?: string;
  credentials_json?: string;
  access_token?: string;
  admin_email?: string;
  domain?: string;
  customer_id?: string;
  lookback_days?: number;
};

type GwsConfigOverlay = {
  authMode?: GwsAuthMode;
  credentialsFile?: string;
  credentialsJson?: string;
  accessToken?: string;
  adminEmail?: string;
  domain?: string;
  customerId?: string;
  lookbackDays?: number;
};

interface ServiceAccountCredentials {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

export interface GwsResolvedConfig {
  authMode: GwsAuthMode;
  credentialsFile?: string;
  accessToken?: string;
  adminEmail?: string;
  domain?: string;
  customerId: string;
  lookbackDays: number;
  serviceAccountEmail?: string;
  serviceAccountPrivateKey?: string;
  tokenUri: string;
  sourceChain: string[];
}

type GwsEndpointStatus = "ok" | "forbidden" | "unauthorized" | "error";

export interface GwsAccessProbe {
  key: string;
  path: string;
  status: GwsEndpointStatus;
  detail: string;
}

export interface GwsAccessCheckResult {
  organization: string;
  authMode: GwsAuthMode;
  status: "healthy" | "limited";
  sourceChain: string[];
  probes: GwsAccessProbe[];
  notes: string[];
  recommendedNextStep: string;
}

interface FrameworkMap {
  fedramp: string[];
  cmmc: string[];
  soc2: string[];
  cis: string[];
  pci_dss: string[];
  disa_stig: string[];
  irap: string[];
  ismap: string[];
  general: string[];
}

interface CheckDefinition {
  id: string;
  title: string;
  category: "identity" | "admin_access" | "integrations" | "monitoring";
  severity: GwsSeverity;
  frameworks: FrameworkMap;
}

export interface GwsFinding {
  id: string;
  title: string;
  category: CheckDefinition["category"];
  status: GwsFindingStatus;
  severity: GwsSeverity;
  summary: string;
  evidence: string[];
  recommendation: string;
  manualNote?: string;
  frameworks: FrameworkMap;
}

export interface GwsAssessmentResult {
  category: CheckDefinition["category"];
  findings: GwsFinding[];
  summary: Record<GwsFindingStatus, number>;
  snapshotSummary: Record<string, number | string>;
  text: string;
}

interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
}

interface TokenInventoryRecord {
  userId: string;
  primaryEmail: string;
  token: JsonRecord;
}

interface GwsIdentityData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  loginActivities: CollectedDataset<JsonRecord[]>;
}

interface GwsAdminAccessData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  adminActivities: CollectedDataset<JsonRecord[]>;
}

interface GwsIntegrationData {
  users: CollectedDataset<JsonRecord[]>;
  roles: CollectedDataset<JsonRecord[]>;
  roleAssignments: CollectedDataset<JsonRecord[]>;
  tokenInventory: CollectedDataset<TokenInventoryRecord[]>;
  tokenActivities: CollectedDataset<JsonRecord[]>;
}

interface GwsMonitoringData {
  loginActivities: CollectedDataset<JsonRecord[]>;
  adminActivities: CollectedDataset<JsonRecord[]>;
  tokenActivities: CollectedDataset<JsonRecord[]>;
  alerts: CollectedDataset<JsonRecord[]>;
}

interface GwsAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type FetchImpl = typeof fetch;

type GwsTokenCacheEntry = {
  token?: string;
  expiresAt?: number;
  pending?: Promise<string>;
};

const tokenCache = new Map<string, GwsTokenCacheEntry>();

const GWS_ACCESS_PROBES = [
  {
    key: "users",
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl("/admin/directory/v1/users", {
        customer: config.customerId,
        maxResults: 1,
        fields: USERS_FIELDS,
      }),
  },
  {
    key: "roles",
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(config.customerId)}/roles`, {
        maxResults: 1,
      }),
  },
  {
    key: "role_assignments",
    url: (config: GwsResolvedConfig) =>
      buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(config.customerId)}/roleassignments`, {
        maxResults: 1,
      }),
  },
  {
    key: "reports_login",
    url: () =>
      buildAdminUrl("/admin/reports/v1/activity/users/all/applications/login", {
        maxResults: 1,
        startTime: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      }),
  },
  {
    key: "alert_center",
    url: () => buildAlertsUrl("/v1beta1/alerts", { pageSize: 1 }),
  },
] as const;

const GWS_CHECKS: Record<string, CheckDefinition> = {
  "GWS-ID-001": {
    id: "GWS-ID-001",
    title: "Privileged users enforce 2-step verification",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2", "IA-2(1)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["1.2"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["administrator MFA enforcement"],
    },
  },
  "GWS-ID-002": {
    id: "GWS-ID-002",
    title: "Broad 2-step verification coverage for active users",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["1.1"],
      pci_dss: ["8.4.1"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["user MFA coverage"],
    },
  },
  "GWS-ID-003": {
    id: "GWS-ID-003",
    title: "Dormant active accounts stay limited",
    category: "identity",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2", "AC-2(3)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["1.8"],
      pci_dss: ["7.2.4"],
      disa_stig: ["SRG-APP-000163"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["stale user review"],
    },
  },
  "GWS-ID-004": {
    id: "GWS-ID-004",
    title: "Super admins stay strongly protected",
    category: "identity",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6", "IA-2"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["1.3"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["super admin hardening"],
    },
  },
  "GWS-ADMIN-001": {
    id: "GWS-ADMIN-001",
    title: "Super admin population stays constrained",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-5", "AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["2.1"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["least privilege for top-tier admins"],
    },
  },
  "GWS-ADMIN-002": {
    id: "GWS-ADMIN-002",
    title: "Suspended or archived privileged accounts are removed",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-2", "AC-2(3)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["2.4"],
      pci_dss: ["7.2.4"],
      disa_stig: ["SRG-APP-000163"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["privileged account lifecycle"],
    },
  },
  "GWS-ADMIN-003": {
    id: "GWS-ADMIN-003",
    title: "Delegated roles reduce Super Admin dependence",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-5", "AC-6"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.3"],
      cis: ["2.2"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["delegated administration"],
    },
  },
  "GWS-ADMIN-004": {
    id: "GWS-ADMIN-004",
    title: "Privileged activity stays observable",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-6"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.1"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-2"],
      general: ["admin audit visibility"],
    },
  },
  "GWS-ADMIN-005": {
    id: "GWS-ADMIN-005",
    title: "Group-based admin grants get explicit review",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2", "AC-6"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["2.3"],
      pci_dss: ["7.2.1"],
      disa_stig: ["SRG-APP-000038"],
      irap: ["ISM-0430"],
      ismap: ["CPS.AC-2"],
      general: ["group-based privileged access review"],
    },
  },
  "GWS-INTEG-001": {
    id: "GWS-INTEG-001",
    title: "Third-party token inventory is readable",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["CA-7", "CM-8"],
      cmmc: ["3.4.1"],
      soc2: ["CC7.1"],
      cis: ["4.1"],
      pci_dss: ["2.4"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1840"],
      ismap: ["CPS.CM-8"],
      general: ["OAuth application visibility"],
    },
  },
  "GWS-INTEG-002": {
    id: "GWS-INTEG-002",
    title: "Privileged users avoid excessive third-party token exposure",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6", "SA-9"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.2"],
      cis: ["4.2"],
      pci_dss: ["7.2.5"],
      disa_stig: ["SRG-APP-000033"],
      irap: ["ISM-0414"],
      ismap: ["CPS.AC-6"],
      general: ["privileged OAuth hygiene"],
    },
  },
  "GWS-INTEG-003": {
    id: "GWS-INTEG-003",
    title: "High-scope third-party apps stay limited",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-8", "SA-9"],
      cmmc: ["3.4.1"],
      soc2: ["CC7.1"],
      cis: ["4.3"],
      pci_dss: ["2.4"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1840"],
      ismap: ["CPS.CM-8"],
      general: ["high-scope OAuth sprawl"],
    },
  },
  "GWS-INTEG-004": {
    id: "GWS-INTEG-004",
    title: "Token activity telemetry stays available",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["4.4"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-6"],
      general: ["OAuth audit telemetry"],
    },
  },
  "GWS-MON-001": {
    id: "GWS-MON-001",
    title: "Alert Center is available for the tenant",
    category: "monitoring",
    severity: "high",
    frameworks: {
      fedramp: ["SI-4", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.1"],
      pci_dss: ["10.6.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.SI-4"],
      general: ["central alerting visibility"],
    },
  },
  "GWS-MON-002": {
    id: "GWS-MON-002",
    title: "Suspicious login backlog stays low",
    category: "monitoring",
    severity: "high",
    frameworks: {
      fedramp: ["SI-4", "IR-5"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.2"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.SI-4"],
      general: ["suspicious login response"],
    },
  },
  "GWS-MON-003": {
    id: "GWS-MON-003",
    title: "Admin audit telemetry stays available",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-2", "AU-6"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.3"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-2"],
      general: ["admin audit logging"],
    },
  },
  "GWS-MON-004": {
    id: "GWS-MON-004",
    title: "Token audit telemetry stays available",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6", "CA-7"],
      cmmc: ["3.3.1"],
      soc2: ["CC7.2"],
      cis: ["5.4"],
      pci_dss: ["10.2.1"],
      disa_stig: ["SRG-APP-000089"],
      irap: ["ISM-1387"],
      ismap: ["CPS.AU-6"],
      general: ["token audit visibility"],
    },
  },
  "GWS-MON-005": {
    id: "GWS-MON-005",
    title: "Open alert backlog is manageable",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["IR-5", "SI-4"],
      cmmc: ["3.6.2"],
      soc2: ["CC7.4"],
      cis: ["5.5"],
      pci_dss: ["12.10.5"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-1807"],
      ismap: ["CPS.IR-5"],
      general: ["alert triage hygiene"],
    },
  },
};

function buildAdminUrl(pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = new URL(`https://admin.googleapis.com${pathname}`);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value === undefined || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function buildAlertsUrl(pathname: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = new URL(`https://alertcenter.googleapis.com${pathname}`);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value === undefined || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" ? value as JsonRecord : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeLower(value: unknown): string {
  return asString(value)?.toLowerCase() ?? "";
}

function normalizeString(value: unknown): string | undefined {
  return asString(value)?.trim();
}

function summarizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function base64Url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

function buildJwtAssertion(config: GwsResolvedConfig, scopes: string[]): string {
  if (!config.serviceAccountEmail || !config.serviceAccountPrivateKey || !config.adminEmail) {
    throw new Error("Service-account auth requires service account credentials plus admin_email.");
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: config.serviceAccountEmail,
    sub: config.adminEmail,
    scope: scopes.join(" "),
    aud: config.tokenUri,
    iat: now,
    exp: now + 3600,
  };

  const encodedHeader = base64Url(JSON.stringify(header));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const privateKey = createPrivateKey(config.serviceAccountPrivateKey);
  const signature = signData("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function tokenCacheKey(config: GwsResolvedConfig, scopes: string[]): string {
  return [
    config.authMode,
    config.serviceAccountEmail ?? "direct",
    config.adminEmail ?? "none",
    scopes.join(" "),
  ].join("::");
}

async function collectDataset<T>(collector: () => Promise<T>): Promise<CollectedDataset<T>> {
  try {
    return { data: await collector() };
  } catch (error) {
    return { data: [] as unknown as T, error: summarizeError(error) };
  }
}

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  worker: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(values.length);
  let index = 0;

  async function runWorker(): Promise<void> {
    while (true) {
      const current = index;
      index += 1;
      if (current >= values.length) return;
      results[current] = await worker(values[current], current);
    }
  }

  const workers = Array.from({ length: Math.max(1, Math.min(limit, values.length)) }, () => runWorker());
  await Promise.all(workers);
  return results;
}

function normalizeRoleName(role: JsonRecord): string {
  return asString(role.roleName) ?? asString(role.name) ?? `role-${asString(role.roleId) ?? "unknown"}`;
}

function isSuperAdminRole(role: JsonRecord | undefined): boolean {
  if (!role) return false;
  if (asBoolean(role.isSuperAdminRole) === true) return true;
  return asArray(role.rolePrivileges).some((privilege) => safeLower(asRecord(privilege).privilegeName) === "super_admin");
}

function isGroupAssignment(assignment: JsonRecord): boolean {
  return safeLower(assignment.assigneeType) === "group";
}

function isUserAssignment(assignment: JsonRecord): boolean {
  return safeLower(assignment.assigneeType) === "user";
}

function getAssignmentUserIds(assignments: JsonRecord[]): Set<string> {
  return new Set(
    assignments
      .filter((assignment) => isUserAssignment(assignment))
      .map((assignment) => asString(assignment.assignedTo))
      .filter((value): value is string => Boolean(value)),
  );
}

function getRoleMap(roles: JsonRecord[]): Map<string, JsonRecord> {
  return new Map(
    roles
      .map((role) => [asString(role.roleId), role] as const)
      .filter(([roleId]) => Boolean(roleId)) as Array<[string, JsonRecord]>,
  );
}

function getUserMap(users: JsonRecord[]): Map<string, JsonRecord> {
  return new Map(
    users
      .map((user) => [asString(user.id), user] as const)
      .filter(([userId]) => Boolean(userId)) as Array<[string, JsonRecord]>,
  );
}

function getDisplayOrganization(config: GwsResolvedConfig): string {
  return config.domain ?? config.customerId;
}

function countByStatus(findings: GwsFinding[]): Record<GwsFindingStatus, number> {
  return findings.reduce(
    (acc, finding) => {
      acc[finding.status] += 1;
      return acc;
    },
    { Pass: 0, Partial: 0, Fail: 0, Manual: 0, Info: 0 } as Record<GwsFindingStatus, number>,
  );
}

function buildFinding(
  definitionId: string,
  status: GwsFindingStatus,
  summary: string,
  evidence: string[],
  recommendation: string,
  manualNote?: string,
): GwsFinding {
  const definition = GWS_CHECKS[definitionId];
  if (!definition) throw new Error(`Unknown GWS check definition: ${definitionId}`);
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    status,
    severity: definition.severity,
    summary,
    evidence,
    recommendation,
    manualNote,
    frameworks: definition.frameworks,
  };
}

function findingTable(findings: GwsFinding[]): string {
  return formatTable(
    ["Check", "Status", "Severity", "Title"],
    findings.map((finding) => [finding.id, finding.status, finding.severity, finding.title]),
  );
}

function buildAssessmentText(
  categoryLabel: string,
  organization: string,
  findings: GwsFinding[],
  snapshotSummary: Record<string, number | string>,
): string {
  const summary = countByStatus(findings);
  return [
    `${categoryLabel} for ${organization}`,
    `Summary: Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}`,
    "",
    "Snapshot:",
    ...Object.entries(snapshotSummary).map(([key, value]) => `- ${key}: ${value}`),
    "",
    findingTable(findings),
    "",
    ...findings.map((finding) => [
      `${finding.id} — ${finding.summary}`,
      ...finding.evidence.map((line) => `  • ${line}`),
      `  Recommendation: ${finding.recommendation}`,
      finding.manualNote ? `  Manual note: ${finding.manualNote}` : "",
    ].filter(Boolean).join("\n")),
  ].join("\n");
}

function renderAssessmentToolResult(result: GwsAssessmentResult) {
  return textResult(result.text, {
    category: result.category,
    findings: result.findings,
    summary: result.summary,
    snapshot_summary: result.snapshotSummary,
  });
}

function probeTable(probes: GwsAccessProbe[]): string {
  return formatTable(
    ["Probe", "Status", "Detail"],
    probes.map((probe) => [probe.key, probe.status, probe.detail]),
  );
}

function renderAccessCheck(result: GwsAccessCheckResult) {
  return textResult(
    [
      `Google Workspace access check for ${result.organization}`,
      `Status: ${result.status}`,
      `Auth mode: ${result.authMode}`,
      "",
      probeTable(result.probes),
      "",
      "Notes:",
      ...result.notes.map((note) => `- ${note}`),
      "",
      `Next step: ${result.recommendedNextStep}`,
    ].join("\n"),
    {
      organization: result.organization,
      auth_mode: result.authMode,
      source_chain: result.sourceChain,
      probes: result.probes,
      status: result.status,
    },
  );
}

function buildExportText(config: GwsResolvedConfig, result: GwsAuditBundleResult): string {
  return [
    `Exported Google Workspace audit bundle for ${getDisplayOrganization(config)}.`,
    `Output directory: ${result.outputDir}`,
    `Zip archive: ${result.zipPath}`,
    `Files written: ${result.fileCount}`,
    `Findings recorded: ${result.findingCount}`,
    `Collection warnings: ${result.errorCount}`,
  ].join("\n");
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 120) || "gws-audit";
}

function frameworkMatrixRow(finding: GwsFinding): string {
  const mappings = Object.entries(finding.frameworks)
    .filter(([, values]) => values.length > 0)
    .map(([key, values]) => `${key}: ${values.join(", ")}`)
    .join(" | ");
  return `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${mappings} |`;
}

function buildFrameworkReport(title: string, findings: GwsFinding[], key: FrameworkKey): string {
  return [
    `# ${title}`,
    "",
    "| Check | Title | Status | Severity | Mapping |",
    "| --- | --- | --- | --- | --- |",
    ...findings
      .filter((finding) => finding.frameworks[key].length > 0)
      .map((finding) => `| ${finding.id} | ${finding.title} | ${finding.status} | ${finding.severity} | ${finding.frameworks[key].join(", ")} |`),
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: GwsFinding[]): string {
  return [
    "# Unified Google Workspace Compliance Matrix",
    "",
    "| Check | Title | Status | Severity | Mappings |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map(frameworkMatrixRow),
    "",
  ].join("\n");
}

function buildFrameworkReports(findings: GwsFinding[]): Record<string, string> {
  return {
    fedramp: buildFrameworkReport("FedRAMP / NIST 800-53 Report", findings, "fedramp"),
    cmmc: buildFrameworkReport("CMMC Report", findings, "cmmc"),
    soc2: buildFrameworkReport("SOC 2 Report", findings, "soc2"),
    cis: buildFrameworkReport("CIS Google Workspace Benchmark Report", findings, "cis"),
    pci_dss: buildFrameworkReport("PCI-DSS Report", findings, "pci_dss"),
    disa_stig: buildFrameworkReport("DISA STIG Report", findings, "disa_stig"),
    irap: buildFrameworkReport("IRAP Report", findings, "irap"),
    ismap: buildFrameworkReport("ISMAP Report", findings, "ismap"),
  };
}

function collectErrors(...datasets: Array<CollectedDataset<unknown>>): string[] {
  return datasets
    .map((dataset) => dataset.error)
    .filter((value): value is string => Boolean(value));
}

function parseDate(value: unknown): number | undefined {
  const stringValue = asString(value);
  if (!stringValue) return undefined;
  const timestamp = Date.parse(stringValue);
  return Number.isFinite(timestamp) ? timestamp : undefined;
}

function countDormantUsers(users: JsonRecord[], cutoffMs: number): number {
  return users.filter((user) => {
    if (asBoolean(user.suspended) === true || asBoolean(user.archived) === true) return false;
    const lastLogin = parseDate(user.lastLoginTime);
    return !lastLogin || lastLogin < cutoffMs;
  }).length;
}

function extractActivityEventNames(activities: JsonRecord[]): string[] {
  const names: string[] = [];
  for (const activity of activities) {
    for (const event of asArray(activity.events)) {
      const name = asString(asRecord(event).name);
      if (name) names.push(name);
    }
  }
  return names;
}

function countMatchingEvents(activities: JsonRecord[], wanted: Set<string>): number {
  return extractActivityEventNames(activities).filter((name) => wanted.has(name)).length;
}

function getPrivilegedUsers(
  users: JsonRecord[],
  roles: JsonRecord[],
  roleAssignments: JsonRecord[],
): {
  privilegedUsers: JsonRecord[];
  superAdmins: JsonRecord[];
  delegatedAdmins: JsonRecord[];
  groupAssignmentCount: number;
} {
  const userMap = getUserMap(users);
  const roleMap = getRoleMap(roles);
  const privilegedUserIds = new Set<string>();
  const superAdminUserIds = new Set<string>();

  for (const user of users) {
    const userId = asString(user.id);
    if (!userId) continue;
    if (asBoolean(user.isAdmin) === true || asBoolean(user.isDelegatedAdmin) === true) {
      privilegedUserIds.add(userId);
    }
    if (asBoolean(user.isAdmin) === true) {
      superAdminUserIds.add(userId);
    }
  }

  for (const assignment of roleAssignments) {
    if (!isUserAssignment(assignment)) continue;
    const userId = asString(assignment.assignedTo);
    if (!userId) continue;
    privilegedUserIds.add(userId);
    const role = roleMap.get(asString(assignment.roleId) ?? "");
    if (isSuperAdminRole(role)) {
      superAdminUserIds.add(userId);
    }
  }

  const privilegedUsers = Array.from(privilegedUserIds)
    .map((userId) => userMap.get(userId))
    .filter((user): user is JsonRecord => Boolean(user));
  const superAdmins = Array.from(superAdminUserIds)
    .map((userId) => userMap.get(userId))
    .filter((user): user is JsonRecord => Boolean(user));
  const delegatedAdmins = privilegedUsers.filter((user) => asBoolean(user.isAdmin) !== true);
  const groupAssignmentCount = roleAssignments.filter((assignment) => isGroupAssignment(assignment)).length;

  return {
    privilegedUsers,
    superAdmins,
    delegatedAdmins,
    groupAssignmentCount,
  };
}

function selectUsersForTokenInventory(
  users: JsonRecord[],
  privilegedUsers: JsonRecord[],
): JsonRecord[] {
  const activeUsers = users.filter((user) => asBoolean(user.suspended) !== true && asBoolean(user.archived) !== true);
  const selected = new Map<string, JsonRecord>();
  for (const user of privilegedUsers) {
    const userId = asString(user.id);
    if (!userId) continue;
    selected.set(userId, user);
  }
  for (const user of activeUsers) {
    if (selected.size >= MAX_TOKEN_USERS) break;
    const userId = asString(user.id);
    if (!userId || selected.has(userId)) continue;
    selected.set(userId, user);
  }
  return Array.from(selected.values()).slice(0, MAX_TOKEN_USERS);
}

function flattenTokens(records: TokenInventoryRecord[]): JsonRecord[] {
  return records.map((record) => record.token);
}

function countHighRiskTokens(records: TokenInventoryRecord[]): number {
  return records.filter((record) => {
    const scopes = asArray(record.token.scopes).map((scope) => asString(scope) ?? "");
    return scopes.some((scope) => HIGH_RISK_SCOPE_PATTERN.test(scope)) || scopes.length >= 6;
  }).length;
}

function uniqueClientDisplayNames(records: TokenInventoryRecord[]): string[] {
  return Array.from(
    new Set(
      records
        .map((record) => asString(record.token.displayText) ?? asString(record.token.clientId) ?? "unknown-client")
        .filter(Boolean),
    ),
  );
}

function countOpenAlerts(alerts: JsonRecord[]): number {
  return alerts.filter((alert) => {
    const status = safeLower(alert.state) || safeLower(alert.status);
    return !["closed", "done", "resolved"].includes(status);
  }).length;
}

async function buildBundleReadme(rootDir: string): Promise<void> {
  await writeSecureTextFile(
    rootDir,
    "README.md",
    [
      "# Google Workspace Audit Bundle Quick Reference",
      "",
      "- `core_data/` contains the raw Google Workspace API payloads collected for this assessment.",
      "- `analysis/` contains normalized findings in JSON and terminal-friendly markdown.",
      "- `reports/` contains executive and framework-specific markdown reports.",
      "- `summary.md` is the quickest human-readable starting point.",
      "",
      "This bundle is read-only evidence collection. It does not write back to the tenant.",
      "",
    ].join("\n"),
  );
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

async function readServiceAccountFromFile(pathname: string): Promise<ServiceAccountCredentials> {
  const contents = readFileSync(pathname, "utf8");
  return parseServiceAccount(contents, pathname);
}

function parseServiceAccount(contents: string, label: string): ServiceAccountCredentials {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch (error) {
    throw new Error(`Failed to parse service account JSON from ${label}: ${summarizeError(error)}`);
  }
  const record = asRecord(parsed);
  const clientEmail = asString(record.client_email);
  const privateKey = asString(record.private_key);
  if (!clientEmail || !privateKey) {
    throw new Error(`Service account JSON from ${label} is missing client_email or private_key.`);
  }
  return {
    client_email: clientEmail,
    private_key: privateKey,
    token_uri: asString(record.token_uri),
  };
}

function normalizeAssessmentArgs(args: RawConfigArgs): RawConfigArgs {
  return {
    ...args,
    auth_mode: normalizeString(args.auth_mode),
    credentials_file: normalizeString(args.credentials_file),
    credentials_json: normalizeString(args.credentials_json),
    access_token: normalizeString(args.access_token),
    admin_email: normalizeString(args.admin_email),
    domain: normalizeString(args.domain),
    customer_id: normalizeString(args.customer_id),
  };
}

const normalizeExportArgs = normalizeAssessmentArgs;

export async function resolveGwsConfiguration(
  args: RawConfigArgs = {},
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsResolvedConfig> {
  const sourceChain: string[] = [];
  const overlays: GwsConfigOverlay[] = [];

  const envOverlay: GwsConfigOverlay = {
    authMode: normalizeString(env.GWS_AUTH_MODE) as GwsAuthMode | undefined,
    credentialsFile: normalizeString(env.GWS_CREDENTIALS_FILE)
      ?? normalizeString(env.GWS_SERVICE_ACCOUNT_FILE)
      ?? normalizeString(env.GOOGLE_APPLICATION_CREDENTIALS),
    credentialsJson: normalizeString(env.GWS_CREDENTIALS_JSON)
      ?? normalizeString(env.GWS_SERVICE_ACCOUNT_JSON),
    accessToken: normalizeString(env.GWS_ACCESS_TOKEN),
    adminEmail: normalizeString(env.GWS_ADMIN_EMAIL),
    domain: normalizeString(env.GWS_DOMAIN),
    customerId: normalizeString(env.GWS_CUSTOMER_ID),
    lookbackDays: env.GWS_LOOKBACK_DAYS ? Number(env.GWS_LOOKBACK_DAYS) : undefined,
  };
  if (Object.values(envOverlay).some((value) => value !== undefined)) {
    overlays.push(envOverlay);
    sourceChain.push("environment");
  }

  const normalizedArgs = normalizeAssessmentArgs(args);
  const argsOverlay: GwsConfigOverlay = {
    authMode: normalizeString(normalizedArgs.auth_mode) as GwsAuthMode | undefined,
    credentialsFile: normalizedArgs.credentials_file,
    credentialsJson: normalizedArgs.credentials_json,
    accessToken: normalizedArgs.access_token,
    adminEmail: normalizedArgs.admin_email,
    domain: normalizedArgs.domain,
    customerId: normalizedArgs.customer_id,
    lookbackDays: normalizedArgs.lookback_days,
  };
  if (Object.values(argsOverlay).some((value) => value !== undefined)) {
    overlays.push(argsOverlay);
    sourceChain.push("arguments");
  }

  const merged = overlays.reduce<GwsConfigOverlay>((acc, overlay) => ({ ...acc, ...overlay }), {});
  const authMode = (merged.authMode
    ?? (merged.accessToken ? "access_token" : "service_account")) as GwsAuthMode;
  const customerId = merged.customerId ?? "my_customer";
  const lookbackDays = Number.isFinite(merged.lookbackDays)
    ? Math.max(1, Math.min(180, Number(merged.lookbackDays)))
    : DEFAULT_LOOKBACK_DAYS;

  let serviceAccount: ServiceAccountCredentials | undefined;
  if (authMode === "service_account") {
    if (merged.credentialsJson) {
      serviceAccount = parseServiceAccount(merged.credentialsJson, "credentials_json");
    } else if (merged.credentialsFile) {
      serviceAccount = await readServiceAccountFromFile(merged.credentialsFile);
    } else {
      throw new Error(
        "Google Workspace service-account auth requires credentials_json or credentials_file (or the matching environment variable).",
      );
    }
    if (!merged.adminEmail) {
      throw new Error("Google Workspace service-account auth requires admin_email for delegated access.");
    }
  }

  if (authMode === "access_token" && !merged.accessToken) {
    throw new Error("Google Workspace access_token auth requires access_token or GWS_ACCESS_TOKEN.");
  }

  return {
    authMode,
    credentialsFile: merged.credentialsFile,
    accessToken: merged.accessToken,
    adminEmail: merged.adminEmail,
    domain: merged.domain,
    customerId,
    lookbackDays,
    serviceAccountEmail: serviceAccount?.client_email,
    serviceAccountPrivateKey: serviceAccount?.private_key,
    tokenUri: serviceAccount?.token_uri ?? "https://oauth2.googleapis.com/token",
    sourceChain,
  };
}

export class GoogleWorkspaceAuditorClient {
  constructor(
    private readonly config: GwsResolvedConfig,
    private readonly fetchImpl: FetchImpl = fetch,
  ) {}

  async fetchJson(url: string, scopes: string[] = GWS_READ_SCOPES): Promise<JsonRecord> {
    const response = await this.request(url, scopes);
    return asRecord(await response.json());
  }

  async probe(url: string, scopes: string[] = GWS_READ_SCOPES): Promise<GwsAccessProbe> {
    const response = await this.request(url, scopes, { allowFailure: true });
    const pathname = new URL(url).pathname;
    if (!response.ok) {
      return {
        key: basename(pathname) || pathname,
        path: pathname,
        status: response.status === 401 ? "unauthorized" : response.status === 403 ? "forbidden" : "error",
        detail: `${response.status} ${response.statusText}`,
      };
    }
    return {
      key: basename(pathname) || pathname,
      path: pathname,
      status: "ok",
      detail: `${response.status} ${response.statusText}`,
    };
  }

  async listUsers(): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (items.length < MAX_USERS) {
      const payload = await this.fetchJson(
        buildAdminUrl("/admin/directory/v1/users", {
          customer: this.config.customerId,
          maxResults: PAGE_SIZE,
          orderBy: "email",
          sortOrder: "ASCENDING",
          projection: "basic",
          showDeleted: "false",
          fields: USERS_FIELDS,
          pageToken,
        }),
      );
      items.push(...asArray(payload.users).map(asRecord));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken) break;
    }
    return items.slice(0, MAX_USERS);
  }

  async listRoles(): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (true) {
      const payload = await this.fetchJson(
        buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(this.config.customerId)}/roles`, {
          maxResults: PAGE_SIZE,
          pageToken,
        }),
      );
      items.push(...asArray(payload.items).map(asRecord));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken) break;
    }
    return items;
  }

  async listRoleAssignments(): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (true) {
      const payload = await this.fetchJson(
        buildAdminUrl(`/admin/directory/v1/customer/${encodeURIComponent(this.config.customerId)}/roleassignments`, {
          maxResults: PAGE_SIZE,
          pageToken,
        }),
      );
      items.push(...asArray(payload.items).map(asRecord));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken) break;
    }
    return items;
  }

  async listActivities(applicationName: "login" | "admin" | "token"): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    const startTime = new Date(Date.now() - this.config.lookbackDays * 24 * 60 * 60 * 1000).toISOString();

    while (items.length < MAX_ACTIVITY_RECORDS) {
      const payload = await this.fetchJson(
        buildAdminUrl(`/admin/reports/v1/activity/users/all/applications/${applicationName}`, {
          startTime,
          maxResults: Math.min(PAGE_SIZE, MAX_ACTIVITY_RECORDS - items.length),
          pageToken,
        }),
      );
      items.push(...asArray(payload.items).map(asRecord));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken) break;
    }

    return items.slice(0, MAX_ACTIVITY_RECORDS);
  }

  async listAlerts(): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    while (items.length < MAX_ALERTS) {
      const payload = await this.fetchJson(
        buildAlertsUrl("/v1beta1/alerts", {
          pageSize: Math.min(PAGE_SIZE, MAX_ALERTS - items.length),
          pageToken,
        }),
      );
      items.push(...asArray(payload.alerts).map(asRecord));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken) break;
    }
    return items.slice(0, MAX_ALERTS);
  }

  async listUserTokens(userKey: string): Promise<JsonRecord[]> {
    const payload = await this.fetchJson(
      buildAdminUrl(`/admin/directory/v1/users/${encodeURIComponent(userKey)}/tokens`),
    );
    return asArray(payload.items).map(asRecord);
  }

  private async request(
    url: string,
    scopes: string[],
    options: { allowFailure?: boolean; attempt?: number } = {},
  ): Promise<Response> {
    const attempt = options.attempt ?? 0;
    const token = await this.getAccessToken(scopes);
    const response = await this.fetchImpl(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
      },
    });

    if (response.ok || options.allowFailure) {
      if (!response.ok && !options.allowFailure && attempt >= MAX_RETRIES) {
        throw new Error(await this.readError(response));
      }
      return response;
    }

    if (response.status === 401 && attempt < MAX_RETRIES) {
      this.clearToken(scopes);
      return this.request(url, scopes, { ...options, attempt: attempt + 1 });
    }

    if ((response.status === 429 || response.status >= 500) && attempt < MAX_RETRIES) {
      await sleep(250 * 2 ** attempt);
      return this.request(url, scopes, { ...options, attempt: attempt + 1 });
    }

    throw new Error(await this.readError(response));
  }

  private async readError(response: Response): Promise<string> {
    try {
      const payload = asRecord(await response.json());
      const error = asRecord(payload.error);
      const message = asString(error.message) ?? asString(payload.message);
      if (message) {
        return `${response.status} ${response.statusText}: ${message}`;
      }
    } catch {
      // fall through
    }
    return `${response.status} ${response.statusText}`;
  }

  private clearToken(scopes: string[]): void {
    tokenCache.delete(tokenCacheKey(this.config, scopes));
  }

  private async getAccessToken(scopes: string[]): Promise<string> {
    if (this.config.authMode === "access_token" && this.config.accessToken) {
      return this.config.accessToken;
    }

    const cacheKey = tokenCacheKey(this.config, scopes);
    const entry = tokenCache.get(cacheKey);
    const now = Date.now();
    if (entry?.token && entry.expiresAt && entry.expiresAt - TOKEN_SKEW_MS > now) {
      return entry.token;
    }
    if (entry?.pending) {
      return entry.pending;
    }

    const pending = this.fetchServiceAccountAccessToken(scopes).then((tokenEntry) => {
      tokenCache.set(cacheKey, tokenEntry);
      return tokenEntry.token;
    }).finally(() => {
      const current = tokenCache.get(cacheKey);
      if (current?.pending) {
        delete current.pending;
      }
    });

    tokenCache.set(cacheKey, { ...entry, pending });
    return pending;
  }

  private async fetchServiceAccountAccessToken(scopes: string[]): Promise<{ token: string; expiresAt: number }> {
    const assertion = buildJwtAssertion(this.config, scopes);
    const response = await this.fetchImpl(this.config.tokenUri, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to obtain Google access token: ${await this.readError(response)}`);
    }

    const payload = asRecord(await response.json());
    const accessToken = asString(payload.access_token);
    const expiresIn = asNumber(payload.expires_in) ?? 3600;
    if (!accessToken) {
      throw new Error("Google token exchange response did not include access_token.");
    }

    return {
      token: accessToken,
      expiresAt: Date.now() + expiresIn * 1000,
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

export function clearGwsTokenCacheForTests(): void {
  tokenCache.clear();
}

export async function runGwsAccessCheck(
  client: GoogleWorkspaceAuditorClient,
  config: GwsResolvedConfig,
): Promise<GwsAccessCheckResult> {
  const probes = await Promise.all(
    GWS_ACCESS_PROBES.map(async (probe) => {
      const result = await client.probe(probe.url(config));
      return {
        ...result,
        key: probe.key,
      };
    }),
  );

  const okKeys = new Set(probes.filter((probe) => probe.status === "ok").map((probe) => probe.key));
  const status = okKeys.has("users") && okKeys.has("roles") && okKeys.has("role_assignments") && okKeys.has("reports_login")
    ? "healthy"
    : "limited";

  const notes = [
    config.authMode === "service_account"
      ? "Service-account auth assumes domain-wide delegation is configured for the supplied admin email."
      : "Access-token mode skips service-account token exchange and uses the provided bearer directly.",
    "The first slice is intentionally bounded to Directory users and roles, Reports audit activity, Alert Center, and token inventory.",
  ];

  return {
    organization: getDisplayOrganization(config),
    authMode: config.authMode,
    status,
    sourceChain: config.sourceChain,
    probes,
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run the focused GWS assessment that matches the question, or export the audit bundle for a full evidence package."
      : "Fix the missing Google scopes or delegated-admin setup, then re-run gws_check_access before trusting posture findings.",
  };
}

export async function collectGwsIdentityData(
  client: GoogleWorkspaceAuditorClient,
): Promise<GwsIdentityData> {
  const [users, roles, roleAssignments, loginActivities] = await Promise.all([
    collectDataset(() => client.listUsers()),
    collectDataset(() => client.listRoles()),
    collectDataset(() => client.listRoleAssignments()),
    collectDataset(() => client.listActivities("login")),
  ]);

  return { users, roles, roleAssignments, loginActivities };
}

export async function collectGwsAdminAccessData(
  client: GoogleWorkspaceAuditorClient,
): Promise<GwsAdminAccessData> {
  const [users, roles, roleAssignments, adminActivities] = await Promise.all([
    collectDataset(() => client.listUsers()),
    collectDataset(() => client.listRoles()),
    collectDataset(() => client.listRoleAssignments()),
    collectDataset(() => client.listActivities("admin")),
  ]);

  return { users, roles, roleAssignments, adminActivities };
}

async function collectTokenInventory(
  client: GoogleWorkspaceAuditorClient,
  users: JsonRecord[],
): Promise<CollectedDataset<TokenInventoryRecord[]>> {
  const records: TokenInventoryRecord[] = [];
  const errors: string[] = [];
  const collected = await mapWithConcurrency(users, 4, async (user) => {
    const userKey = asString(user.primaryEmail) ?? asString(user.id);
    if (!userKey) return { records: [] as TokenInventoryRecord[], error: undefined };
    try {
      const tokens = await client.listUserTokens(userKey);
      return {
        records: tokens.map((token) => ({
          userId: asString(user.id) ?? userKey,
          primaryEmail: asString(user.primaryEmail) ?? userKey,
          token,
        })),
      };
    } catch (error) {
      return {
        records: [] as TokenInventoryRecord[],
        error: `${userKey}: ${summarizeError(error)}`,
      };
    }
  });

  for (const result of collected) {
    records.push(...result.records);
    if (result.error) errors.push(result.error);
  }

  return {
    data: records,
    error: errors.length > 0 ? errors.join("; ") : undefined,
  };
}

export async function collectGwsIntegrationData(
  client: GoogleWorkspaceAuditorClient,
): Promise<GwsIntegrationData> {
  const [users, roles, roleAssignments, tokenActivities] = await Promise.all([
    collectDataset(() => client.listUsers()),
    collectDataset(() => client.listRoles()),
    collectDataset(() => client.listRoleAssignments()),
    collectDataset(() => client.listActivities("token")),
  ]);

  const privilegedContext = getPrivilegedUsers(users.data, roles.data, roleAssignments.data);
  const tokenUsers = selectUsersForTokenInventory(users.data, privilegedContext.privilegedUsers);
  const tokenInventory = await collectTokenInventory(client, tokenUsers);

  return {
    users,
    roles,
    roleAssignments,
    tokenInventory,
    tokenActivities,
  };
}

export async function collectGwsMonitoringData(
  client: GoogleWorkspaceAuditorClient,
): Promise<GwsMonitoringData> {
  const [loginActivities, adminActivities, tokenActivities, alerts] = await Promise.all([
    collectDataset(() => client.listActivities("login")),
    collectDataset(() => client.listActivities("admin")),
    collectDataset(() => client.listActivities("token")),
    collectDataset(() => client.listAlerts()),
  ]);

  return { loginActivities, adminActivities, tokenActivities, alerts };
}

export function assessGwsIdentity(
  data: GwsIdentityData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const users = data.users.data;
  const roles = data.roles.data;
  const roleAssignments = data.roleAssignments.data;
  const privileged = getPrivilegedUsers(users, roles, roleAssignments);
  const activeUsers = users.filter((user) => asBoolean(user.suspended) !== true && asBoolean(user.archived) !== true);
  const enforcedUsers = activeUsers.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const enrolledUsers = activeUsers.filter((user) => asBoolean(user.isEnrolledIn2Sv) === true);
  const privilegedEnforced = privileged.privilegedUsers.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const superAdminEnforced = privileged.superAdmins.filter((user) => asBoolean(user.isEnforcedIn2Sv) === true);
  const dormantCutoff = Date.now() - DORMANT_DAYS * 24 * 60 * 60 * 1000;
  const dormantUsers = countDormantUsers(activeUsers, dormantCutoff);

  const findings: GwsFinding[] = [];

  const privilegedCoverage = privileged.privilegedUsers.length === 0
    ? 0
    : privilegedEnforced.length / privileged.privilegedUsers.length;
  findings.push(
    privileged.privilegedUsers.length === 0
      ? buildFinding(
        "GWS-ID-001",
        "Manual",
        "No privileged users were identified from the collected data, so admin MFA posture could not be confirmed.",
        [
          `Users collected: ${users.length}`,
          `Role assignments collected: ${roleAssignments.length}`,
        ],
        "Confirm the tenant has delegated or super-admin principals assigned, then re-run the assessment.",
        "Google Workspace role coverage is required to distinguish normal users from privileged identities.",
      )
      : privilegedCoverage >= 1
      ? buildFinding(
        "GWS-ID-001",
        "Pass",
        "Every privileged user in the collected dataset enforces 2-step verification.",
        [
          `Privileged users: ${privileged.privilegedUsers.length}`,
          `Privileged users enforced in 2SV: ${privilegedEnforced.length}`,
        ],
        "Keep delegated-admin reviews in place so newly privileged users stay covered by enforced 2SV.",
      )
      : privilegedCoverage >= 0.8
      ? buildFinding(
        "GWS-ID-001",
        "Partial",
        "Most privileged users enforce 2-step verification, but there are still uncovered admin identities.",
        [
          `Privileged users: ${privileged.privilegedUsers.length}`,
          `Privileged users enforced in 2SV: ${privilegedEnforced.length}`,
        ],
        "Require enforced 2-step verification for the remaining privileged users before treating the tenant as strongly hardened.",
      )
      : buildFinding(
        "GWS-ID-001",
        "Fail",
        "Too many privileged users lack enforced 2-step verification.",
        [
          `Privileged users: ${privileged.privilegedUsers.length}`,
          `Privileged users enforced in 2SV: ${privilegedEnforced.length}`,
        ],
        "Make enforced 2-step verification mandatory for privileged users immediately.",
      ),
  );

  const userCoverage = activeUsers.length === 0 ? 0 : enforcedUsers.length / activeUsers.length;
  findings.push(
    activeUsers.length === 0
      ? buildFinding(
        "GWS-ID-002",
        "Manual",
        "No active users were available in the collected dataset, so broad 2SV coverage could not be assessed.",
        [`Collected active users: ${activeUsers.length}`],
        "Verify the delegated admin can read the user directory and re-run the assessment.",
      )
      : userCoverage >= 0.98
      ? buildFinding(
        "GWS-ID-002",
        "Pass",
        "2-step verification enforcement is near-universal across active users.",
        [
          `Active users: ${activeUsers.length}`,
          `Users enforced in 2SV: ${enforcedUsers.length}`,
          `Users enrolled in 2SV: ${enrolledUsers.length}`,
        ],
        "Maintain enrollment and enforcement checks so coverage stays high as users churn.",
      )
      : userCoverage >= 0.85
      ? buildFinding(
        "GWS-ID-002",
        "Partial",
        "2-step verification coverage is substantial but still leaves a meaningful population without enforced protection.",
        [
          `Active users: ${activeUsers.length}`,
          `Users enforced in 2SV: ${enforcedUsers.length}`,
          `Users enrolled in 2SV: ${enrolledUsers.length}`,
        ],
        "Close the remaining MFA enforcement gap, starting with the highest-risk org units and externally reachable users.",
      )
      : buildFinding(
        "GWS-ID-002",
        "Fail",
        "Broad 2-step verification coverage is too low for a strong compliance posture.",
        [
          `Active users: ${activeUsers.length}`,
          `Users enforced in 2SV: ${enforcedUsers.length}`,
          `Users enrolled in 2SV: ${enrolledUsers.length}`,
        ],
        "Roll out enforced 2-step verification for the tenant in stages, prioritizing admins and high-risk populations first.",
      ),
  );

  findings.push(
    dormantUsers === 0
      ? buildFinding(
        "GWS-ID-003",
        "Pass",
        "No dormant active accounts were detected in the collected dataset.",
        [
          `Active users reviewed: ${activeUsers.length}`,
          `Dormant active users (> ${DORMANT_DAYS} days or unknown last login): ${dormantUsers}`,
        ],
        "Keep periodic stale-account reviews in place so unused access does not accumulate.",
      )
      : dormantUsers <= Math.max(2, Math.ceil(activeUsers.length * 0.05))
      ? buildFinding(
        "GWS-ID-003",
        "Partial",
        "A small set of dormant active accounts needs review.",
        [
          `Active users reviewed: ${activeUsers.length}`,
          `Dormant active users (> ${DORMANT_DAYS} days or unknown last login): ${dormantUsers}`,
        ],
        "Review dormant accounts and suspend or archive those that are no longer justified.",
      )
      : buildFinding(
        "GWS-ID-003",
        "Fail",
        "There are too many dormant active accounts in the tenant.",
        [
          `Active users reviewed: ${activeUsers.length}`,
          `Dormant active users (> ${DORMANT_DAYS} days or unknown last login): ${dormantUsers}`,
        ],
        "Perform a tenant-wide stale-account cleanup and tighten the joiner/mover/leaver review cadence.",
      ),
  );

  findings.push(
    privileged.superAdmins.length === 0
      ? buildFinding(
        "GWS-ID-004",
        "Manual",
        "No super-admin accounts were identified from the collected user and role data.",
        [
          `Role assignments collected: ${roleAssignments.length}`,
          `Users with isAdmin=true: ${users.filter((user) => asBoolean(user.isAdmin) === true).length}`,
        ],
        "Confirm super-admin coverage manually if the tenant intentionally relies only on delegated roles.",
      )
      : superAdminEnforced.length === privileged.superAdmins.length
      ? buildFinding(
        "GWS-ID-004",
        "Pass",
        "All identified super admins enforce 2-step verification.",
        [
          `Super admins: ${privileged.superAdmins.length}`,
          `Super admins enforced in 2SV: ${superAdminEnforced.length}`,
        ],
        "Keep the super-admin roster short and review it regularly.",
      )
      : buildFinding(
        "GWS-ID-004",
        "Fail",
        "One or more identified super admins do not enforce 2-step verification.",
        [
          `Super admins: ${privileged.superAdmins.length}`,
          `Super admins enforced in 2SV: ${superAdminEnforced.length}`,
        ],
        "Require enforced 2-step verification for every super-admin account immediately.",
      ),
  );

  const snapshotSummary = {
    active_users: activeUsers.length,
    privileged_users: privileged.privilegedUsers.length,
    super_admins: privileged.superAdmins.length,
    users_enforced_in_2sv: enforcedUsers.length,
    dormant_active_users: dormantUsers,
  };

  return {
    category: "identity",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace identity assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsAdminAccess(
  data: GwsAdminAccessData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const users = data.users.data;
  const roles = data.roles.data;
  const roleAssignments = data.roleAssignments.data;
  const privileged = getPrivilegedUsers(users, roles, roleAssignments);
  const staleCutoff = Date.now() - DORMANT_DAYS * 24 * 60 * 60 * 1000;
  const suspendedPrivileged = privileged.privilegedUsers.filter((user) =>
    asBoolean(user.suspended) === true || asBoolean(user.archived) === true);
  const stalePrivileged = privileged.privilegedUsers.filter((user) => {
    if (asBoolean(user.suspended) === true || asBoolean(user.archived) === true) return false;
    const lastLogin = parseDate(user.lastLoginTime);
    return !lastLogin || lastLogin < staleCutoff;
  });

  const findings: GwsFinding[] = [];
  findings.push(
    privileged.superAdmins.length <= 4
      ? buildFinding(
        "GWS-ADMIN-001",
        "Pass",
        "The tenant keeps the super-admin population constrained.",
        [`Super admins identified: ${privileged.superAdmins.length}`],
        "Maintain at least one break-glass administrator, but keep routine admin work delegated whenever possible.",
      )
      : privileged.superAdmins.length <= 6
      ? buildFinding(
        "GWS-ADMIN-001",
        "Partial",
        "The tenant has a moderately broad super-admin population.",
        [`Super admins identified: ${privileged.superAdmins.length}`],
        "Reduce routine Super Admin usage by migrating operators to delegated roles where possible.",
      )
      : buildFinding(
        "GWS-ADMIN-001",
        "Fail",
        "The super-admin population is broader than a least-privilege posture would usually tolerate.",
        [`Super admins identified: ${privileged.superAdmins.length}`],
        "Shrink the super-admin set and move everyday administration into narrower delegated roles.",
      ),
  );

  findings.push(
    suspendedPrivileged.length === 0
      ? buildFinding(
        "GWS-ADMIN-002",
        "Pass",
        "No suspended or archived privileged accounts were identified.",
        [`Privileged users reviewed: ${privileged.privilegedUsers.length}`],
        "Keep deprovisioning reviews tied to privileged-role assignments.",
      )
      : buildFinding(
        "GWS-ADMIN-002",
        "Fail",
        "Suspended or archived users still appear in the privileged population.",
        [
          `Privileged users reviewed: ${privileged.privilegedUsers.length}`,
          `Suspended or archived privileged users: ${suspendedPrivileged.length}`,
        ],
        "Remove or verify every privileged assignment attached to suspended or archived identities.",
      ),
  );

  findings.push(
    privileged.delegatedAdmins.length > 0
      ? buildFinding(
        "GWS-ADMIN-003",
        "Pass",
        "The tenant uses delegated or custom admin roles in addition to super-admin access.",
        [
          `Delegated admin users identified: ${privileged.delegatedAdmins.length}`,
          `Total privileged users: ${privileged.privilegedUsers.length}`,
        ],
        "Continue using delegated roles to keep Super Admin access exceptional.",
      )
      : buildFinding(
        "GWS-ADMIN-003",
        "Manual",
        "The collected data did not show clear delegated-admin usage beyond Super Admin.",
        [
          `Delegated admin users identified: ${privileged.delegatedAdmins.length}`,
          `Total privileged users: ${privileged.privilegedUsers.length}`,
        ],
        "Review whether the tenant intentionally uses only Super Admin or whether delegated roles should be expanded.",
      ),
  );

  findings.push(
    data.adminActivities.error
      ? buildFinding(
        "GWS-ADMIN-004",
        "Fail",
        "Admin audit activity could not be read with the supplied principal.",
        [`Admin activity error: ${data.adminActivities.error}`],
        "Grant the Reports audit scope and verify delegated-admin permissions for admin activity visibility.",
      )
      : buildFinding(
        "GWS-ADMIN-004",
        "Pass",
        "Admin activity telemetry is readable for the configured lookback window.",
        [`Admin activities collected: ${data.adminActivities.data.length}`],
        "Use the admin activity stream during periodic privileged-access reviews and incident response.",
      ),
  );

  findings.push(
    privileged.groupAssignmentCount === 0
      ? buildFinding(
        "GWS-ADMIN-005",
        "Pass",
        "No group-based role assignments were detected in the collected dataset.",
        [`Group role assignments: ${privileged.groupAssignmentCount}`],
        "Keep group-based privileged grants documented if they are introduced later.",
      )
      : buildFinding(
        "GWS-ADMIN-005",
        "Manual",
        "Group-based role assignments exist and need explicit membership review.",
        [`Group role assignments: ${privileged.groupAssignmentCount}`],
        "Review security-group membership and make sure external or stale principals cannot inherit admin access indirectly.",
        "This first slice does not expand group membership, so the inherited privileged population needs a manual spot check.",
      ),
  );

  const snapshotSummary = {
    privileged_users: privileged.privilegedUsers.length,
    super_admins: privileged.superAdmins.length,
    delegated_admins: privileged.delegatedAdmins.length,
    stale_privileged_users: stalePrivileged.length,
    group_role_assignments: privileged.groupAssignmentCount,
  };

  return {
    category: "admin_access",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace admin-access assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsIntegrations(
  data: GwsIntegrationData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const privileged = getPrivilegedUsers(data.users.data, data.roles.data, data.roleAssignments.data);
  const privilegedIds = new Set(privileged.privilegedUsers.map((user) => asString(user.id)).filter((value): value is string => Boolean(value)));
  const allTokens = data.tokenInventory.data;
  const privilegedTokens = allTokens.filter((record) => privilegedIds.has(record.userId));
  const uniqueClients = uniqueClientDisplayNames(allTokens);
  const highRiskTokens = countHighRiskTokens(allTokens);
  const tokenEvents = extractActivityEventNames(data.tokenActivities.data);

  const findings: GwsFinding[] = [];
  findings.push(
    data.tokenInventory.error
      ? buildFinding(
        "GWS-INTEG-001",
        "Partial",
        "Third-party token inventory was only partially readable.",
        [
          `Token inventory errors: ${data.tokenInventory.error}`,
          `Token records collected: ${allTokens.length}`,
        ],
        "Grant the admin.directory.user.security scope and verify the delegated admin can enumerate third-party tokens.",
      )
      : buildFinding(
        "GWS-INTEG-001",
        "Pass",
        "Third-party token inventory is readable for the sampled users.",
        [
          `Users sampled for token inventory: ${Math.min(MAX_TOKEN_USERS, data.users.data.length)}`,
          `Token records collected: ${allTokens.length}`,
        ],
        "Use the token inventory during third-party app reviews and user-access attestations.",
      ),
  );

  findings.push(
    privilegedTokens.length === 0
      ? buildFinding(
        "GWS-INTEG-002",
        "Pass",
        "No third-party tokens were observed for privileged users in the sampled inventory.",
        [
          `Privileged users sampled: ${Math.min(privileged.privilegedUsers.length, MAX_TOKEN_USERS)}`,
          `Privileged third-party tokens: ${privilegedTokens.length}`,
        ],
        "Keep privileged accounts clean of unnecessary third-party OAuth grants.",
      )
      : privilegedTokens.length <= 3
      ? buildFinding(
        "GWS-INTEG-002",
        "Partial",
        "A small number of privileged users still hold third-party OAuth tokens.",
        [
          `Privileged third-party tokens: ${privilegedTokens.length}`,
          `Privileged token clients: ${uniqueClientDisplayNames(privilegedTokens).join(", ") || "none"}`,
        ],
        "Review each privileged OAuth grant and remove anything not strictly required for administration or incident response.",
      )
      : buildFinding(
        "GWS-INTEG-002",
        "Fail",
        "Privileged-user third-party token exposure is broader than expected.",
        [
          `Privileged third-party tokens: ${privilegedTokens.length}`,
          `Privileged token clients: ${uniqueClientDisplayNames(privilegedTokens).join(", ") || "none"}`,
        ],
        "Perform a privileged OAuth cleanup and require explicit approval for any remaining third-party grants.",
      ),
  );

  findings.push(
    highRiskTokens === 0
      ? buildFinding(
        "GWS-INTEG-003",
        "Pass",
        "No clearly high-scope third-party tokens were found in the sampled inventory.",
        [
          `Third-party clients observed: ${uniqueClients.length}`,
          `High-scope token records: ${highRiskTokens}`,
        ],
        "Keep reviewing third-party client scopes before approving new apps.",
      )
      : highRiskTokens <= 5
      ? buildFinding(
        "GWS-INTEG-003",
        "Partial",
        "A limited set of third-party tokens carries broad scopes.",
        [
          `Third-party clients observed: ${uniqueClients.length}`,
          `High-scope token records: ${highRiskTokens}`,
        ],
        "Review high-scope apps and trim or revoke unnecessary grants, especially those touching admin, Drive, Gmail, or cloud-platform scopes.",
      )
      : buildFinding(
        "GWS-INTEG-003",
        "Fail",
        "High-scope third-party OAuth sprawl is too broad in the sampled inventory.",
        [
          `Third-party clients observed: ${uniqueClients.length}`,
          `High-scope token records: ${highRiskTokens}`,
        ],
        "Run a focused OAuth app review and clean up broad-scope third-party access before treating the environment as well-controlled.",
      ),
  );

  findings.push(
    data.tokenActivities.error
      ? buildFinding(
        "GWS-INTEG-004",
        "Fail",
        "Token activity reports were not readable with the supplied principal.",
        [`Token activity error: ${data.tokenActivities.error}`],
        "Grant the Reports audit scope and confirm the delegated admin can read token audit activity.",
      )
      : buildFinding(
        "GWS-INTEG-004",
        "Pass",
        "Token activity telemetry is readable for the configured lookback window.",
        [
          `Token activity records collected: ${data.tokenActivities.data.length}`,
          `Observed token event names: ${Array.from(new Set(tokenEvents)).slice(0, 6).join(", ") || "none"}`,
        ],
        "Use token-activity reporting to support OAuth app reviews and incident triage.",
      ),
  );

  const snapshotSummary = {
    sampled_users: Math.min(MAX_TOKEN_USERS, data.users.data.length),
    privileged_users: privileged.privilegedUsers.length,
    token_records: allTokens.length,
    privileged_token_records: privilegedTokens.length,
    high_scope_token_records: highRiskTokens,
    token_activity_records: data.tokenActivities.data.length,
  };

  return {
    category: "integrations",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace integrations assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

export function assessGwsMonitoring(
  data: GwsMonitoringData,
  config: GwsResolvedConfig,
): GwsAssessmentResult {
  const suspiciousLogins = countMatchingEvents(data.loginActivities.data, SUSPICIOUS_LOGIN_NAMES);
  const openAlerts = countOpenAlerts(data.alerts.data);

  const findings: GwsFinding[] = [];
  findings.push(
    data.alerts.error
      ? buildFinding(
        "GWS-MON-001",
        "Fail",
        "Alert Center was not readable with the supplied principal.",
        [`Alert Center error: ${data.alerts.error}`],
        "Enable the Alert Center API and grant the apps.alerts scope to the delegated service account.",
      )
      : buildFinding(
        "GWS-MON-001",
        "Pass",
        "Alert Center is readable for the tenant.",
        [`Alerts collected: ${data.alerts.data.length}`],
        "Use Alert Center as one of the tenant’s primary security-monitoring inputs.",
      ),
  );

  findings.push(
    suspiciousLogins === 0
      ? buildFinding(
        "GWS-MON-002",
        "Pass",
        "No suspicious-login events were observed in the current lookback window.",
        [
          `Login activity records collected: ${data.loginActivities.data.length}`,
          `Suspicious login signals: ${suspiciousLogins}`,
        ],
        "Keep reviewing login telemetry for spikes or new event types as part of routine monitoring.",
      )
      : suspiciousLogins <= 5
      ? buildFinding(
        "GWS-MON-002",
        "Partial",
        "A small suspicious-login backlog needs review.",
        [
          `Login activity records collected: ${data.loginActivities.data.length}`,
          `Suspicious login signals: ${suspiciousLogins}`,
        ],
        "Review the suspicious-login events and make sure they were triaged, blocked, or otherwise resolved.",
      )
      : buildFinding(
        "GWS-MON-002",
        "Fail",
        "Suspicious-login volume in the lookback window is too high to ignore.",
        [
          `Login activity records collected: ${data.loginActivities.data.length}`,
          `Suspicious login signals: ${suspiciousLogins}`,
        ],
        "Escalate suspicious-login review immediately and confirm the tenant’s response workflow is keeping up.",
      ),
  );

  findings.push(
    data.adminActivities.error
      ? buildFinding(
        "GWS-MON-003",
        "Fail",
        "Admin audit telemetry was not readable with the supplied principal.",
        [`Admin activity error: ${data.adminActivities.error}`],
        "Grant the Reports audit scope and verify the delegated admin can read admin activities.",
      )
      : buildFinding(
        "GWS-MON-003",
        "Pass",
        "Admin audit telemetry is readable for the configured lookback window.",
        [`Admin activity records collected: ${data.adminActivities.data.length}`],
        "Use admin activity as a standing control for privileged-change review and investigations.",
      ),
  );

  findings.push(
    data.tokenActivities.error
      ? buildFinding(
        "GWS-MON-004",
        "Fail",
        "Token audit telemetry was not readable with the supplied principal.",
        [`Token activity error: ${data.tokenActivities.error}`],
        "Grant the Reports audit scope and confirm token activity is accessible for the delegated admin.",
      )
      : buildFinding(
        "GWS-MON-004",
        "Pass",
        "Token audit telemetry is readable for the configured lookback window.",
        [`Token activity records collected: ${data.tokenActivities.data.length}`],
        "Use token activity in third-party app governance and incident response.",
      ),
  );

  findings.push(
    data.alerts.error
      ? buildFinding(
        "GWS-MON-005",
        "Manual",
        "Open-alert backlog could not be evaluated because Alert Center data was not available.",
        [`Alert Center error: ${data.alerts.error}`],
        "Restore Alert Center access first, then use the backlog signal during monitoring reviews.",
      )
      : openAlerts <= 3
      ? buildFinding(
        "GWS-MON-005",
        "Pass",
        "The open alert backlog is manageable in the current snapshot.",
        [
          `Alerts collected: ${data.alerts.data.length}`,
          `Open alerts: ${openAlerts}`,
        ],
        "Keep alert ownership and closure practices explicit so the backlog stays manageable.",
      )
      : openAlerts <= 10
      ? buildFinding(
        "GWS-MON-005",
        "Partial",
        "The open alert backlog is noticeable and should be reviewed.",
        [
          `Alerts collected: ${data.alerts.data.length}`,
          `Open alerts: ${openAlerts}`,
        ],
        "Review the alert queue, verify ownership, and close or annotate stale alerts.",
      )
      : buildFinding(
        "GWS-MON-005",
        "Fail",
        "The open alert backlog is larger than a healthy review cadence would usually tolerate.",
        [
          `Alerts collected: ${data.alerts.data.length}`,
          `Open alerts: ${openAlerts}`,
        ],
        "Run a focused alert-triage sprint and make sure the queue has clear owners and escalation paths.",
      ),
  );

  const snapshotSummary = {
    login_activity_records: data.loginActivities.data.length,
    suspicious_login_signals: suspiciousLogins,
    admin_activity_records: data.adminActivities.data.length,
    token_activity_records: data.tokenActivities.data.length,
    alerts_collected: data.alerts.data.length,
    open_alerts: openAlerts,
  };

  return {
    category: "monitoring",
    findings,
    summary: countByStatus(findings),
    snapshotSummary,
    text: buildAssessmentText("Google Workspace monitoring assessment", getDisplayOrganization(config), findings, snapshotSummary),
  };
}

function buildExecutiveSummary(
  config: GwsResolvedConfig,
  assessments: GwsAssessmentResult[],
  errors: string[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const summary = countByStatus(findings);
  return [
    "# Google Workspace Audit Executive Summary",
    "",
    `- Organization: ${getDisplayOrganization(config)}`,
    `- Auth mode: ${config.authMode}`,
    `- Customer ID: ${config.customerId}`,
    `- Admin email: ${config.adminEmail ?? "not supplied"}`,
    `- Lookback days: ${config.lookbackDays}`,
    `- Source chain: ${config.sourceChain.join(" -> ") || "direct"}`,
    "",
    "## Findings",
    "",
    `- Pass: ${summary.Pass}`,
    `- Partial: ${summary.Partial}`,
    `- Fail: ${summary.Fail}`,
    `- Manual: ${summary.Manual}`,
    `- Info: ${summary.Info}`,
    "",
    errors.length > 0
      ? [
        "## Collection warnings",
        "",
        ...errors.map((error) => `- ${error}`),
        "",
      ].join("\n")
      : "",
  ].filter(Boolean).join("\n");
}

export async function exportGwsAuditBundle(
  client: GoogleWorkspaceAuditorClient,
  config: GwsResolvedConfig,
  outputRoot: string,
): Promise<GwsAuditBundleResult> {
  const identity = await collectGwsIdentityData(client);
  const adminAccess = await collectGwsAdminAccessData(client);
  const integrations = await collectGwsIntegrationData(client);
  const monitoring = await collectGwsMonitoringData(client);

  const assessments = [
    assessGwsIdentity(identity, config),
    assessGwsAdminAccess(adminAccess, config),
    assessGwsIntegrations(integrations, config),
    assessGwsMonitoring(monitoring, config),
  ];

  const allFindings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [
    ...collectErrors(identity.users, identity.roles, identity.roleAssignments, identity.loginActivities),
    ...collectErrors(adminAccess.users, adminAccess.roles, adminAccess.roleAssignments, adminAccess.adminActivities),
    ...collectErrors(integrations.users, integrations.roles, integrations.roleAssignments, integrations.tokenInventory, integrations.tokenActivities),
    ...collectErrors(monitoring.loginActivities, monitoring.adminActivities, monitoring.tokenActivities, monitoring.alerts),
  ];

  const safeName = safeDirName(`${getDisplayOrganization(config)}-gws-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, safeName);

  await buildBundleReadme(outputDir);
  await writeSecureTextFile(outputDir, "summary.md", assessments.map((assessment) => assessment.text).join("\n\n"));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(allFindings));
  await writeSecureTextFile(outputDir, "analysis/unified-matrix.md", buildUnifiedMatrix(allFindings));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "reports/summary.md", assessments.map((assessment) => assessment.text).join("\n\n"));

  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
    await writeSecureTextFile(outputDir, `reports/${assessment.category}.md`, assessment.text);
  }

  const frameworkReports = buildFrameworkReports(allFindings);
  for (const [name, contents] of Object.entries(frameworkReports)) {
    await writeSecureTextFile(outputDir, `reports/framework-${name}.md`, contents);
  }

  await writeSecureTextFile(outputDir, "core_data/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "core_data/admin_access.json", serializeJson(adminAccess));
  await writeSecureTextFile(outputDir, "core_data/integrations.json", serializeJson(integrations));
  await writeSecureTextFile(outputDir, "core_data/monitoring.json", serializeJson(monitoring));

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return {
    outputDir,
    zipPath,
    fileCount,
    findingCount: allFindings.length,
    errorCount: errors.length,
  };
}

export function registerGwsTools(pi: any): void {
  const authParams = {
    auth_mode: Type.Optional(
      Type.String({
        description: "Optional auth mode override. Supported values: service_account or access_token.",
      }),
    ),
    credentials_file: Type.Optional(
      Type.String({
        description: "Optional service account JSON file path. Falls back to GWS_CREDENTIALS_FILE or GOOGLE_APPLICATION_CREDENTIALS.",
      }),
    ),
    credentials_json: Type.Optional(
      Type.String({
        description: "Optional inline service account JSON payload. Useful when the caller already has the secret material in-memory.",
      }),
    ),
    access_token: Type.Optional(
      Type.String({
        description: "Optional direct bearer token for read-only Google Workspace access. Falls back to GWS_ACCESS_TOKEN.",
      }),
    ),
    admin_email: Type.Optional(
      Type.String({
        description: "Delegated admin email for service-account auth. Falls back to GWS_ADMIN_EMAIL.",
      }),
    ),
    domain: Type.Optional(
      Type.String({
        description: "Optional primary domain label used for display. Falls back to GWS_DOMAIN.",
      }),
    ),
    customer_id: Type.Optional(
      Type.String({
        description: "Optional customer ID. Defaults to my_customer and falls back to GWS_CUSTOMER_ID.",
      }),
    ),
    lookback_days: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: 180,
        description: "Optional audit lookback window in days. Defaults to 30.",
      }),
    ),
  } as const;

  pi.registerTool({
    name: "gws_check_access",
    label: "Check Google Workspace audit access",
    description:
      "Validate Google Workspace read access for delegated service-account or direct access-token auth and show which security-relevant Admin SDK surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const result = await runGwsAccessCheck(client, config);
        return renderAccessCheck(result);
      } catch (error) {
        return errorResult(
          `Google Workspace access check failed: ${summarizeError(error)}`,
          { tool: "gws_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_identity",
    label: "Assess Google Workspace identity posture",
    description:
      "Review Google Workspace user identity posture, including 2-step verification coverage, privileged-user MFA enforcement, super-admin protection, and dormant-account pressure.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsIdentityData(client);
        return renderAssessmentToolResult(assessGwsIdentity(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace identity assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_admin_access",
    label: "Assess Google Workspace admin access",
    description:
      "Review Google Workspace privileged-role population, super-admin sprawl, suspended privileged accounts, delegated-admin use, and admin audit visibility.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsAdminAccessData(client);
        return renderAssessmentToolResult(assessGwsAdminAccess(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace admin-access assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_admin_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_integrations",
    label: "Assess Google Workspace integrations",
    description:
      "Review third-party OAuth token inventory, privileged-user app exposure, high-scope client sprawl, and token-audit visibility in Google Workspace.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsIntegrationData(client);
        return renderAssessmentToolResult(assessGwsIntegrations(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace integrations assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_assess_monitoring",
    label: "Assess Google Workspace monitoring",
    description:
      "Review Google Workspace Alert Center visibility, suspicious-login signals, admin audit coverage, token audit coverage, and the current alert backlog.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const data = await collectGwsMonitoringData(client);
        return renderAssessmentToolResult(assessGwsMonitoring(data, config));
      } catch (error) {
        return errorResult(
          `Google Workspace monitoring assessment failed: ${summarizeError(error)}`,
          { tool: "gws_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_export_audit_bundle",
    label: "Export Google Workspace audit bundle",
    description:
      "Collect the focused Google Workspace identity, admin-access, integrations, and monitoring evidence set, then write a zipped multi-framework audit bundle to disk.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root for the Google Workspace audit bundle. Defaults to ${DEFAULT_OUTPUT_DIR}.`,
        }),
      ),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: RawConfigArgs & { output_dir?: string }) {
      try {
        const config = await resolveGwsConfiguration(args);
        const client = new GoogleWorkspaceAuditorClient(config);
        const result = await exportGwsAuditBundle(
          client,
          config,
          args.output_dir?.trim() || DEFAULT_OUTPUT_DIR,
        );
        return textResult(buildExportText(config, result), {
          organization: getDisplayOrganization(config),
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          file_count: result.fileCount,
          finding_count: result.findingCount,
          error_count: result.errorCount,
        });
      } catch (error) {
        return errorResult(
          `Google Workspace audit export failed: ${summarizeError(error)}`,
          { tool: "gws_export_audit_bundle" },
        );
      }
    },
  });
}
