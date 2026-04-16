/**
 * AWS GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the aws-sec-inspector spec.
 * The first slice stays read-only and focuses on IAM hygiene, logging and
 * detective controls, plus organization-level guardrails.
 */
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
} from "@aws-sdk/client-accessanalyzer";
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  GetTrailStatusCommand,
} from "@aws-sdk/client-cloudtrail";
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
} from "@aws-sdk/client-config-service";
import { fromIni } from "@aws-sdk/credential-providers";
import {
  GuardDutyClient,
  GetDetectorCommand,
  ListDetectorsCommand,
} from "@aws-sdk/client-guardduty";
import {
  GetAccountAuthorizationDetailsCommand,
  GetAccountPasswordPolicyCommand,
  GetAccountSummaryCommand,
  GetAccessKeyLastUsedCommand,
  IAMClient,
  ListAccessKeysCommand,
  ListMFADevicesCommand,
  ListUsersCommand,
} from "@aws-sdk/client-iam";
import {
  ListTargetsForPolicyCommand,
  ListAccountsCommand,
  ListPoliciesCommand,
  OrganizationsClient,
  DescribeOrganizationCommand,
} from "@aws-sdk/client-organizations";
import {
  DescribeHubCommand,
  GetEnabledStandardsCommand,
  SecurityHubClient,
} from "@aws-sdk/client-securityhub";
import { ListInstancesCommand, SSOAdminClient } from "@aws-sdk/client-sso-admin";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
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

const DEFAULT_REGION = "us-east-1";
const DEFAULT_OUTPUT_DIR = "./export/aws";
const DEFAULT_USER_LIMIT = 500;
const DEFAULT_ROLE_LIMIT = 500;
const DEFAULT_STALE_DAYS = 90;
const DEFAULT_MAX_PRIVILEGED_ROLES = 5;
const DEFAULT_MAX_FINDINGS = 200;

export interface AwsResolvedConfig {
  region: string;
  profile?: string;
  accountId?: string;
  sourceChain: string[];
}

export interface AwsAccessSurface {
  name: string;
  service: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface AwsAccessCheckResult {
  status: "healthy" | "limited";
  accountId?: string;
  arn?: string;
  surfaces: AwsAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface AwsFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface AwsAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: AwsFinding[];
}

export interface AwsAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  region?: string;
  profile?: string;
  account_id?: string;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  stale_days?: number;
  role_limit?: number;
  max_privileged_roles?: number;
};

type LoggingArgs = CheckAccessArgs & {
  max_security_hub_standards?: number;
};

type OrgGuardrailArgs = CheckAccessArgs & {
  max_findings?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  user_limit?: number;
  stale_days?: number;
  role_limit?: number;
  max_privileged_roles?: number;
  max_findings?: number;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
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
    extractTimestamp(object.LastUsedDate)
    ?? extractTimestamp(object.CreateDate)
    ?? extractTimestamp(object.PasswordLastUsed)
    ?? extractTimestamp(object.UpdatedAt)
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
  severity: AwsFinding["severity"],
  status: AwsFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): AwsFinding {
  return { id, title, severity, status, summary, mappings, evidence };
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
  return normalized || "aws";
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

export function resolveAwsConfiguration(
  input: Record<string, unknown> = {},
  env: NodeJS.ProcessEnv = process.env,
): AwsResolvedConfig {
  const sourceChain: string[] = [];
  const region = asString(input.region)
    ?? asString(env.AWS_REGION)
    ?? asString(env.AWS_DEFAULT_REGION)
    ?? DEFAULT_REGION;
  if (asString(input.region)) sourceChain.push("arguments-region");
  else if (asString(env.AWS_REGION) || asString(env.AWS_DEFAULT_REGION)) sourceChain.push("environment-region");
  else sourceChain.push("default-region");

  const profile = asString(input.profile) ?? asString(env.AWS_PROFILE);
  if (profile) sourceChain.push(asString(input.profile) ? "arguments-profile" : "environment-profile");

  const accountId = asString(input.account_id) ?? asString(env.AWS_ACCOUNT_ID);
  if (accountId) sourceChain.push(asString(input.account_id) ? "arguments-account" : "environment-account");

  return {
    region,
    profile,
    accountId,
    sourceChain: [...new Set(sourceChain)],
  };
}

function normalizePolicyDocument(policyDocument: unknown): JsonRecord | undefined {
  if (typeof policyDocument === "string") {
    const decoded = decodeURIComponent(policyDocument);
    try {
      return asObject(JSON.parse(decoded));
    } catch {
      return undefined;
    }
  }
  return asObject(policyDocument);
}

function normalizeStatements(policyDocument: unknown): JsonRecord[] {
  const document = normalizePolicyDocument(policyDocument);
  if (!document) return [];
  const statement = document.Statement;
  if (Array.isArray(statement)) {
    return statement.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  const one = asObject(statement);
  return one ? [one] : [];
}

function matchesWildcard(value: unknown): boolean {
  if (typeof value === "string") return value === "*";
  if (Array.isArray(value)) return value.map(String).includes("*");
  return false;
}

function hasAdministratorPolicy(role: JsonRecord): boolean {
  const attached = Array.isArray(role.AttachedManagedPolicies) ? role.AttachedManagedPolicies : [];
  if (attached.some((policy) => {
    const item = asObject(policy);
    return asString(item?.PolicyName) === "AdministratorAccess";
  })) {
    return true;
  }

  const inline = Array.isArray(role.RolePolicyList) ? role.RolePolicyList : [];
  return inline.some((policy) => {
    const item = asObject(policy);
    const statements = normalizeStatements(item?.PolicyDocument);
    return statements.some((statement) => matchesWildcard(statement.Action) && matchesWildcard(statement.Resource));
  });
}

function describeSourceChain(config: AwsResolvedConfig): string {
  return config.profile
    ? `AWS profile ${config.profile} in ${config.region}`
    : `AWS default credential chain in ${config.region}`;
}

export class AwsAuditorClient {
  private readonly sts: STSClient;
  private readonly iam: IAMClient;
  private readonly cloudTrail: CloudTrailClient;
  private readonly securityHub: SecurityHubClient;
  private readonly configService: ConfigServiceClient;
  private readonly guardDuty: GuardDutyClient;
  private readonly organizations: OrganizationsClient;
  private readonly accessAnalyzer: AccessAnalyzerClient;
  private readonly ssoAdmin: SSOAdminClient;
  private readonly now: () => Date;

  constructor(
    private readonly config: AwsResolvedConfig,
    options: { now?: () => Date } = {},
  ) {
    const credentials = config.profile ? fromIni({ profile: config.profile }) : undefined;
    const clientConfig = { region: config.region, credentials };
    this.sts = new STSClient(clientConfig);
    this.iam = new IAMClient(clientConfig);
    this.cloudTrail = new CloudTrailClient(clientConfig);
    this.securityHub = new SecurityHubClient(clientConfig);
    this.configService = new ConfigServiceClient(clientConfig);
    this.guardDuty = new GuardDutyClient(clientConfig);
    this.organizations = new OrganizationsClient(clientConfig);
    this.accessAnalyzer = new AccessAnalyzerClient(clientConfig);
    this.ssoAdmin = new SSOAdminClient(clientConfig);
    this.now = options.now ?? (() => new Date());
  }

  getNow(): Date {
    return this.now();
  }

  getResolvedConfig(): AwsResolvedConfig {
    return this.config;
  }

  async getCallerIdentity(): Promise<JsonRecord> {
    const result = await this.sts.send(new GetCallerIdentityCommand({}));
    return {
      Account: result.Account,
      Arn: result.Arn,
      UserId: result.UserId,
    };
  }

  async getAccountSummary(): Promise<JsonRecord> {
    const result = await this.iam.send(new GetAccountSummaryCommand({}));
    return { SummaryMap: result.SummaryMap ?? {} };
  }

  async getPasswordPolicy(): Promise<JsonRecord | null> {
    try {
      const result = await this.iam.send(new GetAccountPasswordPolicyCommand({}));
      return asObject(result.PasswordPolicy) ?? null;
    } catch {
      return null;
    }
  }

  async listIamUsers(limit = DEFAULT_USER_LIMIT): Promise<JsonRecord[]> {
    const users: JsonRecord[] = [];
    let marker: string | undefined;
    while (users.length < limit) {
      const result = await this.iam.send(new ListUsersCommand({ Marker: marker, MaxItems: Math.min(100, limit - users.length) }));
      for (const user of result.Users ?? []) {
        users.push({
          UserName: user.UserName,
          Arn: user.Arn,
          CreateDate: user.CreateDate,
          PasswordLastUsed: user.PasswordLastUsed,
        });
      }
      if (!result.IsTruncated || !result.Marker) break;
      marker = result.Marker;
    }
    return users;
  }

  async listMfaDevices(userName: string): Promise<JsonRecord[]> {
    const result = await this.iam.send(new ListMFADevicesCommand({ UserName: userName }));
    return (result.MFADevices ?? []).map((device) => ({
      SerialNumber: device.SerialNumber,
      UserName: device.UserName,
    }));
  }

  async listAccessKeys(userName: string): Promise<JsonRecord[]> {
    const result = await this.iam.send(new ListAccessKeysCommand({ UserName: userName }));
    return (result.AccessKeyMetadata ?? []).map((key) => ({
      AccessKeyId: key.AccessKeyId,
      Status: key.Status,
      CreateDate: key.CreateDate,
      UserName: key.UserName,
    }));
  }

  async getAccessKeyLastUsed(accessKeyId: string): Promise<JsonRecord | null> {
    const result = await this.iam.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: accessKeyId }));
    return asObject(result.AccessKeyLastUsed) ?? null;
  }

  async getAccountAuthorizationDetails(limit = DEFAULT_ROLE_LIMIT): Promise<JsonRecord[]> {
    const roles: JsonRecord[] = [];
    let marker: string | undefined;
    while (roles.length < limit) {
      const result = await this.iam.send(new GetAccountAuthorizationDetailsCommand({
        Filter: ["Role"],
        Marker: marker,
        MaxItems: Math.min(100, limit - roles.length),
      }));
      for (const role of result.RoleDetailList ?? []) {
        roles.push({
          RoleName: role.RoleName,
          Arn: role.Arn,
          PermissionsBoundary: role.PermissionsBoundary,
          AttachedManagedPolicies: role.AttachedManagedPolicies,
          RolePolicyList: role.RolePolicyList,
        });
      }
      if (!result.IsTruncated || !result.Marker) break;
      marker = result.Marker;
    }
    return roles;
  }

  async describeTrails(): Promise<JsonRecord[]> {
    const result = await this.cloudTrail.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
    return (result.trailList ?? []).map((trail) => ({
      Name: trail.Name,
      TrailARN: trail.TrailARN,
      IsMultiRegionTrail: trail.IsMultiRegionTrail,
      LogFileValidationEnabled: trail.LogFileValidationEnabled,
      HomeRegion: trail.HomeRegion,
      S3BucketName: trail.S3BucketName,
    }));
  }

  async getTrailStatus(nameOrArn: string): Promise<JsonRecord> {
    const result = await this.cloudTrail.send(new GetTrailStatusCommand({ Name: nameOrArn }));
    return {
      IsLogging: result.IsLogging,
      LatestCloudWatchLogsDeliveryError: result.LatestCloudWatchLogsDeliveryError,
      LatestDeliveryError: result.LatestDeliveryError,
    };
  }

  async getEventSelectors(nameOrArn: string): Promise<JsonRecord> {
    const result = await this.cloudTrail.send(new GetEventSelectorsCommand({ TrailName: nameOrArn }));
    return {
      EventSelectors: result.EventSelectors ?? [],
      AdvancedEventSelectors: result.AdvancedEventSelectors ?? [],
    };
  }

  async describeSecurityHub(): Promise<JsonRecord | null> {
    try {
      const result = await this.securityHub.send(new DescribeHubCommand({}));
      return {
        HubArn: result.HubArn,
        AutoEnableControls: result.AutoEnableControls,
        SubscribedAt: result.SubscribedAt,
      };
    } catch {
      return null;
    }
  }

  async getEnabledSecurityHubStandards(): Promise<JsonRecord[]> {
    const standards: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.securityHub.send(new GetEnabledStandardsCommand({ MaxResults: 100, NextToken: nextToken }));
      for (const standard of result.StandardsSubscriptions ?? []) {
        standards.push({
          StandardsArn: standard.StandardsArn,
          StandardsStatus: standard.StandardsStatus,
          StandardsSubscriptionArn: standard.StandardsSubscriptionArn,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return standards;
  }

  async describeConfigurationRecorders(): Promise<JsonRecord[]> {
    const result = await this.configService.send(new DescribeConfigurationRecordersCommand({}));
    return (result.ConfigurationRecorders ?? []).map((recorder) => ({
      name: recorder.name,
      recordingGroup: recorder.recordingGroup,
      roleARN: recorder.roleARN,
    }));
  }

  async describeConfigurationRecorderStatus(): Promise<JsonRecord[]> {
    const result = await this.configService.send(new DescribeConfigurationRecorderStatusCommand({}));
    return (result.ConfigurationRecordersStatus ?? []).map((status) => ({
      name: status.name,
      recording: status.recording,
      lastStatus: status.lastStatus,
      lastErrorCode: status.lastErrorCode,
      lastErrorMessage: status.lastErrorMessage,
    }));
  }

  async listDetectors(): Promise<string[]> {
    const result = await this.guardDuty.send(new ListDetectorsCommand({}));
    return result.DetectorIds ?? [];
  }

  async getDetector(detectorId: string): Promise<JsonRecord> {
    const result = await this.guardDuty.send(new GetDetectorCommand({ DetectorId: detectorId }));
    return {
      Status: result.Status,
      FindingPublishingFrequency: result.FindingPublishingFrequency,
      DataSources: result.DataSources,
      Features: result.Features,
    };
  }

  async listAnalyzers(): Promise<JsonRecord[]> {
    const analyzers: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.accessAnalyzer.send(new ListAnalyzersCommand({ nextToken, maxResults: 100 }));
      for (const analyzer of result.analyzers ?? []) {
        analyzers.push({
          arn: analyzer.arn,
          name: analyzer.name,
          type: analyzer.type,
          status: analyzer.status,
        });
      }
      nextToken = result.nextToken;
    } while (nextToken);
    return analyzers;
  }

  async listAccessAnalyzerFindings(analyzerArn: string, limit = DEFAULT_MAX_FINDINGS): Promise<JsonRecord[]> {
    const findings: JsonRecord[] = [];
    let nextToken: string | undefined;
    while (findings.length < limit) {
      const result = await this.accessAnalyzer.send(new ListFindingsCommand({
        analyzerArn,
        maxResults: Math.min(100, limit - findings.length),
        nextToken,
      }));
      for (const finding of result.findings ?? []) {
        findings.push({
          id: finding.id,
          status: finding.status,
          resourceType: finding.resourceType,
          resource: finding.resource,
          principal: finding.principal,
          condition: finding.condition,
        });
      }
      if (!result.nextToken) break;
      nextToken = result.nextToken;
    }
    return findings;
  }

  async describeOrganization(): Promise<JsonRecord | null> {
    try {
      const result = await this.organizations.send(new DescribeOrganizationCommand({}));
      return {
        Id: result.Organization?.Id,
        FeatureSet: result.Organization?.FeatureSet,
        ManagementAccountId: result.Organization?.MasterAccountId,
      };
    } catch {
      return null;
    }
  }

  async listAccounts(limit = 1000): Promise<JsonRecord[]> {
    const accounts: JsonRecord[] = [];
    let nextToken: string | undefined;
    while (accounts.length < limit) {
      const result = await this.organizations.send(new ListAccountsCommand({ NextToken: nextToken, MaxResults: Math.min(20, limit - accounts.length) }));
      for (const account of result.Accounts ?? []) {
        accounts.push({
          Id: account.Id,
          Name: account.Name,
          Status: account.Status,
        });
      }
      if (!result.NextToken) break;
      nextToken = result.NextToken;
    }
    return accounts;
  }

  async listScps(): Promise<JsonRecord[]> {
    const policies: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.organizations.send(new ListPoliciesCommand({
        Filter: "SERVICE_CONTROL_POLICY",
        NextToken: nextToken,
        MaxResults: 20,
      }));
      for (const policy of result.Policies ?? []) {
        policies.push({
          Id: policy.Id,
          Name: policy.Name,
          AwsManaged: policy.AwsManaged,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return policies;
  }

  async listPolicyTargets(policyId: string): Promise<JsonRecord[]> {
    const targets: JsonRecord[] = [];
    let nextToken: string | undefined;
    do {
      const result = await this.organizations.send(new ListTargetsForPolicyCommand({
        PolicyId: policyId,
        NextToken: nextToken,
      }));
      for (const target of result.Targets ?? []) {
        targets.push({
          TargetId: target.TargetId,
          Name: target.Name,
          Type: target.Type,
        });
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return targets;
  }

  async listIdentityCenterInstances(): Promise<JsonRecord[]> {
    try {
      const result = await this.ssoAdmin.send(new ListInstancesCommand({}));
      return (result.Instances ?? []).map((instance) => ({
        InstanceArn: instance.InstanceArn,
        IdentityStoreId: instance.IdentityStoreId,
      }));
    } catch {
      return [];
    }
  }
}

async function surface(
  name: string,
  service: string,
  loader: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<AwsAccessSurface> {
  try {
    const value = await loader();
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

export async function checkAwsAccess(
  client: Pick<
    AwsAuditorClient,
    "getCallerIdentity" | "getAccountSummary" | "describeTrails" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "listDetectors" | "listAnalyzers" | "describeOrganization" | "listIdentityCenterInstances" | "getResolvedConfig"
  >,
): Promise<AwsAccessCheckResult> {
  const caller = await client.getCallerIdentity();
  const config = client.getResolvedConfig();
  const surfaces = await Promise.all([
    surface("iam_summary", "iam", () => client.getAccountSummary(), () => 1),
    surface("cloudtrail", "cloudtrail", () => client.describeTrails(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("security_hub", "securityhub", () => client.getEnabledSecurityHubStandards(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("config", "config", () => client.describeConfigurationRecorders(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("guardduty", "guardduty", () => client.listDetectors(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("access_analyzer", "access-analyzer", () => client.listAnalyzers(), (value) => Array.isArray(value) ? value.length : undefined),
    surface("organizations", "organizations", () => client.describeOrganization(), () => 1),
    surface("identity_center", "sso-admin", () => client.listIdentityCenterInstances(), (value) => Array.isArray(value) ? value.length : undefined),
  ]);

  const readableCount = surfaces.filter((item) => item.status === "readable").length;
  const status = readableCount >= 5 ? "healthy" : "limited";
  const accountId = asString(caller.Account);
  const notes = [
    `Authenticated via ${describeSourceChain(config)}.`,
    accountId ? `Current AWS account: ${accountId}` : "Current AWS account could not be determined.",
    `${readableCount}/${surfaces.length} AWS audit surfaces are readable.`,
  ];

  if (config.accountId && config.accountId !== accountId) {
    notes.push(`Requested account hint ${config.accountId} does not match caller account ${accountId ?? "unknown"}.`);
  }

  return {
    status,
    accountId,
    arn: asString(caller.Arn),
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run aws_assess_identity, aws_assess_logging_detection, aws_assess_org_guardrails, or aws_export_audit_bundle."
        : "Grant read-only access to IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, and Organizations APIs for the audit principal.",
  };
}

export async function assessAwsIdentity(
  client: Pick<
    AwsAuditorClient,
    "getNow" | "getAccountSummary" | "getPasswordPolicy" | "listIamUsers" | "listMfaDevices" | "listAccessKeys" | "getAccessKeyLastUsed" | "getAccountAuthorizationDetails"
  >,
  options: {
    userLimit?: number;
    staleDays?: number;
    roleLimit?: number;
    maxPrivilegedRoles?: number;
  } = {},
): Promise<AwsAssessmentResult> {
  const now = client.getNow();
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 5000);
  const staleDays = clampNumber(options.staleDays, DEFAULT_STALE_DAYS, 1, 3650);
  const roleLimit = clampNumber(options.roleLimit, DEFAULT_ROLE_LIMIT, 1, 5000);
  const maxPrivilegedRoles = clampNumber(options.maxPrivilegedRoles, DEFAULT_MAX_PRIVILEGED_ROLES, 1, 100);

  const [summary, passwordPolicy, users, roles] = await Promise.all([
    client.getAccountSummary(),
    client.getPasswordPolicy(),
    client.listIamUsers(userLimit),
    client.getAccountAuthorizationDetails(roleLimit),
  ]);

  const summaryMap = asObject(summary.SummaryMap) ?? {};
  const accountMfaEnabled = asNumber(summaryMap.AccountMFAEnabled) ?? 0;
  const accountAccessKeysPresent = asNumber(summaryMap.AccountAccessKeysPresent) ?? 0;

  const usersWithoutMfa: string[] = [];
  const staleAccessKeys: Array<{ userName: string; accessKeyId: string; ageDays?: number }> = [];
  const dormantUsers: string[] = [];

  for (const user of users) {
    const userName = asString(user.UserName) ?? "unknown";
    const mfaDevices = await client.listMfaDevices(userName);
    if (mfaDevices.length === 0) usersWithoutMfa.push(userName);

    const passwordAge = daysBetween(now, extractTimestamp(user.PasswordLastUsed));
    const accessKeys = await client.listAccessKeys(userName);
    for (const key of accessKeys) {
      const accessKeyId = asString(key.AccessKeyId);
      if (!accessKeyId) continue;
      const lastUsed = await client.getAccessKeyLastUsed(accessKeyId);
      const ageDays = daysBetween(now, extractTimestamp(lastUsed) ?? extractTimestamp(key.CreateDate));
      if (ageDays !== undefined && ageDays > staleDays) {
        staleAccessKeys.push({ userName, accessKeyId, ageDays });
      }
    }

    if ((passwordAge !== undefined && passwordAge > staleDays) || (passwordAge === undefined && accessKeys.length === 0)) {
      dormantUsers.push(userName);
    }
  }

  const privilegedRoles = roles.filter(hasAdministratorPolicy);
  const rolesWithoutBoundaries = privilegedRoles.filter((role) => !role.PermissionsBoundary);

  const findings = [
    finding(
      "AWS-IAM-01",
      "Root account MFA and access keys",
      "critical",
      accountMfaEnabled !== 1 || accountAccessKeysPresent > 0 ? "fail" : "pass",
      accountMfaEnabled !== 1 || accountAccessKeysPresent > 0
        ? `Root MFA enabled=${accountMfaEnabled === 1}; root access keys present=${accountAccessKeysPresent}.`
        : "Root account shows MFA enabled and no access keys present.",
      ["FedRAMP IA-2(1)", "FedRAMP AC-6(1)", "CMMC 3.1.5", "CIS AWS 1.4"],
      { account_mfa_enabled: accountMfaEnabled, account_access_keys_present: accountAccessKeysPresent },
    ),
    finding(
      "AWS-IAM-02",
      "IAM user MFA coverage",
      "high",
      usersWithoutMfa.length > 0 ? "fail" : "pass",
      usersWithoutMfa.length > 0
        ? `${usersWithoutMfa.length}/${users.length} IAM users are missing MFA.`
        : "All sampled IAM users have MFA devices.",
      ["FedRAMP IA-2(1)", "FedRAMP IA-2(2)", "CMMC 3.5.3", "PCI-DSS 8.4.2"],
      { user_count: users.length, users_without_mfa: usersWithoutMfa.slice(0, 25) },
    ),
    finding(
      "AWS-IAM-03",
      "Password policy strength",
      "high",
      !passwordPolicy
        || (asNumber(passwordPolicy.MinimumPasswordLength) ?? 0) < 14
        || passwordPolicy.RequireSymbols !== true
        || passwordPolicy.RequireNumbers !== true
        || passwordPolicy.RequireUppercaseCharacters !== true
        || passwordPolicy.RequireLowercaseCharacters !== true
        ? "fail"
        : "pass",
      !passwordPolicy
        ? "No account password policy was visible."
        : `Minimum length ${(asNumber(passwordPolicy.MinimumPasswordLength) ?? 0)} with complexity requirements present=${[
            passwordPolicy.RequireSymbols,
            passwordPolicy.RequireNumbers,
            passwordPolicy.RequireUppercaseCharacters,
            passwordPolicy.RequireLowercaseCharacters,
          ].every((value) => value === true)}.`,
      ["FedRAMP IA-5(1)", "CMMC 3.5.7", "SOC 2 CC6.1", "CIS AWS 1.8"],
      { password_policy: passwordPolicy ?? {} },
    ),
    finding(
      "AWS-IAM-04",
      "Access key rotation",
      "high",
      staleAccessKeys.length > 0 ? "fail" : "pass",
      staleAccessKeys.length > 0
        ? `${staleAccessKeys.length} access keys are older than ${staleDays} days or unused beyond that threshold.`
        : `No sampled access key exceeded the ${staleDays}-day staleness threshold.`,
      ["FedRAMP IA-5(1)", "FedRAMP AC-2(3)", "CMMC 3.5.8", "CIS AWS 1.12"],
      { stale_access_keys: staleAccessKeys.slice(0, 25) },
    ),
    finding(
      "AWS-IAM-05",
      "Privileged role boundaries",
      "medium",
      rolesWithoutBoundaries.length > maxPrivilegedRoles ? "fail" : rolesWithoutBoundaries.length > 0 ? "warn" : "pass",
      rolesWithoutBoundaries.length > 0
        ? `${rolesWithoutBoundaries.length}/${privilegedRoles.length} privileged roles lack permission boundaries.`
        : "No sampled privileged role lacked a permission boundary.",
      ["FedRAMP AC-6(1)", "FedRAMP AC-6(2)", "CMMC 3.1.5", "CIS AWS 1.16"],
      {
        privileged_roles: privilegedRoles.length,
        roles_without_boundaries: rolesWithoutBoundaries.slice(0, 25).map((role) => role.RoleName ?? role.Arn),
        max_privileged_roles: maxPrivilegedRoles,
      },
    ),
    finding(
      "AWS-IAM-06",
      "Dormant IAM users",
      "low",
      dormantUsers.length > 0 ? "warn" : "pass",
      dormantUsers.length > 0
        ? `${dormantUsers.length} IAM users appear dormant beyond ${staleDays} days or without recent password activity.`
        : "No dormant IAM users were detected from the sampled password activity.",
      ["FedRAMP AC-2(3)", "CMMC 3.1.12", "SOC 2 CC6.2", "CIS AWS 1.12"],
      { dormant_users: dormantUsers.slice(0, 25) },
    ),
  ];

  return {
    title: "AWS identity posture",
    summary: {
      users: users.length,
      users_without_mfa: usersWithoutMfa.length,
      stale_access_keys: staleAccessKeys.length,
      privileged_roles: privilegedRoles.length,
      roles_without_boundaries: rolesWithoutBoundaries.length,
      dormant_users: dormantUsers.length,
    },
    findings,
  };
}

function hasAnyDataEvents(selectors: JsonRecord): boolean {
  const eventSelectors = Array.isArray(selectors.EventSelectors) ? selectors.EventSelectors : [];
  const advanced = Array.isArray(selectors.AdvancedEventSelectors) ? selectors.AdvancedEventSelectors : [];
  return eventSelectors.some((selector) => {
    const item = asObject(selector);
    const resources = Array.isArray(item?.DataResources) ? item?.DataResources : [];
    return resources.length > 0;
  }) || advanced.length > 0;
}

export async function assessAwsLoggingDetection(
  client: Pick<
    AwsAuditorClient,
    "describeTrails" | "getTrailStatus" | "getEventSelectors" | "describeSecurityHub" | "getEnabledSecurityHubStandards" | "describeConfigurationRecorders" | "describeConfigurationRecorderStatus" | "listDetectors" | "getDetector"
  >,
): Promise<AwsAssessmentResult> {
  const [trails, hub, standards, recorders, recorderStatuses, detectorIds] = await Promise.all([
    client.describeTrails(),
    client.describeSecurityHub(),
    client.getEnabledSecurityHubStandards().catch(() => []),
    client.describeConfigurationRecorders().catch(() => []),
    client.describeConfigurationRecorderStatus().catch(() => []),
    client.listDetectors().catch(() => []),
  ]);

  const trailDetails = await Promise.all(trails.map(async (trail) => {
    const nameOrArn = asString(trail.TrailARN) ?? asString(trail.Name) ?? "";
    const status = nameOrArn ? await client.getTrailStatus(nameOrArn).catch(() => ({})) : {};
    const selectors = nameOrArn ? await client.getEventSelectors(nameOrArn).catch(() => ({})) : {};
    return {
      Name: asString(trail.Name),
      TrailARN: asString(trail.TrailARN),
      IsMultiRegionTrail: trail.IsMultiRegionTrail === true,
      LogFileValidationEnabled: trail.LogFileValidationEnabled === true,
      status: asObject(status) ?? {},
      selectors: asObject(selectors) ?? {},
    } as JsonRecord;
  }));

  const goodTrails = trailDetails.filter((trail) =>
    trail.IsMultiRegionTrail === true
    && trail.LogFileValidationEnabled === true
    && asObject(trail.status)?.IsLogging === true,
  );
  const trailsWithDataEvents = trailDetails.filter((trail) => hasAnyDataEvents(asObject(trail.selectors) ?? {}));

  const configHealthy = recorders.some((recorder) => {
    const name = asString(recorder.name);
    const status = recorderStatuses.find((item) => asString(item.name) === name);
    return status?.recording === true;
  });

  const detectors = await Promise.all(detectorIds.map((detectorId) =>
    client.getDetector(detectorId).catch(() => ({} as JsonRecord)),
  ));
  const enabledDetectors = detectors.filter((detector) => asString(detector.Status) === "ENABLED");

  const findings = [
    finding(
      "AWS-LOG-01",
      "Multi-region CloudTrail with validation",
      "critical",
      goodTrails.length > 0 ? "pass" : "fail",
      goodTrails.length > 0
        ? `${goodTrails.length} CloudTrail trail(s) are multi-region, logging, and log-file validation enabled.`
        : "No multi-region CloudTrail trail with active logging and log-file validation was detected.",
      ["FedRAMP AU-2", "FedRAMP AU-9", "CMMC 3.3.1", "CIS AWS 3.1"],
      { trails: trailDetails.map((trail) => ({ name: trail.Name, is_multi_region: trail.IsMultiRegionTrail, validation: trail.LogFileValidationEnabled, is_logging: asObject(trail.status)?.IsLogging })) },
    ),
    finding(
      "AWS-LOG-02",
      "CloudTrail data events",
      "medium",
      trailsWithDataEvents.length > 0 ? "pass" : "warn",
      trailsWithDataEvents.length > 0
        ? `${trailsWithDataEvents.length} trail(s) capture data events or advanced event selectors.`
        : "No CloudTrail data event coverage was detected.",
      ["FedRAMP AU-12", "CMMC 3.3.1", "SOC 2 CC7.2", "CIS AWS 3.3"],
      { data_event_trails: trailsWithDataEvents.map((trail) => trail.Name ?? trail.TrailARN) },
    ),
    finding(
      "AWS-LOG-03",
      "Security Hub enablement",
      "high",
      hub && standards.length > 0 ? "pass" : hub ? "warn" : "fail",
      hub
        ? `${standards.length} enabled Security Hub standard subscription(s) were visible.`
        : "Security Hub does not appear enabled in the configured region.",
      ["FedRAMP CA-7", "FedRAMP SI-4", "SOC 2 CC7.1", "PCI-DSS 11.5.1"],
      { hub_enabled: Boolean(hub), standard_count: standards.length },
    ),
    finding(
      "AWS-LOG-04",
      "GuardDuty detectors",
      "high",
      enabledDetectors.length > 0 ? "pass" : "fail",
      enabledDetectors.length > 0
        ? `${enabledDetectors.length} GuardDuty detector(s) are enabled.`
        : "No enabled GuardDuty detector was detected.",
      ["FedRAMP SI-4", "FedRAMP IR-4", "SOC 2 CC7.2", "CIS AWS 1.1"],
      { detector_count: detectorIds.length, enabled_detectors: enabledDetectors.length },
    ),
    finding(
      "AWS-LOG-05",
      "AWS Config recording",
      "high",
      configHealthy ? "pass" : "fail",
      configHealthy
        ? `${recorders.length} configuration recorder(s) were visible with active recording.`
        : "No active AWS Config recorder was detected.",
      ["FedRAMP CM-2", "FedRAMP CM-6", "SOC 2 CC7.1", "CIS AWS 3.5"],
      {
        recorders: recorders.map((recorder) => ({ name: recorder.name, all_supported: asObject(recorder.recordingGroup)?.allSupported })),
        recorder_statuses: recorderStatuses,
      },
    ),
  ];

  return {
    title: "AWS logging and detection posture",
    summary: {
      trails: trailDetails.length,
      compliant_trails: goodTrails.length,
      security_hub_standards: standards.length,
      guardduty_detectors: detectorIds.length,
      enabled_guardduty_detectors: enabledDetectors.length,
      config_recorders: recorders.length,
    },
    findings,
  };
}

export async function assessAwsOrgGuardrails(
  client: Pick<
    AwsAuditorClient,
    "describeOrganization" | "listAccounts" | "listScps" | "listPolicyTargets" | "listAnalyzers" | "listAccessAnalyzerFindings" | "listIdentityCenterInstances"
  >,
  options: { maxFindings?: number } = {},
): Promise<AwsAssessmentResult> {
  const maxFindings = clampNumber(options.maxFindings, DEFAULT_MAX_FINDINGS, 1, 5000);
  const [organization, accounts, scps, analyzers, identityCenterInstances] = await Promise.all([
    client.describeOrganization().catch(() => null),
    client.listAccounts().catch(() => []),
    client.listScps().catch(() => []),
    client.listAnalyzers().catch(() => []),
    client.listIdentityCenterInstances().catch(() => []),
  ]);

  const scpTargets = await Promise.all(scps.map(async (policy) => ({
    policyId: asString(policy.Id) ?? "",
    name: asString(policy.Name) ?? asString(policy.Id) ?? "policy",
    targets: await client.listPolicyTargets(asString(policy.Id) ?? "").catch(() => []),
  })));
  const attachedScps = scpTargets.filter((policy) => policy.targets.length > 0);

  const activeAnalyzers = analyzers.filter((analyzer) => asString(analyzer.status) === "ACTIVE");
  const findingLists = await Promise.all(activeAnalyzers.map(async (analyzer) => ({
    analyzerArn: asString(analyzer.arn) ?? "",
    findings: await client.listAccessAnalyzerFindings(asString(analyzer.arn) ?? "", maxFindings).catch(() => []),
  })));
  const activeExternalFindings = findingLists.flatMap((item) => item.findings).filter((finding) => {
    const status = asString(finding.status)?.toUpperCase();
    return !status || status === "ACTIVE";
  });

  const findings = [
    finding(
      "AWS-ORG-01",
      "Organizations visibility",
      "medium",
      organization ? "pass" : "warn",
      organization
        ? `AWS Organizations is visible with ${accounts.length} account(s).`
        : "AWS Organizations data was not visible; this may be a standalone account or missing permissions.",
      ["FedRAMP PM-2", "SOC 2 CC2.1", "CIS AWS 1.1"],
      { organization: organization ?? {}, accounts: accounts.length },
    ),
    finding(
      "AWS-ORG-02",
      "Service control policies",
      "high",
      scps.length === 0 ? "warn" : attachedScps.length > 0 ? "pass" : "fail",
      scps.length === 0
        ? "No service control policies were visible."
        : attachedScps.length > 0
          ? `${attachedScps.length}/${scps.length} SCPs are attached to at least one target.`
          : "SCPs exist but none appeared attached to accounts or OUs.",
      ["FedRAMP AC-3", "FedRAMP CM-7", "SOC 2 CC6.8", "CIS AWS 1.20"],
      { scp_count: scps.length, attached_scp_count: attachedScps.length, sample: attachedScps.slice(0, 20) },
    ),
    finding(
      "AWS-ORG-03",
      "Access Analyzer enablement",
      "high",
      activeAnalyzers.length > 0 ? "pass" : "fail",
      activeAnalyzers.length > 0
        ? `${activeAnalyzers.length} active Access Analyzer instance(s) were visible.`
        : "No active IAM Access Analyzer instance was detected.",
      ["FedRAMP AC-3", "FedRAMP AC-6", "SOC 2 CC6.3", "CIS AWS 1.16"],
      { analyzers: analyzers },
    ),
    finding(
      "AWS-ORG-04",
      "External access findings",
      activeExternalFindings.length > 0 ? "high" : "low",
      activeExternalFindings.length > 0 ? "warn" : "pass",
      activeExternalFindings.length > 0
        ? `${activeExternalFindings.length} active Access Analyzer finding(s) indicate external or cross-account access to review.`
        : "No active Access Analyzer findings were visible in the sampled analyzers.",
      ["FedRAMP AC-3", "FedRAMP AC-4", "SOC 2 CC6.6", "CIS AWS 1.16"],
      { active_finding_count: activeExternalFindings.length, sample: activeExternalFindings.slice(0, 20) },
    ),
    finding(
      "AWS-ORG-05",
      "Identity Center visibility",
      "low",
      identityCenterInstances.length > 0 ? "pass" : "warn",
      identityCenterInstances.length > 0
        ? `${identityCenterInstances.length} IAM Identity Center instance(s) were visible.`
        : "No IAM Identity Center instance was visible from the configured region and credentials.",
      ["FedRAMP AC-2", "FedRAMP IA-2", "SOC 2 CC6.2", "PCI-DSS 8.4.2"],
      { identity_center_instances: identityCenterInstances.length },
    ),
  ];

  return {
    title: "AWS organization guardrails",
    summary: {
      accounts: accounts.length,
      scps: scps.length,
      attached_scps: attachedScps.length,
      analyzers: analyzers.length,
      active_external_findings: activeExternalFindings.length,
      identity_center_instances: identityCenterInstances.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: AwsAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.service,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `AWS access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Service", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AwsAssessmentResult): string {
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
  config: AwsResolvedConfig,
  assessments: AwsAssessmentResult[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# AWS Audit Bundle",
    "",
    `Region: ${config.region}`,
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

function buildControlMatrix(findings: AwsFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# AWS Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# AWS Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native AWS tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible AWS audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Credentials are resolved through the AWS SDK chain and are not written to this bundle.",
  ].join("\n");
}

export async function exportAwsAuditBundle(
  client: AwsAuditorClient,
  config: AwsResolvedConfig,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AwsAuditBundleResult> {
  const access = await checkAwsAccess(client);
  const identity = await assessAwsIdentity(client, {
    userLimit: options.user_limit,
    staleDays: options.stale_days,
    roleLimit: options.role_limit,
    maxPrivilegedRoles: options.max_privileged_roles,
  });
  const loggingDetection = await assessAwsLoggingDetection(client);
  const orgGuardrails = await assessAwsOrgGuardrails(client, {
    maxFindings: options.max_findings,
  });

  const assessments = [identity, loggingDetection, orgGuardrails];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${config.accountId ?? "aws-account"}-${config.region}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    region: config.region,
    profile: config.profile ?? null,
    account_id_hint: config.accountId ?? null,
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      user_limit: options.user_limit ?? DEFAULT_USER_LIMIT,
      stale_days: options.stale_days ?? DEFAULT_STALE_DAYS,
      role_limit: options.role_limit ?? DEFAULT_ROLE_LIMIT,
      max_privileged_roles: options.max_privileged_roles ?? DEFAULT_MAX_PRIVILEGED_ROLES,
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
    region: asString(value.region),
    profile: asString(value.profile),
    account_id: asString(value.account_id),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    stale_days: asNumber(value.stale_days),
    role_limit: asNumber(value.role_limit),
    max_privileged_roles: asNumber(value.max_privileged_roles),
  };
}

function normalizeOrgGuardrailArgs(args: unknown): OrgGuardrailArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_findings: asNumber(value.max_findings),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    user_limit: asNumber(value.user_limit),
    stale_days: asNumber(value.stale_days),
    role_limit: asNumber(value.role_limit),
    max_privileged_roles: asNumber(value.max_privileged_roles),
    max_findings: asNumber(value.max_findings),
  };
}

function createClient(args: CheckAccessArgs): AwsAuditorClient {
  return new AwsAuditorClient(resolveAwsConfiguration(args));
}

const authParams = {
  region: Type.Optional(Type.String({ description: `AWS region. Defaults to AWS_REGION, AWS_DEFAULT_REGION, or ${DEFAULT_REGION}.` })),
  profile: Type.Optional(Type.String({ description: "AWS shared-config profile to use. Defaults to AWS_PROFILE or the default SDK chain." })),
  account_id: Type.Optional(Type.String({ description: "Optional expected AWS account ID hint for operator context." })),
};

export function registerAwsTools(pi: any): void {
  pi.registerTool({
    name: "aws_check_access",
    label: "Check AWS audit access",
    description:
      "Validate read-only AWS audit access across IAM, CloudTrail, Security Hub, Config, GuardDuty, Access Analyzer, Organizations, and Identity Center surfaces.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAwsAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "aws_check_access", ...result });
      } catch (error) {
        return errorResult(
          `AWS access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_identity",
    label: "Assess AWS identity posture",
    description:
      "Assess AWS IAM hygiene, including root-account protection, IAM user MFA, password policy, access key rotation, dormant users, and privileged roles without permission boundaries.",
    parameters: Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum IAM users to sample. Defaults to 500.", default: 500 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for keys and dormant users. Defaults to 90.", default: 90 })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum IAM roles to inspect. Defaults to 500.", default: 500 })),
      max_privileged_roles: Type.Optional(Type.Number({ description: "Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5.", default: 5 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessAwsIdentity(createClient(args), {
          userLimit: args.user_limit,
          staleDays: args.stale_days,
          roleLimit: args.role_limit,
          maxPrivilegedRoles: args.max_privileged_roles,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `AWS identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_logging_detection",
    label: "Assess AWS logging and detection",
    description:
      "Assess AWS CloudTrail, Security Hub, GuardDuty, and Config posture, including multi-region trail coverage, log validation, data events, standards enablement, and active recording.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: LoggingArgs) {
      try {
        const result = await assessAwsLoggingDetection(createClient(args));
        return textResult(formatAssessmentText(result), { tool: "aws_assess_logging_detection", ...result });
      } catch (error) {
        return errorResult(
          `AWS logging and detection assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_logging_detection" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_assess_org_guardrails",
    label: "Assess AWS organization guardrails",
    description:
      "Assess AWS Organizations visibility, service control policies, Access Analyzer coverage, active external-access findings, and IAM Identity Center visibility.",
    parameters: Type.Object({
      ...authParams,
      max_findings: Type.Optional(Type.Number({ description: "Maximum Access Analyzer findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeOrgGuardrailArgs,
    async execute(_toolCallId: string, args: OrgGuardrailArgs) {
      try {
        const result = await assessAwsOrgGuardrails(createClient(args), {
          maxFindings: args.max_findings,
        });
        return textResult(formatAssessmentText(result), { tool: "aws_assess_org_guardrails", ...result });
      } catch (error) {
        return errorResult(
          `AWS organization guardrail assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_assess_org_guardrails" },
        );
      }
    },
  });

  pi.registerTool({
    name: "aws_export_audit_bundle",
    label: "Export AWS audit bundle",
    description:
      "Export an AWS audit package with access checks, identity findings, logging and detection findings, organization guardrails, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum IAM users to sample. Defaults to 500.", default: 500 })),
      stale_days: Type.Optional(Type.Number({ description: "Staleness threshold in days for keys and dormant users. Defaults to 90.", default: 90 })),
      role_limit: Type.Optional(Type.Number({ description: "Maximum IAM roles to inspect. Defaults to 500.", default: 500 })),
      max_privileged_roles: Type.Optional(Type.Number({ description: "Maximum tolerated privileged roles without permission boundaries before failing. Defaults to 5.", default: 5 })),
      max_findings: Type.Optional(Type.Number({ description: "Maximum Access Analyzer findings to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAwsConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAwsAuditBundle(new AwsAuditorClient(config), config, outputRoot, args);
        return textResult(
          [
            "AWS audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "aws_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `AWS audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "aws_export_audit_bundle" },
        );
      }
    },
  });
}
