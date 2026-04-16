import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assessAwsIdentity,
  assessAwsLoggingDetection,
  assessAwsOrgGuardrails,
  checkAwsAccess,
  exportAwsAuditBundle,
  resolveAwsConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/aws.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    region: "us-east-1",
    profile: "prod-audit",
    accountId: "123456789012",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveAwsConfiguration prefers explicit args over environment defaults", () => {
  const resolved = resolveAwsConfiguration(
    { region: "us-west-2", profile: "audit", account_id: "111122223333" },
    { AWS_REGION: "eu-west-1", AWS_PROFILE: "env-profile" },
  );

  assert.equal(resolved.region, "us-west-2");
  assert.equal(resolved.profile, "audit");
  assert.equal(resolved.accountId, "111122223333");
  assert.ok(resolved.sourceChain.includes("arguments-region"));
  assert.ok(resolved.sourceChain.includes("arguments-profile"));
});

test("checkAwsAccess reports readable AWS audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCallerIdentity() {
      return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/auditor" };
    },
    async getAccountSummary() {
      return { SummaryMap: { Users: 3 } };
    },
    async describeTrails() {
      return [{ Name: "org-trail" }];
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async listAnalyzers() {
      return [{ arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/org", status: "ACTIVE" }];
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listIdentityCenterInstances() {
      return [{ InstanceArn: "arn:aws:sso:::instance/ssoins-1" }];
    },
  };

  const result = await checkAwsAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.match(result.recommendedNextStep, /aws_assess_identity/);
});

test("assessAwsIdentity flags root, MFA, password, key, and boundary issues", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getAccountSummary() {
      return { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } };
    },
    async getPasswordPolicy() {
      return {
        MinimumPasswordLength: 12,
        RequireSymbols: true,
        RequireNumbers: false,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
      };
    },
    async listIamUsers() {
      return [
        { UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" },
        { UserName: "bob", PasswordLastUsed: "2025-12-01T00:00:00Z" },
        { UserName: "carol" },
      ];
    },
    async listMfaDevices(userName) {
      return userName === "alice" ? [] : [{ SerialNumber: `mfa-${userName}` }];
    },
    async listAccessKeys(userName) {
      if (userName === "bob") {
        return [{ AccessKeyId: "AKIABOB", CreateDate: "2025-01-01T00:00:00Z" }];
      }
      return [];
    },
    async getAccessKeyLastUsed() {
      return { LastUsedDate: "2025-01-02T00:00:00Z" };
    },
    async getAccountAuthorizationDetails() {
      return [
        {
          RoleName: "AdminRole",
          AttachedManagedPolicies: [{ PolicyName: "AdministratorAccess" }],
        },
      ];
    },
  };

  const result = await assessAwsIdentity(client, { staleDays: 90, maxPrivilegedRoles: 5 });
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-05")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-IAM-06")?.status, "warn");
});

test("assessAwsLoggingDetection classifies trail, Security Hub, GuardDuty, and Config posture", async () => {
  const client = {
    async describeTrails() {
      return [
        {
          Name: "org-trail",
          TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
          IsMultiRegionTrail: true,
          LogFileValidationEnabled: true,
        },
      ];
    },
    async getTrailStatus() {
      return { IsLogging: true };
    },
    async getEventSelectors() {
      return { EventSelectors: [] };
    },
    async describeSecurityHub() {
      return { HubArn: "arn:aws:securityhub:us-east-1:123456789012:hub/default" };
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "cis" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default", recordingGroup: { allSupported: true } }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
  };

  const result = await assessAwsLoggingDetection(client);
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-04")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-LOG-05")?.status, "pass");
});

test("assessAwsOrgGuardrails flags external access and missing Identity Center", async () => {
  const client = {
    async describeOrganization() {
      return { Id: "o-example", FeatureSet: "ALL" };
    },
    async listAccounts() {
      return [{ Id: "1111" }, { Id: "2222" }, { Id: "3333" }];
    },
    async listScps() {
      return [{ Id: "p-1", Name: "DenyRegions" }];
    },
    async listPolicyTargets() {
      return [{ TargetId: "ou-1", Name: "Prod", Type: "ORGANIZATIONAL_UNIT" }];
    },
    async listAnalyzers() {
      return [{ arn: "arn:analyzer", status: "ACTIVE" }];
    },
    async listAccessAnalyzerFindings() {
      return [{ id: "f-1", status: "ACTIVE", resource: "arn:aws:s3:::public-bucket" }];
    },
    async listIdentityCenterInstances() {
      return [];
    },
  };

  const result = await assessAwsOrgGuardrails(client, { maxFindings: 50 });
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-02")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AWS-ORG-05")?.status, "warn");
});

test("exportAwsAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-aws-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getCallerIdentity() {
      return { Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/auditor" };
    },
    async getAccountSummary() {
      return { SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } };
    },
    async getPasswordPolicy() {
      return {
        MinimumPasswordLength: 16,
        RequireSymbols: true,
        RequireNumbers: true,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
      };
    },
    async listIamUsers() {
      return [{ UserName: "alice", PasswordLastUsed: "2026-04-14T00:00:00Z" }];
    },
    async listMfaDevices() {
      return [{ SerialNumber: "mfa-alice" }];
    },
    async listAccessKeys() {
      return [];
    },
    async getAccessKeyLastUsed() {
      return null;
    },
    async getAccountAuthorizationDetails() {
      return [];
    },
    async describeTrails() {
      return [{ Name: "org-trail", TrailARN: "arn:trail", IsMultiRegionTrail: true, LogFileValidationEnabled: true }];
    },
    async getTrailStatus() {
      return { IsLogging: true };
    },
    async getEventSelectors() {
      return { AdvancedEventSelectors: [{ Name: "data-events" }] };
    },
    async describeSecurityHub() {
      return { HubArn: "arn:hub" };
    },
    async getEnabledSecurityHubStandards() {
      return [{ StandardsArn: "cis" }];
    },
    async describeConfigurationRecorders() {
      return [{ name: "default" }];
    },
    async describeConfigurationRecorderStatus() {
      return [{ name: "default", recording: true }];
    },
    async listDetectors() {
      return ["detector-1"];
    },
    async getDetector() {
      return { Status: "ENABLED" };
    },
    async describeOrganization() {
      return { Id: "o-example" };
    },
    async listAccounts() {
      return [{ Id: "123456789012" }];
    },
    async listScps() {
      return [{ Id: "p-1", Name: "DenyRegions" }];
    },
    async listPolicyTargets() {
      return [{ TargetId: "r-root", Type: "ROOT" }];
    },
    async listAnalyzers() {
      return [{ arn: "arn:analyzer", status: "ACTIVE" }];
    },
    async listAccessAnalyzerFindings() {
      return [];
    },
    async listIdentityCenterInstances() {
      return [{ InstanceArn: "arn:sso" }];
    },
  };

  const result = await exportAwsAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 16);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us-east-1");
  assert.equal(metadata.profile, "prod-audit");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-aws-path-");
  const outside = createTempBase("grclanker-aws-outside-");
  const nested = join(base, "nested");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
  assert.ok(!existsSync(nested));
});
