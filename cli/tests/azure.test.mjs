import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assessAzureIdentity,
  assessAzureMonitoring,
  assessAzureSubscriptionGuardrails,
  checkAzureAccess,
  exportAzureAuditBundle,
  resolveAzureConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/azure.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    tenantId: "tenant-123",
    subscriptionId: "sub-123",
    graphToken: "graph-token",
    managementToken: "arm-token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveAzureConfiguration prefers explicit args over environment defaults", () => {
  const resolved = resolveAzureConfiguration(
    {
      tenant_id: "tenant-arg",
      subscription_id: "sub-arg",
      graph_token: "graph-arg",
      management_token: "arm-arg",
    },
    {
      AZURE_TENANT_ID: "tenant-env",
      AZURE_SUBSCRIPTION_ID: "sub-env",
      AZURE_GRAPH_TOKEN: "graph-env",
      AZURE_MANAGEMENT_TOKEN: "arm-env",
    },
    () => undefined,
  );

  assert.equal(resolved.tenantId, "tenant-arg");
  assert.equal(resolved.subscriptionId, "sub-arg");
  assert.equal(resolved.graphToken, "graph-arg");
  assert.equal(resolved.managementToken, "arm-arg");
  assert.ok(resolved.sourceChain.includes("arguments-tenant"));
  assert.ok(resolved.sourceChain.includes("arguments-subscription"));
});

test("checkAzureAccess reports readable audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { id: "org-1" };
    },
    async listConditionalAccessPolicies() {
      return [{ id: "ca-1" }];
    },
    async listDirectoryRoles() {
      return [{ id: "role-1" }];
    },
    async listSecureScores() {
      return [{ currentScore: 45, maxScore: 60 }];
    },
    async listDefenderPricings() {
      return [{ id: "pricing-1" }];
    },
    async listRoleAssignments() {
      return [{ id: "assignment-1" }];
    },
    async listDiagnosticSettings() {
      return [{ id: "diag-1" }];
    },
    async listSecurityContacts() {
      return [{ id: "contact-1" }];
    },
  };

  const result = await checkAzureAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.match(result.recommendedNextStep, /azure_assess_identity/);
});

test("assessAzureIdentity flags weak auth baseline and privileged role sprawl", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async listConditionalAccessPolicies() {
      return [
        {
          id: "ca-1",
          state: "enabled",
          displayName: "Require MFA for admins",
          grantControls: { builtInControls: ["mfa"] },
          conditions: { clientAppTypes: ["all"] },
        },
      ];
    },
    async listUserRegistrationDetails() {
      return [
        { userPrincipalName: "alice@example.com", isMfaRegistered: true },
        { userPrincipalName: "bob@example.com", isMfaRegistered: false },
      ];
    },
    async listDirectoryRoles() {
      return [
        { id: "ga", displayName: "Global Administrator" },
        { id: "sec", displayName: "Security Administrator" },
      ];
    },
    async listDirectoryRoleMembers(roleId) {
      return roleId === "ga"
        ? [{ id: "user-1" }, { id: "user-2" }, { id: "user-3" }, { id: "user-4" }, { id: "user-5" }]
        : [{ id: "user-6" }];
    },
    async getSecurityDefaultsPolicy() {
      return { isEnabled: false };
    },
    async listServicePrincipals() {
      return [
        {
          displayName: "App One",
          passwordCredentials: [{ endDateTime: "2026-04-20T00:00:00Z" }],
          keyCredentials: [],
        },
      ];
    },
  };

  const result = await assessAzureIdentity(client);
  assert.equal(result.findings.find((item) => item.id === "AZURE-ID-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AZURE-ID-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-ID-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AZURE-ID-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AZURE-ID-05")?.status, "warn");
});

test("assessAzureMonitoring classifies score, telemetry, and defender coverage", async () => {
  const client = {
    async listSecureScores() {
      return [{ currentScore: 40, maxScore: 80 }];
    },
    async listSecurityAlerts() {
      return [{ id: "alert-1" }];
    },
    async listDirectoryAudits() {
      return [{ id: "audit-1" }];
    },
    async listSignIns() {
      return [];
    },
    async listDefenderPricings() {
      return [
        { properties: { pricingTier: "Standard" } },
        { properties: { pricingTier: "Free" } },
      ];
    },
    async listDiagnosticSettings() {
      return [];
    },
  };

  const result = await assessAzureMonitoring(client);
  assert.equal(result.findings.find((item) => item.id === "AZURE-MON-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-MON-02")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "AZURE-MON-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-MON-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-MON-05")?.status, "fail");
});

test("assessAzureSubscriptionGuardrails flags RBAC and missing contacts", async () => {
  const client = {
    async listRoleAssignments() {
      return [
        {
          properties: {
            roleDefinitionId: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/owner-role",
            principalType: "User",
          },
        },
        {
          properties: {
            roleDefinitionId: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/contrib-role",
            principalType: "ServicePrincipal",
          },
        },
      ];
    },
    async listRoleDefinitions() {
      return [
        { id: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/owner-role", properties: { roleName: "Owner" } },
        { id: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/contrib-role", properties: { roleName: "Contributor" } },
      ];
    },
    async listSecurityContacts() {
      return [];
    },
    async listNetworkWatchers() {
      return [];
    },
  };

  const result = await assessAzureSubscriptionGuardrails(client);
  assert.equal(result.findings.find((item) => item.id === "AZURE-SUB-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-SUB-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-SUB-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AZURE-SUB-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AZURE-SUB-05")?.status, "fail");
});

test("exportAzureAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-azure-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getOrganization() {
      return { id: "org-1" };
    },
    async listConditionalAccessPolicies() {
      return [{ id: "ca-1", state: "enabled", grantControls: { builtInControls: ["mfa"] }, conditions: { clientAppTypes: ["exchangeActiveSync"] } }];
    },
    async listDirectoryRoles() {
      return [];
    },
    async listSecureScores() {
      return [{ currentScore: 60, maxScore: 80 }];
    },
    async listDefenderPricings() {
      return [{ properties: { pricingTier: "Standard" } }];
    },
    async listRoleAssignments() {
      return [];
    },
    async listDiagnosticSettings() {
      return [{ id: "diag-1" }];
    },
    async listSecurityContacts() {
      return [{ properties: { email: "soc@example.com" } }];
    },
    async listUserRegistrationDetails() {
      return [{ isMfaRegistered: true }];
    },
    async listDirectoryRoleMembers() {
      return [];
    },
    async getSecurityDefaultsPolicy() {
      return { isEnabled: true };
    },
    async listServicePrincipals() {
      return [];
    },
    async listSecurityAlerts() {
      return [];
    },
    async listDirectoryAudits() {
      return [{ id: "audit-1" }];
    },
    async listSignIns() {
      return [{ id: "signin-1" }];
    },
    async listRoleDefinitions() {
      return [];
    },
    async listNetworkWatchers() {
      return [{ id: "nw-1" }];
    },
  };

  const result = await exportAzureAuditBundle(client, sampleConfig(), base, { max_assignments: 25 });
  assert.ok(result.outputDir.startsWith(realpathSync(base)));
  assert.ok(existsSync(result.zipPath));

  const executiveSummary = readFileSync(join(result.outputDir, "reports", "executive-summary.md"), "utf8");
  assert.match(executiveSummary, /Azure Audit Bundle/);
  const findingsJson = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.ok(Array.isArray(findingsJson));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-azure-output-");
  const nested = resolveSecureOutputPath(base, "bundle");
  assert.ok(nested.startsWith(realpathSync(base)));

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const target = createTempBase("grclanker-azure-symlink-target-");
  const linked = join(base, "linked");
  symlinkSync(target, linked);
  assert.throws(() => resolveSecureOutputPath(base, "linked/out"), /Refusing to use symlinked parent directory/);
});
