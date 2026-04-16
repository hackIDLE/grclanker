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
  assessOciIdentity,
  assessOciLoggingDetection,
  assessOciTenancyGuardrails,
  checkOciAccess,
  exportOciAuditBundle,
  resolveOciConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/oci.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    configFile: "/tmp/oci/config",
    profile: "prod-audit",
    region: "us-ashburn-1",
    tenancyOcid: "ocid1.tenancy.oc1..aaaaexample",
    compartmentOcid: "ocid1.compartment.oc1..aaaaexample",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveOciConfiguration prefers explicit arguments over environment and config", () => {
  const resolved = resolveOciConfiguration(
    {
      config_file: "/tmp/custom-oci-config",
      profile: "audit",
      region: "eu-frankfurt-1",
      tenancy_ocid: "ocid1.tenancy.oc1..explicit",
      compartment_ocid: "ocid1.compartment.oc1..explicit",
    },
    {
      OCI_CONFIG_FILE: "/tmp/env-oci-config",
      OCI_CLI_PROFILE: "env-profile",
      OCI_REGION: "us-phoenix-1",
      OCI_TENANCY_OCID: "ocid1.tenancy.oc1..env",
      OCI_COMPARTMENT_OCID: "ocid1.compartment.oc1..env",
    },
    () => `
[audit]
region=uk-london-1
tenancy=ocid1.tenancy.oc1..config
`,
  );

  assert.equal(resolved.configFile, "/tmp/custom-oci-config");
  assert.equal(resolved.profile, "audit");
  assert.equal(resolved.region, "eu-frankfurt-1");
  assert.equal(resolved.tenancyOcid, "ocid1.tenancy.oc1..explicit");
  assert.equal(resolved.compartmentOcid, "ocid1.compartment.oc1..explicit");
  assert.ok(resolved.sourceChain.includes("arguments-config-file"));
  assert.ok(resolved.sourceChain.includes("arguments-profile"));
  assert.ok(resolved.sourceChain.includes("arguments-region"));
});

test("checkOciAccess reports readable OCI surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listCompartments() {
      return [{ id: "root" }, { id: "child" }];
    },
    async listUsers() {
      return [{ id: "u1" }];
    },
    async getAuthenticationPolicy() {
      return { passwordPolicy: { minimumPasswordLength: 16 } };
    },
    async listAuditEvents() {
      return [{ id: "evt-1" }, { id: "evt-2" }];
    },
    async listCloudGuardTargets() {
      return [{ id: "target-1" }];
    },
    async listSecurityLists() {
      return [{ id: "sl-1" }];
    },
    async listVaults() {
      return [{ id: "vault-1" }];
    },
    async getObjectStorageNamespace() {
      return "tenantns";
    },
    async listBuckets() {
      return [{ name: "logs" }];
    },
  };

  const result = await checkOciAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.match(result.recommendedNextStep, /oci_assess_identity/);
});

test("assessOciIdentity flags weak password policy, missing MFA, stale credentials, and broad policies", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getAuthenticationPolicy() {
      return {
        passwordPolicy: {
          minimumPasswordLength: 12,
          passwordExpiresAfterDays: 180,
          isLowerCaseCharactersRequired: true,
          isUpperCaseCharactersRequired: true,
          isNumericCharactersRequired: false,
          isSpecialCharactersRequired: true,
        },
      };
    },
    async listUsers() {
      return [
        { id: "u1", name: "alice", capabilities: { canUseConsolePassword: true } },
        { id: "u2", name: "bob", capabilities: { canUseConsolePassword: true } },
      ];
    },
    async listMfaTotpDevices(userId) {
      return userId === "u1" ? [] : [{ id: "mfa-bob" }];
    },
    async listApiKeys(userId) {
      if (userId === "u1") {
        return [{ fingerprint: "fp-1", timeCreated: "2025-01-01T00:00:00Z" }];
      }
      return [];
    },
    async listCustomerSecretKeys() {
      return [{ id: "secret-1", timeCreated: "2025-02-01T00:00:00Z" }];
    },
    async listAuthTokens() {
      return [{ id: "token-1", timeCreated: "2025-03-01T00:00:00Z" }];
    },
    async listPolicies() {
      return [{ name: "AdminAll", statements: ["Allow group Admins to manage all-resources in tenancy"] }];
    },
    async listCompartments() {
      return [{ id: "root", compartmentId: "root", name: "root" }];
    },
  };

  const result = await assessOciIdentity(client, { staleDays: 90, maxKeys: 50, maxPolicies: 50 });
  assert.equal(result.findings.find((item) => item.id === "OCI-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-IAM-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-IAM-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-IAM-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "OCI-IAM-05")?.status, "warn");
});

test("assessOciLoggingDetection classifies Cloud Guard, audit events, and event rules", async () => {
  const client = {
    async listCloudGuardTargets() {
      return [{ id: "target-1", lifecycleState: "ACTIVE" }];
    },
    async listCloudGuardProblems() {
      return [{ id: "prob-1", lifecycleState: "OPEN", severity: "HIGH" }];
    },
    async listResponderRecipes() {
      return [{ id: "recipe-1", lifecycleState: "ACTIVE" }];
    },
    async listAuditEvents() {
      return [{ id: "evt-1" }];
    },
    async listEventRules() {
      return [{ id: "rule-1", condition: "identity policy changes" }];
    },
  };

  const result = await assessOciLoggingDetection(client, { lookbackDays: 7 });
  assert.equal(result.findings.find((item) => item.id === "OCI-LOG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "OCI-LOG-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-LOG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "OCI-LOG-04")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "OCI-LOG-05")?.status, "pass");
});

test("assessOciTenancyGuardrails flags exposed network paths, bastions, keys, and public buckets", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async listSecurityLists() {
      return [
        {
          id: "sl-1",
          ingressSecurityRules: [
            {
              source: "0.0.0.0/0",
              tcpOptions: { destinationPortRange: { min: 22, max: 22 } },
            },
          ],
        },
      ];
    },
    async listNetworkSecurityGroups() {
      return [{ id: "nsg-1" }];
    },
    async listNetworkSecurityGroupRules() {
      return [
        {
          source: "0.0.0.0/0",
          tcpOptions: { destinationPortRange: { min: 3389, max: 3389 } },
        },
      ];
    },
    async listInternetGateways() {
      return [{ id: "igw-1" }];
    },
    async listBastions() {
      return [{ id: "bastion-1", maxSessionTtlInSeconds: 14400, clientCidrBlockAllowList: [] }];
    },
    async listBastionSessions() {
      return [{ id: "session-1", timeCreated: "2026-04-15T12:00:00Z" }];
    },
    async listVaults() {
      return [{ id: "vault-1", displayName: "core-vault", managementEndpoint: "https://kms.example" }];
    },
    async listKeys() {
      return [{ id: "key-1", displayName: "legacy-key", algorithm: "AES", timeCreated: "2024-01-01T00:00:00Z" }];
    },
    async getObjectStorageNamespace() {
      return "tenantns";
    },
    async listBuckets() {
      return [{ name: "public-assets", publicAccessType: "ObjectRead" }];
    },
    async listPreauthenticatedRequests() {
      return [{ id: "par-1", timeExpires: "2026-06-30T00:00:00Z" }];
    },
  };

  const result = await assessOciTenancyGuardrails(client);
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-05")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "OCI-GRD-06")?.status, "fail");
});

test("exportOciAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-oci-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async listCompartments() {
      return [
        { id: "root", compartmentId: "root", name: "root" },
        { id: "child", compartmentId: "root", name: "root:prod" },
      ];
    },
    async listUsers() {
      return [{ id: "u1", name: "alice", capabilities: { canUseConsolePassword: true } }];
    },
    async getAuthenticationPolicy() {
      return {
        passwordPolicy: {
          minimumPasswordLength: 16,
          passwordExpiresAfterDays: 90,
          isLowerCaseCharactersRequired: true,
          isUpperCaseCharactersRequired: true,
          isNumericCharactersRequired: true,
          isSpecialCharactersRequired: true,
        },
      };
    },
    async listAuditEvents() {
      return [{ id: "evt-1" }];
    },
    async listCloudGuardTargets() {
      return [{ id: "target-1", lifecycleState: "ACTIVE" }];
    },
    async listSecurityLists() {
      return [];
    },
    async listVaults() {
      return [{ id: "vault-1", displayName: "core-vault", managementEndpoint: "https://kms.example" }];
    },
    async getObjectStorageNamespace() {
      return "tenantns";
    },
    async listBuckets() {
      return [];
    },
    async listMfaTotpDevices() {
      return [{ id: "mfa-1" }];
    },
    async listApiKeys() {
      return [];
    },
    async listCustomerSecretKeys() {
      return [];
    },
    async listAuthTokens() {
      return [];
    },
    async listPolicies() {
      return [];
    },
    async listCloudGuardProblems() {
      return [];
    },
    async listResponderRecipes() {
      return [{ id: "recipe-1", lifecycleState: "ACTIVE" }];
    },
    async listEventRules() {
      return [{ id: "rule-1", condition: "policy changes" }];
    },
    async listNetworkSecurityGroups() {
      return [];
    },
    async listNetworkSecurityGroupRules() {
      return [];
    },
    async listInternetGateways() {
      return [];
    },
    async listBastions() {
      return [];
    },
    async listBastionSessions() {
      return [];
    },
    async listKeys() {
      return [{ id: "key-1", displayName: "rotated-key", algorithm: "AES", timeCreated: "2026-01-01T00:00:00Z" }];
    },
    async listPreauthenticatedRequests() {
      return [];
    },
  };

  const result = await exportOciAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 16);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us-ashburn-1");
  assert.equal(metadata.profile, "prod-audit");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-oci-path-");
  const outside = createTempBase("grclanker-oci-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
