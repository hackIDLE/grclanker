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
  assessGcpIdentity,
  assessGcpLoggingDetection,
  assessGcpOrgGuardrails,
  checkGcpAccess,
  exportGcpAuditBundle,
  resolveGcpConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/gcp.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    organizationId: "123456789012",
    projectId: "prod-audit",
    accessToken: "token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveGcpConfiguration prefers explicit args over environment defaults", () => {
  const resolved = resolveGcpConfiguration(
    { organization_id: "123456789012", project_id: "project-a", access_token: "arg-token" },
    { GCP_ORGANIZATION_ID: "999999999999", GCP_PROJECT_ID: "env-project", GCP_ACCESS_TOKEN: "env-token" },
    () => undefined,
  );

  assert.equal(resolved.organizationId, "123456789012");
  assert.equal(resolved.projectId, "project-a");
  assert.equal(resolved.accessToken, "arg-token");
  assert.ok(resolved.sourceChain.includes("arguments-organization"));
  assert.ok(resolved.sourceChain.includes("arguments-project"));
  assert.ok(resolved.sourceChain.includes("arguments-access-token"));
});

test("checkGcpAccess reports readable GCP audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { name: "organizations/123456789012", displayName: "Example Org" };
    },
    async listProjects() {
      return [{ projectId: "prod-audit", displayName: "Prod Audit" }];
    },
    async searchAllIamPolicies() {
      return [{ resource: "//cloudresourcemanager.googleapis.com/projects/prod-audit" }];
    },
    async getLoggingSettings() {
      return { storageLocation: "global" };
    },
    async listLogSinks() {
      return [{ name: "audit-sink" }];
    },
    async listSccSources() {
      return [{ name: "organizations/123456789012/sources/1" }];
    },
    async getEffectiveOrgPolicy() {
      return { policy: { booleanPolicy: { enforced: true } } };
    },
  };

  const result = await checkGcpAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 7);
  assert.match(result.recommendedNextStep, /gcp_assess_identity/);
});

test("assessGcpIdentity flags privileged bindings, stale keys, and default service accounts", async () => {
  const client = {
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async listProjects() {
      return [{ projectId: "prod-audit", displayName: "Prod Audit" }];
    },
    async listServiceAccounts() {
      return [{ email: "svc@prod-audit.iam.gserviceaccount.com" }];
    },
    async listServiceAccountKeys() {
      return [{ name: "keys/1", validAfterTime: "2025-01-01T00:00:00Z" }];
    },
    async searchAllIamPolicies() {
      return [
        {
          resource: "//cloudresourcemanager.googleapis.com/projects/prod-audit",
          policy: {
            bindings: [
              {
                role: "roles/owner",
                members: ["serviceAccount:123-compute@developer.gserviceaccount.com"],
              },
              {
                role: "roles/viewer",
                members: ["serviceAccount:svc@shared-services.iam.gserviceaccount.com"],
              },
            ],
          },
        },
      ];
    },
  };

  const result = await assessGcpIdentity(client, { staleDays: 90, maxKeys: 50 });
  assert.equal(result.findings.find((item) => item.id === "GCP-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "GCP-IAM-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "GCP-IAM-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "GCP-IAM-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "GCP-IAM-05")?.status, "fail");
});

test("assessGcpLoggingDetection classifies logging and SCC posture", async () => {
  const client = {
    async listProjects() {
      return [{ projectId: "prod-audit", displayName: "Prod Audit" }];
    },
    async getLoggingSettings() {
      return { storageLocation: "global" };
    },
    async listLogSinks() {
      return [{ name: "audit-sink" }];
    },
    async listLogBuckets() {
      return [{ name: "bucket-1", retentionDays: 90 }];
    },
    async listRecentAdminActivity() {
      return [{ insertId: "1" }];
    },
    async listRecentDataAccess() {
      return [];
    },
    async listSccSources() {
      return [{ name: "organizations/123456789012/sources/1" }];
    },
    async listSccFindings() {
      return [{ finding: { state: "ACTIVE" } }];
    },
  };

  const result = await assessGcpLoggingDetection(client, { maxProjects: 10, maxFindings: 20 });
  assert.equal(result.findings.find((item) => item.id === "GCP-LOG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "GCP-LOG-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "GCP-LOG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "GCP-LOG-04")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "GCP-LOG-05")?.status, "pass");
});

test("assessGcpOrgGuardrails flags missing policy constraints", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { displayName: "Example Org" };
    },
    async listProjects() {
      return [{ projectId: "prod-audit", displayName: "Prod Audit" }];
    },
    async getEffectiveOrgPolicy(_projectId, constraint) {
      if (constraint === "constraints/iam.disableServiceAccountKeyCreation") {
        return { policy: { booleanPolicy: { enforced: true } } };
      }
      if (constraint === "constraints/iam.disableServiceAccountKeyUpload") {
        return { policy: { booleanPolicy: { enforced: false } } };
      }
      return null;
    },
  };

  const result = await assessGcpOrgGuardrails(client);
  assert.equal(result.findings.find((item) => item.id === "GCP-ORG-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "GCP-ORG-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "GCP-ORG-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "GCP-ORG-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "GCP-ORG-05")?.status, "fail");
});

test("exportGcpAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-gcp-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => new Date("2026-04-16T00:00:00.000Z"),
    async getOrganization() {
      return { displayName: "Example Org" };
    },
    async listProjects() {
      return [{ projectId: "prod-audit", displayName: "Prod Audit" }];
    },
    async searchAllIamPolicies() {
      return [];
    },
    async getLoggingSettings() {
      return { storageLocation: "global" };
    },
    async listLogSinks() {
      return [{ name: "audit-sink" }];
    },
    async listSccSources() {
      return [{ name: "organizations/123456789012/sources/1" }];
    },
    async getEffectiveOrgPolicy() {
      return { policy: { booleanPolicy: { enforced: true } } };
    },
    async listServiceAccounts() {
      return [];
    },
    async listServiceAccountKeys() {
      return [];
    },
    async listLogBuckets() {
      return [{ name: "bucket-1", retentionDays: 90 }];
    },
    async listRecentAdminActivity() {
      return [{ insertId: "1" }];
    },
    async listRecentDataAccess() {
      return [{ insertId: "2" }];
    },
    async listSccFindings() {
      return [];
    },
  };

  const result = await exportGcpAuditBundle(client, sampleConfig(), base, { max_projects: 5, max_findings: 20 });
  assert.ok(result.outputDir.startsWith(realpathSync(base)));
  assert.ok(existsSync(result.zipPath));

  const executiveSummary = readFileSync(join(result.outputDir, "reports", "executive-summary.md"), "utf8");
  assert.match(executiveSummary, /GCP Audit Bundle/);
  const findingsJson = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.ok(Array.isArray(findingsJson));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-gcp-output-");
  const nested = resolveSecureOutputPath(base, "bundle");
  assert.ok(nested.startsWith(realpathSync(base)));

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const target = createTempBase("grclanker-gcp-symlink-target-");
  const linked = join(base, "linked");
  symlinkSync(target, linked);
  assert.throws(() => resolveSecureOutputPath(base, "linked/out"), /Refusing to use symlinked parent directory/);
});
