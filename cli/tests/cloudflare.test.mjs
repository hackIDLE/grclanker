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
  assessCloudflareIdentity,
  assessCloudflareTrafficControls,
  assessCloudflareZoneSecurity,
  checkCloudflareAccess,
  exportCloudflareAuditBundle,
  resolveCloudflareConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/cloudflare.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    apiToken: "token-123",
    accountId: "acc-123",
    baseUrl: "https://api.cloudflare.com/client/v4",
    timeoutMs: 30000,
    authMethod: "token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

test("resolveCloudflareConfiguration prefers explicit arguments over environment defaults", () => {
  const resolved = resolveCloudflareConfiguration(
    {
      api_token: "arg-token",
      account_id: "arg-account",
      base_url: "https://example.com/client/v4",
      timeout_seconds: 10,
    },
    {
      CLOUDFLARE_API_TOKEN: "env-token",
      CLOUDFLARE_ACCOUNT_ID: "env-account",
      CLOUDFLARE_API_BASE_URL: "https://env.example/client/v4",
    },
  );

  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.accountId, "arg-account");
  assert.equal(resolved.baseUrl, "https://example.com/client/v4");
  assert.equal(resolved.timeoutMs, 10000);
  assert.equal(resolved.authMethod, "token");
  assert.ok(resolved.sourceChain.includes("arguments-api-token"));
});

test("checkCloudflareAccess reports readable Cloudflare surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async verifyCurrentToken() {
      return { result: { status: "active", policies: [{ id: "p1" }] } };
    },
    async listAccounts() {
      return [{ id: "acc-123" }];
    },
    async listZones() {
      return [{ id: "zone-1", name: "example.com" }];
    },
    async getZoneSettings() {
      return [{ id: "ssl", value: "strict" }];
    },
    async getDnssec() {
      return { status: "active" };
    },
    async listMembers() {
      return [{ id: "member-1" }];
    },
    async listAccessApplications() {
      return [{ id: "app-1" }];
    },
    async listAuditLogs() {
      return [{ id: "evt-1" }];
    },
  };

  const result = await checkCloudflareAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 8);
  assert.match(result.recommendedNextStep, /cloudflare_assess_identity/);
});

test("assessCloudflareIdentity flags global keys, super admins, and thin Zero Trust coverage", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig({ authMethod: "global_key", apiToken: undefined, apiKey: "legacy", email: "user@example.com" }),
    async verifyCurrentToken() {
      return null;
    },
    async listAccounts() {
      return [{ id: "acc-123" }];
    },
    async listZones() {
      return [{ id: "zone-1" }, { id: "zone-2" }];
    },
    async listUserTokens() {
      return [{ id: "tok-1" }];
    },
    async listMembers() {
      return [
        { id: "m1", roles: [{ name: "Super Administrator" }] },
        { id: "m2", roles: [{ name: "Super Administrator" }] },
        { id: "m3", roles: [{ name: "Super Administrator" }] },
      ];
    },
    async listAccessApplications() {
      return [];
    },
    async listAccessPolicies() {
      return [];
    },
    async listIdentityProviders() {
      return [];
    },
  };

  const result = await assessCloudflareIdentity(client, {
    maxSuperAdmins: 2,
    memberLimit: 50,
    tokenLimit: 50,
    zoneLimit: 20,
  });
  assert.equal(result.findings.find((item) => item.id === "CF-IAM-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "CF-IAM-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-IAM-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-IAM-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-IAM-05")?.status, "warn");
});

test("assessCloudflareZoneSecurity classifies TLS, DNSSEC, and managed edge protections", async () => {
  const client = {
    async listZones() {
      return [
        { id: "zone-1", name: "good.example" },
        { id: "zone-2", name: "bad.example" },
      ];
    },
    async getZoneSettings(zoneId) {
      if (zoneId === "zone-1") {
        return [
          { id: "ssl", value: "strict" },
          { id: "min_tls_version", value: "1.2" },
          { id: "always_use_https", value: "on" },
          { id: "automatic_https_rewrites", value: "on" },
          { id: "security_header", value: { strict_transport_security: { enabled: true } } },
        ];
      }
      return [
        { id: "ssl", value: "flexible" },
        { id: "min_tls_version", value: "1.0" },
        { id: "always_use_https", value: "off" },
        { id: "automatic_https_rewrites", value: "off" },
        { id: "security_header", value: { strict_transport_security: { enabled: false } } },
      ];
    },
    async getDnssec(zoneId) {
      return zoneId === "zone-1" ? { status: "active" } : { status: "disabled" };
    },
    async listFirewallRules(zoneId) {
      return zoneId === "zone-1" ? [{ id: "fw-1" }] : [];
    },
    async listZoneRulesets() {
      return [];
    },
    async getUniversalSslSettings(zoneId) {
      return zoneId === "zone-1" ? { enabled: true } : { enabled: false };
    },
  };

  const result = await assessCloudflareZoneSecurity(client, { zoneLimit: 20 });
  assert.equal(result.findings.find((item) => item.id === "CF-ZONE-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-ZONE-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "CF-ZONE-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "CF-ZONE-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-ZONE-05")?.status, "warn");
});

test("assessCloudflareTrafficControls flags rate limits, page rules, bot controls, and missing account controls", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listAccounts() {
      return [{ id: "acc-123" }];
    },
    async listZones() {
      return [
        { id: "zone-1", name: "good.example" },
        { id: "zone-2", name: "bad.example" },
      ];
    },
    async listRateLimits(zoneId) {
      return zoneId === "zone-1" ? [{ id: "rl-1" }] : [];
    },
    async listPageRules(zoneId) {
      return zoneId === "zone-2"
        ? [{
            id: "pr-1",
            targets: [{ constraint: { value: "/admin/*" } }],
            actions: [{ id: "disable_security", value: "on" }],
          }]
        : [];
    },
    async getBotManagement(zoneId) {
      return zoneId === "zone-1" ? { fight_mode: true } : null;
    },
    async listAuditLogs() {
      return [];
    },
    async listGatewayRules() {
      return [];
    },
    async listIpAccessRules() {
      return [];
    },
  };

  const result = await assessCloudflareTrafficControls(client, { zoneLimit: 20, auditLimit: 50 });
  assert.equal(result.findings.find((item) => item.id === "CF-TRF-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-TRF-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-TRF-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-TRF-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "CF-TRF-05")?.status, "warn");
});

test("exportCloudflareAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-cloudflare-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async verifyCurrentToken() {
      return { result: { status: "active", policies: [{ id: "p1" }] } };
    },
    async listAccounts() {
      return [{ id: "acc-123" }];
    },
    async listZones() {
      return [{ id: "zone-1", name: "example.com" }];
    },
    async getZoneSettings() {
      return [
        { id: "ssl", value: "strict" },
        { id: "min_tls_version", value: "1.2" },
        { id: "always_use_https", value: "on" },
        { id: "automatic_https_rewrites", value: "on" },
        { id: "security_header", value: { strict_transport_security: { enabled: true } } },
      ];
    },
    async getDnssec() {
      return { status: "active" };
    },
    async listMembers() {
      return [{ id: "member-1", roles: [{ name: "Administrator" }] }];
    },
    async listAccessApplications() {
      return [{ id: "app-1" }];
    },
    async listAuditLogs() {
      return [{ id: "evt-1" }];
    },
    async listAccessPolicies() {
      return [{ id: "policy-1" }];
    },
    async listIdentityProviders() {
      return [{ id: "idp-1" }];
    },
    async listUserTokens() {
      return [{ id: "tok-1", expires_on: "2026-12-31T00:00:00Z" }];
    },
    async listFirewallRules() {
      return [{ id: "fw-1" }];
    },
    async listZoneRulesets() {
      return [];
    },
    async getUniversalSslSettings() {
      return { enabled: true };
    },
    async listRateLimits() {
      return [{ id: "rl-1" }];
    },
    async listPageRules() {
      return [];
    },
    async getBotManagement() {
      return { fight_mode: true };
    },
    async listGatewayRules() {
      return [{ id: "gw-1" }];
    },
    async listIpAccessRules() {
      return [{ id: "ip-1" }];
    },
  };

  const result = await exportCloudflareAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 15);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.auth_method, "token");
  assert.equal(metadata.account_id, "acc-123");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-cloudflare-path-");
  const outside = createTempBase("grclanker-cloudflare-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
