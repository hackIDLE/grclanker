import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AnsibleAapClient,
  assessAnsibleHostCoverage,
  assessAnsibleJobHealth,
  assessAnsiblePlatformSecurity,
  checkAnsibleAccess,
  exportAnsibleAuditBundle,
  resolveAnsibleConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/ansible.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("resolveAnsibleConfiguration prefers explicit non-secret args and keeps passwords in env", () => {
  const resolved = resolveAnsibleConfiguration(
    {
      url: "https://aap.example.com/api/v2/",
      username: " arg-user ",
      timeout_seconds: "12",
    },
    {
      AAP_URL: "https://env-aap.example.com",
      AAP_USERNAME: "env-user",
      AAP_PASSWORD: "env-password",
    },
  );

  assert.equal(resolved.baseUrl, "https://aap.example.com");
  assert.equal(resolved.username, "arg-user");
  assert.equal(resolved.password, "env-password");
  assert.equal(resolved.timeoutMs, 12_000);
  assert.ok(resolved.sourceChain.includes("environment-password"));

  assert.throws(
    () => resolveAnsibleConfiguration({ url: "https://aap.example.com", password: "nope" }, {}),
    /AAP_PASSWORD must be provided via environment/,
  );
});

test("AnsibleAapClient sends bearer auth and follows AAP pagination", async () => {
  const seenAuth = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seenAuth.push(init.headers?.authorization);

    if (url.pathname === "/api/v2/jobs/" && !url.searchParams.get("page")) {
      assert.equal(url.searchParams.get("page_size"), "100");
      return jsonResponse({
        count: 2,
        next: "/api/v2/jobs/?page=2&page_size=100",
        results: [{ id: 1, status: "failed" }],
      });
    }

    if (url.pathname === "/api/v2/jobs/" && url.searchParams.get("page") === "2") {
      return jsonResponse({
        count: 2,
        next: null,
        results: [{ id: 2, status: "successful" }],
      });
    }

    return jsonResponse({ detail: "not found" }, 404);
  };

  const client = new AnsibleAapClient(
    {
      baseUrl: "https://aap.example.com",
      token: "aap-token",
      timeoutMs: 30_000,
      sourceChain: ["tests"],
    },
    { fetchImpl },
  );

  const jobs = await client.list("/api/v2/jobs/");
  assert.equal(jobs.length, 2);
  assert.deepEqual(seenAuth, ["Bearer aap-token", "Bearer aap-token"]);
});

test("checkAnsibleAccess reports readable AAP audit surfaces", async () => {
  const counts = {
    "/api/v2/organizations/": 2,
    "/api/v2/users/": 10,
    "/api/v2/teams/": 3,
    "/api/v2/inventories/": 4,
    "/api/v2/hosts/": 20,
    "/api/v2/job_templates/": 8,
    "/api/v2/jobs/": 100,
    "/api/v2/credentials/": 6,
    "/api/v2/schedules/": 5,
    "/api/v2/projects/": 4,
    "/api/v2/activity_stream/": 12,
    "/api/v2/settings/authentication/": 1,
  };
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/api/v2/me/") {
      return jsonResponse({ count: 1, results: [{ id: 1, username: "auditor" }] });
    }
    if (url.pathname === "/api/v2/ping/") {
      return jsonResponse({ version: "4.5.0" });
    }
    if (url.pathname in counts) {
      return jsonResponse({ count: counts[url.pathname], results: [] });
    }
    return jsonResponse({ detail: "not found" }, 404);
  };

  const client = new AnsibleAapClient(
    {
      baseUrl: "https://aap.example.com",
      token: "aap-token",
      timeoutMs: 30_000,
      sourceChain: ["tests"],
    },
    { fetchImpl },
  );

  const result = await checkAnsibleAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 12);
  assert.match(result.recommendedNextStep, /ansible_assess_job_health/);
});

test("assessAnsibleJobHealth flags low success and chronic failures", async () => {
  const client = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    async list(path) {
      assert.equal(path, "/api/v2/jobs/");
      return [
        { id: 4, name: "Patch Linux", unified_job_template: 10, status: "failed", launch_type: "manual", started: "2026-04-14T00:00:00Z" },
        { id: 3, name: "Patch Linux", unified_job_template: 10, status: "failed", launch_type: "manual", started: "2026-04-13T00:00:00Z" },
        { id: 2, name: "Patch Linux", unified_job_template: 10, status: "failed", launch_type: "scheduled", started: "2026-04-12T00:00:00Z" },
        { id: 1, name: "Baseline", unified_job_template: 11, status: "successful", launch_type: "scheduled", started: "2026-04-11T00:00:00Z" },
      ];
    },
  };

  const result = await assessAnsibleJobHealth(client, { minSuccessRate: 90, maxManualRate: 25 });
  assert.equal(result.summary.total_jobs, 4);
  assert.equal(result.findings.find((item) => item.id === "AAP-JOB-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-JOB-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-JOB-03")?.status, "warn");
});

test("assessAnsibleHostCoverage flags unmanaged, stale, disabled, and sync health gaps", async () => {
  const client = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    async list(path) {
      if (path === "/api/v2/hosts/") {
        return [
          { id: 1, name: "never-ran", enabled: true, last_job: null },
          { id: 2, name: "stale", enabled: true, last_job_host_summary: { finished: "2026-01-01T00:00:00Z" } },
          { id: 3, name: "disabled", enabled: false, last_job_host_summary: { finished: "2026-04-14T00:00:00Z" } },
        ];
      }
      if (path === "/api/v2/inventory_sources/") {
        return [{ id: 9, name: "aws", status: "failed", last_updated: "2026-04-10T00:00:00Z" }];
      }
      return [];
    },
  };

  const result = await assessAnsibleHostCoverage(client, { staleHostDays: 30, criticalStaleHostDays: 60 });
  assert.equal(result.summary.total_hosts, 3);
  assert.equal(result.findings.find((item) => item.id === "AAP-HOST-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-HOST-02")?.severity, "critical");
  assert.equal(result.findings.find((item) => item.id === "AAP-HOST-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AAP-HOST-04")?.status, "warn");
});

test("assessAnsiblePlatformSecurity flags RBAC, auth, audit, credential, token, and project risks", async () => {
  const client = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    async get(path) {
      if (path === "/api/v2/settings/authentication/") {
        return { AUTH_LDAP_SERVER_URI: "" };
      }
      return {};
    },
    async list(path) {
      if (path === "/api/v2/organizations/") return [{ id: 1, name: "Default" }];
      if (path === "/api/v2/organizations/1/admins/") {
        return [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }];
      }
      if (path === "/api/v2/credentials/") {
        return [{ id: 1, name: "machine", modified: "2025-01-01T00:00:00Z" }];
      }
      if (path === "/api/v2/tokens/") {
        return [{ id: 1, created: "2025-01-01T00:00:00Z", expires: null }];
      }
      if (path === "/api/v2/projects/") {
        return [{ id: 1, name: "local playbooks", scm_type: "manual", last_update_failed: false }];
      }
      if (path === "/api/v2/notification_templates/") return [];
      if (path === "/api/v2/activity_stream/") {
        return [{ id: 1, timestamp: "2026-04-10T00:00:00Z" }];
      }
      return [];
    },
  };

  const result = await assessAnsiblePlatformSecurity(client, {
    maxOrgAdmins: 3,
    staleCredentialDays: 90,
    staleTokenDays: 90,
  });
  assert.equal(result.findings.find((item) => item.id === "AAP-RBAC-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-RBAC-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-AUDIT-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-CRED-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "AAP-CRED-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AAP-PROJ-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "AAP-AUDIT-02")?.status, "warn");
});

test("exportAnsibleAuditBundle writes reports, normalized evidence, and archive", async () => {
  const base = createTempBase("grclanker-ansible-export-");
  const countMap = {
    "/api/v2/organizations/": 1,
    "/api/v2/users/": 5,
    "/api/v2/teams/": 2,
    "/api/v2/inventories/": 1,
    "/api/v2/hosts/": 2,
    "/api/v2/job_templates/": 2,
    "/api/v2/jobs/": 3,
    "/api/v2/credentials/": 1,
    "/api/v2/schedules/": 1,
    "/api/v2/projects/": 1,
    "/api/v2/activity_stream/": 1,
    "/api/v2/settings/authentication/": 1,
  };
  const fakeClient = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    async count(path) {
      return countMap[path] ?? 0;
    },
    async get(path) {
      if (path === "/api/v2/me/") {
        return { count: 1, results: [{ id: 1, username: "auditor" }] };
      }
      if (path === "/api/v2/ping/") {
        return { version: "4.5.0" };
      }
      if (path === "/api/v2/settings/authentication/") {
        return { AUTH_LDAP_SERVER_URI: "ldaps://ldap.example.com" };
      }
      return {};
    },
    async list(path) {
      if (path === "/api/v2/jobs/") {
        return [
          { id: 1, name: "Patch Linux", unified_job_template: 10, status: "successful", launch_type: "scheduled", started: "2026-04-14T00:00:00Z" },
          { id: 2, name: "Patch Linux", unified_job_template: 10, status: "failed", launch_type: "manual", started: "2026-04-13T00:00:00Z" },
        ];
      }
      if (path === "/api/v2/hosts/") {
        return [
          { id: 1, name: "fresh", enabled: true, last_job_host_summary: { finished: "2026-04-14T00:00:00Z" } },
          { id: 2, name: "stale", enabled: true, last_job_host_summary: { finished: "2026-02-01T00:00:00Z" } },
        ];
      }
      if (path === "/api/v2/inventory_sources/") return [{ id: 1, name: "aws", status: "successful", last_updated: "2026-04-14T00:00:00Z" }];
      if (path === "/api/v2/organizations/") return [{ id: 1, name: "Default" }];
      if (path === "/api/v2/organizations/1/admins/") return [{ id: 1 }, { id: 2 }];
      if (path === "/api/v2/credentials/") return [{ id: 1, name: "machine", modified: "2026-04-01T00:00:00Z" }];
      if (path === "/api/v2/tokens/") return [{ id: 1, created: "2026-04-01T00:00:00Z", expires: "2026-06-01T00:00:00Z" }];
      if (path === "/api/v2/projects/") return [{ id: 1, name: "playbooks", scm_type: "git", last_update_failed: false }];
      if (path === "/api/v2/notification_templates/") return [{ id: 1, name: "security alerts" }];
      if (path === "/api/v2/activity_stream/") return [{ id: 1, timestamp: "2026-04-14T00:00:00Z" }];
      return [];
    },
  };
  const config = {
    baseUrl: "https://aap.example.com",
    token: "aap-token",
    timeoutMs: 30_000,
    sourceChain: ["tests"],
  };

  const result = await exportAnsibleAuditBundle(fakeClient, config, base, {
    days: 30,
    job_limit: 20,
    host_limit: 20,
  });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.findingCount >= 15);
  assert.ok(existsSync(join(result.outputDir, "summary.md")));
  assert.ok(existsSync(join(result.outputDir, "reports", "executive-summary.md")));
  assert.ok(existsSync(join(result.outputDir, "reports", "control-matrix.md")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "access.json")));
  assert.match(readFileSync(join(result.outputDir, "summary.md"), "utf8"), /Ansible AAP job execution health/);
  assert.equal(readFileSync(result.zipPath).subarray(0, 2).toString("utf8"), "PK");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-ansible-paths-");
  const outside = createTempBase("grclanker-ansible-outside-");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const symlinkTarget = join(base, "symlink-target");
  const symlinkParent = join(base, "symlink-parent");
  writeFileSync(symlinkTarget, "x");
  symlinkSync(outside, symlinkParent);

  assert.throws(() => resolveSecureOutputPath(base, "symlink-parent/file.txt"), /symlinked parent directory/);
});
