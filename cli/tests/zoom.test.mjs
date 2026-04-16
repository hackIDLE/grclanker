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
  ZoomApiClient,
  assessZoomCollaborationGovernance,
  assessZoomIdentity,
  assessZoomMeetingSecurity,
  checkZoomAccess,
  exportZoomAuditBundle,
  resolveSecureOutputPath,
  resolveZoomConfiguration,
} from "../dist/extensions/grc-tools/zoom.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    accountId: "acct-123",
    token: "zoom-token",
    baseUrl: "https://api.zoom.us/v2",
    oauthBaseUrl: "https://zoom.us",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

test("resolveZoomConfiguration prefers explicit args over environment values", () => {
  const resolved = resolveZoomConfiguration(
    {
      account_id: "acct-explicit",
      token: "arg-token",
      client_id: "arg-client",
      client_secret: "arg-secret",
      base_url: "https://api.zoomgov.com/v2",
      oauth_base_url: "https://zoomgov.com",
      timeout_seconds: 9,
    },
    {
      ZOOM_ACCOUNT_ID: "acct-env",
      ZOOM_TOKEN: "env-token",
      ZOOM_CLIENT_ID: "env-client",
      ZOOM_CLIENT_SECRET: "env-secret",
    },
  );

  assert.equal(resolved.accountId, "acct-explicit");
  assert.equal(resolved.token, "arg-token");
  assert.equal(resolved.baseUrl, "https://api.zoomgov.com/v2");
  assert.equal(resolved.oauthBaseUrl, "https://zoomgov.com");
  assert.equal(resolved.timeoutMs, 9000);
  assert.ok(resolved.sourceChain.includes("arguments-account"));
  assert.ok(resolved.sourceChain.includes("arguments-token"));
});

test("ZoomApiClient exchanges Server-to-Server OAuth credentials and paginates users", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      search: url.search,
      method: init.method ?? "GET",
      auth: headerValue(init.headers, "authorization"),
    });

    if (url.pathname === "/oauth/token") {
      return jsonResponse({ access_token: "oauth-token", expires_in: 3600 });
    }

    if (!url.searchParams.get("next_page_token")) {
      return jsonResponse({
        users: [{ id: "user-1" }],
        next_page_token: "page-2",
      });
    }

    return jsonResponse({ users: [{ id: "user-2" }] });
  };

  const client = new ZoomApiClient(resolveZoomConfiguration({
    account_id: "acct-123",
    client_id: "client-id",
    client_secret: "client-secret",
  }, {}), { fetchImpl });
  const users = await client.listUsers(2);

  assert.deepEqual(users.map((user) => user.id), ["user-1", "user-2"]);
  assert.equal(seen[0].pathname, "/oauth/token");
  assert.match(seen[0].auth, /^Basic /);
  assert.equal(seen[1].pathname, "/v2/users");
  assert.equal(seen[1].auth, "Bearer oauth-token");
  assert.ok(seen.some((item) => item.search.includes("next_page_token=page-2")));
});

test("checkZoomAccess reports readable Zoom audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: "user-1", email: "auditor@example.com" };
    },
    async getAccountSettings() {
      return { schedule_meeting: { require_password_for_scheduling_new_meetings: true } };
    },
    async getAccountLockSettings() {
      return { schedule_meeting: { require_password_for_scheduling_new_meetings: true } };
    },
    async listUsers() {
      return [{ id: "user-1" }];
    },
    async listRoles() {
      return [{ id: "role-1" }];
    },
    async listGroups() {
      return [{ id: "group-1" }];
    },
    async listOperationLogs() {
      return [{ id: "log-1" }];
    },
    async listImGroups() {
      return [{ id: "imgroup-1" }];
    },
    async getManagedDomains() {
      return [{ domain: "example.com" }];
    },
    async listTrustedDomains() {
      return [{ domain: "partners.example.com" }];
    },
    async getPhoneRecordingPolicies() {
      return { automatic_recording: true };
    },
  };

  const result = await checkZoomAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 11);
  assert.match(result.recommendedNextStep, /zoom_assess_identity/);
});

test("assessZoomIdentity flags non-SSO users, admin MFA gaps, and unverified domains", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listUsers() {
      return [
        { id: "admin-1", email: "admin-1@example.com", login_type: "sso" },
        { id: "admin-2", email: "admin-2@example.com", login_type: "password" },
        { id: "user-3", email: "user-3@example.com", login_type: "sso" },
      ];
    },
    async listRoles() {
      return [{ id: "role-admin", name: "Account Admin" }];
    },
    async listRoleMembers() {
      return [{ id: "admin-1" }, { id: "admin-2" }, { id: "admin-3" }];
    },
    async getUserSettings(userId) {
      if (userId === "admin-1") {
        return { feature: { two_factor_auth: true } };
      }
      if (userId === "admin-2") {
        return { feature: { two_factor_auth: false } };
      }
      return {};
    },
    async getManagedDomains() {
      return [
        { domain: "example.com", verified: true },
        { domain: "contractor.example.com", status: "pending" },
      ];
    },
  };

  const result = await assessZoomIdentity(client, { userLimit: 100, maxAdmins: 2 });
  assert.equal(result.findings.find((item) => item.id === "ZOOM-ID-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-ID-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-ID-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-ID-04")?.status, "warn");
});

test("assessZoomCollaborationGovernance flags permissive trust, weak recording policy, and missing logs", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getAccountSettings() {
      return {
        in_meeting: { file_transfer: true },
        recording: {
          auto_delete_cmr: false,
          local_recording: true,
        },
      };
    },
    async listTrustedDomains() {
      return [{ domain: "*" }];
    },
    async listImGroups() {
      return [];
    },
    async listGroups() {
      return [{ id: "group-1", name: "Everyone" }];
    },
    async getGroupSettings() {
      return {
        in_meeting: { file_transfer: true },
        recording: { local_recording: true },
      };
    },
    async getGroupLockSettings() {
      return {};
    },
    async listOperationLogs() {
      return [];
    },
    async getPhoneCallHandlingSettings() {
      return { recording_enabled: false };
    },
    async getPhoneRecordingPolicies() {
      return { automatic_recording: false };
    },
  };

  const result = await assessZoomCollaborationGovernance(client, {
    groupLimit: 10,
    operationLogLimit: 50,
    maxRecordingRetentionDays: 365,
  });
  assert.equal(result.findings.find((item) => item.id === "ZOOM-COLLAB-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-COLLAB-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-COLLAB-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-COLLAB-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-COLLAB-05")?.status, "fail");
});

test("assessZoomMeetingSecurity flags missing meeting defaults and weak hygiene", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getAccountSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: false,
          meeting_authentication: false,
          embed_password_in_join_link: true,
          use_pmi_for_scheduled_meetings: true,
        },
        in_meeting: {
          waiting_room: false,
          screen_sharing: "all participants",
          file_transfer: true,
          e2e_encryption: false,
          data_center_regions: [],
        },
        recording: {
          local_recording: true,
        },
      };
    },
    async getAccountLockSettings() {
      return {};
    },
    async listGroups() {
      return [{ id: "group-1", name: "General" }];
    },
    async getGroupSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: false,
          meeting_authentication: false,
        },
        in_meeting: {
          waiting_room: false,
          file_transfer: true,
        },
        recording: {
          local_recording: true,
        },
      };
    },
    async getGroupLockSettings() {
      return {};
    },
  };

  const result = await assessZoomMeetingSecurity(client, { groupLimit: 10 });
  assert.equal(result.findings.find((item) => item.id === "ZOOM-MTG-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-MTG-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-MTG-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-MTG-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "ZOOM-MTG-05")?.status, "fail");
});

test("exportZoomAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-zoom-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: "user-1", email: "auditor@example.com" };
    },
    async getAccountSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: true,
          meeting_authentication: true,
          embed_password_in_join_link: false,
          use_pmi_for_scheduled_meetings: false,
        },
        in_meeting: {
          waiting_room: true,
          screen_sharing: "host",
          file_transfer: false,
          e2e_encryption: true,
          data_center_regions: ["us"],
        },
        recording: {
          auto_delete_cmr: true,
          auto_delete_cmr_days: 90,
          local_recording: false,
        },
      };
    },
    async getAccountLockSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: true,
        },
      };
    },
    async listUsers() {
      return [
        { id: "admin-1", email: "admin-1@example.com", login_type: "sso" },
        { id: "user-2", email: "user-2@example.com", login_type: "sso" },
      ];
    },
    async listRoles() {
      return [{ id: "role-admin", name: "Account Admin" }];
    },
    async listRoleMembers() {
      return [{ id: "admin-1" }];
    },
    async getUserSettings() {
      return { feature: { two_factor_auth: true } };
    },
    async listGroups() {
      return [{ id: "group-1", name: "Finance" }];
    },
    async getGroupSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: true,
          meeting_authentication: true,
        },
        in_meeting: {
          waiting_room: true,
          file_transfer: false,
        },
        recording: {
          local_recording: false,
        },
      };
    },
    async getGroupLockSettings() {
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: true,
        },
      };
    },
    async listOperationLogs() {
      return [{ id: "log-1" }];
    },
    async listImGroups() {
      return [{ id: "imgroup-1" }];
    },
    async getManagedDomains() {
      return [{ domain: "example.com", verified: true }];
    },
    async listTrustedDomains() {
      return [{ domain: "partners.example.com" }];
    },
    async getPhoneCallHandlingSettings() {
      return { recording_enabled: true };
    },
    async getPhoneRecordingPolicies() {
      return { automatic_recording: true };
    },
  };

  const result = await exportZoomAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 14);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.account_id, "acct-123");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.ok(existsSync(join(result.outputDir, "reports", "meeting-security.md")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-zoom-path-");
  const outside = createTempBase("grclanker-zoom-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
