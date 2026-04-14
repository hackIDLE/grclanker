import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GoogleWorkspaceAuditorClient,
  assessGwsAdminAccess,
  assessGwsIdentity,
  assessGwsIntegrations,
  assessGwsMonitoring,
  clearGwsTokenCacheForTests,
  exportGwsAuditBundle,
  resolveGwsConfiguration,
  resolveSecureOutputPath,
  runGwsAccessCheck,
} from "../dist/extensions/grc-tools/gws.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function createSampleConfig(overrides = {}) {
  return {
    authMode: "access_token",
    accessToken: "ya29.test",
    adminEmail: "admin@example.com",
    domain: "example.com",
    customerId: "my_customer",
    lookbackDays: 30,
    tokenUri: "https://oauth2.googleapis.com/token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function createUsers() {
  return [
    {
      id: "u-super",
      primaryEmail: "super@example.com",
      isAdmin: true,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: true,
      isEnrolledIn2Sv: true,
      lastLoginTime: "2030-01-10T00:00:00Z",
    },
    {
      id: "u-delegated",
      primaryEmail: "delegated@example.com",
      isAdmin: false,
      isDelegatedAdmin: true,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: false,
      isEnrolledIn2Sv: true,
      lastLoginTime: "2030-01-09T00:00:00Z",
    },
    {
      id: "u-user",
      primaryEmail: "user@example.com",
      isAdmin: false,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: true,
      isEnrolledIn2Sv: true,
      lastLoginTime: "2030-01-08T00:00:00Z",
    },
    {
      id: "u-dormant",
      primaryEmail: "dormant@example.com",
      isAdmin: false,
      isDelegatedAdmin: false,
      suspended: false,
      archived: false,
      isEnforcedIn2Sv: false,
      isEnrolledIn2Sv: false,
      lastLoginTime: "2020-01-01T00:00:00Z",
    },
  ];
}

function createRoles() {
  return [
    {
      roleId: "1",
      roleName: "_SEED_ADMIN_ROLE",
      isSystemRole: true,
      isSuperAdminRole: true,
      rolePrivileges: [{ privilegeName: "SUPER_ADMIN" }],
    },
    {
      roleId: "2",
      roleName: "_GROUPS_ADMIN_ROLE",
      isSystemRole: true,
      rolePrivileges: [{ privilegeName: "GROUPS_ALL" }],
    },
  ];
}

function createRoleAssignments() {
  return [
    {
      roleAssignmentId: "ra-1",
      roleId: "2",
      assignedTo: "u-delegated",
      assigneeType: "USER",
      scopeType: "CUSTOMER",
    },
    {
      roleAssignmentId: "ra-2",
      roleId: "2",
      assignedTo: "group-1",
      assigneeType: "GROUP",
      scopeType: "CUSTOMER",
    },
  ];
}

function createLoginActivities() {
  return [
    {
      id: { applicationName: "login" },
      events: [{ name: "login_success" }, { name: "suspicious_login" }],
      actor: { email: "super@example.com" },
    },
    {
      id: { applicationName: "login" },
      events: [{ name: "gov_attack_warning" }],
      actor: { email: "user@example.com" },
    },
  ];
}

function createAdminActivities() {
  return [
    {
      id: { applicationName: "admin" },
      events: [{ name: "CHANGE_APPLICATION_SETTING" }],
      actor: { email: "super@example.com" },
    },
  ];
}

function createTokenActivities() {
  return [
    {
      id: { applicationName: "token" },
      events: [{ name: "authorize" }],
      actor: {
        email: "delegated@example.com",
        applicationInfo: { applicationName: "Example App" },
      },
    },
  ];
}

function createAlerts() {
  return [
    {
      alertId: "a-1",
      source: "Google Operations",
      state: "open",
      type: "User reported phishing",
    },
    {
      alertId: "a-2",
      source: "Google Operations",
      state: "closed",
      type: "Suspicious login",
    },
  ];
}

function createTokenInventory() {
  return [
    {
      userId: "u-delegated",
      primaryEmail: "delegated@example.com",
      token: {
        clientId: "client-1",
        displayText: "Drive Syncer",
        scopes: [
          "https://www.googleapis.com/auth/drive",
          "https://www.googleapis.com/auth/admin.directory.user.readonly",
        ],
      },
    },
    {
      userId: "u-user",
      primaryEmail: "user@example.com",
      token: {
        clientId: "client-2",
        displayText: "Calendar Helper",
        scopes: ["https://www.googleapis.com/auth/calendar"],
      },
    },
  ];
}

test("resolveGwsConfiguration prefers explicit args over environment values and loads service account JSON", async () => {
  const base = createTempBase("grclanker-gws-config-");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const credentialsPath = join(base, "sa.json");
  writeFileSync(
    credentialsPath,
    JSON.stringify({
      client_email: "svc@example-project.iam.gserviceaccount.com",
      private_key: privateKeyPem,
      token_uri: "https://oauth2.googleapis.com/token",
    }),
  );

  const resolved = await resolveGwsConfiguration(
    {
      auth_mode: "service_account",
      credentials_file: credentialsPath,
      admin_email: "admin@example.com",
      domain: "arg.example.com",
      lookback_days: 45,
    },
    {
      GWS_AUTH_MODE: "access_token",
      GWS_ACCESS_TOKEN: "env-token",
      GWS_ADMIN_EMAIL: "env-admin@example.com",
      GWS_DOMAIN: "env.example.com",
      GWS_LOOKBACK_DAYS: "7",
    },
  );

  assert.equal(resolved.authMode, "service_account");
  assert.equal(resolved.adminEmail, "admin@example.com");
  assert.equal(resolved.domain, "arg.example.com");
  assert.equal(resolved.lookbackDays, 45);
  assert.equal(resolved.serviceAccountEmail, "svc@example-project.iam.gserviceaccount.com");
  assert.match(resolved.serviceAccountPrivateKey, /BEGIN PRIVATE KEY/);
  assert.deepEqual(resolved.sourceChain, ["environment", "arguments"]);
});

test("GoogleWorkspaceAuditorClient refreshes service-account tokens and handles pagination", async () => {
  clearGwsTokenCacheForTests();
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const state = {
    tokenRequests: 0,
    firstUsers401: true,
  };

  const config = createSampleConfig({
    authMode: "service_account",
    accessToken: undefined,
    adminEmail: "admin@example.com",
    serviceAccountEmail: "svc@example-project.iam.gserviceaccount.com",
    serviceAccountPrivateKey: privateKeyPem,
  });

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());

    if (url.origin === "https://oauth2.googleapis.com" && url.pathname === "/token") {
      state.tokenRequests += 1;
      return new Response(
        JSON.stringify({
          access_token: `ya29.token.${state.tokenRequests}`,
          expires_in: 3600,
          token_type: "Bearer",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname === "/admin/directory/v1/users") {
      if (state.firstUsers401) {
        state.firstUsers401 = false;
        return new Response(JSON.stringify({ error: { message: "expired token" } }), {
          status: 401,
          headers: { "content-type": "application/json" },
        });
      }
      const pageToken = url.searchParams.get("pageToken");
      return new Response(
        JSON.stringify(
          pageToken
            ? {
              users: [{ id: "u-2", primaryEmail: "user2@example.com" }],
            }
            : {
              users: [{ id: "u-1", primaryEmail: "user1@example.com" }],
              nextPageToken: "page-2",
            },
        ),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname === "/admin/directory/v1/customer/my_customer/roles") {
      return new Response(JSON.stringify({ items: [{ roleId: "1", roleName: "_SEED_ADMIN_ROLE", isSuperAdminRole: true }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/admin/directory/v1/customer/my_customer/roleassignments") {
      return new Response(JSON.stringify({ items: [{ roleId: "1", assignedTo: "u-1", assigneeType: "USER" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/admin/reports/v1/activity/users/all/applications/login") {
      return new Response(JSON.stringify({ items: [{ events: [{ name: "login_success" }] }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/v1beta1/alerts") {
      return new Response(JSON.stringify({ alerts: [{ alertId: "a-1", state: "closed" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: { message: `unexpected URL ${url}` } }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  };

  const client = new GoogleWorkspaceAuditorClient(config, fetchImpl);
  const users = await client.listUsers();
  assert.equal(users.length, 2);
  assert.equal(state.tokenRequests, 2);

  const access = await runGwsAccessCheck(client, config);
  assert.equal(access.status, "healthy");
});

test("GWS assessments produce stable findings across identity, admin, integrations, and monitoring", () => {
  const config = createSampleConfig();
  const identity = assessGwsIdentity({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    loginActivities: dataset(createLoginActivities()),
  }, config);
  const admin = assessGwsAdminAccess({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    adminActivities: dataset(createAdminActivities()),
  }, config);
  const integrations = assessGwsIntegrations({
    users: dataset(createUsers()),
    roles: dataset(createRoles()),
    roleAssignments: dataset(createRoleAssignments()),
    tokenInventory: dataset(createTokenInventory()),
    tokenActivities: dataset(createTokenActivities()),
  }, config);
  const monitoring = assessGwsMonitoring({
    loginActivities: dataset(createLoginActivities()),
    adminActivities: dataset(createAdminActivities()),
    tokenActivities: dataset(createTokenActivities()),
    alerts: dataset(createAlerts()),
  }, config);

  assert.equal(identity.findings.length, 4);
  assert.equal(admin.findings.length, 5);
  assert.equal(integrations.findings.length, 4);
  assert.equal(monitoring.findings.length, 5);
  assert.equal(identity.findings.find((finding) => finding.id === "GWS-ID-001").status, "Fail");
  assert.equal(admin.findings.find((finding) => finding.id === "GWS-ADMIN-005").status, "Manual");
  assert.equal(integrations.findings.find((finding) => finding.id === "GWS-INTEG-002").status, "Partial");
  assert.equal(monitoring.findings.find((finding) => finding.id === "GWS-MON-002").status, "Partial");
});

test("exportGwsAuditBundle writes reports and archive", async () => {
  const base = createTempBase("grclanker-gws-export-");
  const config = createSampleConfig();
  const fakeClient = {
    listUsers: async () => createUsers(),
    listRoles: async () => createRoles(),
    listRoleAssignments: async () => createRoleAssignments(),
    listActivities: async (applicationName) => {
      if (applicationName === "login") return createLoginActivities();
      if (applicationName === "admin") return createAdminActivities();
      return createTokenActivities();
    },
    listAlerts: async () => createAlerts(),
    listUserTokens: async (userKey) => {
      if (userKey === "delegated@example.com") {
        return [createTokenInventory()[0].token];
      }
      if (userKey === "user@example.com") {
        return [createTokenInventory()[1].token];
      }
      return [];
    },
  };

  const result = await exportGwsAuditBundle(fakeClient, config, base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(join(result.outputDir, "summary.md")));
  assert.ok(existsSync(join(result.outputDir, "reports", "executive-summary.md")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.match(readFileSync(join(result.outputDir, "summary.md"), "utf8"), /Google Workspace identity assessment/);
  assert.ok(result.findingCount >= 18);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-gws-paths-");
  const outside = createTempBase("grclanker-gws-outside-");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const symlinkTarget = join(base, "symlink-target");
  const symlinkParent = join(base, "symlink-parent");
  writeFileSync(symlinkTarget, "x");
  symlinkSync(outside, symlinkParent);

  assert.throws(() => resolveSecureOutputPath(base, "symlink-parent/file.txt"), /symlinked parent directory/);
});
