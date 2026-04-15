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
  GwsCliCommandError,
  checkGwsCliAccess,
  collectGwsOperatorEvidenceBundle,
  investigateGwsAlerts,
  resolveGwsCliExecutable,
  reviewGwsTokenActivity,
  traceGwsAdminActivity,
} from "../dist/extensions/grc-tools/gws-ops.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function createFakeBinary(base, name = "gws") {
  const pathname = join(base, name);
  writeFileSync(pathname, "#!/bin/sh\n");
  return pathname;
}

function parseParams(args) {
  const paramsIndex = args.indexOf("--params");
  if (paramsIndex === -1) return {};
  return JSON.parse(args[paramsIndex + 1]);
}

function createRunner() {
  return async ({ executable, args }) => {
    const command = [executable.displayExecutable, ...args].join(" ");
    if (args[0] === "--version") {
      return {
        executable: executable.executable,
        displayExecutable: executable.displayExecutable,
        args,
        command,
        stdout: "gws 0.22.5",
        stderr: "",
        exitCode: 0,
      };
    }

    if (args[0] === "alertcenter:v1beta1") {
      return {
        executable: executable.executable,
        displayExecutable: executable.displayExecutable,
        args,
        command,
        stdout: JSON.stringify({
          alerts: [
            {
              alertId: "a-1",
              type: "Suspicious login",
              severity: "high",
              state: "open",
              source: "Google Operations",
              createTime: "2030-01-01T00:00:00Z",
            },
            {
              alertId: "a-2",
              type: "Password spray",
              severity: "medium",
              state: "closed",
              source: "Google Operations",
              createTime: "2030-01-02T00:00:00Z",
            },
          ],
        }),
        stderr: "",
        exitCode: 0,
      };
    }

    if (args[0] === "admin-reports") {
      const params = parseParams(args);
      const applicationName = params.applicationName;
      if (applicationName === "admin") {
        return {
          executable: executable.executable,
          displayExecutable: executable.displayExecutable,
          args,
          command,
          stdout: JSON.stringify({
            items: [
              {
                id: { time: "2030-01-01T12:00:00Z", uniqueQualifier: "u1" },
                actor: { email: "admin@example.com", ipAddress: "203.0.113.1" },
                events: [{ name: "CHANGE_APPLICATION_SETTING" }],
              },
            ],
          }),
          stderr: "",
          exitCode: 0,
        };
      }

      if (applicationName === "token") {
        return {
          executable: executable.executable,
          displayExecutable: executable.displayExecutable,
          args,
          command,
          stdout: JSON.stringify({
            items: [
              {
                id: { time: "2030-01-01T12:05:00Z", uniqueQualifier: "u2" },
                actor: {
                  email: "user@example.com",
                  applicationInfo: { applicationName: "Drive Syncer" },
                },
                events: [{ name: "authorize" }, { name: "request" }],
              },
            ],
          }),
          stderr: "",
          exitCode: 0,
        };
      }
    }

    throw new Error(`Unexpected mocked gws command: ${command}`);
  };
}

test("resolveGwsCliExecutable prefers explicit binary path", () => {
  const base = createTempBase("grclanker-gws-ops-bin-");
  const fake = createFakeBinary(base);

  const resolved = resolveGwsCliExecutable({ gwsBin: fake });
  assert.equal(resolved.executable, fake);
  assert.equal(resolved.installed, true);
  assert.equal(resolved.source, "argument");
});

test("checkGwsCliAccess previews the probe command in dry-run mode", async () => {
  const base = createTempBase("grclanker-gws-ops-check-");
  const fake = createFakeBinary(base);

  const result = await checkGwsCliAccess({ gwsBin: fake, dry_run: true }, createRunner());
  assert.equal(result.status, "preview");
  assert.equal(result.version, "gws 0.22.5");
  assert.match(result.command.command, /admin-reports activities list/);
});

test("checkGwsCliAccess maps auth failures cleanly", async () => {
  const base = createTempBase("grclanker-gws-ops-auth-");
  const fake = createFakeBinary(base);
  const runner = async ({ executable, args }) => {
    const command = [executable.displayExecutable, ...args].join(" ");
    if (args[0] === "--version") {
      return {
        executable: executable.executable,
        displayExecutable: executable.displayExecutable,
        args,
        command,
        stdout: "gws 0.22.5",
        stderr: "",
        exitCode: 0,
      };
    }
    throw new GwsCliCommandError("auth", "Credentials missing", command, 2);
  };

  await assert.rejects(
    () => checkGwsCliAccess({ gwsBin: fake }, runner),
    (error) => error instanceof GwsCliCommandError && error.kind === "auth",
  );
});

test("investigateGwsAlerts parses alert records from gws output", async () => {
  const base = createTempBase("grclanker-gws-ops-alerts-");
  const fake = createFakeBinary(base);

  const result = await investigateGwsAlerts({ gwsBin: fake, max_results: 25 }, createRunner());
  assert.equal(result.count, 2);
  assert.equal(result.records[0].id, "a-1");
  assert.match(result.command.command, /alertcenter:v1beta1 alerts list/);
});

test("traceGwsAdminActivity normalizes activity records", async () => {
  const base = createTempBase("grclanker-gws-ops-admin-");
  const fake = createFakeBinary(base);

  const result = await traceGwsAdminActivity({ gwsBin: fake, lookback_days: 10 }, createRunner());
  assert.equal(result.count, 1);
  assert.equal(result.records[0].actor, "admin@example.com");
  assert.equal(result.records[0].eventNames[0], "CHANGE_APPLICATION_SETTING");
});

test("reviewGwsTokenActivity highlights token telemetry without inventory cloning", async () => {
  const base = createTempBase("grclanker-gws-ops-token-");
  const fake = createFakeBinary(base);

  const result = await reviewGwsTokenActivity({ gwsBin: fake }, createRunner());
  assert.equal(result.count, 1);
  assert.equal(result.records[0].application, "Drive Syncer");
  assert.match(result.notes.join(" "), /not a full tenant-wide token inventory/i);
});

test("collectGwsOperatorEvidenceBundle writes raw evidence, summaries, and a zip", async () => {
  const base = createTempBase("grclanker-gws-ops-bundle-");
  const fake = createFakeBinary(base);
  const outputRoot = join(base, "export");

  const result = await collectGwsOperatorEvidenceBundle(
    {
      gwsBin: fake,
      output_dir: outputRoot,
      max_results: 10,
      lookback_days: 7,
    },
    createRunner(),
  );

  assert.ok("outputDir" in result);
  assert.equal(result.commandCount, 3);
  assert.equal(result.recordCount, 4);
  assert.equal(existsSync(join(result.outputDir, "README.md")), true);
  assert.equal(existsSync(join(result.outputDir, "summary.md")), true);
  assert.equal(existsSync(join(result.outputDir, "analysis", "alerts.json")), true);
  assert.equal(existsSync(join(result.outputDir, "raw", "token_activity.json")), true);
  assert.equal(existsSync(result.zipPath), true);
  assert.match(readFileSync(join(result.outputDir, "commands.json"), "utf8"), /admin-reports/);
});

test("collectGwsOperatorEvidenceBundle previews commands in dry-run mode", async () => {
  const base = createTempBase("grclanker-gws-ops-preview-");
  const fake = createFakeBinary(base);

  const result = await collectGwsOperatorEvidenceBundle(
    {
      gwsBin: fake,
      dry_run: true,
      lookback_days: 7,
    },
    createRunner(),
  );

  assert.equal(result.mode, "dry_run");
  assert.equal(result.commands.length, 3);
});

test("collectGwsOperatorEvidenceBundle rejects symlinked output roots", async () => {
  const base = createTempBase("grclanker-gws-ops-symlink-");
  const fake = createFakeBinary(base);
  const safeRoot = join(base, "safe");
  const realOutside = join(base, "outside");
  writeFileSync(join(base, "placeholder.txt"), "ok");
  const symlinkRoot = join(base, "link-root");

  try {
    writeFileSync(join(base, "seed.txt"), "seed");
    symlinkSync(base, symlinkRoot, "dir");
  } catch {
    return;
  }

  await assert.rejects(
    () => collectGwsOperatorEvidenceBundle(
      {
        gwsBin: fake,
        output_dir: symlinkRoot,
      },
      createRunner(),
    ),
    /symlink/i,
  );

  assert.equal(existsSync(realOutside), false);
  assert.equal(existsSync(safeRoot), false);
});
