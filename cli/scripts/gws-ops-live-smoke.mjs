import {
  GwsCliCommandError,
  checkGwsCliAccess,
  resolveGwsCliExecutable,
  traceGwsAdminActivity,
} from "../dist/extensions/grc-tools/gws-ops.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

try {
  const executable = resolveGwsCliExecutable();
  if (!executable.installed) {
    log(
      "Skipping Google Workspace CLI operator smoke test: `gws` is not installed. Install googleworkspace/cli and authenticate it first.",
    );
    process.exit(0);
  }

  const access = await checkGwsCliAccess();
  log(`gws executable: ${access.executable}`);
  log(`gws version: ${access.version}`);
  log(`Bridge status: ${access.status}`);

  const activity = await traceGwsAdminActivity({ lookback_days: 7, max_results: 5 });
  log(`Admin activity records: ${activity.count}`);
  log("Google Workspace CLI operator smoke test passed.");
} catch (error) {
  if (error instanceof GwsCliCommandError && (error.kind === "missing" || error.kind === "auth")) {
    log(`Skipping Google Workspace CLI operator smoke test: ${error.message}`);
    process.exit(0);
  }

  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
