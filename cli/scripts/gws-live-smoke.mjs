import {
  GoogleWorkspaceAuditorClient,
  assessGwsIdentity,
  collectGwsIdentityData,
  resolveGwsConfiguration,
  runGwsAccessCheck,
} from "../dist/extensions/grc-tools/gws.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const hasServiceAccount = Boolean(
    (process.env.GWS_CREDENTIALS_FILE?.trim()
      || process.env.GWS_SERVICE_ACCOUNT_FILE?.trim()
      || process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim()
      || process.env.GWS_CREDENTIALS_JSON?.trim()
      || process.env.GWS_SERVICE_ACCOUNT_JSON?.trim())
    && process.env.GWS_ADMIN_EMAIL?.trim(),
  );
  const hasAccessToken = Boolean(process.env.GWS_ACCESS_TOKEN?.trim());
  return hasServiceAccount || hasAccessToken;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Google Workspace smoke test: set GWS_CREDENTIALS_FILE + GWS_ADMIN_EMAIL (or GWS_CREDENTIALS_JSON + GWS_ADMIN_EMAIL) or GWS_ACCESS_TOKEN to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = await resolveGwsConfiguration();
  const client = new GoogleWorkspaceAuditorClient(config);
  const access = await runGwsAccessCheck(client, config);

  log(`Google Workspace org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Google Workspace smoke test stopped because the supplied principal could not read enough core Directory / Reports surfaces.",
    );
  }

  const identity = await collectGwsIdentityData(client);
  const assessment = assessGwsIdentity(identity, config);
  log(`Identity findings: ${assessment.findings.length}`);
  log(
    `Summary: Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  log("Live Google Workspace smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
