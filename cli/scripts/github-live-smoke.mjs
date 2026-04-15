import {
  GitHubAuditorClient,
  assessGitHubOrgAccess,
  collectGitHubOrgAccessData,
  resolveGitHubConfiguration,
  runGitHubAccessCheck,
} from "../dist/extensions/grc-tools/github.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const hasPat = Boolean(process.env.GITHUB_TOKEN?.trim() || process.env.GH_TOKEN?.trim());
  const hasApp = Boolean(
    process.env.GITHUB_APP_ID?.trim()
    && (process.env.GITHUB_APP_PRIVATE_KEY?.trim() || process.env.GITHUB_APP_PRIVATE_KEY_PATH?.trim())
    && process.env.GITHUB_APP_INSTALLATION_ID?.trim(),
  );
  const hasOrg = Boolean(process.env.GITHUB_ORG?.trim() || process.env.GH_ORG?.trim());
  return hasOrg && (hasPat || hasApp);
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live GitHub smoke test: set GITHUB_ORG and either GITHUB_TOKEN / GH_TOKEN or the GitHub App env vars to run against a real organization.",
    );
    process.exit(0);
  }

  const config = await resolveGitHubConfiguration();
  const client = new GitHubAuditorClient(config);
  const access = await runGitHubAccessCheck(client, config);

  log(`GitHub org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live GitHub smoke test stopped because the supplied principal could not read enough core org-security surfaces.",
    );
  }

  const orgAccess = await collectGitHubOrgAccessData(client, config);
  const assessment = assessGitHubOrgAccess(orgAccess, config);
  log(`Org-access findings: ${assessment.findings.length}`);
  log(
    `Summary: Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  log("Live GitHub smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
