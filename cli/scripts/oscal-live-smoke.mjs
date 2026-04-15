import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  checkOscalTrestle,
  createOscalModel,
  initOscalWorkspace,
  validateOscalModel,
} from "../dist/extensions/grc-tools/oscal.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

try {
  const status = await checkOscalTrestle({});
  if (!status.installed) {
    log("Skipping live OSCAL smoke test: compliance-trestle is not installed on this machine.");
    for (const note of status.notes) {
      log(`- ${note}`);
    }
    process.exit(0);
  }

  const workspaceDir = process.env.OSCAL_SMOKE_WORKSPACE?.trim()
    ? resolve(process.cwd(), process.env.OSCAL_SMOKE_WORKSPACE.trim())
    : mkdtempSync(join(tmpdir(), "grclanker-oscal-live-"));

  log(`Using workspace: ${workspaceDir}`);
  await initOscalWorkspace({ workspace_dir: workspaceDir, mode: "local" });

  const created = await createOscalModel({
    workspace_dir: workspaceDir,
    model_type: "catalog",
    name: "smoke-catalog",
    format: "json",
  });
  log(`Created model: ${created.filePath}`);

  const validated = await validateOscalModel({
    workspace_dir: workspaceDir,
    model_type: "catalog",
    name: "smoke-catalog",
  });
  log(`Validation target: ${validated.selector}`);
  log("Live OSCAL smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
