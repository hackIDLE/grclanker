import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { main } from "@mariozechner/pi-coding-agent";

/**
 * Launch the GRC Clanker companion via Pi.
 *
 * Pi discovers project resources from the package root:
 *   .pi/SYSTEM.md / .pi/agents/ → project prompt + agent personas
 *   package.json#pi            → extensions, prompts, skills
 *
 * We set cwd to appRoot so Pi finds the package manifest and .pi config.
 */
export async function launchCompanion(
  appRoot: string,
  workflow?: string,
): Promise<void> {
  // Change to companion dir so Pi discovers package + .pi resources.
  process.chdir(appRoot);

  const args: string[] = [];

  // If a workflow was specified, load its prompt as the initial message.
  if (workflow) {
    const promptPath = join(appRoot, "prompts", `${workflow}.md`);
    if (!existsSync(promptPath)) {
      console.error(`Workflow prompt not found: ${promptPath}`);
      process.exit(1);
    }
    const prompt = readFileSync(promptPath, "utf-8");
    args.push(prompt);
  }

  await main(args);
}
