import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  getRegisteredToolSummaries,
  groupRegisteredTools,
} from "../dist/pi/tool-catalog.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "../..");
const defaultOutputPath = resolve(repoRoot, "src/content/docs/docs/tools/catalog.md");

function escapePipe(value) {
  return String(value).replaceAll("|", "\\|");
}

export function buildToolCatalogMarkdown(tools = getRegisteredToolSummaries()) {
  const domainCount = tools.filter((tool) => tool.kind === "domain").length;
  const computeCount = tools.filter((tool) => tool.kind === "compute").length;
  const lines = [
    "---",
    "title: Tool Catalog",
    "description: Bundled grclanker GRC and compute tools grouped by domain.",
    "---",
    "",
    "`grclanker tools` lists the same bundled extension registration surface the agent uses at runtime. Use `grclanker tools <name>` for detailed parameter help, or `grclanker tools --json` for automation.",
    "",
    "Current bundled surface:",
    "",
    `- ${domainCount} domain tools`,
    `- ${computeCount} compute backend tools`,
    "",
  ];

  for (const group of groupRegisteredTools(tools)) {
    const sortedTools = [...group.tools].sort((left, right) => left.name.localeCompare(right.name));
    lines.push(`## ${group.group}`, "", "| Tool | Purpose |", "|---|---|");
    for (const tool of sortedTools) {
      lines.push(`| \`${tool.name}\` | ${escapePipe(tool.label)} |`);
    }
    lines.push("");
  }

  return lines.join("\n").trimEnd() + "\n";
}

export async function writeToolCatalogDocs(outputPath = defaultOutputPath) {
  const markdown = buildToolCatalogMarkdown();
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, markdown, "utf8");
  return outputPath;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outputPath = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : defaultOutputPath;
  await writeToolCatalogDocs(outputPath);
  console.log(`Wrote tool catalog docs to ${outputPath}`);
}
