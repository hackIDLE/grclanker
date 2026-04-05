/**
 * GRC Clanker extension for Pi.
 *
 * Registers all GRC domain tools: CMVP module validation,
 * KEV vulnerability intelligence, and EPSS scoring.
 *
 * This is the main entry point loaded by Pi's extension system.
 */
import { VERSION } from "@mariozechner/pi-coding-agent";
import { registerCmvpTools } from "./grc-tools/cmvp.js";
import { registerKevsTools } from "./grc-tools/kevs.js";

const WORKFLOWS = ["investigate", "audit", "assess", "validate"];
const AGENT_COUNT = 2;
const DOMAIN_TOOL_COUNT = 8;

function buildHeaderLines(toolCount: number): string[] {
  return [
    "    ____ ____   ____ _        _    _   _ _  _______ ____  ",
    "   / ___|  _ \\ / ___| |      / \\  | \\ | | |/ / ____|  _ \\ ",
    "  | |  _| |_) | |   | |     / _ \\ |  \\| | ' /|  _| | |_) |",
    "  | |_| |  _ <| |___| |___ / ___ \\| |\\  | . \\| |___|  _ < ",
    "   \\____|_| \\_\\\\____|_____/_/   \\_\\_| \\_|_|\\_\\_____|_| \\_\\",
    "",
    `  grclanker v${VERSION} :: local GRC companion on Pi`,
    `  ${toolCount} tools online :: ${DOMAIN_TOOL_COUNT} domain tools :: ${AGENT_COUNT} subagents ready`,
    `  workflows :: ${WORKFLOWS.map((name) => `/${name}`).join("  ")}`,
    "  coverage  :: CMVP  KEV  EPSS  framework mapping  posture triage",
  ];
}

export default function grcTools(pi: any): void {
  registerCmvpTools(pi);
  registerKevsTools(pi);

  pi.on?.("session_start", async (_event: unknown, ctx: any) => {
    if (!ctx.hasUI) return;

    const toolCount = pi.getAllTools?.().length ?? DOMAIN_TOOL_COUNT;
    ctx.ui.setTitle?.("grclanker");
    ctx.ui.setStatus?.("grc-clanker", `${DOMAIN_TOOL_COUNT} domain tools ready`);
    ctx.ui.setWorkingMessage?.("Correlating evidence...");
    ctx.ui.setHiddenThinkingLabel?.("GRC analysis");
    ctx.ui.setHeader?.((_tui: unknown, theme: { bold: (value: string) => string; fg: (tone: string, value: string) => string }) => ({
      render() {
        const lines = buildHeaderLines(toolCount);
        return lines.map((line, index) => {
          if (index <= 4) return theme.bold(theme.fg("accent", line));
          if (index === 6) return theme.fg("text", line);
          if (index === 7) return theme.fg("muted", line);
          if (index >= 8) return theme.fg("dim", line);
          return line;
        });
      },
      invalidate() {},
    }));
  });
}
