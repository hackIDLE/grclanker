/**
 * NIST Cryptographic Module Validation Program (CMVP) tools.
 *
 * Wraps the static JSON API at ethanolivertroy.github.io/NIST-CMVP-API
 * (same data source as cmvp-tui). Enables searching validated, historical,
 * and in-process cryptographic modules for FIPS 140-2/140-3 compliance.
 */
import { Type } from "@sinclair/typebox";
import { cachedFetch, formatTable } from "./shared.js";

const BASE = "https://ethanolivertroy.github.io/NIST-CMVP-API/api";

// 24-hour cache — CMVP data updates weekly via GitHub Actions
const TTL = 24 * 60 * 60 * 1000;

// --- Types mirroring the NIST-CMVP-API JSON schema ---

interface CmvpMetadata {
  generated_at: string;
  total_modules: number;
  total_historical_modules: number;
  total_modules_in_process: number;
  source: string;
  version: string;
}

interface CmvpModule {
  "Certificate Number": string;
  "Certificate Number_url"?: string;
  "Vendor Name": string;
  "Module Name": string;
  "Module Type": string;
  "Validation Date": string;
  standard: string;
  status: string;
  overall_level: number;
  sunset_date?: string;
  caveat?: string;
  description?: string;
  algorithms?: string[];
  security_policy_url?: string;
  certificate_detail_url?: string;
}

interface ModulesResponse {
  metadata: CmvpMetadata;
  modules: CmvpModule[];
}

interface ModuleInProcess {
  "Module Name": string;
  "Vendor Name": string;
  Standard: string;
  Status: string;
}

interface InProcessResponse {
  metadata: CmvpMetadata;
  modules_in_process: ModuleInProcess[];
}

// --- Helpers ---

function matchesQuery(module: CmvpModule, query: string): boolean {
  const q = query.toLowerCase();
  return (
    module["Module Name"].toLowerCase().includes(q) ||
    module["Vendor Name"].toLowerCase().includes(q) ||
    module["Certificate Number"].toLowerCase().includes(q) ||
    (module.description ?? "").toLowerCase().includes(q)
  );
}

function formatModule(m: CmvpModule): string {
  const lines = [
    `Certificate #${m["Certificate Number"]} — ${m["Module Name"]}`,
    `  Vendor:     ${m["Vendor Name"]}`,
    `  Type:       ${m["Module Type"]}`,
    `  Standard:   ${m.standard}`,
    `  Level:      ${m.overall_level}`,
    `  Status:     ${m.status}`,
    `  Validated:  ${m["Validation Date"]}`,
  ];
  if (m.sunset_date) lines.push(`  Sunset:     ${m.sunset_date}`);
  if (m.algorithms?.length)
    lines.push(`  Algorithms: ${m.algorithms.slice(0, 5).join(", ")}${m.algorithms.length > 5 ? ` (+${m.algorithms.length - 5} more)` : ""}`);
  if (m.caveat) lines.push(`  Caveat:     ${m.caveat.slice(0, 120)}`);
  if (m.certificate_detail_url)
    lines.push(`  URL:        ${m.certificate_detail_url}`);
  return lines.join("\n");
}

// --- Tool registration ---

export function registerCmvpTools(pi: any): void {
  pi.registerTool({
    name: "cmvp_search_modules",
    label: "Search FIPS Validated Modules",
    description:
      "Search NIST CMVP for currently validated cryptographic modules by vendor, module name, or certificate number. Returns FIPS 140-2/140-3 certification details.",
    input: Type.Object({
      query: Type.String({
        description:
          "Search term: vendor name, module name, or certificate number (e.g., 'OpenSSL', 'AWS', '4282')",
      }),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10)",
          default: 10,
        }),
      ),
    }),
    execute: async (args: { query: string; limit?: number }) => {
      try {
        const data = await cachedFetch<ModulesResponse>(
          `${BASE}/modules.json`,
          TTL,
        );
        const matches = data.modules
          .filter((m) => matchesQuery(m, args.query))
          .slice(0, args.limit ?? 10);

        if (matches.length === 0) {
          return {
            success: true,
            text: `No active CMVP modules found matching "${args.query}". Try searching historical modules with cmvp_search_historical, or check modules in process with cmvp_search_in_process.`,
          };
        }

        const header = `Found ${matches.length} active FIPS module(s) matching "${args.query}" (of ${data.metadata.total_modules} total):\n`;
        const body = matches.map(formatModule).join("\n\n");
        return { success: true, text: header + body };
      } catch (err) {
        return {
          success: false,
          error: `CMVP API error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "cmvp_search_historical",
    label: "Search Historical/Expired FIPS Modules",
    description:
      "Search NIST CMVP historical list for expired or revoked cryptographic module certifications.",
    input: Type.Object({
      query: Type.String({
        description: "Search term: vendor name, module name, or certificate number",
      }),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    execute: async (args: { query: string; limit?: number }) => {
      try {
        const data = await cachedFetch<ModulesResponse>(
          `${BASE}/historical-modules.json`,
          TTL,
        );
        const matches = data.modules
          .filter((m) => matchesQuery(m, args.query))
          .slice(0, args.limit ?? 10);

        if (matches.length === 0) {
          return {
            success: true,
            text: `No historical CMVP modules found matching "${args.query}".`,
          };
        }

        const header = `Found ${matches.length} historical module(s) matching "${args.query}" (of ${data.metadata.total_historical_modules} total):\n`;
        const body = matches.map(formatModule).join("\n\n");
        return { success: true, text: header + body };
      } catch (err) {
        return {
          success: false,
          error: `CMVP API error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "cmvp_search_in_process",
    label: "Search FIPS Modules In Process",
    description:
      "Search for cryptographic modules currently in the NIST CMVP validation pipeline (not yet certified).",
    input: Type.Object({
      query: Type.String({
        description: "Search term: vendor name or module name",
      }),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    execute: async (args: { query: string; limit?: number }) => {
      try {
        const data = await cachedFetch<InProcessResponse>(
          `${BASE}/modules-in-process.json`,
          TTL,
        );
        const q = args.query.toLowerCase();
        const matches = data.modules_in_process
          .filter(
            (m) =>
              m["Module Name"].toLowerCase().includes(q) ||
              m["Vendor Name"].toLowerCase().includes(q),
          )
          .slice(0, args.limit ?? 10);

        if (matches.length === 0) {
          return {
            success: true,
            text: `No in-process CMVP modules found matching "${args.query}".`,
          };
        }

        const header = `Found ${matches.length} module(s) in CMVP validation pipeline matching "${args.query}" (of ${data.metadata.total_modules_in_process} total):\n\n`;
        const table = formatTable(
          ["Module", "Vendor", "Standard", "Status"],
          matches.map((m) => [
            m["Module Name"].slice(0, 50),
            m["Vendor Name"].slice(0, 30),
            m.Standard,
            m.Status,
          ]),
        );
        return { success: true, text: header + table };
      } catch (err) {
        return {
          success: false,
          error: `CMVP API error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "cmvp_get_module",
    label: "Get FIPS Module by Certificate Number",
    description:
      "Retrieve detailed information about a specific FIPS validated module by its certificate number.",
    input: Type.Object({
      cert_number: Type.String({
        description: "CMVP certificate number (e.g., '4282')",
      }),
    }),
    execute: async (args: { cert_number: string }) => {
      try {
        // Search active first, then historical
        const active = await cachedFetch<ModulesResponse>(
          `${BASE}/modules.json`,
          TTL,
        );
        let module = active.modules.find(
          (m) => m["Certificate Number"] === args.cert_number,
        );

        if (!module) {
          const historical = await cachedFetch<ModulesResponse>(
            `${BASE}/historical-modules.json`,
            TTL,
          );
          module = historical.modules.find(
            (m) => m["Certificate Number"] === args.cert_number,
          );
        }

        if (!module) {
          return {
            success: true,
            text: `No CMVP module found with certificate #${args.cert_number}.`,
          };
        }

        return { success: true, text: formatModule(module) };
      } catch (err) {
        return {
          success: false,
          error: `CMVP API error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });
}
