/**
 * CISA Known Exploited Vulnerabilities (KEV) and EPSS tools.
 *
 * Wraps the same APIs as kevs-tui:
 * - CISA KEV catalog (raw GitHub JSON)
 * - FIRST EPSS scoring API
 * - NVD CVSS API for severity context
 *
 * Enables vulnerability prioritization with exploit intelligence.
 */
import { Type } from "@sinclair/typebox";
import { cachedFetch, throttledFetch, formatTable } from "./shared.js";

// --- URLs ---
const KEV_URL =
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";

// 4-hour cache for KEV (updates ~weekly), 1-hour for EPSS
const KEV_TTL = 4 * 60 * 60 * 1000;
const EPSS_TTL = 60 * 60 * 1000;

// --- Types ---

interface KevVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
  cwes?: string[];
}

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevVulnerability[];
}

interface EpssEntry {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

interface EpssResponse {
  status: string;
  total: number;
  data: EpssEntry[];
}

// --- Helpers ---

function formatKev(v: KevVulnerability, epss?: EpssEntry): string {
  const lines = [
    `${v.cveID} — ${v.vulnerabilityName}`,
    `  Vendor:      ${v.vendorProject}`,
    `  Product:     ${v.product}`,
    `  Added:       ${v.dateAdded}`,
    `  Due:         ${v.dueDate}`,
    `  Ransomware:  ${v.knownRansomwareCampaignUse}`,
    `  Action:      ${v.requiredAction}`,
  ];
  if (v.shortDescription) {
    lines.push(`  Description: ${v.shortDescription.slice(0, 200)}`);
  }
  if (epss) {
    const score = (parseFloat(epss.epss) * 100).toFixed(1);
    const pct = (parseFloat(epss.percentile) * 100).toFixed(1);
    lines.push(`  EPSS:        ${score}% probability (${pct}th percentile)`);
  }
  if (v.notes) lines.push(`  Notes:       ${v.notes.slice(0, 150)}`);
  return lines.join("\n");
}

async function fetchEpss(cveIds: string[]): Promise<Map<string, EpssEntry>> {
  const map = new Map<string, EpssEntry>();
  if (cveIds.length === 0) return map;

  // Batch by 100 per EPSS API limits
  for (let i = 0; i < cveIds.length; i += 100) {
    const batch = cveIds.slice(i, i + 100);
    const url = `${EPSS_URL}?cve=${batch.join(",")}`;
    try {
      const data = await throttledFetch<EpssResponse>(url, 100);
      for (const entry of data.data) {
        map.set(entry.cve, entry);
      }
    } catch {
      // EPSS enrichment is best-effort — don't fail the whole query
    }
  }
  return map;
}

// --- Tool registration ---

export function registerKevsTools(pi: any): void {
  pi.registerTool({
    name: "kevs_search",
    label: "Search Known Exploited Vulnerabilities",
    description:
      "Search the CISA KEV catalog for known exploited vulnerabilities by CVE ID, vendor, product, or keyword. Results include EPSS exploit probability scores.",
    input: Type.Object({
      query: Type.String({
        description:
          "Search term: CVE ID (e.g., 'CVE-2024-1234'), vendor, product name, or keyword",
      }),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    execute: async (args: { query: string; limit?: number }) => {
      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);
        const q = args.query.toLowerCase();

        const matches = catalog.vulnerabilities
          .filter(
            (v) =>
              v.cveID.toLowerCase().includes(q) ||
              v.vendorProject.toLowerCase().includes(q) ||
              v.product.toLowerCase().includes(q) ||
              v.vulnerabilityName.toLowerCase().includes(q) ||
              v.shortDescription.toLowerCase().includes(q),
          )
          .slice(0, args.limit ?? 10);

        if (matches.length === 0) {
          return {
            success: true,
            text: `No KEV entries found matching "${args.query}". This means no known actively exploited vulnerabilities match your search in the CISA catalog (${catalog.count} total entries).`,
          };
        }

        // Enrich with EPSS scores
        const epssMap = await fetchEpss(matches.map((v) => v.cveID));

        const header = `Found ${matches.length} KEV entry/entries matching "${args.query}" (catalog has ${catalog.count} total):\n\n`;
        const body = matches
          .map((v) => formatKev(v, epssMap.get(v.cveID)))
          .join("\n\n");
        return { success: true, text: header + body };
      } catch (err) {
        return {
          success: false,
          error: `KEV search error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "kevs_get_epss",
    label: "Get EPSS Exploit Probability",
    description:
      "Get the EPSS (Exploit Prediction Scoring System) probability score for one or more CVE IDs. Higher score = more likely to be exploited in the next 30 days.",
    input: Type.Object({
      cve_ids: Type.Array(Type.String(), {
        description:
          "List of CVE IDs to score (e.g., ['CVE-2024-1234', 'CVE-2024-5678'])",
      }),
    }),
    execute: async (args: { cve_ids: string[] }) => {
      try {
        const epssMap = await fetchEpss(args.cve_ids);

        if (epssMap.size === 0) {
          return {
            success: true,
            text: `No EPSS scores found for the provided CVE IDs. The CVEs may be too new or not yet scored.`,
          };
        }

        const rows = args.cve_ids.map((cve) => {
          const entry = epssMap.get(cve);
          if (!entry) return [cve, "Not scored", "N/A"];
          const score = (parseFloat(entry.epss) * 100).toFixed(2);
          const pct = (parseFloat(entry.percentile) * 100).toFixed(1);
          return [cve, `${score}%`, `${pct}th`];
        });

        const header = "EPSS Exploit Probability Scores:\n\n";
        const table = formatTable(
          ["CVE ID", "EPSS Score", "Percentile"],
          rows,
        );
        const footer =
          "\n\nEPSS: Probability of exploitation in the next 30 days. >10% is high risk.";
        return { success: true, text: header + table + footer };
      } catch (err) {
        return {
          success: false,
          error: `EPSS API error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "kevs_recent",
    label: "List Recently Added KEV Entries",
    description:
      "List the most recently added entries to the CISA Known Exploited Vulnerabilities catalog, with EPSS scores. Useful for staying current on actively exploited threats.",
    input: Type.Object({
      days: Type.Optional(
        Type.Number({
          description: "Look back this many days (default: 30)",
          default: 30,
        }),
      ),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    execute: async (args: { days?: number; limit?: number }) => {
      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - (args.days ?? 30));
        const cutoffStr = cutoff.toISOString().split("T")[0];

        const recent = catalog.vulnerabilities
          .filter((v) => v.dateAdded >= cutoffStr)
          .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
          .slice(0, args.limit ?? 10);

        if (recent.length === 0) {
          return {
            success: true,
            text: `No new KEV entries in the last ${args.days ?? 30} days.`,
          };
        }

        const epssMap = await fetchEpss(recent.map((v) => v.cveID));

        const header = `${recent.length} KEV entries added in the last ${args.days ?? 30} days:\n\n`;
        const body = recent
          .map((v) => formatKev(v, epssMap.get(v.cveID)))
          .join("\n\n");
        return { success: true, text: header + body };
      } catch (err) {
        return {
          success: false,
          error: `KEV fetch error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });

  pi.registerTool({
    name: "kevs_check_ransomware",
    label: "Check Ransomware-Linked Vulnerabilities",
    description:
      "Find KEV entries with known ransomware campaign use. Critical for prioritizing patches against ransomware threats.",
    input: Type.Object({
      vendor: Type.Optional(
        Type.String({ description: "Filter by vendor/project name" }),
      ),
      limit: Type.Optional(Type.Number({ default: 20 })),
    }),
    execute: async (args: { vendor?: string; limit?: number }) => {
      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);

        let ransomware = catalog.vulnerabilities.filter(
          (v) => v.knownRansomwareCampaignUse === "Known",
        );

        if (args.vendor) {
          const v = args.vendor.toLowerCase();
          ransomware = ransomware.filter(
            (r) =>
              r.vendorProject.toLowerCase().includes(v) ||
              r.product.toLowerCase().includes(v),
          );
        }

        const results = ransomware
          .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
          .slice(0, args.limit ?? 20);

        if (results.length === 0) {
          return {
            success: true,
            text: args.vendor
              ? `No ransomware-linked KEV entries found for vendor "${args.vendor}".`
              : "No ransomware-linked KEV entries found.",
          };
        }

        const header = `${results.length} ransomware-linked vulnerabilities${args.vendor ? ` for "${args.vendor}"` : ""} (of ${ransomware.length} total ransomware-linked KEVs):\n\n`;
        const table = formatTable(
          ["CVE", "Vendor", "Product", "Added", "Due Date"],
          results.map((v) => [
            v.cveID,
            v.vendorProject.slice(0, 20),
            v.product.slice(0, 25),
            v.dateAdded,
            v.dueDate,
          ]),
        );
        return { success: true, text: header + table };
      } catch (err) {
        return {
          success: false,
          error: `KEV fetch error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });
}
