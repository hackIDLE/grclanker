import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  clearFedrampCachesForTests,
  inspectFedrampOfficialSources,
  loadFedrampCatalog,
  normalizeFedrampApplicability,
  normalizeFedrampFrmr,
  resolveFedrampKsi,
  resolveFedrampProcess,
  resolveFedrampRequirement,
  searchFedrampCatalog,
} from "../dist/extensions/grc-tools/fedramp-source.js";
import { buildFedrampDocsSnapshot } from "../dist/extensions/grc-tools/fedramp-docs.js";

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const frmrFixture = {
  info: {
    title: "FedRAMP Machine-Readable Documentation",
    description: "Fixture FRMR payload",
    version: "0.9.43-beta",
    last_updated: "2026-04-08",
  },
  FRD: {
    data: {
      both: {
        "FRD-ACV": {
          fka: "FRD-ALL-31",
          term: "Accepted Vulnerability",
          alts: ["accepted vulnerability", "accepted vulnerabilities"],
          definition: "A vulnerability the provider does not intend to remediate within the recommended period.",
          updated: [{ date: "2026-02-04", comment: "Renamed during standardization." }],
        },
      },
    },
  },
  FRR: {
    ADS: {
      info: {
        name: "Authorization Data Sharing",
        short_name: "ADS",
        web_name: "authorization-data-sharing",
        effective: {
          rev5: {
            is: "optional",
            current_status: "Open Beta",
          },
          "20x": {
            is: "required",
            current_status: "Phase 2 Pilot",
          },
        },
      },
      front_matter: {
        purpose: "Providers share authorization data in human-readable and machine-readable form.",
        expected_outcomes: [
          "Agencies can programmatically access authorization data.",
          "Providers can manage authorization data in a trust center.",
        ],
        authority: [
          {
            reference: "OMB M-24-15",
            reference_url: "https://www.fedramp.gov/docs/authority/m-24-15",
            description: "Modernizing FedRAMP memo.",
          },
        ],
      },
      labels: {
        CSO: {
          name: "General Provider Responsibilities",
          description: "Applies to all providers.",
        },
        TRC: {
          name: "FedRAMP-Compatible Trust Centers",
          description: "Applies to trust centers.",
        },
      },
      data: {
        both: {
          CSO: {
            "ADS-CSO-PUB": {
              fka: "FRR-ADS-01",
              name: "Public Information",
              statement:
                "Providers MUST publicly share up-to-date information about the cloud service offering in both human-readable and machine-readable formats.",
              primary_key_word: "MUST",
              affects: ["Providers"],
              terms: ["Cloud Service Offering", "Machine-Readable"],
              following_information: ["Direct link to the FedRAMP Marketplace", "Service Model"],
              updated: [{ date: "2026-02-04", comment: "Added machine-readable emphasis." }],
            },
          },
        },
        "20x": {
          TRC: {
            "ADS-TRC-API": {
              name: "Programmatic Access",
              statement:
                "Trust centers MUST provide documented programmatic access to all authorization data.",
              primary_key_word: "MUST",
              affects: ["Trust Centers"],
              terms: ["Authorization data", "Machine-Readable"],
              updated: [{ date: "2026-02-04", comment: "No material changes." }],
            },
          },
        },
        rev5: {
          CSO: {
            "ADS-CSO-BETA": {
              name: "Rev5 Beta Signup",
              statement: "Rev5 providers SHOULD notify FedRAMP before joining the ADS beta.",
              primary_key_word: "SHOULD",
              affects: ["Providers"],
              terms: ["Authorization data"],
              timeframe_type: "days",
              timeframe_num: 7,
            },
          },
        },
      },
    },
  },
  KSI: {
    AFR: {
      id: "KSI-AFR",
      name: "Authorization by FedRAMP",
      short_name: "AFR",
      web_name: "authorization-by-fedramp",
      theme:
        "A secure cloud service provider seeking FedRAMP authorization addresses all FedRAMP 20x requirements and recommendations.",
      indicators: {
        "KSI-AFR-ADS": {
          fka: "KSI-AFR-03",
          name: "Authorization Data Sharing",
          statement:
            "Determine how authorization data will be shared with all necessary parties in alignment with the ADS process.",
          reference: "Authorization Data Sharing",
          reference_url: "https://fedramp.gov/docs/20x/authorization-data-sharing",
          controls: ["ac-3", "au-2", "ra-5"],
          terms: ["Authorization data", "All Necessary Parties"],
          updated: [{ date: "2026-02-04", comment: "Renamed during standardization." }],
        },
      },
    },
  },
};

test("normalizeFedrampFrmr flattens definitions, requirements, and KSI records", () => {
  const catalog = normalizeFedrampFrmr(frmrFixture);

  assert.equal(catalog.info.version, "0.9.43-beta");
  assert.equal(catalog.definitions.length, 1);
  assert.equal(catalog.processes.length, 1);
  assert.equal(catalog.requirements.length, 3);
  assert.equal(catalog.ksiDomains.length, 1);
  assert.equal(catalog.ksiIndicators.length, 1);
  assert.equal(catalog.requirements.find((item) => item.id === "ADS-CSO-PUB")?.appliesTo, "both");
  assert.equal(catalog.ksiIndicators[0]?.fka, "KSI-AFR-03");
});

test("search and resolvers support current IDs, former IDs, and unique names", () => {
  const catalog = normalizeFedrampFrmr(frmrFixture);

  const fkaMatch = searchFedrampCatalog(catalog, "FRR-ADS-01", {
    section: "requirement",
    appliesTo: normalizeFedrampApplicability("any"),
    limit: 10,
  });
  assert.equal(fkaMatch[0]?.id, "ADS-CSO-PUB");

  assert.equal(resolveFedrampProcess(catalog, "authorization-data-sharing").id, "ADS");
  assert.equal(resolveFedrampRequirement(catalog, "FRR-ADS-01").id, "ADS-CSO-PUB");

  const ksiMatch = resolveFedrampKsi(catalog, "KSI-AFR-03");
  assert.equal(ksiMatch.kind, "indicator");
  if (ksiMatch.kind === "indicator") {
    assert.equal(ksiMatch.indicator.id, "KSI-AFR-ADS");
  }
});

test("loadFedrampCatalog writes cache and falls back to stale disk data if refresh fails", async () => {
  const originalFetch = globalThis.fetch;
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-home-"));
  const calls = [];

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);

    if (url === "https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json") {
      return jsonResponse(frmrFixture);
    }

    if (url === "https://api.github.com/repos/FedRAMP/docs") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/docs",
        updated_at: "2026-04-13T17:52:17Z",
        default_branch: "main",
      });
    }

    if (
      url ===
      "https://api.github.com/repos/FedRAMP/docs/contents/FRMR.documentation.json?ref=main"
    ) {
      return jsonResponse({
        sha: "abcdef1234567890abcdef1234567890abcdef12",
        html_url:
          "https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json",
      });
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearFedrampCachesForTests();

  try {
    const live = await loadFedrampCatalog({ refresh: true, homeDir });
    assert.equal(live.cacheStatus, "live");
    assert.equal(live.provenance.blobSha, "abcdef1234567890abcdef1234567890abcdef12");
    assert.ok(calls.some((url) => url.includes("FRMR.documentation.json")));

    clearFedrampCachesForTests();
    globalThis.fetch = async () => {
      throw new Error("network unavailable");
    };

    const stale = await loadFedrampCatalog({ refresh: true, homeDir });
    assert.equal(stale.cacheStatus, "stale");
    assert.match(stale.notes[0] ?? "", /stale FedRAMP cache/i);
    assert.equal(stale.catalog.info.version, "0.9.43-beta");
  } finally {
    globalThis.fetch = originalFetch;
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("inspectFedrampOfficialSources reports the official rules repo as placeholder when it is not populated", async () => {
  const originalFetch = globalThis.fetch;
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-sources-"));

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url === "https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json") {
      return jsonResponse(frmrFixture);
    }

    if (url === "https://api.github.com/repos/FedRAMP/docs") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/docs",
        updated_at: "2026-04-13T17:52:17Z",
        default_branch: "main",
      });
    }

    if (
      url ===
      "https://api.github.com/repos/FedRAMP/docs/contents/FRMR.documentation.json?ref=main"
    ) {
      return jsonResponse({
        sha: "abcdef1234567890abcdef1234567890abcdef12",
        html_url:
          "https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json",
      });
    }

    if (url === "https://api.github.com/repos/FedRAMP/rules") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/rules",
        updated_at: "2026-04-12T15:15:27Z",
        default_branch: "main",
      });
    }

    if (url === "https://api.github.com/repos/FedRAMP/rules/contents/?ref=main") {
      return jsonResponse([
        { name: ".gitignore", type: "file" },
        { name: "README.md", type: "file" },
      ]);
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearFedrampCachesForTests();

  try {
    const status = await inspectFedrampOfficialSources({ refresh: true, homeDir });
    assert.equal(status.primary.version, "0.9.43-beta");
    assert.equal(status.secondary.state, "placeholder");
    assert.ok(status.notes.some((note) => note.includes("FedRAMP/rules")));
  } finally {
    globalThis.fetch = originalFetch;
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("buildFedrampDocsSnapshot is deterministic and includes provenance banners", () => {
  const catalog = normalizeFedrampFrmr(frmrFixture);
  const primary = {
    org: "FedRAMP",
    repo: "docs",
    branch: "main",
    repoUrl: "https://github.com/FedRAMP/docs",
    path: "FRMR.documentation.json",
    rawUrl: "https://raw.githubusercontent.com/FedRAMP/docs/main/FRMR.documentation.json",
    blobSha: "abcdef1234567890abcdef1234567890abcdef12",
    fileHtmlUrl: "https://github.com/FedRAMP/docs/blob/main/FRMR.documentation.json",
    repoUpdatedAt: "2026-04-13T17:52:17Z",
    version: "0.9.43-beta",
    upstreamLastUpdated: "2026-04-08",
  };
  const secondary = {
    org: "FedRAMP",
    repo: "rules",
    branch: "main",
    repoUrl: "https://github.com/FedRAMP/rules",
    repoUpdatedAt: "2026-04-12T15:15:27Z",
    state: "placeholder",
    rootEntries: [".gitignore", "README.md"],
    notes: ["The official FedRAMP/rules repo exists, but it is still placeholder-level."],
  };

  const first = buildFedrampDocsSnapshot(catalog, { primary, secondary });
  const second = buildFedrampDocsSnapshot(catalog, { primary, secondary });

  assert.deepEqual(first, second);
  assert.ok(first.some((file) => file.path === "fedramp/index.md"));
  assert.ok(first.some((file) => file.path === "fedramp/processes/authorization-data-sharing.md"));
  assert.ok(first.some((file) => file.path === "fedramp/ksi/authorization-by-fedramp.md"));

  const overview = first.find((file) => file.path === "fedramp/index.md")?.content ?? "";
  assert.match(overview, /official FedRAMP GitHub organization/i);
  assert.match(overview, /0.9.43-beta/);
  assert.match(overview, /FRMR.documentation\.json/);
});
