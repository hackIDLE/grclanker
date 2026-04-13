import { Type } from "@sinclair/typebox";

import {
  type FedrampApplicability,
  type FedrampKsiDomainRecord,
  type FedrampKsiIndicatorRecord,
  type FedrampProcessRecord,
  type FedrampRequirementRecord,
  domainIndicators,
  inspectFedrampOfficialSources,
  loadFedrampCatalog,
  normalizeFedrampApplicability,
  normalizeFedrampSearchSection,
  processRequirements,
  requirementCountsByApplicability,
  resolveFedrampKsi,
  resolveFedrampProcess,
  resolveFedrampRequirement,
  searchFedrampCatalog,
} from "./fedramp-source.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type CheckSourcesArgs = { refresh?: boolean };
type SearchArgs = {
  query: string;
  section?: "definition" | "process" | "requirement" | "ksi" | "any";
  applies_to?: FedrampApplicability | "any";
  limit?: number;
};
type QueryArgs = { query: string };
type ReadinessArgs = {
  query: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
  limit?: number;
};

type ReadinessChecklistItem = {
  id: string;
  appliesTo: FedrampApplicability;
  keyword: string | null;
  labelCode: string;
  labelName: string;
  statement: string;
};

type ReadinessBrief =
  | {
      kind: "process";
      subject: FedrampProcessRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    }
  | {
      kind: "ksi-indicator";
      subject: FedrampKsiIndicatorRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    }
  | {
      kind: "ksi-domain";
      subject: FedrampKsiDomainRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    };

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function clampLimit(value: number | undefined, fallback = 10): number {
  const parsed = value ?? fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), 50);
}

function normalizeCheckArgs(args: unknown): CheckSourcesArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return { refresh: value.refresh === true };
  }
  return {};
}

function normalizeSearchArgs(args: unknown): SearchArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), section: "any", applies_to: "any", limit: 10 };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query:
        asString(value.query) ??
        asString(value.term) ??
        asString(value.id) ??
        asString(value.requirement_id) ??
        asString(value.process_id) ??
        "",
      section: normalizeFedrampSearchSection(asString(value.section)),
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework),
      ),
      limit: clampLimit(asNumber(value.limit)),
    };
  }

  return { query: "", section: "any", applies_to: "any", limit: 10 };
}

function normalizeQueryArgs(args: unknown): QueryArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query:
        asString(value.query) ??
        asString(value.id) ??
        asString(value.process) ??
        asString(value.process_id) ??
        asString(value.requirement_id) ??
        asString(value.ksi) ??
        asString(value.indicator) ??
        asString(value.slug) ??
        "",
    };
  }

  return { query: "" };
}

function normalizeReadinessArgs(args: unknown): ReadinessArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), applies_to: "any", audience: "provider", limit: 8 };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      query:
        asString(value.query) ??
        asString(value.id) ??
        asString(value.process) ??
        asString(value.process_id) ??
        asString(value.ksi) ??
        asString(value.indicator) ??
        "",
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework),
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "provider",
      limit: clampLimit(asNumber(value.limit), 8),
    };
  }

  return { query: "", applies_to: "any", audience: "provider", limit: 8 };
}

function missingQueryResult(toolName: string, example: string) {
  return errorResult(
    `${toolName} requires a non-empty query. Example: ${example}`,
    { tool: toolName },
  );
}

function formatProvenanceNote(provenance: {
  repo: string;
  path: string;
  branch: string;
  blobSha: string | null;
  version: string;
  upstreamLastUpdated: string;
  cacheStatus: string;
}) {
  return `Source: ${provenance.repo}/${provenance.path} @ ${provenance.branch}${provenance.blobSha ? ` (${provenance.blobSha.slice(0, 12)})` : ""} · FRMR ${provenance.version} · upstream ${provenance.upstreamLastUpdated} · ${provenance.cacheStatus}`;
}

function formatSourceCheckText(status: Awaited<ReturnType<typeof inspectFedrampOfficialSources>>): string {
  const primary = status.primary;
  const secondary = status.secondary;
  const lines = [
    "Official FedRAMP GitHub sources",
    "",
    `Primary source:   ${primary.org}/${primary.repo}`,
    `Source path:      ${primary.path}`,
    `Branch:           ${primary.branch}`,
    `Blob SHA:         ${primary.blobSha ?? "Unavailable"}`,
    `FRMR version:     ${primary.version}`,
    `Upstream updated: ${primary.upstreamLastUpdated}`,
    `Repo updated_at:  ${primary.repoUpdatedAt ?? "Unavailable"}`,
    `Cache status:     ${status.cacheStatus}`,
    "",
    `Secondary source: ${secondary.org}/${secondary.repo}`,
    `State:            ${secondary.state}`,
    `Repo updated_at:  ${secondary.repoUpdatedAt ?? "Unavailable"}`,
    `Root entries:     ${secondary.rootEntries.length > 0 ? secondary.rootEntries.join(", ") : "Unavailable"}`,
  ];

  if (status.notes.length > 0) {
    lines.push("", "Notes:");
    for (const note of status.notes) {
      lines.push(`- ${note}`);
    }
  }

  return lines.join("\n");
}

function formatSearchText(
  matches: ReturnType<typeof searchFedrampCatalog>,
  query: string,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const rows = matches.map((match) => [
    match.section,
    match.id,
    match.appliesTo,
    match.title.length > 48 ? `${match.title.slice(0, 45)}...` : match.title,
  ]);

  return [
    `Found ${matches.length} FedRAMP match(es) for "${query}".`,
    "",
    formatTable(["section", "id", "applies_to", "title"], rows),
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  ].join("\n");
}

function formatProcessText(
  process: ReturnType<typeof resolveFedrampProcess>,
  requirements: ReturnType<typeof processRequirements>,
  counts: ReturnType<typeof requirementCountsByApplicability>,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines = [
    `${process.name} [${process.shortName}]`,
    `Process ID:       ${process.id}`,
    `Web slug:         ${process.webName}`,
    `Applies to:       ${process.applicability.join(", ")}`,
    `Requirements:     both ${counts.both}, 20x ${counts["20x"]}, rev5 ${counts.rev5}`,
    `Official page:    ${process.sourceUrl ?? "Unavailable"}`,
    "",
  ];

  if (process.purpose) {
    lines.push(`Purpose: ${process.purpose}`, "");
  }

  if (process.expectedOutcomes.length > 0) {
    lines.push("Expected outcomes:");
    for (const outcome of process.expectedOutcomes.slice(0, 5)) {
      lines.push(`- ${outcome}`);
    }
    lines.push("");
  }

  if (process.labels.length > 0) {
    lines.push("Label groups:");
    for (const label of process.labels) {
      lines.push(`- ${label.code}: ${label.name}`);
    }
    lines.push("");
  }

  if (requirements.length > 0) {
    const sampleRows = requirements.slice(0, 8).map((requirement) => [
      requirement.id,
      requirement.appliesTo,
      requirement.primaryKeyWord ?? "",
      requirement.name ?? requirement.labelName,
    ]);
    lines.push("Requirement samples:", formatTable(["id", "applies_to", "keyword", "name"], sampleRows), "");
  }

  lines.push(
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

function formatRequirementText(
  requirement: FedrampRequirementRecord,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines = [
    `${requirement.id}${requirement.fka ? ` (formerly ${requirement.fka})` : ""}`,
    `Process:          ${requirement.processName} [${requirement.processShortName}]`,
    `Applies to:       ${requirement.appliesTo}`,
    `Label group:      ${requirement.labelCode} - ${requirement.labelName}`,
    `Keyword:          ${requirement.primaryKeyWord ?? "Unspecified"}`,
    `Name:             ${requirement.name ?? "Unspecified"}`,
    "",
    requirement.statement,
  ];

  if (requirement.followingInformation.length > 0) {
    lines.push("", "Checklist items:");
    for (const item of requirement.followingInformation) {
      lines.push(`- ${item}`);
    }
  }

  if (requirement.terms.length > 0) {
    lines.push("", `Terms: ${requirement.terms.join(", ")}`);
  }

  if (requirement.affects.length > 0) {
    lines.push("", `Affects: ${requirement.affects.join(", ")}`);
  }

  if (requirement.updated.length > 0) {
    lines.push("", `Recent update: ${requirement.updated[0]!.date} — ${requirement.updated[0]!.comment}`);
  }

  lines.push(
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

function formatIndicatorSummary(indicator: FedrampKsiIndicatorRecord): string {
  return [
    `${indicator.id}${indicator.fka ? ` (formerly ${indicator.fka})` : ""} — ${indicator.name}`,
    indicator.statement,
    indicator.reference ? `Reference: ${indicator.reference}${indicator.referenceUrl ? ` (${indicator.referenceUrl})` : ""}` : "",
    indicator.controls.length > 0 ? `Rev5 controls: ${indicator.controls.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function filterRequirementsByApplicability(
  requirements: FedrampRequirementRecord[],
  appliesTo: FedrampApplicability | "any",
): FedrampRequirementRecord[] {
  if (appliesTo === "any") return requirements;
  if (appliesTo === "both") {
    return requirements.filter((requirement) => requirement.appliesTo === "both");
  }
  return requirements.filter(
    (requirement) => requirement.appliesTo === appliesTo || requirement.appliesTo === "both",
  );
}

function requirementPriority(
  requirement: FedrampRequirementRecord,
  audience: ReadinessArgs["audience"],
): number {
  let score = 0;
  if (requirement.primaryKeyWord === "MUST") score += 300;
  else if (requirement.primaryKeyWord === "SHOULD") score += 200;
  else if (requirement.primaryKeyWord === "MAY") score += 100;

  if (requirement.appliesTo === "both") score += 40;
  else if (requirement.appliesTo === "20x") score += 30;
  else if (requirement.appliesTo === "rev5") score += 20;

  if (audience === "provider") {
    if (["CSO", "CSX", "CSL", "UTC"].includes(requirement.labelCode)) score += 35;
    if (requirement.labelCode === "TRC") score += 15;
  } else if (audience === "trust-center") {
    if (requirement.labelCode === "TRC") score += 35;
    if (requirement.labelCode === "UTC") score += 20;
  }

  if (/programmatic access|publicly share|persistently|quarterly|notify|log access|inventory/i.test(requirement.statement)) {
    score += 10;
  }

  return score;
}

function toChecklistItems(requirements: FedrampRequirementRecord[]): ReadinessChecklistItem[] {
  return requirements.map((requirement) => ({
    id: requirement.id,
    appliesTo: requirement.appliesTo,
    keyword: requirement.primaryKeyWord,
    labelCode: requirement.labelCode,
    labelName: requirement.labelName,
    statement: requirement.statement,
  }));
}

function dedupeStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)));
}

export function inferFedrampArtifactSuggestions(
  processIds: string[],
  requirements: FedrampRequirementRecord[],
  indicators: FedrampKsiIndicatorRecord[],
): string[] {
  const text = [
    ...requirements.map((requirement) => requirement.statement),
    ...requirements.flatMap((requirement) => requirement.followingInformation),
    ...indicators.map((indicator) => indicator.statement),
  ].join(" \n ");

  const suggestions: string[] = [];
  const lower = text.toLowerCase();

  if (/human-readable|machine-readable|publicly share|public webpage/.test(lower)) {
    suggestions.push("Public trust-center or documentation page plus a machine-readable authorization data feed.");
  }
  if (/programmatic access|api|download/.test(lower)) {
    suggestions.push("Documented API or export interface for authorization data, including access instructions.");
  }
  if (/inventory|history/.test(lower)) {
    suggestions.push("Access inventory or history export showing who can view or retrieve authorization data.");
  }
  if (/log access|log access|access log/.test(lower)) {
    suggestions.push("Access-log summaries for authorization data and trust-center activity.");
  }
  if (/plan and process|procedure|methodology/.test(lower)) {
    suggestions.push("Written process or methodology documents for the relevant FedRAMP workflow.");
  }
  if (/report|quarterly review|ongoing authorization report|oar/.test(lower)) {
    suggestions.push("Recurring report artifacts, such as ongoing authorization or quarterly review outputs.");
  }
  if (/notify|notification|inbox/.test(lower)) {
    suggestions.push("Notification runbook, inbox ownership, and escalation routing records.");
  }
  if (/validate|validation|cadence|persistently/.test(lower)) {
    suggestions.push("Automated validation job evidence and cadence records showing continuous checks.");
  }
  if (/secure configuration|configuration guidance|shared responsibility/.test(lower) || processIds.includes("SCG")) {
    suggestions.push("Secure configuration guide plus shared-responsibility guidance for customers.");
  }
  if (/vulnerability|accepted vulnerability|remediation/.test(lower) || processIds.includes("VDR")) {
    suggestions.push("Vulnerability handling evidence, remediation tracking, and accepted-risk records.");
  }
  if (/cryptographic module|fips|cmvp/.test(lower) || processIds.includes("UCM")) {
    suggestions.push("Cryptographic module inventory and CMVP or FIPS references for relevant protections.");
  }
  if (/incident/.test(lower) || processIds.includes("ICP") || processIds.includes("FSI")) {
    suggestions.push("Incident communications procedure, government contact path, and inbox operations evidence.");
  }
  if (/scope|service list|boundary|customer responsibilities/.test(lower) || processIds.includes("MAS")) {
    suggestions.push("Service inventory, boundary description, and minimum assessment scope record.");
  }
  if (/independent assessment|assessor/.test(lower) || processIds.includes("PVA")) {
    suggestions.push("Independent assessment outputs preserved without modification, plus validation linkage to VDR.");
  }

  return dedupeStrings(suggestions).slice(0, 8);
}

export function inferFedrampWorkstreams(
  processIds: string[],
  requirements: FedrampRequirementRecord[],
  indicators: FedrampKsiIndicatorRecord[],
): string[] {
  const workstreams = new Set<string>();

  const mapped = {
    ADS: [
      "authorization data publishing",
      "trust-center operations",
      "programmatic access",
      "access inventory and access logging",
    ],
    CCM: [
      "ongoing authorization reporting",
      "quarterly review operations",
      "continuous monitoring coordination",
    ],
    FSI: ["security inbox operations", "government contact routing"],
    ICP: ["incident communications", "government notification workflow"],
    MAS: ["assessment scope definition", "service inventory and boundary management"],
    PVA: [
      "persistent validation automation",
      "validation cadence tracking",
      "assessment-result intake",
      "VDR linkage",
    ],
    SCG: ["secure-by-default configuration", "customer hardening guidance"],
    SCN: ["change governance", "significant-change notification workflow"],
    UCM: ["cryptographic module inventory", "approved cryptography usage"],
    VDR: ["vulnerability detection", "remediation tracking", "accepted-risk handling"],
  } as const;

  for (const processId of processIds) {
    for (const item of mapped[processId as keyof typeof mapped] ?? []) {
      workstreams.add(item);
    }
  }

  const lower = [
    ...requirements.map((requirement) => requirement.statement),
    ...indicators.map((indicator) => indicator.statement),
  ]
    .join(" \n ")
    .toLowerCase();

  if (/machine-readable|human-readable/.test(lower)) workstreams.add("public documentation and machine-readable publishing");
  if (/programmatic access|api/.test(lower)) workstreams.add("API enablement for authorization data");
  if (/persistently|validation/.test(lower)) workstreams.add("continuous validation and evidence capture");
  if (/log access|inventory/.test(lower)) workstreams.add("access governance and auditability");
  if (/notify|notification/.test(lower)) workstreams.add("notification and escalation management");
  if (/incident/.test(lower)) workstreams.add("incident response coordination");

  return Array.from(workstreams).slice(0, 8);
}

function resolveLinkedProcess(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  reference: string | null,
): FedrampProcessRecord | undefined {
  if (!reference) return undefined;
  const normalized = reference.trim().toLowerCase();
  return loaded.catalog.processes.find((process) =>
    [
      process.id,
      process.name,
      process.shortName,
      process.webName,
    ].some((candidate) => candidate.trim().toLowerCase() === normalized),
  );
}

export function buildFedrampReadinessBrief(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: ReadinessArgs,
): ReadinessBrief {
  const audience = args.audience ?? "provider";
  const appliesTo = args.applies_to ?? "any";
  const limit = args.limit ?? 8;

  try {
    const process = resolveFedrampProcess(loaded.catalog, args.query);
    const allRequirements = processRequirements(loaded.catalog, process.id);
    const filteredRequirements = filterRequirementsByApplicability(allRequirements, appliesTo);
    const prioritized = filteredRequirements
      .slice()
      .sort((left, right) => {
        const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
        return delta !== 0 ? delta : left.id.localeCompare(right.id);
      })
      .slice(0, limit);
    const linkedIndicators = loaded.catalog.ksiIndicators.filter(
      (indicator) =>
        resolveLinkedProcess(loaded, indicator.reference)?.id === process.id,
    );
    const artifactSuggestions = inferFedrampArtifactSuggestions([process.id], filteredRequirements, linkedIndicators);
    const workstreams = inferFedrampWorkstreams([process.id], filteredRequirements, linkedIndicators);
    const checklist = toChecklistItems(prioritized);
    const lines = [
      `${process.name} readiness brief`,
      `Audience:        ${audience}`,
      `Applies to:      ${appliesTo}`,
      `Official page:   ${process.sourceUrl ?? "Unavailable"}`,
      "",
      "Priority checklist:",
      ...checklist.map((item) => `- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`),
    ];

    if (artifactSuggestions.length > 0) {
      lines.push("", "Likely artifacts to have ready (inferred from official requirements):");
      for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
    }

    if (workstreams.length > 0) {
      lines.push("", "Operational workstreams (inferred from official requirements):");
      for (const workstream of workstreams) lines.push(`- ${workstream}`);
    }

    if (linkedIndicators.length > 0) {
      lines.push("", "Linked KSI indicators:");
      for (const indicator of linkedIndicators.slice(0, 6)) {
        lines.push(`- ${indicator.id} — ${indicator.name}`);
      }
    }

    lines.push(
      "",
      formatProvenanceNote({
        repo: loaded.provenance.repo,
        path: loaded.provenance.path,
        branch: loaded.provenance.branch,
        blobSha: loaded.provenance.blobSha,
        version: loaded.provenance.version,
        upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
        cacheStatus: loaded.cacheStatus,
      }),
    );

    return {
      kind: "process",
      subject: process,
      linkedProcesses: [process],
      linkedIndicators,
      checklist,
      artifactSuggestions,
      workstreams,
      text: lines.join("\n"),
    };
  } catch {
    const match = resolveFedrampKsi(loaded.catalog, args.query);
    if (match.kind === "indicator") {
      const linkedProcess = resolveLinkedProcess(loaded, match.indicator.reference);
      const linkedProcesses = linkedProcess ? [linkedProcess] : [];
      const processRequirementsList = linkedProcess
        ? filterRequirementsByApplicability(processRequirements(loaded.catalog, linkedProcess.id), appliesTo)
        : [];
      const prioritized = processRequirementsList
        .slice()
        .sort((left, right) => {
          const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
          return delta !== 0 ? delta : left.id.localeCompare(right.id);
        })
        .slice(0, limit);
      const checklist = toChecklistItems(prioritized);
      const artifactSuggestions = inferFedrampArtifactSuggestions(
        linkedProcesses.map((process) => process.id),
        processRequirementsList,
        [match.indicator],
      );
      const workstreams = inferFedrampWorkstreams(
        linkedProcesses.map((process) => process.id),
        processRequirementsList,
        [match.indicator],
      );
      const lines = [
        `${match.indicator.name} readiness brief`,
        `Audience:        ${audience}`,
        `Applies to:      20x${appliesTo !== "any" ? ` (requested filter: ${appliesTo})` : ""}`,
        `Linked process:  ${linkedProcess ? `${linkedProcess.name} [${linkedProcess.shortName}]` : "No direct process match found"}`,
        "",
        formatIndicatorSummary(match.indicator),
      ];

      if (checklist.length > 0) {
        lines.push("", "Priority process checklist:");
        for (const item of checklist) {
          lines.push(`- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`);
        }
      }

      if (artifactSuggestions.length > 0) {
        lines.push("", "Likely artifacts to have ready (inferred from official sources):");
        for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
      }

      if (workstreams.length > 0) {
        lines.push("", "Operational workstreams (inferred from official sources):");
        for (const workstream of workstreams) lines.push(`- ${workstream}`);
      }

      lines.push(
        "",
        formatProvenanceNote({
          repo: loaded.provenance.repo,
          path: loaded.provenance.path,
          branch: loaded.provenance.branch,
          blobSha: loaded.provenance.blobSha,
          version: loaded.provenance.version,
          upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
          cacheStatus: loaded.cacheStatus,
        }),
      );

      return {
        kind: "ksi-indicator",
        subject: match.indicator,
        linkedProcesses,
        linkedIndicators: [match.indicator],
        checklist,
        artifactSuggestions,
        workstreams,
        text: lines.join("\n"),
      };
    }

    const indicators = domainIndicators(loaded.catalog, match.domain.id);
    const linkedProcesses = dedupeStrings(
      indicators
        .map((indicator) => resolveLinkedProcess(loaded, indicator.reference)?.id ?? "")
        .filter(Boolean),
    )
      .map((processId) => loaded.catalog.processes.find((process) => process.id === processId))
      .filter((process): process is FedrampProcessRecord => Boolean(process));
    const linkedRequirements = linkedProcesses.flatMap((process) =>
      filterRequirementsByApplicability(processRequirements(loaded.catalog, process.id), appliesTo),
    );
    const prioritized = linkedRequirements
      .slice()
      .sort((left, right) => {
        const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
        return delta !== 0 ? delta : left.id.localeCompare(right.id);
      })
      .slice(0, limit);
    const checklist = toChecklistItems(prioritized);
    const artifactSuggestions = inferFedrampArtifactSuggestions(
      linkedProcesses.map((process) => process.id),
      linkedRequirements,
      indicators,
    );
    const workstreams = inferFedrampWorkstreams(
      linkedProcesses.map((process) => process.id),
      linkedRequirements,
      indicators,
    );
    const lines = [
      `${match.domain.name} readiness brief`,
      `Audience:        ${audience}`,
      `Applies to:      20x${appliesTo !== "any" ? ` (requested filter: ${appliesTo})` : ""}`,
      "",
      match.domain.theme,
      "",
      "Linked processes:",
      ...linkedProcesses.map((process) => `- ${process.name} [${process.shortName}]`),
      "",
      "Indicators:",
      ...indicators.slice(0, 10).map((indicator) => `- ${indicator.id} — ${indicator.name}`),
    ];

    if (checklist.length > 0) {
      lines.push("", "Priority process checklist:");
      for (const item of checklist) {
        lines.push(`- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`);
      }
    }

    if (artifactSuggestions.length > 0) {
      lines.push("", "Likely artifacts to have ready (inferred from official sources):");
      for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
    }

    if (workstreams.length > 0) {
      lines.push("", "Operational workstreams (inferred from official sources):");
      for (const workstream of workstreams) lines.push(`- ${workstream}`);
    }

    lines.push(
      "",
      formatProvenanceNote({
        repo: loaded.provenance.repo,
        path: loaded.provenance.path,
        branch: loaded.provenance.branch,
        blobSha: loaded.provenance.blobSha,
        version: loaded.provenance.version,
        upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
        cacheStatus: loaded.cacheStatus,
      }),
    );

    return {
      kind: "ksi-domain",
      subject: match.domain,
      linkedProcesses,
      linkedIndicators: indicators,
      checklist,
      artifactSuggestions,
      workstreams,
      text: lines.join("\n"),
    };
  }
}

function formatKsiText(
  match: ReturnType<typeof resolveFedrampKsi>,
  indicators: FedrampKsiIndicatorRecord[],
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines: string[] = [];

  if (match.kind === "domain") {
    lines.push(
      `${match.domain.name} [${match.domain.shortName}]`,
      `Domain ID:        ${match.domain.id}`,
      `Web slug:         ${match.domain.webName}`,
      "",
      match.domain.theme,
      "",
      "Indicators:",
    );

    for (const indicator of indicators) {
      lines.push(`- ${indicator.id} — ${indicator.name}`);
    }
  } else {
    lines.push(
      `${match.indicator.name}`,
      `Indicator ID:     ${match.indicator.id}${match.indicator.fka ? ` (formerly ${match.indicator.fka})` : ""}`,
      `Domain:           ${match.indicator.domainName} [${match.indicator.domainShortName}]`,
      "",
      match.indicator.statement,
    );

    if (match.indicator.reference) {
      lines.push(
        "",
        `Reference: ${match.indicator.reference}${match.indicator.referenceUrl ? ` (${match.indicator.referenceUrl})` : ""}`,
      );
    }

    if (match.indicator.controls.length > 0) {
      lines.push("", `Mapped Rev5 controls: ${match.indicator.controls.join(", ")}`);
    }

    if (match.indicator.terms.length > 0) {
      lines.push("", `Terms: ${match.indicator.terms.join(", ")}`);
    }
  }

  lines.push(
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

export function registerFedrampTools(pi: any): void {
  pi.registerTool({
    name: "fedramp_check_sources",
    label: "Check official FedRAMP sources",
    description:
      "Inspect the official FedRAMP GitHub sources grclanker uses, including FRMR version, source path, cache status, and the current state of FedRAMP/rules.",
    parameters: Type.Object({
      refresh: Type.Optional(
        Type.Boolean({
          description: "Force a live refresh from the official GitHub sources.",
          default: false,
        }),
      ),
    }),
    prepareArguments: normalizeCheckArgs,
    async execute(_toolCallId: string, args: CheckSourcesArgs) {
      try {
        const status = await inspectFedrampOfficialSources({ refresh: args.refresh });
        return textResult(formatSourceCheckText(status), {
          tool: "fedramp_check_sources",
          refresh: args.refresh ?? false,
          fetched_at: status.fetchedAt,
          cache_status: status.cacheStatus,
          primary: status.primary,
          secondary: status.secondary,
          notes: status.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP source check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_check_sources", refresh: args.refresh ?? false },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_search_frmr",
    label: "Search official FedRAMP FRMR data",
    description:
      "Search official FedRAMP machine-readable definitions, process docs, requirements, and KSIs grounded in the FedRAMP/docs GitHub repo.",
    parameters: Type.Object({
      query: Type.String({
        description: "Search term such as ADS, Authorization Data Sharing, FRR-ADS-01, KSI-AFR-ADS, or Accepted Vulnerability.",
      }),
      section: Type.Optional(
        Type.Union([
          Type.Literal("definition"),
          Type.Literal("process"),
          Type.Literal("requirement"),
          Type.Literal("ksi"),
          Type.Literal("any"),
        ]),
      ),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10).",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_search_frmr", '{"query":"Authorization Data Sharing"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const matches = searchFedrampCatalog(loaded.catalog, args.query, {
          section: args.section ?? "any",
          appliesTo: args.applies_to ?? "any",
          limit: args.limit,
        });

        if (matches.length === 0) {
          return textResult(`No official FedRAMP FRMR matches found for "${args.query}".`, {
            tool: "fedramp_search_frmr",
            query: args.query,
            section: args.section ?? "any",
            applies_to: args.applies_to ?? "any",
            count: 0,
            provenance: loaded.provenance,
          });
        }

        return textResult(formatSearchText(matches, args.query, loaded.provenance, loaded.cacheStatus), {
          tool: "fedramp_search_frmr",
          query: args.query,
          section: args.section ?? "any",
          applies_to: args.applies_to ?? "any",
          count: matches.length,
          matches,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP FRMR search failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_search_frmr", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_process",
    label: "Get official FedRAMP process",
    description:
      "Resolve an official FedRAMP process such as ADS, PVA, SCG, VDR, or CCM from the FRMR documentation.",
    parameters: Type.Object({
      query: Type.String({
        description: "Process query such as ADS, authorization-data-sharing, or Persistent Validation and Assessment.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_process", '{"query":"ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const process = resolveFedrampProcess(loaded.catalog, args.query);
        const requirements = processRequirements(loaded.catalog, process.id);
        const counts = requirementCountsByApplicability(loaded.catalog, process.id);
        return textResult(
          formatProcessText(process, requirements, counts, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_process",
            query: args.query,
            process,
            requirement_count: requirements.length,
            requirements: requirements.map((requirement) => ({
              id: requirement.id,
              applies_to: requirement.appliesTo,
              label_code: requirement.labelCode,
              keyword: requirement.primaryKeyWord,
              name: requirement.name,
            })),
            counts,
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP process lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_process", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_requirement",
    label: "Get official FedRAMP requirement",
    description:
      "Resolve a single official FedRAMP FRMR requirement or recommendation by current ID, former ID, or unique name.",
    parameters: Type.Object({
      query: Type.String({
        description: "Requirement query such as ADS-CSO-PUB or FRR-ADS-01.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_requirement", '{"query":"ADS-CSO-PUB"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const requirement = resolveFedrampRequirement(loaded.catalog, args.query);
        return textResult(
          formatRequirementText(requirement, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_requirement",
            query: args.query,
            requirement,
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP requirement lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_requirement", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_ksi",
    label: "Get official FedRAMP KSI",
    description:
      "Resolve a FedRAMP key security indicator domain or a specific indicator by current ID, former ID, or unique name.",
    parameters: Type.Object({
      query: Type.String({
        description: "KSI query such as AFR, KSI-AFR-ADS, KSI-AFR-03, or Authorization Data Sharing.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_ksi", '{"query":"KSI-AFR-ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const match = resolveFedrampKsi(loaded.catalog, args.query);
        const indicators =
          match.kind === "domain"
            ? domainIndicators(loaded.catalog, match.domain.id)
            : domainIndicators(loaded.catalog, match.indicator.domainId);
        return textResult(
          formatKsiText(match, indicators, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_ksi",
            query: args.query,
            kind: match.kind,
            result: match.kind === "domain" ? match.domain : match.indicator,
            indicators: indicators.map((indicator) => ({
              id: indicator.id,
              fka: indicator.fka,
              name: indicator.name,
              reference: indicator.reference,
              controls: indicator.controls,
            })),
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP KSI lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_ksi", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_assess_readiness",
    label: "Assess FedRAMP readiness",
    description:
      "Turn an official FedRAMP process or KSI into a practical readiness brief with prioritized checklist items, likely artifacts, and inferred workstreams for providers or trust centers.",
    parameters: Type.Object({
      query: Type.String({
        description: "Process or KSI query such as ADS, PVA, KSI-AFR, or KSI-AFR-ADS.",
      }),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Max checklist items to prioritize (default: 8).",
          default: 8,
        }),
      ),
    }),
    prepareArguments: normalizeReadinessArgs,
    async execute(_toolCallId: string, args: ReadinessArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_assess_readiness", '{"query":"ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const brief = buildFedrampReadinessBrief(loaded, args);
        return textResult(brief.text, {
          tool: "fedramp_assess_readiness",
          query: args.query,
          audience: args.audience ?? "provider",
          applies_to: args.applies_to ?? "any",
          kind: brief.kind,
          subject:
            brief.kind === "process"
              ? {
                  id: brief.subject.id,
                  name: brief.subject.name,
                  short_name: brief.subject.shortName,
                  web_name: brief.subject.webName,
                }
              : brief.kind === "ksi-domain"
                ? {
                    id: brief.subject.id,
                    name: brief.subject.name,
                    short_name: brief.subject.shortName,
                    web_name: brief.subject.webName,
                  }
                : {
                    id: brief.subject.id,
                    name: brief.subject.name,
                    domain_id: brief.subject.domainId,
                  },
          checklist: brief.checklist,
          linked_processes: brief.linkedProcesses.map((process) => ({
            id: process.id,
            name: process.name,
            short_name: process.shortName,
          })),
          linked_indicators: brief.linkedIndicators.map((indicator) => ({
            id: indicator.id,
            name: indicator.name,
            reference: indicator.reference,
            controls: indicator.controls,
          })),
          artifact_suggestions: brief.artifactSuggestions,
          workstreams: brief.workstreams,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP readiness assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_assess_readiness", query: args.query },
        );
      }
    },
  });
}
