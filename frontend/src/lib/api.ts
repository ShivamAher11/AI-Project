
import fullFixture from "../../../fixtures/analysis-full.json";
import partialFixture from "../../../fixtures/analysis-partial.json";

const viteEnv = import.meta.env ?? {};
export const API_BASE = viteEnv.VITE_API_URL ?? "http://localhost:8000/api/v1";
// Fixture mode remains available for local demos; Docker builds default to the real API.
export const USE_FIXTURES = viteEnv.VITE_USE_FIXTURES !== "false";
export const MAX_FILE_BYTES = 100 * 1024 * 1024;

export type JobStatus = "CREATED" | "VALIDATING" | "STATIC_ANALYSIS" | "RE_ANALYSIS" | "NORMALIZING" | "DETECTION" | "AI_ANALYSIS" | "REPORTING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED";
export type Confidence = "LOW" | "MED" | "HIGH";
export type Severity = "Low" | "Medium" | "High" | "Critical";

export interface StatusSnapshot {
  id: string;
  status: JobStatus;
  stage: string;
  progress: number;
  decomp_status: "OK" | "FAILED" | "TIMEOUT" | "NOT_RUN";
  ai_status: "OK" | "DEGRADED" | "DISABLED" | "NOT_RUN" | "FAILED";
  error?: { code: string; message: string } | null;
}

export interface FindingView {
  id: string;
  groupId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  weight: number;
  observed: string;
  interpretation: string;
  alternative: string;
  attackMappings: Array<{ techniqueId: string; name: string; label: "Likely" | "Possible" }>;
  evidence: Array<{ id: string; sourceType: string; sourceId: string; excerpt: string; offsetOrAddress: string | null; reason: string }>;
}

export interface RiskLine { title: string; weight: number }

export interface OverviewView {
  id: string;
  status: JobStatus;
  stage: string;
  progress: number;
  decompStatus: StatusSnapshot["decomp_status"];
  aiStatus: StatusSnapshot["ai_status"];
  source: "fixture" | "ghidra" | "none";
  file: { name: string; size: number; format: string; arch: string; bitness: number | null; entry: string | null; sha256: string; md5: string; extensionMismatch: boolean };
  counts: { sections: number; imports: number; strings: number; functions: number; findings: number };
  risk: { score: number; rating: Severity; breakdown: RiskLine[] };
  findings: FindingView[];
  versions: { scoring: string; rules: string; schema: string };
}

type NormalizedFixture = typeof fullFixture;

const fixtureFor = (id: string): NormalizedFixture => id.toLowerCase().includes("partial")
      ? partialFixture as NormalizedFixture
  : fullFixture as NormalizedFixture;

function ratingFor(score: number): Severity {
  if (score <= 30) return "Low";
  if (score <= 60) return "Medium";
  if (score <= 80) return "High";
  return "Critical";
}

function fixtureOverview(id: string): OverviewView {
  const data = fixtureFor(id);
  const hitByGroup = new Map(data.rule_hits.map((hit) => [hit.rule_id, hit]));
  const findings: FindingView[] = data.findings.slice(0, 5).map((finding) => {
    const groupId = finding.group_id ?? "STATIC_INDICATOR";
    const hit = hitByGroup.get(groupId);
    const weight = hit?.weight ?? finding.weight;
    const title = groupId === "G_INJECTION" ? "Process injection pattern" :
      groupId === "G_REG_PERSIST" ? "Run key persistence pattern" : groupId.replace(/_/g, " ");
    return {
      id: finding.finding_id,
      groupId,
      title,
      severity: groupId === "G_INJECTION" ? "High" : weight >= 20 ? "High" : weight >= 10 ? "Medium" : "Low",
      confidence: "MED",
      weight,
      observed: groupId === "G_INJECTION"
        ? "A single function references OpenProcess, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread."
        : "Registry imports and a CurrentVersion\\Run key string occur in the static input.",
      interpretation: "Behaviorally suspicious pattern; this heuristic is not a verdict.",
      alternative: "These APIs can also appear in debugging, administration, or installer code.",
      attackMappings: groupId === "G_INJECTION" ? [{ techniqueId: "T1055", name: "Process Injection", label: "Likely" as const }] : groupId === "G_REG_PERSIST" ? [{ techniqueId: "T1547.001", name: "Registry Run", label: "Likely" as const }] : [],
      evidence: (hit?.evidence_refs ?? []).map((ref, index) => ({ id: `E${index + 1}`, sourceType: ref.split(":")[0] ?? "rule", sourceId: ref, excerpt: ref, offsetOrAddress: null, reason: "Matched by the current rule set." })),
    };
  });
  const breakdown = data.rule_hits.filter((hit) => !hit.absorbed).map((hit) => ({
    title: hit.rule_id,
    weight: Math.max(0, hit.weight),
  }));
  const score = Math.min(100, breakdown.reduce((sum, row) => sum + row.weight, 0));
  const partial = data.status === "PARTIAL";
  return {
    id,
    status: data.status as JobStatus,
    stage: data.status,
    progress: data.status === "COMPLETED" ? 100 : partial ? 95 : 0,
    decompStatus: data.decomp_status as OverviewView["decompStatus"],
    aiStatus: partial ? "DISABLED" : "OK",
    source: "fixture",
    file: {
      name: data.file.original_filename,
      size: data.file.size,
      format: data.file.format.toUpperCase(),
      arch: data.file.arch,
      bitness: data.file.bitness,
      entry: data.file.entry_point,
      sha256: data.sha256,
      md5: data.md5,
      extensionMismatch: data.file.extension_mismatch,
    },
    counts: { sections: data.sections.length, imports: data.imports.length, strings: data.strings.length, functions: data.functions.length, findings: findings.length },
    risk: { score, rating: ratingFor(score), breakdown },
    findings,
    versions: { scoring: String(data.versions.scoring), rules: String(data.versions.rules), schema: "1.0" },
  };
}

export function fixtureId(state: "full" | "partial"): string { return `fixture-${state}`; }

export function fileAdvisories(file: File): string[] {
  const notes: string[] = [];
  if (file.size > MAX_FILE_BYTES) notes.push("This file is over the 100 MB limit and will be rejected by the API.");
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (extension && !["exe", "dll"].includes(extension)) notes.push("The extension is unusual for the current PE x64 pipeline; file magic is authoritative.");
  if (file.size === 0) notes.push("This file is empty and the API will reject it.");
  return notes;
}

export async function uploadFile(file: File): Promise<{ id: string; status: JobStatus }> {
  if (USE_FIXTURES) {
    const state = /partial|timeout/i.test(file.name) ? "partial" : "full";
    return { id: fixtureId(state), status: state === "full" ? "COMPLETED" : "PARTIAL" };
  }
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(`${API_BASE}/analyses`, { method: "POST", body });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    const code = error?.error?.code;
    if (response.status === 413 || code === "PAYLOAD_TOO_LARGE") throw new Error("File too large. Maximum upload size is 100 MB.");
    if (response.status === 400 && code === "EMPTY_FILE") throw new Error("The selected file is empty.");
    if (response.status === 400 && code === "UNSUPPORTED_FORMAT") throw new Error("Unsupported format. Upload a PE or ELF binary; scripts, ZIP, and PDF files are not accepted.");
    throw new Error(error?.error?.message ?? "Upload failed. Please try again.");
  }
  return response.json() as Promise<{ id: string; status: JobStatus }>;
}

export async function getOverview(id: string): Promise<OverviewView> {
  if (USE_FIXTURES) {
    await new Promise((resolve) => window.setTimeout(resolve, 180));
    return fixtureOverview(id);
  }
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/overview`);
  if (!response.ok) throw new Error("Could not load this analysis.");
  const data = await response.json();
  return {
    id, status: data.states.status, stage: data.states.status, progress: ["COMPLETED", "PARTIAL"].includes(data.states.status) ? 100 : 0,
    decompStatus: data.states.decomp_status, aiStatus: data.states.ai_status,
    source: data.states.source,
    file: { name: data.file.filename, size: data.file.size, format: data.file.format?.toUpperCase() ?? "UNKNOWN", arch: data.file.arch, bitness: null, entry: data.file.entry_point, sha256: data.hashes.sha256, md5: data.hashes.md5, extensionMismatch: false },
    counts: data.counts,
    risk: { score: data.risk.score ?? 0, rating: (data.risk.rating ? String(data.risk.rating).slice(0, 1).toUpperCase() + String(data.risk.rating).slice(1).toLowerCase() : ratingFor(data.risk.score ?? 0)) as Severity, breakdown: (data.risk.breakdown ?? []).map((line: { title: string; weight: number }) => ({ title: line.title, weight: line.weight })) },
    findings: (data.top_findings ?? []).map(mapFinding),
    versions: data.versions,
  };
}

export async function getFindings(id: string): Promise<FindingView[]> {
  if (USE_FIXTURES) return fixtureOverview(id).findings;
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/findings`);
  if (!response.ok) throw new Error("Could not load findings.");
  const data = await response.json();
  return (data.items ?? []).map(mapFinding);
}

function mapFinding(finding: any): FindingView {
  return { id: finding.id, groupId: finding.group_id ?? finding.type ?? "RULE", title: finding.title,
    severity: (String(finding.severity).slice(0, 1).toUpperCase() + String(finding.severity).slice(1).toLowerCase()) as Severity,
    confidence: ({ low: "LOW", medium: "MED", high: "HIGH" } as Record<string, Confidence>)[String(finding.confidence).toLowerCase()] ?? "LOW",
    weight: finding.score_contribution ?? finding.weight ?? 0, observed: finding.description,
    interpretation: finding.interpretation ?? "Behaviorally suspicious pattern; heuristic, not a verdict.",
    alternative: finding.alternative_explanation ?? finding.alternative ?? "There may be a benign explanation.",
    attackMappings: (finding.attack_mappings ?? []).map((item: any) => ({ techniqueId: item.technique_id, name: item.name, label: item.label })),
    evidence: (finding.evidence ?? []).map((item: any, index: number) => typeof item === "string"
      ? ({ id: `E${index + 1}`, sourceType: item.split(":")[0] ?? "rule", sourceId: item, excerpt: item, offsetOrAddress: null, reason: "Matched by the current rule set." })
      : ({ id: item.id, sourceType: item.source_type, sourceId: item.source_id, excerpt: item.excerpt, offsetOrAddress: item.offset_or_address, reason: item.reason ?? "Evidence supporting this finding." })) };
}

export async function getStatus(id: string): Promise<StatusSnapshot> {
  if (USE_FIXTURES) {
    const overview = fixtureOverview(id);
    return { id, status: overview.status, stage: overview.stage, progress: overview.progress,
      decomp_status: overview.decompStatus, ai_status: overview.aiStatus };
  }
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/status`);
  if (!response.ok) throw new Error("Could not read analysis status.");
  return response.json() as Promise<StatusSnapshot>;
}


export interface FunctionView {
  id: string;
  address: string;
  name: string;
  centrality: number;
  decompilerStatus: string;
  decompiledExcerpt: string | null;
  artifactAvailable: boolean;
}

export interface FunctionDetailView extends FunctionView {
  signature?: string | null;
  size?: number | null;
  assemblyExcerpt?: string | null;
  decompiledFull?: string | null;
  artifactTruncated?: boolean;
}

// Convert the backend/fixture function format
// into a consistent frontend format.
function mapFunction(item: any): FunctionView {
  return {
    id: item.id,
    address: item.address,
    name: item.name ?? "Unnamed function",
    centrality: item.centrality ?? 0,
    decompilerStatus: item.decompiler_status ?? "NOT_RUN",
    decompiledExcerpt: item.decompiled_excerpt ?? null,
    artifactAvailable: item.artifact_available ?? Boolean(item.artifact),
  };
}

// Retrieve all functions for an analysis.
export async function getFunctions(
  analysisId: string
): Promise<FunctionView[]> {
  if (USE_FIXTURES) {
    const data = fixtureFor(analysisId);

    return data.functions.map((item: any) => ({
      ...mapFunction(item),
    }));
  }

  const response = await fetch(
    `${API_BASE}/analyses/${encodeURIComponent(analysisId)}/functions`
  );

  if (!response.ok) {
    throw new Error("Could not load functions.");
  }

  const data = await response.json();

  return (data.items ?? []).map(mapFunction);
}

// Retrieve details of one function.
export async function getFunctionDetail(
  analysisId: string,
  functionId: string,
  loadFull = false
): Promise<FunctionDetailView> {
  if (USE_FIXTURES) {
    const data = fixtureFor(analysisId);

    const item = data.functions.find(
      (fn: any) => fn.id === functionId
    );

    if (!item) {
      throw new Error("Function not found.");
    }

    return {
      ...mapFunction(item),
      signature: item.signature ?? null,
      size: item.size ?? null,
      assemblyExcerpt: item.assembly_excerpt ?? null,
      decompiledFull: item.decompiled_excerpt ?? null,
    };
  }

  const url =
    `${API_BASE}/analyses/${encodeURIComponent(analysisId)}` +
    `/functions/${encodeURIComponent(functionId)}` +
    (loadFull ? "?load_full=true" : "");

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error("Could not load function details.");
  }

  const item = await response.json();

  return {
    ...mapFunction(item),
    decompiledFull: item.decompiled_full ?? null,
    artifactTruncated: item.artifact_truncated ?? false,
  };
}

export interface CallEdgeView {
  caller: string;
  callee: string;
  type: string;
}

export interface StaticGraphView {
  functions: FunctionView[];
  edges: CallEdgeView[];
}

// Retrieve function nodes and call relationships for the graph.
export async function getStaticGraph(
  analysisId: string
): Promise<StaticGraphView> {
  // Fixture mode: use available functions.
  // Fixtures currently do not provide verified call edges.
  if (USE_FIXTURES) {
    const data = fixtureFor(analysisId);

    return {
      functions: data.functions.map((item: any) => mapFunction(item)),
      edges: [],
    };
  }

  const response = await fetch(
    `${API_BASE}/analyses/${encodeURIComponent(analysisId)}/static`
  );

  if (!response.ok) {
    throw new Error("Could not load static graph data.");
  }

  const data = await response.json();

  return {
    functions: (data.functions ?? []).map(mapFunction),
    edges: (data.edges ?? []).map((edge: any) => ({
      caller: edge.caller,
      callee: edge.callee,
      type: edge.type ?? "call",
    })),
  };
}