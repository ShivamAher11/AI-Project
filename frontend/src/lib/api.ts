import fullFixture from "../../../fixtures/analysis-full.json";
import partialFixture from "../../../fixtures/analysis-partial.json";

const viteEnv = import.meta.env ?? {};
export const API_BASE = viteEnv.VITE_API_URL ?? "http://localhost:8000/api/v1";
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

export interface AiAssessmentView {
  schema_version: string;
  verdict: "LIKELY_MALICIOUS" | "LIKELY_BENIGN" | "INCONCLUSIVE";
  summary: string;
  evidence_ids: string[];
  rationale: string;
  uncertainty: string;
  limitations: string[];
  disclaimer: string;
  generated_at: string;
  model: string;
  input_sha256: string;
  stages?: { func?: string; correlate?: string; report?: string };
  tokens_used?: number;
  tool_calls?: number;
  correlation?: {
    behavior_findings?: Array<{
      title: string;
      description: string;
      evidence_ids: string[];
      affected_function_ids: string[];
    }>;
    uncertainty?: string;
    rationale?: string;
  } | null;
}

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
  aiReport: AiAssessmentView | null;
  versions: { scoring: string; rules: string; schema: string };
}

export interface AiSummaryView {
  schema_version: string;
  function_id: string;
  purpose: string;
  behavior: string[];
  evidence_ids: string[];
  suspicious_indicators: string[];
  uncertainty: string;
  alternative_explanation: string;
  suggested_technique_id: string | null;
  rationale: string;
}

export interface FunctionDetailView {
  id: string;
  address: string;
  name: string;
  centrality: number;
  decompiler_status: string;
  decompiled_excerpt: string | null;
  artifact_available: boolean;
  ai_summary: AiSummaryView | null;
  decompiled_full: string | null;
  artifact_truncated: boolean | null;
  signature?: string | null;
  size?: number | null;
  assembly_excerpt?: string | null;
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
export interface CallEdgeView { caller: string; callee: string; type: string }
export interface StaticGraphView { functions: FunctionView[]; edges: CallEdgeView[] }

function mapFunction(item: Record<string, unknown>): FunctionView {
  return {
    id: String(item.id ?? ""),
    address: String(item.address ?? ""),
    name: String(item.name ?? "Unnamed function"),
    centrality: Number(item.centrality ?? 0),
    decompilerStatus: String(item.decompilerStatus ?? item.decompiler_status ?? "NOT_RUN"),
    decompiledExcerpt: (item.decompiledExcerpt ?? item.decompiled_excerpt ?? null) as string | null,
    artifactAvailable: Boolean(item.artifactAvailable ?? item.artifact_available),
  };
}

export async function getFunctions(analysisId: string): Promise<FunctionView[]> {
  if (USE_FIXTURES) return fixtureFor(analysisId).functions.map((item) => mapFunction(item as Record<string, unknown>));
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(analysisId)}/functions`);
  if (!response.ok) throw new Error("Could not load functions.");
  const data = await response.json() as { items: Record<string, unknown>[] };
  return data.items.map(mapFunction);
}

export async function getStaticGraph(analysisId: string): Promise<StaticGraphView> {
  if (USE_FIXTURES) {
    const fixture = fixtureFor(analysisId);
    return { functions: fixture.functions.map((item) => mapFunction(item as Record<string, unknown>)), edges: fixture.edges };
  }
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(analysisId)}/static`);
  if (!response.ok) throw new Error("Could not load graph.");
  const data = await response.json() as { functions?: Record<string, unknown>[]; edges?: CallEdgeView[] };
  return {
    functions: (data.functions ?? []).map(mapFunction),
    edges: data.edges ?? [],
  };
}

type FuncRow = { id: string; address: string; name: string; centrality: number; decompiler_status: string; decompiled_excerpt: string | null; signature: string | null; artifact: Record<string, unknown> | null; size: number | null; assembly_excerpt: string | null };

function findFuncById(data: unknown, fid: string): FuncRow | null {
  const normalized = data as { functions?: FuncRow[] };
  return (normalized.functions ?? []).find((f) => f.id === fid) ?? null;
}

export async function getFunctionDetail(id: string, fid: string, load_full = false): Promise<FunctionDetailView> {
  if (USE_FIXTURES) {
    const fixture = fixtureFor(id);
    const func = findFuncById(fixture, fid);
    if (!func) throw new Error("Function not found.");
    return {
      id: func.id,
      address: func.address,
      name: func.name,
      centrality: func.centrality,
      decompiler_status: func.decompiler_status,
      decompiled_excerpt: func.decompiled_excerpt,
      artifact_available: Boolean(func.artifact),
      ai_summary: null,
      decompiled_full: null,
      artifact_truncated: null,
      signature: func.signature ?? null,
      size: func.size ?? null,
      assembly_excerpt: func.assembly_excerpt ?? null,
    };
  }
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/functions/${encodeURIComponent(fid)}?load_full=${load_full}`);
  if (!response.ok) throw new Error("Could not load function detail.");
  return response.json() as unknown as FunctionDetailView;
}

export async function requestFunctionSummary(id: string, fid: string): Promise<AiSummaryView> {
  if (USE_FIXTURES) throw new Error("Function AI summaries require the live API.");
  const response = await fetch(
    `${API_BASE}/ai/analyses/${encodeURIComponent(id)}/functions/${encodeURIComponent(fid)}/summary`,
    { method: "POST" },
  );
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data?.error?.message ?? data?.detail?.message ?? "Could not summarize this function.";
    throw new Error(detail);
  }
  return data.summary as AiSummaryView;
}

export function fixtureId(state: "full" | "partial"): string { return `fixture-${state}`; }

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
  const fixture = fixtureFor(id);
  const score = 40;
  return {
    id: fixtureId(id.toLowerCase().includes("partial") ? "partial" : "full"),
    status: fixture.status as JobStatus,
    stage: fixture.status as JobStatus,
    progress: fixture.status === "COMPLETED" ? 100 : 95,
    decompStatus: fixture.decomp_status as StatusSnapshot["decomp_status"],
    aiStatus: (fixture as NormalizedFixture & { ai_status?: StatusSnapshot["ai_status"] }).ai_status ?? "DISABLED",
    source: (fixture.source ?? "fixture") as OverviewView["source"],
    file: {
      name: fixture.file.original_filename,
      size: fixture.file.size,
      format: fixture.file.format,
      arch: fixture.file.arch,
      bitness: fixture.file.bitness,
      entry: fixture.file.entry_point,
      sha256: fixture.sha256,
      md5: fixture.md5,
      extensionMismatch: fixture.file.extension_mismatch,
    },
    counts: {
      sections: fixture.sections.length,
      imports: fixture.imports.length,
      strings: fixture.strings.length,
      functions: fixture.functions.length,
      findings: fixture.findings.length,
    },
    risk: { score, rating: ratingFor(score), breakdown: [] },
    findings: fixture.findings.map((f: Record<string, unknown>) => ({
      id: String(f.finding_id ?? ""),
      groupId: String(f.group_id ?? "RULE"),
      title: String(f.group_id ?? "Rule-based finding"),
      severity: "Medium",
      confidence: "MED",
      weight: Number(f.weight ?? 0),
      observed: `Rule ${String(f.group_id)} matched with weight ${Number(f.weight ?? 0)}.`,
      interpretation: "Behaviorally suspicious pattern; heuristic, not a verdict.",
      alternative: "There may be a benign explanation.",
      attackMappings: [],
      evidence: [],
    })),
    aiReport: null,
    versions: { scoring: fixture.versions.scoring, rules: fixture.versions.rules, schema: fixture.versions.prompts },
  };
}

export function fileAdvisories(file: File): string[] {
  const advisories: string[] = [];
  if (file.size === 0) advisories.push("File is empty.");
  if (file.size > MAX_FILE_BYTES) advisories.push(`File exceeds ${MAX_FILE_BYTES / (1024 * 1024)} MB limit.`);
  return advisories;
}

export async function uploadFile(file: File): Promise<{ id: string; status: JobStatus }> {
  if (USE_FIXTURES) {
    return { id: fixtureId("full"), status: "COMPLETED" };
  }
  const formData = new FormData();
  formData.append("file", file);
  const response = await fetch(`${API_BASE}/analyses`, { method: "POST", body: formData });
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    throw new Error(data?.error?.message ?? "Upload failed.");
  }
  const data = await response.json();
  return { id: data.id, status: data.status as JobStatus };
}

function mapOverview(data: unknown, fallbackId = ""): OverviewView {
  const d = data as Record<string, unknown>;
  const file = d.file as Record<string, unknown> | undefined;
  const hashes = d.hashes as Record<string, unknown> | undefined;
  const risk = d.risk as Record<string, unknown> | undefined;
  const counts = d.counts as Record<string, unknown> | undefined;
  const versions = d.versions as Record<string, unknown> | undefined;
  const states = d.states as Record<string, unknown> | undefined;
  return {
    id: String(d.analysis_id ?? d.id ?? fallbackId),
    status: (states?.status ?? d.status ?? "CREATED") as JobStatus,
    stage: String(states?.stage ?? d.stage ?? ""),
    progress: Number(states?.progress ?? d.progress ?? 0),
    decompStatus: (states?.decomp_status ?? d.decomp_status ?? "NOT_RUN") as StatusSnapshot["decomp_status"],
    aiStatus: (states?.ai_status ?? d.ai_status ?? "NOT_RUN") as StatusSnapshot["ai_status"],
    source: (String(states?.source ?? d.source ?? "none") as OverviewView["source"]),
    file: {
      name: String(file?.filename ?? file?.name ?? ""),
      size: Number(file?.size ?? 0),
      format: String(file?.format ?? ""),
      arch: String(file?.arch ?? ""),
      bitness: file?.bitness === null || file?.bitness === undefined ? null : Number(file.bitness),
      entry: String(file?.entry_point ?? file?.entry ?? ""),
      sha256: String(hashes?.sha256 ?? ""),
      md5: String(hashes?.md5 ?? ""),
      extensionMismatch: Boolean(file?.extension_mismatch ?? file?.extensionMismatch ?? false),
    },
    counts: {
      sections: Number(counts?.sections ?? 0),
      imports: Number(counts?.imports ?? 0),
      strings: Number(counts?.strings ?? 0),
      functions: Number(counts?.functions ?? 0),
      findings: Number(counts?.findings ?? 0),
    },
    risk: {
      score: Number(risk?.score ?? 0),
      rating: ratingFor(Number(risk?.score ?? 0)),
      breakdown: (Array.isArray(risk?.breakdown) ? risk.breakdown : []).map((item: unknown) => {
        const r = item as Record<string, unknown>;
        return { title: String(r.title ?? ""), weight: Number(r.weight ?? 0) };
      }),
    },
    findings: (Array.isArray(d.top_findings ?? d.findings ?? []) ? ((d.top_findings ?? d.findings ?? []) as unknown[]) : []).map((item: unknown) => mapFinding(item)),
    aiReport: (d.ai_report ?? d.aiReport ?? null) as AiAssessmentView | null,
    versions: {
      scoring: String(versions?.scoring ?? ""),
      rules: String(versions?.rules ?? ""),
      schema: String(versions?.schema ?? ""),
    },
  };
}

export async function getOverview(id: string): Promise<OverviewView> {
  if (USE_FIXTURES) return fixtureOverview(id);
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/overview`);
  if (!response.ok) throw new Error("Could not load analysis overview.");
  const data = await response.json();
  return mapOverview(data, id);
}

export async function getFindings(id: string): Promise<FindingView[]> {
  if (USE_FIXTURES) return fixtureOverview(id).findings;
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/findings`);
  if (!response.ok) throw new Error("Could not load findings.");
  const data = await response.json() as { items: FindingView[] };
  return (data.items ?? []).map(mapFinding);
}

function mapFinding(finding: unknown): FindingView {
  const f = finding as Record<string, unknown>;
  return {
    id: String(f.id ?? ""),
    groupId: String(f.group_id ?? f.type ?? "RULE"),
    title: String(f.title ?? ""),
    severity: (String(f.severity).slice(0, 1).toUpperCase() + String(f.severity).slice(1).toLowerCase()) as Severity,
    confidence: ({ low: "LOW", medium: "MED", high: "HIGH" } as Record<string, Confidence>)[String(f.confidence).toLowerCase()] ?? "LOW",
    weight: Number(f.score_contribution ?? f.weight ?? 0) || 0,
    observed: String(f.description ?? ""),
    interpretation: String(f.interpretation ?? "Behaviorally suspicious pattern; heuristic, not a verdict."),
    alternative: String(f.alternative_explanation ?? f.alternative ?? "There may be a benign explanation."),
    attackMappings: (Array.isArray(f.attack_mappings) ? f.attack_mappings : []).map((item: unknown) => {
      const m = item as Record<string, unknown>;
      return { techniqueId: String(m.technique_id ?? ""), name: String(m.name ?? ""), label: String(m.label ?? "Possible") as "Likely" | "Possible" };
    }),
    evidence: (Array.isArray(f.evidence) ? f.evidence : []).map((item: unknown, index: number) => {
      if (typeof item === "string") {
        return { id: `E${index + 1}`, sourceType: item.split(":")[0] ?? "rule", sourceId: item, excerpt: item, offsetOrAddress: null, reason: "Matched by the current rule set." };
      }
      const e = item as Record<string, unknown>;
      return { id: String(e.id ?? `E${index + 1}`), sourceType: String(e.source_type ?? ""), sourceId: String(e.source_id ?? ""), excerpt: String(e.excerpt ?? ""), offsetOrAddress: e.offset_or_address === null || e.offset_or_address === undefined ? null : String(e.offset_or_address), reason: String(e.reason ?? "Evidence supporting this finding.") };
    }),
  };
}

export async function getStatus(id: string): Promise<StatusSnapshot> {
  if (USE_FIXTURES) {
    const overview = fixtureOverview(id);
    return { id, status: overview.status, stage: overview.stage, progress: overview.progress,
      decomp_status: overview.decompStatus, ai_status: overview.aiStatus };
  }
  const response = await fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/status`);
  if (!response.ok) throw new Error("Could not read analysis status.");
  return response.json() as unknown as StatusSnapshot;
}

export interface AiExplanationResponse {
  analysis_id: string;
  model: string;
  generated_at: string;
  input_sha256: string;
  explanation: string;
  disclaimer: string;
}

export async function generateAiExplanation(id: string): Promise<AiExplanationResponse> {
  if (USE_FIXTURES) throw new Error("On-demand AI explanations require the live API, not fixture mode.");
  const response = await fetch(`${API_BASE}/ai/analyses/${encodeURIComponent(id)}/explanation`, { method: "POST" });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data?.error?.message ?? data?.detail?.message ?? "AI explanation request failed.";
    throw new Error(detail);
  }
  return data as AiExplanationResponse;
}
