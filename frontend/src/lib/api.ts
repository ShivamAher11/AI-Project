import fullFixture from "../../../fixtures/analysis-full.json";
import partialFixture from "../../../fixtures/analysis-partial.json";

const viteEnv = import.meta.env ?? {};
export const API_BASE = viteEnv.VITE_API_URL ?? "http://localhost:8000/api/v1";
// Fixture mode defaults on until the overview endpoint lands in Prompt 8.
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
  evidence: string[];
}

export interface RiskLine { label: string; points: number; absorbed: boolean }

export interface OverviewView {
  id: string;
  status: JobStatus;
  stage: string;
  progress: number;
  decompStatus: StatusSnapshot["decomp_status"];
  aiStatus: StatusSnapshot["ai_status"];
  source: "fixture" | "real" | "none";
  file: { name: string; size: number; format: string; arch: string; bitness: number | null; entry: string | null; sha256: string; md5: string; extensionMismatch: boolean };
  counts: { sections: number; imports: number; strings: number; functions: number; findings: number };
  risk: { score: number; rating: Severity; breakdown: RiskLine[] };
  findings: FindingView[];
  versions: { lief: string; ghidra: string; jdk: string; capstone: string; scoring: string; rules: string; prompts: string };
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
      evidence: hit?.evidence_refs ?? [],
    };
  });
  const breakdown = data.rule_hits.filter((hit) => !hit.absorbed).map((hit) => ({
    label: hit.rule_id,
    points: Math.max(0, hit.weight),
    absorbed: Boolean(hit.absorbed),
  }));
  const score = Math.min(100, breakdown.reduce((sum, row) => sum + row.points, 0));
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
    versions: { ...data.toolchain, ...data.versions },
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
  const [statusResponse, staticResponse] = await Promise.all([
    fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/status`),
    fetch(`${API_BASE}/analyses/${encodeURIComponent(id)}/static`),
  ]);
  if (!statusResponse.ok || !staticResponse.ok) throw new Error("Could not load this analysis.");
  const status = await statusResponse.json() as StatusSnapshot;
  const data = await staticResponse.json();
  const emptyScore = 0;
  return {
    id, status: status.status, stage: status.stage, progress: status.progress,
    decompStatus: status.decomp_status, aiStatus: status.ai_status,
    source: data.source ?? "none",
    file: { name: data.file.original_filename ?? "Uploaded binary", size: data.file.size, format: data.file.format?.toUpperCase() ?? "UNKNOWN", arch: data.file.arch, bitness: data.file.bitness, entry: data.file.entry_point, sha256: data.file.sha256, md5: data.file.md5, extensionMismatch: data.file.extension_mismatch },
    counts: { sections: data.sections.length, imports: data.imports.length, strings: data.strings.length, functions: data.functions.length, findings: 0 },
    risk: { score: emptyScore, rating: "Low", breakdown: [] }, findings: [],
    versions: { lief: "1.0.0", ghidra: "NOT_RUN", jdk: "NOT_RUN", capstone: "NOT_RUN", scoring: "1.0", rules: "1.0", prompts: "1.0" },
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
  return response.json() as Promise<StatusSnapshot>;
}
