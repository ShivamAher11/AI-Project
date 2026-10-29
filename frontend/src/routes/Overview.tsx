import { useEffect, useState } from "react";
import { getOverview, getStatus, type OverviewView, type StatusSnapshot } from "../lib/api";
import { subscribeAnalysisEvents, type AnalysisEvent } from "../lib/sse";
import { RiskBreakdown } from "../components/RiskBreakdown";
import { SSEBanner } from "../components/SSEBanner";
import { FindingCard } from "../components/FindingCard";
import { USE_FIXTURES } from "../lib/api";

function LoadingSkeleton() {
  return <div className="skeleton-stack" aria-label="Loading analysis overview" aria-busy="true">
    <div className="skeleton skeleton-title" /><div className="skeleton skeleton-meta" />
    <div className="skeleton-grid"><div className="skeleton skeleton-card" /><div className="skeleton skeleton-card" /></div>
    <div className="skeleton skeleton-card wide" />
  </div>;
}

export function OverviewPage({ analysisId, navigate }: { analysisId: string; navigate: (to: string) => void }) {
  const [overview, setOverview] = useState<OverviewView | null>(null);
  const [status, setStatus] = useState<StatusSnapshot | null>(null);
  const [lastEvent, setLastEvent] = useState<AnalysisEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setOverview(null); setStatus(null); setLastEvent(null); setError("");
    getOverview(analysisId).then((data) => { if (active) setOverview(data); }).catch((e: unknown) => {
      if (active) setError(e instanceof Error ? e.message : "Could not load this analysis.");
    });
    getStatus(analysisId).then((data) => { if (active) setStatus(data); }).catch(() => undefined);
    const stopEvents = subscribeAnalysisEvents(analysisId, (event) => {
      if (!active) return;
      setLastEvent(event);
      if (event.data.status) setStatus((current) => ({ ...(current ?? { id: analysisId, status: "CREATED", stage: "CREATED", progress: 0, decomp_status: "NOT_RUN", ai_status: "NOT_RUN" }), ...event.data } as StatusSnapshot));
    }, setConnected);
    let poll = 0;
    if (!USE_FIXTURES) {
      const refresh = async () => {
        try { const value = await getStatus(analysisId); if (active) setStatus(value); } catch { /* SSE remains the live progress channel. */ }
        if (active && !["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"].includes(status?.status ?? "")) poll = window.setTimeout(refresh, 3000);
      };
      poll = window.setTimeout(refresh, 3000);
    }
    return () => { active = false; stopEvents(); window.clearTimeout(poll); };
    // Reset and connect once per analysis id; status polling is deliberately separate.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId]);

  if (error) return <div className="error-panel" role="alert"><h1>Overview unavailable</h1><p>{error}</p></div>;
  if (!overview || !status) return <LoadingSkeleton />;

  const live = { ...overview, ...status, decompStatus: status.decomp_status ?? overview.decompStatus, aiStatus: status.ai_status ?? overview.aiStatus };
  return <div className="overview-page">
    <div className="page-heading">
      <div><div className="eyebrow">ANALYSIS OVERVIEW</div><h1>{overview.file.name}</h1><p className="subheading">Static triage summary <span className="dot-separator">·</span> <span className="mono">{analysisId}</span></p></div>
      <span className={`status-pill status-${live.status.toLowerCase()}`}><span className="status-dot" />{live.status}</span>
    </div>
    <SSEBanner status={live} connected={connected} lastEvent={lastEvent} source={overview.source} />

    <div className="overview-grid">
      <section className="panel identity-panel">
        <div className="panel-heading"><div><div className="eyebrow">FILE IDENTITY</div><h2>Static metadata</h2></div><span className="format-chip">{overview.file.format} · {overview.file.arch}</span></div>
        <dl className="identity-grid">
          <div><dt>File size</dt><dd>{formatBytes(overview.file.size)}</dd></div>
          <div><dt>Architecture</dt><dd>{overview.file.bitness ? `${overview.file.bitness}-bit ${overview.file.arch}` : overview.file.arch}</dd></div>
          <div><dt>Entry point</dt><dd className="mono">{overview.file.entry ?? "—"}</dd></div>
          <div><dt>Sections</dt><dd>{overview.counts.sections}</dd></div>
          <div><dt>Imports</dt><dd>{overview.counts.imports}</dd></div>
          <div><dt>Strings</dt><dd>{overview.counts.strings}</dd></div>
        </dl>
        {overview.file.extensionMismatch && <p className="inline-note">Extension differs from detected format; magic bytes are authoritative.</p>}
        <div className="hash-block"><span className="hash-label">SHA-256</span><code>{overview.file.sha256}</code><span className="hash-label">MD5</span><code>{overview.file.md5}</code></div>
      </section>
      <RiskBreakdown risk={overview.risk} />
    </div>

    <section className="panel findings-panel">
      <div className="panel-heading"><div><div className="eyebrow">RULE-BASED INDICATORS</div><h2>Top findings <span className="count-chip">{overview.counts.findings}</span></h2></div><button className="text-button" onClick={() => navigate(`/analyses/${encodeURIComponent(analysisId)}/findings`)}>View all findings</button></div>
      {overview.findings.length
        ? <div className="finding-list">{overview.findings.slice(0, 5).map((finding) => <div className="finding-link" key={finding.id} role="link" tabIndex={0} onClick={() => navigate(`/analyses/${encodeURIComponent(analysisId)}/findings`)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") navigate(`/analyses/${encodeURIComponent(analysisId)}/findings`); }}><FindingCard finding={finding} /></div>)}</div>
        : <div className="empty-state"><span className="empty-icon" aria-hidden="true">—</span><strong>No indicators by current rule set.</strong><span>Does not prove benign.</span></div>}
    </section>

    <section className="panel provenance-panel">
      <div className="panel-heading"><div><div className="eyebrow">PROVENANCE</div><h2>Versions and counts</h2></div><span className="fixture-source">source: {overview.source}</span></div>
      <div className="provenance-grid">
        <Version label="Scoring" value={overview.versions.scoring} /><Version label="Rules" value={overview.versions.rules} />
        <Version label="Schema" value={overview.versions.schema} />
      </div>
      <div className="counts-row"><span>{overview.counts.functions} functions</span><span>{overview.counts.findings} findings</span><span>{overview.counts.imports} imports</span></div>
    </section>
    <footer className="page-footnote">Static Risk is a heuristic, not a verdict. Extracted content is untrusted input.</footer>
  </div>;
}

function Version({ label, value }: { label: string; value: string }) {
  return <div className="version-item"><span>{label}</span><code>{value}</code></div>;
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}
