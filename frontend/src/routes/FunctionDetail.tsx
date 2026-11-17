import { useEffect, useState } from "react";
import { getFunctionDetail, type FunctionDetailView, type AiSummaryView } from "../lib/api";
import { SeverityBadge } from "../components/RiskBreakdown";

function LoadingSkeleton() {
  return <div className="skeleton-stack" aria-label="Loading function detail" aria-busy="true">
    <div className="skeleton skeleton-title" /><div className="skeleton skeleton-meta" />
    <div className="skeleton-grid"><div className="skeleton skeleton-card" /><div className="skeleton skeleton-card" /></div>
    <div className="skeleton skeleton-card wide" />
  </div>;
}

function renderBehaviorList(behavior: string[]) {
  return (
    <ul className="behavior-list">
      {behavior.map((item, index) => <li key={index}>{item}</li>)}
    </ul>
  );
}

export function FunctionDetailPage({ analysisId, fid, navigate }: { analysisId: string; fid: string; navigate: (to: string) => void }) {
  const [detail, setDetail] = useState<FunctionDetailView | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    setDetail(null); setError(""); setBusy(true);
    getFunctionDetail(analysisId, fid, true).then((result) => {
      if (active) { setDetail(result); setBusy(false); }
    }).catch((reason: unknown) => {
      if (active) { setError(reason instanceof Error ? reason.message : "Could not load function detail."); setBusy(false); }
    });
    return () => { active = false; };
  }, [analysisId, fid]);

  if (error) return <div className="error-panel" role="alert"><h1>Function unavailable</h1><p>{error}</p></div>;
  if (busy || !detail) return <LoadingSkeleton />;

  const summary = detail.ai_summary;
  const hasSummary = summary !== null && summary !== undefined;

  return <div className="function-detail-page">
    <div className="page-heading">
      <div><div className="eyebrow">FUNCTION DETAIL</div><h1>{detail.name}</h1><p className="subheading mono">{detail.address}</p></div>
      <button className="button" type="button" onClick={() => navigate(`/analyses/${encodeURIComponent(analysisId)}/overview`)}>Back to overview</button>
    </div>

    <section className="panel function-meta-panel">
      <div className="panel-heading"><div><div className="eyebrow">FUNCTION METADATA</div><h2>Static function</h2></div></div>
      <dl className="identity-grid">
        <div><dt>Address</dt><dd className="mono">{detail.address}</dd></div>
        <div><dt>Size</dt><dd>{detail.size ?? "Not available"}</dd></div>
        <div><dt>Signature</dt><dd>{detail.signature ?? "Not available"}</dd></div>
        <div><dt>Centrality</dt><dd>{(detail.centrality * 100).toFixed(1)}%</dd></div>
        <div><dt>Decompiler</dt><dd><span className={`status-pill status-${detail.decompiler_status.toLowerCase() === "ok" ? "completed" : "failed"}`}>{detail.decompiler_status}</span></dd></div>
        <div><dt>Artifact</dt><dd>{detail.artifact_available ? "Available" : "Not available"}</dd></div>
      </dl>
    </section>

    <section className="panel">
      <div className="panel-heading"><h2>Decompiled code</h2></div>
      {detail.decompiled_full || detail.decompiled_excerpt
        ? <pre className="code-view"><code>{detail.decompiled_full ?? detail.decompiled_excerpt}</code></pre>
        : <div className="empty-state">Decompiled code is not available for this function.</div>}
    </section>

    <section className="panel">
      <div className="panel-heading"><h2>Assembly excerpt</h2></div>
      {detail.assembly_excerpt
        ? <pre className="code-view"><code>{detail.assembly_excerpt}</code></pre>
        : <div className="empty-state">Assembly information is not available for this function.</div>}
    </section>

    <section className="panel ai-interpretation-panel">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">AI INTERPRETATION — VERIFY</div>
          <h2>AI-generated summary</h2>
          <p className="ai-help">Model-generated interpretation of selected static evidence. Deterministic findings and risk are unchanged.</p>
        </div>
      </div>
      {!hasSummary && <div className="empty-state"><span className="empty-icon" aria-hidden="true">—</span><strong>No AI summary available for this function.</strong><span>The function may not have been selected for summarization, or AI was disabled.</span></div>}
      {hasSummary && (
        <>
          <div className="ai-block"><span className="section-label">PURPOSE</span><p>{summary.purpose}</p></div>
          <div className="ai-block"><span className="section-label">BEHAVIOR</span>{renderBehaviorList(summary.behavior)}</div>
          {summary.suspicious_indicators.length > 0 && <div className="ai-block"><span className="section-label">SUSPICIOUS INDICATORS</span><p>{summary.suspicious_indicators.join("; ")}</p></div>}
          <div className="ai-block"><span className="section-label">ALTERNATIVE EXPLANATION</span><p>{summary.alternative_explanation}</p></div>
          <div className="ai-block"><span className="section-label">UNCERTAINTY</span><p>{summary.uncertainty}</p></div>
          <div className="ai-block"><span className="section-label">RATIONALE</span><p>{summary.rationale}</p></div>
          {summary.suggested_technique_id && <div className="ai-block"><span className="section-label">SUGGESTED ATT&CK</span><p>{summary.suggested_technique_id}</p></div>}
          <div className="evidence-row"><span className="section-label">EVIDENCE REFERENCES</span><div className="evidence-chips">
            {summary.evidence_ids.map((evidenceId, index) => <button key={index} className="evidence-chip">{`E${index + 1}:${evidenceId}`}</button>)}
          </div></div>
          <p className="ai-help">Raw binaries are never sent to the model. Only bounded snippets and metadata for this function are used.</p>
        </>
      )}
    </section>
  </div>;
}
