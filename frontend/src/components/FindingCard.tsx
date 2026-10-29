import type { FindingView } from "../lib/api";
import { useState } from "react";
import { SeverityBadge } from "./RiskBreakdown";

export function FindingCard({ finding }: { finding: FindingView }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  return <article className="finding-card">
    <div className="finding-title-row">
      <div><div className="finding-rule">{finding.groupId}</div><h3>{finding.title}</h3></div>
      <div className="badge-stack"><SeverityBadge severity={finding.severity} /><ConfidenceBadge confidence={finding.confidence} /></div>
    </div>
    <div className="finding-sections">
      <div className="observed-block"><span className="section-label">OBSERVED</span><p>{finding.observed}</p></div>
      <div><span className="section-label">ALTERNATIVE EXPLANATION</span><p>{finding.alternative}</p></div>
    </div>
    {finding.attackMappings.length > 0 && <p className="attack-line">{finding.attackMappings.map((item) => `${item.label} ${item.techniqueId} - ${item.name}`).join(" · ")}</p>}
    <div className="evidence-row"><span className="section-label">EVIDENCE</span><div className="evidence-chips">
      {finding.evidence.map((item, index) => { const label = `E${index + 1}:${item.sourceType} ${item.sourceId}`; return <button className="evidence-chip" key={item.id} aria-expanded={expanded === item.id} onClick={() => setExpanded(expanded === item.id ? null : item.id)}>{label}</button>; })}
    </div></div>
    {finding.evidence.filter((item) => item.id === expanded).map((item) => <div className="evidence-detail" key={item.id}><strong>{item.excerpt}</strong>{item.offsetOrAddress && <code>Offset/address: {item.offsetOrAddress}</code>}<span>{item.reason}</span></div>)}
  </article>;
}

function ConfidenceBadge({ confidence }: { confidence: FindingView["confidence"] }) {
  return <span className={`confidence-badge confidence-${confidence.toLowerCase()}`}>{confidence}</span>;
}
