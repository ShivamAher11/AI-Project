import type { FindingView } from "../lib/api";
import { SeverityBadge } from "./RiskBreakdown";

export function FindingCard({ finding }: { finding: FindingView }) {
  return <article className="finding-card">
    <div className="finding-title-row">
      <div><div className="finding-rule">{finding.groupId}</div><h3>{finding.title}</h3></div>
      <div className="badge-stack"><SeverityBadge severity={finding.severity} /><ConfidenceBadge confidence={finding.confidence} /></div>
    </div>
    <div className="finding-sections">
      <div><span className="section-label">OBSERVED</span><p>{finding.observed}</p></div>
      <div><span className="section-label">INTERPRETATION</span><p>{finding.interpretation}</p></div>
      <div><span className="section-label">ALTERNATIVE</span><p>{finding.alternative}</p></div>
    </div>
    <div className="evidence-row"><span className="section-label">EVIDENCE</span><div className="evidence-chips">
      {finding.evidence.map((ref) => <span className="evidence-chip" key={ref}>{ref}</span>)}
    </div></div>
  </article>;
}

function ConfidenceBadge({ confidence }: { confidence: FindingView["confidence"] }) {
  return <span className={`confidence-badge confidence-${confidence.toLowerCase()}`}>{confidence}</span>;
}
