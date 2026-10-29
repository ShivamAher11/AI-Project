import type { OverviewView, Severity } from "../lib/api";

export function RiskBreakdown({ risk }: { risk: OverviewView["risk"] }) {
  return <section className="panel risk-panel" aria-labelledby="risk-title">
    <div className="eyebrow">DETERMINISTIC SCORE</div>
    <div className="risk-main">
      <div><h2 id="risk-title">Static Risk</h2><p className="risk-caption">Heuristic, not verdict</p></div>
      <div className="risk-value"><strong>{risk.score}</strong><span>/100</span></div>
    </div>
    <div className="risk-rating-row"><span>Risk band</span><SeverityBadge severity={risk.rating} /></div>
    <div className="breakdown-preview" aria-label="Risk score breakdown">
      <span className="breakdown-label">Breakdown</span>
      {risk.breakdown.length ? <span className="breakdown-summary">{risk.breakdown.map((line) => `+${line.points} ${line.label}`).join(" · ")}</span> : <span className="breakdown-summary">No score contributions</span>}
    </div>
    <details className="risk-details">
      <summary>How calculated · view {risk.breakdown.length} contributions</summary>
      {risk.breakdown.length ? <ul>{risk.breakdown.map((line) => <li key={line.label}>
        <span>{line.label}{line.absorbed && <small> absorbed</small>}</span><strong>{line.absorbed ? "0" : `+${line.points}`}</strong>
      </li>)}</ul> : <p>No rule-hit contributions are present in this fixture.</p>}
      <p className="calculation-note">Score is the sum of non-absorbed deterministic rule contributions, capped at 100. Bands: Low ≤30, Medium ≤60, High ≤80, Critical &gt;80.</p>
    </details>
  </section>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity.toLowerCase()}`}>{severity}</span>;
}
