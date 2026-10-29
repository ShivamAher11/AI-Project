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
      {risk.breakdown.length ? <span className="breakdown-summary">{risk.breakdown.map((line) => `+${line.weight} ${line.title}`).join(" · ")}</span> : <span className="breakdown-summary">No score contributions</span>}
    </div>
    <details className="risk-details">
      <summary>How calculated · view {risk.breakdown.length} contributions</summary>
      {risk.breakdown.length ? <table className="breakdown-table"><thead><tr><th>Rule or group</th><th>Weight</th></tr></thead><tbody>{risk.breakdown.map((line) => <tr key={line.title}><td>{line.title}</td><td>+{line.weight}</td></tr>)}</tbody></table> : <p>No rule-hit contributions are present.</p>}
      <p className="calculation-note">How is this calculated? Sum of rule weights, capped at 100. Heuristic, not a verdict. Finding severity is separate from the overall risk band.</p>
    </details>
  </section>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity.toLowerCase()}`}>{severity}</span>;
}
