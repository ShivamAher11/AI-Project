import { useEffect, useState } from "react";
import { FindingCard } from "../components/FindingCard";
import { getFindings, type FindingView } from "../lib/api";

export function FindingsPage({ analysisId }: { analysisId: string }) {
  const [items, setItems] = useState<FindingView[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { let active = true; setItems(null); setError("");
    getFindings(analysisId).then((result) => { if (active) setItems(result); }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : "Could not load findings."); });
    return () => { active = false; };
  }, [analysisId]);
  if (error) return <div className="error-panel" role="alert"><h1>Findings unavailable</h1><p>{error}</p></div>;
  return <section className="overview-page">
    <div className="page-heading"><div><div className="eyebrow">ANALYSIS FINDINGS</div><h1>Rule-based findings</h1><p className="subheading mono">{analysisId}</p></div></div>
    {!items ? <div className="skeleton skeleton-card" aria-busy="true" aria-label="Loading findings" /> : items.length
      ? <div className="finding-list">{items.map((finding) => <FindingCard key={finding.id} finding={finding} />)}</div>
      : <div className="panel empty-state"><strong>No indicators by current rule set.</strong><span>Does not prove benign.</span></div>}
  </section>;
}
