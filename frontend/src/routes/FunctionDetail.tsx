
import { useEffect, useState } from "react";
import {
  getFunctionDetail,
  type FunctionDetailView,
} from "../lib/api";

interface FunctionDetailPageProps {
  analysisId: string;
  functionId: string;
  navigate: (to: string) => void;
}

export function FunctionDetailPage({
  analysisId,
  functionId,
  navigate,
}: FunctionDetailPageProps) {
  const [fn, setFn] = useState<FunctionDetailView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadFunction() {
      try {
        setLoading(true);
        setError(null);

        const result = await getFunctionDetail(
          analysisId,
          functionId,
          true
        );

        if (active) {
          setFn(result);
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load function details."
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    loadFunction();

    return () => {
      active = false;
    };
  }, [analysisId, functionId]);

  const backToFunctions = () => {
    navigate(
      `/analyses/${encodeURIComponent(analysisId)}/functions`
    );
  };

  if (loading) {
    return (
      <div className="panel empty-state">
        Loading function details...
      </div>
    );
  }

  if (error || !fn) {
    return (
      <div className="page-stack">
        <button className="text-button" onClick={backToFunctions}>
          ← Back to functions
        </button>

        <div className="panel error-state" role="alert">
          <strong>Unable to load function details</strong>
          <p>{error ?? "Function not found."}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-stack function-detail-page">
      <button className="text-button" onClick={backToFunctions}>
        ← Back to functions
      </button>

      <section className="page-heading">
        <div>
          <div className="eyebrow">FUNCTION ANALYSIS</div>
          <h1>{fn.name}</h1>
          <p className="page-description">
            Detailed inspection of the selected binary function.
          </p>
        </div>

        <span className="count-chip">
          {fn.decompilerStatus.replace(/_/g, " ")}
        </span>
      </section>

      <section className="stats-grid">
        <div className="panel stat-card">
          <span className="eyebrow">FUNCTION ADDRESS</span>
          <strong>{fn.address}</strong>
        </div>

        <div className="panel stat-card">
          <span className="eyebrow">FUNCTION SIZE</span>
          <strong>{fn.size ?? "Not available"}</strong>
        </div>

        <div className="panel stat-card">
          <span className="eyebrow">CENTRALITY</span>
          <strong>
            {Number.isFinite(fn.centrality)
              ? `${(fn.centrality * 100).toFixed(1)}%`
              : "Not available"}
          </strong>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Function information</h2>
        </div>

        <p>
          <strong>Signature:</strong>{" "}
          {fn.signature ?? "Not available"}
        </p>

        <p>
          <strong>Decompiler status:</strong>{" "}
          {fn.decompilerStatus}
        </p>

        <p>
          <strong>Artifact available:</strong>{" "}
          {fn.artifactAvailable ? "Yes" : "No"}
        </p>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Decompiled code</h2>
        </div>

        {fn.decompiledFull || fn.decompiledExcerpt ? (
          <pre className="code-view">
            <code>
              {fn.decompiledFull ?? fn.decompiledExcerpt}
            </code>
          </pre>
        ) : (
          <div className="empty-state">
            Decompiled code is not available for this function.
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Assembly excerpt</h2>
        </div>

        {fn.assemblyExcerpt ? (
          <pre className="code-view">
            <code>{fn.assemblyExcerpt}</code>
          </pre>
        ) : (
          <div className="empty-state">
            Assembly information is not available for this function.
          </div>
        )}
      </section>
    </div>
  );
}