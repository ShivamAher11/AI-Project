
import { useEffect, useState } from "react";
import { getFunctions } from "../lib/api";
import type { FunctionView } from "../lib/api";
import { FunctionTable } from "../components/FunctionTable";

interface FunctionsPageProps {
  analysisId: string;
  navigate: (to: string) => void;
}

export function FunctionsPage({
  analysisId,
  navigate,
}: FunctionsPageProps) {
  const [functions, setFunctions] = useState<FunctionView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadFunctions() {
      try {
        setLoading(true);
        setError(null);

        const result = await getFunctions(analysisId);

        if (active) {
          setFunctions(result);
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load functions."
          );
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    loadFunctions();

    return () => {
      active = false;
    };
  }, [analysisId]);

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <div className="eyebrow">STATIC ANALYSIS</div>
          <h1>Functions</h1>
          <p className="page-description">
            Explore extracted functions, their addresses,
            decompiler status and analysis details.
          </p>
        </div>

        <div className="count-chip">
          {functions.length} functions
        </div>
      </section>

      {loading && (
        <div className="panel empty-state">
          Loading extracted functions...
        </div>
      )}

      {error && (
        <div className="panel error-state" role="alert">
          <strong>Unable to load functions</strong>
          <p>{error}</p>
          <button
            className="text-button"
            onClick={() => window.location.reload()}
          >
            Retry
          </button>
        </div>
      )}

      {!loading && !error && functions.length === 0 && (
        <div className="panel empty-state">
          <strong>No functions available</strong>
          <span>
            The current analysis did not return any extracted functions.
          </span>
        </div>
      )}

      {!loading && !error && functions.length > 0 && (
        <>
          <div className="stats-grid">
            <div className="panel stat-card">
              <span className="eyebrow">TOTAL FUNCTIONS</span>
              <strong>{functions.length}</strong>
            </div>

            <div className="panel stat-card">
              <span className="eyebrow">DECOMPILER PROCESSED</span>
              <strong>
                {
                  functions.filter(
                    (fn) =>
                      fn.decompilerStatus.toUpperCase() === "OK"
                  ).length
                }
              </strong>
            </div>

            <div className="panel stat-card">
              <span className="eyebrow">ARTIFACTS AVAILABLE</span>
              <strong>
                {
                  functions.filter(
                    (fn) => fn.artifactAvailable
                  ).length
                }
              </strong>
            </div>
          </div>

          <FunctionTable
            functions={functions}
            onSelect={(functionId) =>
              navigate(
                `/analyses/${encodeURIComponent(analysisId)}/functions/${encodeURIComponent(functionId)}`
              )
            }
          />
        </>
      )}
    </div>
  );
}