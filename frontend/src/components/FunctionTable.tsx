
import { useMemo, useState } from "react";
import type { FunctionView } from "../lib/api";

interface FunctionTableProps {
  functions: FunctionView[];
  onSelect: (functionId: string) => void;
}

export function FunctionTable({
  functions,
  onSelect,
}: FunctionTableProps) {
  const [search, setSearch] = useState("");

  const filteredFunctions = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return functions;

    return functions.filter((fn) =>
      fn.name.toLowerCase().includes(query) ||
      fn.address.toLowerCase().includes(query)
    );
  }, [functions, search]);

  function statusLabel(status: string) {
    if (status.toLowerCase() === "ok") return "Processed";
    if (status.toLowerCase() === "failed") return "Failed";
    if (status.toLowerCase() === "not_run") return "Not run";

    return status.replace(/_/g, " ");
  }

  return (
    <section className="panel function-panel">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">FUNCTION ANALYSIS</div>
          <h2>Extracted functions</h2>
        </div>

        <span className="count-chip">
          {filteredFunctions.length} / {functions.length}
        </span>
      </div>

      <div className="function-toolbar">
        <input
          type="search"
          className="function-search"
          placeholder="Search by function name or address..."
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Search functions"
        />
      </div>

      {filteredFunctions.length === 0 ? (
        <div className="empty-state">
          <strong>No functions found.</strong>
          <span>Try another name or address.</span>
        </div>
      ) : (
        <div className="function-table-wrap">
          <table className="function-table">
            <thead>
              <tr>
                <th>Function name</th>
                <th>Address</th>
                <th>Decompiler status</th>
                <th>Centrality</th>
                <th>Details</th>
              </tr>
            </thead>

            <tbody>
              {filteredFunctions.map((fn) => (
                <tr key={fn.id}>
                  <td className="function-name">{fn.name}</td>

                  <td>
                    <code>{fn.address}</code>
                  </td>

                  <td>
                    <span className="function-status">
                      {statusLabel(fn.decompilerStatus)}
                    </span>
                  </td>

                  <td>
                    {Number.isFinite(fn.centrality)
                      ? `${(fn.centrality * 100).toFixed(1)}%`
                      : "—"}
                  </td>

                  <td>
                    <button
                      className="text-button"
                      onClick={() => onSelect(fn.id)}
                    >
                      View details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}