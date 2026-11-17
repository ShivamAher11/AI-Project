
import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core } from "cytoscape";
import { getStaticGraph } from "../lib/api";
import type { StaticGraphView } from "../lib/api";

interface GraphPageProps {
  analysisId: string;
}

export function GraphPage({ analysisId }: GraphPageProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  const [graphData, setGraphData] = useState<StaticGraphView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadGraph() {
      try {
        setLoading(true);
        setError(null);

        const result = await getStaticGraph(analysisId);

        if (active) {
          setGraphData(result);
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load call graph."
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    loadGraph();

    return () => {
      active = false;
    };
  }, [analysisId]);

  useEffect(() => {
    if (!containerRef.current || !graphData || loading || error) {
      return;
    }

    const functionIds = new Set(
      graphData.functions.map((fn) => fn.id)
    );

    const nodes = graphData.functions.map((fn) => ({
      data: {
        id: fn.id,
        label: fn.name,
        address: fn.address,
        centrality: fn.centrality,
      },
    }));

    // Only use edges whose endpoints exist in the function list.
    const edges = graphData.edges
      .filter(
        (edge) =>
          functionIds.has(edge.caller) &&
          functionIds.has(edge.callee)
      )
      .map((edge, index) => ({
        data: {
          id: `edge-${index}`,
          source: edge.caller,
          target: edge.callee,
          label: edge.type,
        },
      }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      layout: edges.length > 0
        ? {
            name: "cose",
            animate: false,
            nodeRepulsion: () => 12000,
            idealEdgeLength: () => 150,
            padding: 40,
            }
        : {
            name: "grid",
            animate: false,
            rows: 3,
            padding: 40,
            },
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#39739c",
            label: "data(label)",
            color: "#26384d",
            "font-size": "10px",
            "text-wrap": "wrap",
            "text-max-width": "130px",
            "text-valign": "bottom",
            "text-margin-y": 8,
            width: 34,
            height: 34,
            "border-width": 2,
            "border-color": "#d9eaf5",
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#aab8c5",
            "target-arrow-color": "#aab8c5",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "8px",
            color: "#68788a",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: "node:selected",
          style: {
            "background-color": "#e09b45",
            "border-color": "#f4d7ad",
            "border-width": 4,
          },
        },
      ],
    });

    cyRef.current = cy;

    cy.on("tap", "node", (event) => {
      const node = event.target;
      setSelectedFunction({
        name: String(node.data("label")),
        address: String(node.data("address")),
        centrality: Number(node.data("centrality") ?? 0),
      });
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graphData, loading, error]);

  const [selectedFunction, setSelectedFunction] = useState<{
    name: string;
    address: string;
    centrality: number;
  } | null>(null);

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <div className="eyebrow">STATIC ANALYSIS</div>
          <h1>Call Graph</h1>
          <p className="page-description">
            Explore relationships between extracted functions.
            Select a node to inspect its details.
          </p>
        </div>

        <span className="count-chip">
          {graphData?.functions.length ?? 0} functions
        </span>
      </section>

      {loading && (
        <div className="panel empty-state">
          Loading call graph...
        </div>
      )}

      {error && (
        <div className="panel error-state" role="alert">
          <strong>Unable to load call graph</strong>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && graphData && (
        <>
          <div className="stats-grid">
            <div className="panel stat-card">
              <span className="eyebrow">FUNCTIONS</span>
              <strong>{graphData.functions.length}</strong>
            </div>

            <div className="panel stat-card">
              <span className="eyebrow">CALL RELATIONSHIPS</span>
              <strong>{graphData.edges.length}</strong>
            </div>
          </div>

          <section className="panel graph-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">FUNCTION RELATIONSHIPS</div>
                <h2>Function call network</h2>
              </div>
              <span className="count-chip">
                Interactive graph
              </span>
            </div>

            {graphData.functions.length === 0 ? (
              <div className="empty-state">
                No function data is available for this analysis.
              </div>
            ) : (
              <div ref={containerRef} className="cytoscape-container" />
            )}

            {graphData.functions.length > 0 &&
              graphData.edges.length === 0 && (
                <p className="graph-note">
                  No call relationships were supplied by the current
                  data source. Function nodes are shown without
                  connecting edges.
                </p>
              )}
          </section>

          {selectedFunction && (
            <section className="panel selected-function">
              <div className="eyebrow">SELECTED FUNCTION</div>
              <h2>{selectedFunction.name}</h2>
              <p>
                Address: <code>{selectedFunction.address}</code>
              </p>
              <p>
                Centrality:{" "}
                {(selectedFunction.centrality * 100).toFixed(1)}%
              </p>
            </section>
          )}
        </>
      )}
    </div>
  );
}