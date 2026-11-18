import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { getStaticGraph } from "../lib/api";
import type { StaticGraphView } from "../lib/api";

interface GraphPageProps {
  analysisId: string;
}

export function GraphPage({ analysisId }: GraphPageProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<any>(null);

  const [graphData, setGraphData] = useState<StaticGraphView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadGraph() {
      try {
        setLoading(true);
        setError(null);
        const data = await getStaticGraph(analysisId);
        if (active) setGraphData(data);
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Could not load graph.");
          setLoading(false);
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

    const functionIds = new Set(graphData.functions.map((fn) => fn.id));

    const nodes = graphData.functions.map((fn) => ({
      data: { id: fn.id, label: fn.name },
      classes: "internal",
    }));

    const edges = graphData.edges
      .filter((edge) => functionIds.has(edge.caller) && functionIds.has(edge.callee))
      .map((edge, index) => ({
        data: { id: `e${index}`, source: edge.caller, target: edge.callee },
        classes: edge.type === "indirect" ? "indirect" : "direct",
      }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        { selector: "node", style: { label: "data(label)" } },
        { selector: "edge", style: { "curve-style": "bezier" } },
      ],
    });

    cyRef.current = cy;

    cy.on("tap", "node", (event: any) => {
      const node = event.target;
      const nodeId = node.data("id");
      setSelectedFunction(nodeId);
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graphData, loading, error]);

  const [selectedFunction, setSelectedFunction] = useState<{
    id: string;
    address: string;
    name: string;
    centrality: number;
  } | null>(null);

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <div className="eyebrow">CALL GRAPH</div>
          <h1>Call Graph</h1>
          <p className="page-description">
            Explore the function call graph. Click nodes to explore.
          </p>
        </div>
      </section>

      {loading && (
        <div className="panel empty-state">
          Loading graph...
        </div>
      )}

      {error && (
        <div className="panel error-state" role="alert">
          <strong>Unable to load graph</strong>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && graphData?.functions.length === 0 && (
        <div className="panel empty-state">
          No call graph data is available for this analysis.
        </div>
      )}

      {!loading && !error && graphData && graphData.functions.length > 0 && (
        <div
          id="cy"
          ref={containerRef}
          style={{ width: "100%", height: "calc(100vh - 200px)" }}
        />
      )}
    </div>
  );
}
