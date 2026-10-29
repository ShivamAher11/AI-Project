import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

const API = "http://localhost:8000/api/v1";

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("");
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    if (!analysisId) return;
    let active = true;
    const poll = async () => {
      try {
        const [statusResponse, staticResponse] = await Promise.all([
          fetch(`${API}/analyses/${analysisId}/status`),
          fetch(`${API}/analyses/${analysisId}/static`),
        ]);
        if (!active) return;
        if (statusResponse.ok) setStatus((await statusResponse.json()).status);
        if (staticResponse.ok) {
          const value = await staticResponse.json();
          setReport(value);
        }
      } catch {
        if (active) setError("Could not reach the analysis API.");
      }
      if (active) window.setTimeout(poll, 1500);
    };
    void poll();
    return () => { active = false; };
  }, [analysisId]);

  const upload = async () => {
    if (!file) return;
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const response = await fetch(`${API}/analyses`, { method: "POST", body: form });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.message ?? "Upload failed.");
      setAnalysisId(body.id);
      setStatus(body.status);
      setReport(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed.");
    }
  };

  return (
    <main style={{ fontFamily: "system-ui", margin: "3rem auto", maxWidth: 900, padding: "0 1rem", color: "#172033" }}>
      <h1>AI-Assisted Reverse Engineering Assistant</h1>
      <p>Static analysis triage. Results are heuristic and are not a malware verdict.</p>
      <section style={{ display: "flex", gap: 12, alignItems: "center", margin: "2rem 0" }}>
        <input aria-label="Choose a binary" type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
        <button disabled={!file} onClick={() => void upload()}>Upload for analysis</button>
      </section>
      {error && <p role="alert" style={{ color: "#b42318" }}>{error}</p>}
      {analysisId && <section>
        <h2>Analysis</h2>
        <p><strong>ID:</strong> {analysisId}</p>
        <p><strong>Status:</strong> {status}</p>
        {report && <>
          <p aria-label="decompilation source" style={{ display: "inline-block", padding: "0.5rem 0.75rem", background: "#fff4d6", borderRadius: 6 }}>
            <strong>source: {report.source}</strong>{report.source === "fixture" ? " — fixture output, not real Ghidra" : ""}
          </p>
          <p>{report.functions?.length ?? 0} functions · {report.edges?.length ?? 0} call edges</p>
          {report.functions?.slice(0, 20).map((fn: any) => <article key={fn.id} style={{ borderTop: "1px solid #ddd", padding: "0.6rem 0" }}>
            <strong>{fn.name}</strong> <code>{fn.address}</code> · PageRank {Number(fn.centrality).toFixed(3)}
          </article>)}
        </>}
      </section>}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode><App /></React.StrictMode>,
);
