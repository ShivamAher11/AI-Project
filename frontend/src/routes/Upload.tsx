import { useState } from "react";
import { fileAdvisories, fixtureId, uploadFile, USE_FIXTURES, type JobStatus } from "../lib/api";

export function UploadPage({ navigate }: { navigate: (to: string) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [advisory, setAdvisory] = useState<string[]>([]);
  const [fixtureState, setFixtureState] = useState<"full" | "partial">("full");

  const select = (selected: File | null) => {
    setFile(selected);
    setError("");
    setAdvisory(selected ? fileAdvisories(selected) : []);
    if (selected && /partial|timeout/i.test(selected.name)) setFixtureState("partial");
  };
  const open = async (state?: "full" | "partial") => {
    setError(""); setBusy(true);
    try {
      let result: { id: string; status: JobStatus };
      if (USE_FIXTURES) {
        const preview = state ?? fixtureState;
        result = { id: fixtureId(preview), status: preview === "full" ? "COMPLETED" : "PARTIAL" };
      }
      else if (file) result = await uploadFile(file);
      else throw new Error("Choose a file first.");
      navigate(`/analyses/${encodeURIComponent(result.id)}/overview`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed.");
    } finally { setBusy(false); }
  };

  return <div className="upload-page">
    <div className="eyebrow">NEW STATIC ANALYSIS</div>
    <h1>Review a binary</h1>
    <p className="upload-intro">Inspect static metadata, rule indicators, and analysis progress. Files are never executed.</p>
    {USE_FIXTURES && <div className="fixture-notice"><span className="fixture-dot" />Fixture mode is on. Files are not sent to the API; choose a scenario below to preview the overview.</div>}

    <label className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); select(event.dataTransfer.files[0] ?? null); }}>
      <input className="file-input" type="file" accept=".exe,.dll,.elf,.so" aria-label="Choose binary file" onChange={(event) => select(event.target.files?.[0] ?? null)} />
      <span className="upload-symbol" aria-hidden="true">＋</span>
      <strong>{file ? file.name : "Drop a file here, or browse"}</strong>
      <span className="dropzone-meta">PE x64 supported now · up to 100 MB · files are analyzed statically</span>
      {file && <span className="selected-size">{(file.size / (1024 * 1024)).toFixed(2)} MB</span>}
    </label>
    {advisory.length > 0 && <ul className="advisory-list">{advisory.map((item) => <li key={item}>{item}</li>)}</ul>}
    {error && <p className="upload-error" role="alert">{error}</p>}

    {USE_FIXTURES ? <div className="fixture-actions">
      <div><h2>Choose a preview state</h2><p>Fixture data shows both the complete and partial analysis layouts.</p></div>
      <div className="button-row"><button className="button button-primary" disabled={busy} onClick={() => void open("full")}>Open full fixture</button><button className="button button-secondary" disabled={busy} onClick={() => void open("partial")}>Open partial fixture</button></div>
      {file && <button className="text-button" disabled={busy} onClick={() => void open()}>{busy ? "Opening…" : `Use selected file as ${fixtureState} fixture`}</button>}
    </div> : <div className="upload-submit-row"><button className="button button-primary" disabled={!file || busy} onClick={() => void open()}>{busy ? "Uploading…" : "Upload and analyze"}</button><span>Only the uploaded file is sent; the filename is display metadata.</span></div>}

    <div className="upload-footnote"><strong>Static analysis only.</strong> No binary or extracted content is run. Results are heuristic, not a malware verdict.</div>
  </div>;
}
