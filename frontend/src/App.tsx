import { useEffect, useState } from "react";
import { OverviewPage } from "./routes/Overview";
import { UploadPage } from "./routes/Upload";
import { USE_FIXTURES } from "./lib/api";
import { FindingsPage } from "./routes/Findings";

function useRouter() {
  const [path, setPath] = useState(`${window.location.pathname}${window.location.search}`);
  useEffect(() => {
    const pop = () => setPath(`${window.location.pathname}${window.location.search}`);
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  const navigate = (to: string) => {
    window.history.pushState({}, "", to);
    setPath(`${window.location.pathname}${window.location.search}`);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  return { path, navigate };
}

export function App() {
  const { path, navigate } = useRouter();
  const overviewMatch = path.match(/^\/analyses\/([^/]+)\/overview(?:\?.*)?$/);
  const findingsMatch = path.match(/^\/analyses\/([^/]+)\/findings(?:\?.*)?$/);
  const analysisId = overviewMatch?.[1] ?? findingsMatch?.[1];
  return (
    <div className="app-frame">
      <header className="topbar">
        <a className="brand" href="/upload" onClick={(event) => { event.preventDefault(); navigate("/upload"); }}>
            <span className="brand-mark" aria-hidden="true">R</span>
          <span>Static Analysis <span className="brand-muted">Workbench</span></span>
        </a>
        <nav className="header-nav" aria-label="Primary navigation">
          <button onClick={() => navigate("/upload")}>Upload</button>
          {analysisId && <><button onClick={() => navigate(`/analyses/${analysisId}/overview`)}>Overview</button><button onClick={() => navigate(`/analyses/${analysisId}/findings`)}>Findings</button></>}
        </nav>
        <div className="topbar-right">
          {USE_FIXTURES && <span className="mode-pill">Fixture mode</span>}
          <span className="topbar-caption">AI-assisted triage · static only</span>
        </div>
      </header>
      <div className="app-content">
        <aside className="sidebar" aria-label="Main navigation">
          <span className="sidebar-label">WORKSPACE</span>
          <button className={`nav-item ${!analysisId ? "active" : ""}`} onClick={() => navigate("/upload")}>
            <span className="nav-icon" aria-hidden="true">↑</span> New analysis
          </button>
          <span className="sidebar-label sidebar-later">ANALYSIS</span>
          {analysisId ? <><button className={`nav-item ${overviewMatch ? "active" : ""}`} onClick={() => navigate(`/analyses/${analysisId}/overview`)}>
            <span className="nav-icon" aria-hidden="true">◫</span> Overview
          </button><button className={`nav-item ${findingsMatch ? "active" : ""}`} onClick={() => navigate(`/analyses/${analysisId}/findings`)}>
            <span className="nav-icon" aria-hidden="true">≡</span> Findings
          </button></> : <p className="sidebar-hint">Upload a file to start a static review.</p>}
          <div className="sidebar-footer">Static analysis only<br />No files are executed.</div>
        </aside>
        <main className="main-pane">
          {overviewMatch
            ? <OverviewPage analysisId={decodeURIComponent(overviewMatch[1])} navigate={navigate} />
            : findingsMatch ? <FindingsPage analysisId={decodeURIComponent(findingsMatch[1])} />
            : <UploadPage navigate={navigate} />}
        </main>
      </div>
    </div>
  );
}
