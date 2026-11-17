import { useEffect, useState } from "react";
import { OverviewPage } from "./routes/Overview";
import { FunctionDetailPage } from "./routes/FunctionDetail";
import { UploadPage } from "./routes/Upload";
import { USE_FIXTURES } from "./lib/api";
import { FindingsPage } from "./routes/Findings";
import { FunctionsPage } from "./routes/Functions";
import { GraphPage } from "./routes/Graph";
import { ReportPage } from "./routes/Report";

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
  const functionMatch = path.match(/^\/analyses\/([^/]+)\/functions\/([^/]+)(?:\?.*)?$/);
  const functionsMatch = path.match(/^\/analyses\/([^/]+)\/functions(?:\?.*)?$/);
  const graphMatch = path.match(/^\/analyses\/([^/]+)\/graph(?:\?.*)?$/);
  const reportMatch = path.match(/^\/analyses\/([^/]+)\/report(?:\?.*)?$/);
  const analysisId = overviewMatch?.[1] ?? findingsMatch?.[1] ?? functionsMatch?.[1] ?? graphMatch?.[1] ?? reportMatch?.[1] ?? functionMatch?.[1];
  return (
    <div className="app-frame">
      <header className="topbar">
        <a className="brand" href="/upload" onClick={(event) => { event.preventDefault(); navigate("/upload"); }}>
            <span className="brand-mark" aria-hidden="true">R</span>
          <span>Static Analysis <span className="brand-muted">Workbench</span></span>
        </a>
        <nav className="header-nav" aria-label="Primary navigation">
          <button onClick={() => navigate("/upload")}>Upload</button>
          {analysisId && <><button onClick={() => navigate(`/analyses/${analysisId}/overview`)}>Overview</button><button onClick={() => navigate(`/analyses/${analysisId}/findings`)}>Findings</button><button onClick={() => navigate(`/analyses/${analysisId}/functions`)}>Functions</button><button onClick={() => navigate(`/analyses/${analysisId}/graph`)}>Call Graph</button><button onClick={() => navigate(`/analyses/${analysisId}/report`)}>Report</button></>}
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
          </button><button className={`nav-item ${functionsMatch ? "active" : ""}`} onClick={() => navigate(`/analyses/${analysisId}/functions`)}>ƒ&nbsp; Functions</button><button className={`nav-item ${graphMatch ? "active" : ""}`} onClick={() => navigate(`/analyses/${analysisId}/graph`)}>◎&nbsp; Call Graph</button><button className={`nav-item ${reportMatch ? "active" : ""}`} onClick={() => navigate(`/analyses/${analysisId}/report`)}>▤&nbsp; Report</button></> : <p className="sidebar-hint">Upload a file to start a static review.</p>}
          <div className="sidebar-footer">Static analysis only<br />No files are executed.</div>
        </aside>
        <main className="main-pane">
          {reportMatch ? <ReportPage analysisId={decodeURIComponent(reportMatch[1])} />
            : graphMatch ? <GraphPage analysisId={decodeURIComponent(graphMatch[1])} />
            : functionsMatch ? <FunctionsPage analysisId={decodeURIComponent(functionsMatch[1])} navigate={navigate} />
            : overviewMatch
            ? <OverviewPage analysisId={decodeURIComponent(overviewMatch[1])} navigate={navigate} />
            : findingsMatch ? <FindingsPage analysisId={decodeURIComponent(findingsMatch[1])} />
            : functionMatch ? <FunctionDetailPage analysisId={decodeURIComponent(functionMatch[1])} fid={decodeURIComponent(functionMatch[2])} navigate={navigate} />
            : <UploadPage navigate={navigate} />}
        </main>
      </div>
    </div>
  );
}
