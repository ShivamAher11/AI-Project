import type { StatusSnapshot } from "../lib/api";
import type { AnalysisEvent } from "../lib/sse";

export function SSEBanner({ status, connected, lastEvent, source }: {
  status: StatusSnapshot; connected: boolean; lastEvent: AnalysisEvent | null; source: string;
}) {
  const messages: Array<{ kind: string; text: string }> = [];
  if (status.status === "PARTIAL" && status.decomp_status === "TIMEOUT") messages.push({ kind: "warning", text: "Partial — decomp TIMEOUT, static available" });
  else if (status.status === "PARTIAL") messages.push({ kind: "warning", text: "Partial — static results are available; some analysis stages did not run." });
  if (["DISABLED", "DEGRADED", "NOT_RUN", "FAILED"].includes(status.ai_status)) messages.push({ kind: "neutral", text: "AI not run in this build" });
  if (source === "fixture") messages.push({ kind: "fixture", text: "Source: fixture" });

  return <section className="live-panel" aria-live="polite" aria-label="Live analysis progress">
    <div className="live-topline">
      <div className="live-indicator"><span className={`connection-dot ${connected ? "connected" : "reconnecting"}`} />
        <span>{connected ? "Live updates connected" : "Reconnecting to live updates"}</span></div>
      <span className="live-stage">{prettyStage(status.stage)} <strong>{Math.max(0, Math.min(100, status.progress))}%</strong></span>
    </div>
    <div className="progress-track" role="progressbar" aria-label="Analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={status.progress}>
      <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, status.progress))}%` }} />
    </div>
    {messages.length > 0 && <div className="banner-list">{messages.map((message) => <div className={`notice notice-${message.kind}`} key={message.text}>{message.text}</div>)}</div>}
    {lastEvent && <span className="sr-only">Last event: {lastEvent.type}</span>}
  </section>;
}

function prettyStage(stage: string): string {
  return stage.toLowerCase().replace(/_/g, " ").replace(/\b\w/g, (letter: string) => letter.toUpperCase());
}
