import { API_BASE, USE_FIXTURES, fixtureId, type JobStatus, type StatusSnapshot } from "./api";

export type AnalysisEventName = "connected" | "stage_change" | "progress" | "partial" | "completed" | "failed" | "cancelled";
export interface AnalysisEvent { type: AnalysisEventName; data: Partial<StatusSnapshot> & Record<string, unknown> }
export type EventHandler = (event: AnalysisEvent) => void;

const TERMINAL = new Set<JobStatus>(["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"]);

export function subscribeAnalysisEvents(id: string, onEvent: EventHandler, onConnection?: (connected: boolean) => void): () => void {
  if (USE_FIXTURES) return fixtureStream(id, onEvent, onConnection);

  let closed = false;
  let source: EventSource | null = null;
  let retryTimer = 0;
  let backoff = 1000;
  const connect = () => {
    if (closed) return;
    source = new EventSource(`${API_BASE}/analyses/${encodeURIComponent(id)}/events`);
    source.onopen = () => { backoff = 1000; onConnection?.(true); };
    source.onerror = () => {
      onConnection?.(false);
      source?.close();
      if (closed) return;
      retryTimer = window.setTimeout(connect, backoff);
      backoff = Math.min(30_000, backoff * 2);
    };
    const names: AnalysisEventName[] = ["connected", "stage_change", "progress", "partial", "completed", "failed", "cancelled"];
    for (const name of names) source.addEventListener(name, (raw) => {
      const message = raw as MessageEvent<string>;
      let data: AnalysisEvent["data"] = {};
      try { data = JSON.parse(message.data) as AnalysisEvent["data"]; } catch { /* Keep the event type if an older server sends empty data. */ }
      onEvent({ type: name, data });
      if (name === "partial" || name === "completed" || name === "failed" || name === "cancelled") {
        onConnection?.(true);
        source?.close();
      }
    });
  };
  connect();
  return () => { closed = true; window.clearTimeout(retryTimer); source?.close(); onConnection?.(false); };
}

function fixtureStream(id: string, onEvent: EventHandler, onConnection?: (connected: boolean) => void): () => void {
  const timers: number[] = [];
  const partial = id === fixtureId("partial");
  const finalStatus: JobStatus = partial ? "PARTIAL" : "COMPLETED";
  const steps: Array<[number, AnalysisEventName, Partial<StatusSnapshot>]> = [
    [0, "connected", { id, status: "CREATED", stage: "CREATED", progress: 0 }],
    [450, "stage_change", { id, status: "STATIC_ANALYSIS", stage: "STATIC_ANALYSIS", progress: 25 }],
    [950, "progress", { id, status: "RE_ANALYSIS", stage: "RE_ANALYSIS", progress: 60 }],
    [1450, "stage_change", { id, status: "NORMALIZING", stage: "NORMALIZING", progress: 80 }],
    [1950, partial ? "partial" : "completed", { id, status: finalStatus, stage: finalStatus, progress: partial ? 95 : 100 }],
  ];
  onConnection?.(true);
  for (const [delay, type, data] of steps) timers.push(window.setTimeout(() => onEvent({ type, data }), delay));
  return () => { for (const timer of timers) window.clearTimeout(timer); onConnection?.(false); };
}
