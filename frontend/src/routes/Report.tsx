import { useEffect, useState } from "react";
import { getOverview, getFindings, getStatus } from "../lib/api";
import type { OverviewView, FindingView } from "../lib/api";
import { Markdown } from "../components/Markdown";

interface ReportPageProps {
  analysisId: string;
}

function buildMarkdown(
  overview: OverviewView,
  findings: FindingView[]
): string {
  const lines: string[] = [
    "# Static Binary Analysis Report",
    "",
    `**File:** ${overview.file.name}`,
    `**Analysis ID:** ${overview.id}`,
    `**Format:** ${overview.file.format}`,
    `**Architecture:** ${overview.file.arch}`,
    `**File size:** ${overview.file.size} bytes`,
    `**Analysis status:** ${overview.status}`,
    `**Report generated:** ${new Date().toLocaleString()}`,
    "",
    "## File Hashes",
    "",
    `- **SHA-256:** ${overview.file.sha256}`,
    `- **MD5:** ${overview.file.md5}`,
    "",
    "## Risk Assessment",
    "",
    `- **Risk score:** ${overview.risk.score}/100`,
    `- **Risk rating:** ${overview.risk.rating}`,
    "",
    "### Risk Score Breakdown",
    "",
    "| Indicator | Score contribution |",
    "|---|---:|",
    ...overview.risk.breakdown.map(
      (item) => `| ${item.title} | ${item.weight} |`
    ),
    "",
    "## Analysis Statistics",
    "",
    `- Sections: ${overview.counts.sections}`,
    `- Imports: ${overview.counts.imports}`,
    `- Strings: ${overview.counts.strings}`,
    `- Functions: ${overview.counts.functions}`,
    `- Findings: ${findings.length}`,
    "",
    "## AI Assessment",
    "",
    `- **Verdict:** ${overview.aiReport?.verdict ?? "Not available"}`,
    `- **Model:** ${overview.aiReport?.model ?? "Not available"}`,
    `- **Generated at:** ${overview.aiReport?.generated_at ?? "Not available"}`,
    "",
    "### Summary",
    "",
    overview.aiReport?.summary ?? (overview.stage === "AI_ANALYSIS"
      ? "The automatic AI assessment is being generated. This report will refresh when analysis finishes."
      : overview.aiStatus === "DEGRADED" || overview.aiStatus === "DISABLED" || overview.aiStatus === "FAILED"
        ? "Automatic AI assessment did not complete. Deterministic findings remain available."
        : "No AI assessment was saved for this analysis."),
    "",
    "### Rationale",
    "",
    overview.aiReport?.rationale ?? "No rationale provided.",
    "",
    "### Uncertainty",
    "",
    overview.aiReport?.uncertainty ?? "No uncertainty stated.",
    "",
    "### Limitations",
    "",
    ...(overview.aiReport?.limitations ?? []).map((limitation) => `- ${limitation}`),
    "",
    "### Evidence References",
    "",
    ...(overview.aiReport?.evidence_ids ?? []).map((evidenceId, index) => `- E${index + 1}: ${evidenceId}`),
    "",
    "### Disclaimer",
    "",
    overview.aiReport?.disclaimer ?? "AI-generated assessment of selected static evidence; not a verdict.",
    "",
    "## Correlated Behaviors",
    "",
    ...(overview.aiReport?.correlation?.behavior_findings?.length
      ? overview.aiReport.correlation.behavior_findings.flatMap((behavior) => [
          `### ${behavior.title}`,
          "",
          behavior.description,
          "",
          `Evidence: ${behavior.evidence_ids.join(", ") || "None cited"}`,
          "",
        ])
      : [overview.aiReport ? "No correlated behaviors were validated." : "AI enrichment is not available yet.", ""]),
    "## Findings",
    "",
  ];

  if (findings.length === 0) {
    lines.push("No findings were returned for this analysis.", "");
  }

  findings.forEach((finding, index) => {
    lines.push(
      `### ${index + 1}. ${finding.title}`,
      "",
      `- **Severity:** ${finding.severity}`,
      `- **Confidence:** ${finding.confidence}`,
      `- **Score contribution:** ${finding.weight}`,
      `- **Group:** ${finding.groupId}`,
      "",
      "**Observation**",
      "",
      finding.observed || "No observation provided.",
      "",
      "**Interpretation**",
      "",
      finding.interpretation || "No interpretation provided.",
      "",
      "**Alternative explanation**",
      "",
      finding.alternative || "No alternative explanation provided.",
      "",
      "**ATT&CK mappings**",
      ""
    );

    if (finding.attackMappings.length === 0) {
      lines.push("No ATT&CK mappings supplied.", "");
    } else {
      finding.attackMappings.forEach((mapping) => {
        lines.push(
          `- ${mapping.techniqueId} — ${mapping.name} (${mapping.label})`
        );
      });
      lines.push("");
    }

    lines.push("**Evidence**", "");

    if (finding.evidence.length === 0) {
      lines.push("No evidence records supplied.", "");
    } else {
      finding.evidence.forEach((evidence) => {
        lines.push(
          `- **${evidence.sourceType} / ${evidence.sourceId}:** ${evidence.excerpt}`,
          `  - Address/offset: ${evidence.offsetOrAddress ?? "Not available"}`,
          `  - Reason: ${evidence.reason}`
        );
      });
      lines.push("");
    }
  });

  lines.push(
    "## Important Disclaimer",
    "",
    "This report summarizes static analysis results. Heuristic findings and ATT&CK mappings are indicators for further investigation, not proof of malicious activity. A benign explanation may exist. The analyzed binary was not executed as part of this static analysis report.",
    ""
  );

  return lines.join("\n");
}

export function ReportPage({ analysisId }: ReportPageProps) {
  const [overview, setOverview] = useState<OverviewView | null>(null);
  const [findings, setFindings] = useState<FindingView[]>([]);
  const [report, setReport] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadReport() {
      try {
        setLoading(true);
        setError(null);

        const [overviewData, findingsData] = await Promise.all([
          getOverview(analysisId),
          getFindings(analysisId),
        ]);

        if (active) {
          setOverview(overviewData);
          setFindings(findingsData);
          setReport(buildMarkdown(overviewData, findingsData));
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : "Unable to generate the report."
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    loadReport();

    let timer = 0;
    const refresh = async () => {
      try {
        const status = await getStatus(analysisId);
        if (active) {
          setOverview((current) => current ? {
            ...current,
            status: status.status,
            stage: status.stage,
            progress: status.progress,
            aiStatus: status.ai_status,
          } : current);
        }
        if (active && ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"].includes(status.status)) {
          const [overviewData, findingsData] = await Promise.all([
            getOverview(analysisId),
            getFindings(analysisId),
          ]);
          if (active) {
            setOverview(overviewData);
            setFindings(findingsData);
            setReport(buildMarkdown(overviewData, findingsData));
          }
          return;
        }
      } catch { /* Keep the report visible; retry while the analysis is active. */ }
      if (active) timer = window.setTimeout(refresh, 2500);
    };
    timer = window.setTimeout(refresh, 2500);
    return () => { active = false; window.clearTimeout(timer); };
  }, [analysisId]);

  useEffect(() => {
    if (overview) setReport(buildMarkdown(overview, findings));
  }, [overview, findings]);

  function downloadReport() {
    if (!report || !overview) return;

    const blob = new Blob([report], {
      type: "text/markdown;charset=utf-8",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = `analysis-report-${overview.id}.md`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <div className="eyebrow">ANALYSIS OUTPUT</div>
          <h1>Analysis Report</h1>
          <p className="page-description">
            Review and export the static analysis results.
          </p>
        </div>

        <button
          className="primary-button"
          onClick={downloadReport}
          disabled={loading || !!error || !report}
        >
          Download Markdown
        </button>

      </section>

      {loading && (
        <div className="panel empty-state">
          Preparing analysis report...
        </div>
      )}

      {error && (
        <div className="panel error-state" role="alert">
          <strong>Unable to generate report</strong>
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && overview && (
        <>
          <div className="stats-grid">
            <div className="panel stat-card">
              <span className="eyebrow">RISK SCORE</span>
              <strong>{overview.risk.score}/100</strong>
            </div>

            <div className="panel stat-card">
              <span className="eyebrow">RISK RATING</span>
              <strong>{overview.risk.rating}</strong>
            </div>

            <div className="panel stat-card">
              <span className="eyebrow">TOTAL FINDINGS</span>
              <strong>{findings.length}</strong>
            </div>
          </div>

          <section className="panel report-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">REPORT PREVIEW</div>
                <h2>{overview.file.name}</h2>
              </div>

              <span className="count-chip">
                Markdown report
              </span>
            </div>

            <div className="report-preview">
              <Markdown text={report} className="report-markdown" />
            </div>
          </section>
        </>
      )}
    </div>
  );
}
