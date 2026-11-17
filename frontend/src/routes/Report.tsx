
import { useEffect, useState } from "react";
import { getOverview, getFindings } from "../lib/api";
import type { OverviewView, FindingView } from "../lib/api";

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

    return () => {
      active = false;
    };
  }, [analysisId]);

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

            <pre className="report-preview">{report}</pre>
          </section>
        </>
      )}
    </div>
  );
}