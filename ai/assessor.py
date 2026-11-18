"""Stage 2+3 AI pipeline: evidence correlation and report synthesis.

Stage 2 (correlate): takes function summaries, rule hits, findings, imports,
strings, and call edges → behavior findings with evidence IDs and affected
function IDs.

Stage 3 (report): takes metadata, deterministic findings, risk score,
function summaries, correlations, and tool results → final evidence-based
assessment with verdict, summary, evidence_ids, rationale, uncertainty,
and limitations.

All model output is validated strictly against versioned schemas. Raw binary
content, file paths, and credentials are never sent to the model.

Rate limiting:
- LLM_RPM caps requests per minute.
- LLM_TPM_LIMIT caps output tokens per minute.
- MAX_OUTPUT_TOKENS_PER_ANALYSIS caps total output tokens per analysis.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai.cache import AICache, cache_key
from ai.provider import AIConfigurationError, AIProviderError, LLMProvider
from ai.schemas.validate import (
    SchemaValidationError,
    validate_assessment,
    validate_correlation,
)

PROMPT_DIR = Path(__file__).resolve().parent / "prompts_v1.0"
CORRELATE_PROMPT_VERSION = "1.0"
CORRELATE_SCHEMA_VERSION = "1.0"
REPORT_PROMPT_VERSION = "1.5"
REPORT_SCHEMA_VERSION = "1.0"
MAX_REPAIRS = 2
MAX_OUTPUT_TOKENS_PER_CALL = 1500
MAX_OUTPUT_TOKENS_PER_ANALYSIS = 60000
LLM_TPM_LIMIT = int(os.getenv("LLM_TPM_LIMIT", "30000"))
LLM_RPM = int(os.getenv("LLM_RPM", "60"))

# Verdicts that require at least one evidence ID.
_LIKELY_VERDICTS = {"LIKELY_MALICIOUS", "LIKELY_BENIGN"}


@dataclass
class AssessResult:
    """Outcome of the Stage 2+3 assessment pipeline."""

    stage: str  # "correlate" or "report"
    output: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    tokens_used: int = 0
    requests_used: int = 0


@dataclass
class PipelineBudget:
    """Tracks tool calls and output tokens across the AI pipeline."""

    calls: int = 0
    output_bytes: int = 0
    calls_log: list[dict[str, Any]] = field(default_factory=list)

    def remaining_calls(self, max_calls: int = 52) -> int:
        return max(0, max_calls - self.calls)

    def check_capacity(self, max_calls: int = 52, max_output_bytes: int = 60_000 * 4) -> None:
        if self.calls >= max_calls:
            raise AIProviderError(
                f"Tool call budget exhausted ({max_calls} calls)."
            )
        if self.output_bytes >= max_output_bytes:
            raise AIProviderError(
                f"Tool output budget exhausted ({max_output_bytes} bytes)."
            )

    def record_call(self, output_bytes: int) -> None:
        self.calls += 1
        self.output_bytes += output_bytes


def _load_prompt(name: str) -> dict[str, Any]:
    path = PROMPT_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_text(value: Any, limit: int = 500) -> str:
    if value is None:
        return ""
    cleaned = "".join(
        ch if ch in "\n\t" or ord(ch) >= 32 else " " for ch in str(value)
    )
    return cleaned[:limit]


def _count_evidence_ids(output: dict[str, Any]) -> set[str]:
    """Collect every evidence ID referenced by a validated output."""
    ids: set[str] = set()
    for key in ("evidence_ids",):
        for item in output.get(key, []) or []:
            if isinstance(item, str):
                ids.add(item)
    for finding in output.get("behavior_findings", []) or []:
        for item in finding.get("evidence_ids", []) or []:
            if isinstance(item, str):
                ids.add(item)
    return ids


def _normalize_assessment_output(
    output: Any, *, evidence_ids: set[str]
) -> Any:
    """Normalize common report-shape omissions without inventing evidence."""
    if not isinstance(output, dict):
        return output
    normalized = dict(output)
    if isinstance(normalized.get("limitations"), str):
        limitation = normalized["limitations"].strip()
        normalized["limitations"] = [limitation] if limitation else []
    if "evidence_ids" not in normalized:
        response_text = "\n".join(
            value
            for key in ("summary", "rationale", "uncertainty", "limitations")
            for value in (
                normalized.get(key, [])
                if isinstance(normalized.get(key), list)
                else [normalized.get(key, "")]
            )
            if isinstance(value, str)
        )
        # Recover only exact IDs from this analysis that the model cited in its text.
        normalized["evidence_ids"] = sorted(
            evidence_id for evidence_id in evidence_ids if evidence_id in response_text
        )
    return normalized


def _evidence_catalog(normalized: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return detector evidence references with the observations they identify."""
    catalog: dict[str, dict[str, Any]] = {}
    for row in normalized.get("imports", []):
        name = row.get("name", "")
        key = json.dumps(
            [row.get("library"), name, row.get("address")],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        ref = "I-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        catalog[ref] = {
            "source_type": "import",
            "excerpt": name,
            "library": row.get("library"),
            "address": row.get("address"),
        }

    for row in normalized.get("strings", []):
        key = json.dumps(
            [row.get("offset"), row.get("value")],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        ref = "STR-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        catalog[ref] = {
            "source_type": "string",
            "excerpt": _safe_text(row.get("value"), 300),
            "address": row.get("offset"),
        }

    for row in normalized.get("functions", []):
        text = "\n".join(
            part or ""
            for part in (row.get("decompiled_excerpt"), row.get("assembly_excerpt"))
        )
        if text:
            catalog[f"F:{row['id']}"] = {
                "source_type": "function",
                "excerpt": _safe_text(text, 300),
                "address": row.get("address"),
            }

    return catalog


class ReportAssessor:
    """Orchestrates Stage 2 correlation and Stage 3 report synthesis.

    Uses an injectable provider (MockProvider in tests, LLMProvider live).
    All output is validated strictly. Evidence IDs are grounded to the
    current analysis. Budget (calls + output tokens) is tracked across
    both stages.
    """

    def __init__(
        self,
        provider: Any,
        cache: AICache | None = None,
        *,
        max_repairs: int = MAX_REPAIRS,
    ) -> None:
        self.provider = provider
        self.cache = cache or AICache()
        self.max_repairs = max_repairs
        self.tokens_used = 0
        self.requests_used = 0
        self.budget = PipelineBudget()
        self.calls_log: list[dict[str, Any]] = []
        self.request_times: list[float] = []
        self.tokens_per_minute: list[tuple[float, int]] = []

    def _check_rate_limits(self, est_tokens: int) -> None:
        """Enforce LLM_RPM and LLM_TPM_LIMIT before a call.

        Raises AIProviderError if the call would exceed either per-minute limit.
        """
        now = time.monotonic()
        window = 60.0

        # Prune old entries.
        self.request_times = [t for t in self.request_times if now - t < window]
        self.tokens_per_minute = [
            (t, tokens)
            for t, tokens in self.tokens_per_minute
            if now - t < window
        ]

        if len(self.request_times) >= LLM_RPM:
            raise AIProviderError(
                f"LLM rate limit exceeded ({LLM_RPM} requests/minute)."
            )

        minute_tokens = sum(tokens for _, tokens in self.tokens_per_minute)
        if minute_tokens + est_tokens > LLM_TPM_LIMIT:
            raise AIProviderError(
                f"LLM token rate limit exceeded ({LLM_TPM_LIMIT} tokens/minute)."
            )

    def _record_call(self, est_tokens: int) -> None:
        now = time.monotonic()
        self.request_times.append(now)
        self.tokens_per_minute.append((now, est_tokens))

    # ------------------------------------------------------------------
    # Stage 2: correlate
    # ------------------------------------------------------------------
    def correlate(
        self,
        *,
        analysis_id: str,
        input_hash: str,
        normalized: dict[str, Any],
        function_summaries: dict[str, dict[str, Any] | None],
        tool_results: list[dict[str, Any]] | None = None,
    ) -> AssessResult:
        """Run Stage 2 behavior correlation."""
        prompt = _load_prompt("correlate.json")
        system_prompt = prompt["system"]
        template = prompt["user_template"]

        # Build bounded context from validated function summaries only.
        valid_summaries = {
            fid: s for fid, s in (function_summaries or {}).items() if s is not None
        }

        summaries_text = json.dumps(
            [
                {"function_id": fid, **{k: v for k, v in s.items() if k != "evidence_ids"}}
                for fid, s in valid_summaries.items()
            ],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        if len(summaries_text) > 40000:
            summaries_text = summaries_text[:40000]

        rule_hits = normalized.get("rule_hits", [])
        findings = normalized.get("findings", [])
        imports = normalized.get("imports", [])
        strings = normalized.get("strings", [])
        edges = normalized.get("edges", [])

        # Collect all valid evidence IDs from the normalized analysis.
        all_evidence_ids: set[str] = set()
        for sig in normalized.get("signals", []):
            for ref in sig.get("evidence_refs", []) or []:
                all_evidence_ids.add(ref)
        for hit in rule_hits:
            for ref in hit.get("evidence_refs", []) or []:
                all_evidence_ids.add(ref)
        for fid, summary in valid_summaries.items():
            for ref in summary.get("evidence_ids", []) or []:
                all_evidence_ids.add(ref)

        context = {
            "analysis_id": analysis_id,
            "input_hash": input_hash,
            "rule_hits": rule_hits,
            "summaries": summaries_text,
            "imports": imports,
            "strings": strings,
            "edges": edges,
            "evidence": json.dumps(
                {"analysis_id": analysis_id, "evidence_count": len(all_evidence_ids)},
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        }

        rendered = json.dumps(context, ensure_ascii=True, separators=(",", ":"))
        function_ids = {f["id"] for f in normalized.get("functions", [])}

        model_name = "mock"
        config = getattr(self.provider, "config", None)
        if config is not None:
            model_name = getattr(config, "model", "mock") or "mock"

        key = cache_key(
            model=model_name,
            prompt_version=CORRELATE_PROMPT_VERSION,
            schema_version=CORRELATE_SCHEMA_VERSION,
            input_hash=input_hash + ":correlate",
        )
        cached = self.cache.get(key)
        if cached is not None:
            return AssessResult(
                stage="correlate",
                output=cached,
                error_code=None,
                error_message=None,
                tokens_used=0,
                requests_used=0,
            )

        self.budget.check_capacity()
        user_prompt = template.format(
            analysis_id=analysis_id,
            input_hash=input_hash,
            rule_hits=json.dumps(rule_hits, ensure_ascii=True),
            summaries=summaries_text,
            imports=json.dumps(imports, ensure_ascii=True),
            strings=json.dumps(strings, ensure_ascii=True),
            edges=json.dumps(edges, ensure_ascii=True),
            evidence=rendered,
        )

        est_tokens = len(rendered) // 4
        try:
            self._check_rate_limits(est_tokens)
        except AIProviderError as exc:
            return AssessResult(
                stage="correlate",
                output=None,
                error_code="RATE_LIMIT",
                error_message=str(exc),
            )

        last_error = ""
        output: dict[str, Any] | None = None
        for attempt in range(self.max_repairs + 1):
            try:
                raw = self.provider.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=MAX_OUTPUT_TOKENS_PER_CALL,
                    response_format={"type": "json_object"},
                )
            except AIConfigurationError as exc:
                return AssessResult(
                    stage="correlate",
                    output=None,
                    error_code="AI_DISABLED",
                    error_message=str(exc),
                )
            except AIProviderError as exc:
                last_error = str(exc)
                if "429" in str(exc) and self.tokens_used < MAX_OUTPUT_TOKENS_PER_ANALYSIS:
                    continue
                return AssessResult(
                    stage="correlate",
                    output=None,
                    error_code="AI_PROVIDER_UNAVAILABLE",
                    error_message=last_error,
                )
            except (ValueError, KeyError, TypeError) as exc:
                last_error = f"unparseable model output: {exc}"
                continue
            try:
                validate_correlation(
                    raw,
                    evidence_ids=all_evidence_ids,
                    function_ids=function_ids,
                )
            except SchemaValidationError as exc:
                last_error = str(exc)
                if attempt < self.max_repairs:
                    continue
                return AssessResult(
                    stage="correlate",
                    output=None,
                    error_code="GROUNDING_FAIL",
                    error_message=last_error,
                )
            output = raw
            break

        if output is None:
            return AssessResult(
                stage="correlate",
                output=None,
                error_code="GROUNDING_FAIL",
                error_message=last_error or "correlation output dropped after repairs",
            )

        est_tokens = len(rendered) // 4 + len(json.dumps(output)) // 4
        self.tokens_used += est_tokens
        self.requests_used += 1
        output_bytes = len(json.dumps(output).encode("utf-8"))
        self.budget.record_call(output_bytes)
        self._record_call(est_tokens)
        self.calls_log.append(
            {
                "stage": "correlate",
                "input_hash": input_hash,
                "est_tokens": est_tokens,
                "output_bytes": output_bytes,
            }
        )
        self.cache.set(key, output)
        return AssessResult(
            stage="correlate",
            output=output,
            error_code=None,
            error_message=None,
            tokens_used=est_tokens,
            requests_used=1,
        )

    # ------------------------------------------------------------------
    # Stage 3: report
    # ------------------------------------------------------------------
    def report(
        self,
        *,
        analysis_id: str,
        input_hash: str,
        normalized: dict[str, Any],
        correlation_output: dict[str, Any] | None,
        function_summaries: dict[str, dict[str, Any] | None],
        tool_results: list[dict[str, Any]] | None = None,
    ) -> AssessResult:
        """Run Stage 3 report synthesis and produce the final assessment."""
        prompt = _load_prompt("report.json")
        system_prompt = prompt["system"]
        template = prompt["user_template"]

        valid_summaries = {
            fid: s for fid, s in (function_summaries or {}).items() if s is not None
        }

        summaries_text = json.dumps(
            [
                {"function_id": fid, **{k: v for k, v in s.items() if k != "evidence_ids"}}
                for fid, s in valid_summaries.items()
            ],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        if len(summaries_text) > 40000:
            summaries_text = summaries_text[:40000]

        metadata = {
            "original_filename": normalized.get("file", {}).get("original_filename", ""),
            "format": normalized.get("file", {}).get("format", ""),
            "arch": normalized.get("file", {}).get("arch", ""),
            "size": normalized.get("file", {}).get("size", 0),
            "entry_point": normalized.get("file", {}).get("entry_point", ""),
            "sha256": normalized.get("sha256", ""),
            "parser_coverage": normalized.get("parser_coverage", "none"),
            "parser_limitations": normalized.get("parser_limitations", ""),
        }

        findings = normalized.get("findings", [])
        scoring = normalized.get("scoring", {})
        risk_score = scoring.get("score", 0)
        risk_rating = scoring.get("rating", "Low")

        correlations_text = json.dumps(correlation_output or {}, ensure_ascii=True, separators=(",", ":"))
        if len(correlations_text) > 20000:
            correlations_text = correlations_text[:20000]

        tool_results_text = json.dumps(tool_results or [], ensure_ascii=True, separators=(",", ":"))
        if len(tool_results_text) > 10000:
            tool_results_text = tool_results_text[:10000]

        # Collect all valid evidence IDs from the normalized analysis + summaries + correlation.
        all_evidence_ids: set[str] = set()
        for sig in normalized.get("signals", []):
            for ref in sig.get("evidence_refs", []) or []:
                all_evidence_ids.add(ref)
        for hit in normalized.get("rule_hits", []):
            for ref in hit.get("evidence_refs", []) or []:
                all_evidence_ids.add(ref)
        for fid, summary in valid_summaries.items():
            for ref in summary.get("evidence_ids", []) or []:
                all_evidence_ids.add(ref)
        if correlation_output:
            for ref in correlation_output.get("evidence_ids", []) or []:
                all_evidence_ids.add(ref)
            for finding in correlation_output.get("behavior_findings", []) or []:
                for ref in finding.get("evidence_ids", []) or []:
                    all_evidence_ids.add(ref)

        evidence_catalog = _evidence_catalog(normalized)

        context = {
            "analysis_id": analysis_id,
            "input_hash": input_hash,
            "metadata": metadata,
            "findings": findings,
            "risk_score": risk_score,
            "risk_rating": risk_rating,
            "summaries": summaries_text,
            "correlations": correlations_text,
            "tool_results": tool_results_text,
            "evidence": json.dumps(
                {
                    "analysis_id": analysis_id,
                    "observations": [
                        {"id": evidence_id, **evidence_catalog[evidence_id]}
                        for evidence_id in sorted(all_evidence_ids)
                        if evidence_id in evidence_catalog
                    ],
                    "unresolved_evidence_ids": sorted(
                        all_evidence_ids - evidence_catalog.keys()
                    ),
                    "finding_count": len(findings),
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        }

        rendered = json.dumps(context, ensure_ascii=True, separators=(",", ":"))

        model_name = "mock"
        config = getattr(self.provider, "config", None)
        if config is not None:
            model_name = getattr(config, "model", "mock") or "mock"

        key = cache_key(
            model=model_name,
            prompt_version=REPORT_PROMPT_VERSION,
            schema_version=REPORT_SCHEMA_VERSION,
            input_hash=input_hash + ":report",
        )
        cached = self.cache.get(key)
        if cached is not None:
            return AssessResult(
                stage="report",
                output=cached,
                error_code=None,
                error_message=None,
                tokens_used=0,
                requests_used=0,
            )

        self.budget.check_capacity()
        user_prompt = template.format(
            analysis_id=analysis_id,
            input_hash=input_hash,
            metadata=json.dumps(metadata, ensure_ascii=True),
            findings=json.dumps(findings, ensure_ascii=True),
            risk_score=risk_score,
            risk_rating=risk_rating,
            summaries=summaries_text,
            correlations=correlations_text,
            tool_results=tool_results_text,
            evidence=rendered,
        )

        est_tokens = len(rendered) // 4
        try:
            self._check_rate_limits(est_tokens)
        except AIProviderError as exc:
            return AssessResult(
                stage="report",
                output=None,
                error_code="RATE_LIMIT",
                error_message=str(exc),
            )

        last_error = ""
        output: dict[str, Any] | None = None
        for attempt in range(self.max_repairs + 1):
            try:
                raw = self.provider.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=MAX_OUTPUT_TOKENS_PER_CALL,
                    response_format={"type": "json_object"},
                )
            except AIConfigurationError as exc:
                return AssessResult(
                    stage="report",
                    output=None,
                    error_code="AI_DISABLED",
                    error_message=str(exc),
                )
            except AIProviderError as exc:
                last_error = str(exc)
                if "429" in str(exc) and self.tokens_used < MAX_OUTPUT_TOKENS_PER_ANALYSIS:
                    continue
                return AssessResult(
                    stage="report",
                    output=None,
                    error_code="AI_PROVIDER_UNAVAILABLE",
                    error_message=last_error,
                )
            except (ValueError, KeyError, TypeError) as exc:
                last_error = f"unparseable model output: {exc}"
                continue
            try:
                raw = _normalize_assessment_output(raw, evidence_ids=all_evidence_ids)
                validate_assessment(raw, evidence_ids=all_evidence_ids)
            except SchemaValidationError as exc:
                last_error = str(exc)
                if attempt < self.max_repairs:
                    continue
                return AssessResult(
                    stage="report",
                    output=None,
                    error_code="GROUNDING_FAIL",
                    error_message=last_error,
                )
            output = raw
            break

        if output is None:
            return AssessResult(
                stage="report",
                output=None,
                error_code="GROUNDING_FAIL",
                error_message=last_error or "assessment output dropped after repairs",
            )

        est_tokens = len(rendered) // 4 + len(json.dumps(output)) // 4
        self.tokens_used += est_tokens
        self.requests_used += 1
        output_bytes = len(json.dumps(output).encode("utf-8"))
        self.budget.record_call(output_bytes)
        self._record_call(est_tokens)
        self.calls_log.append(
            {
                "stage": "report",
                "input_hash": input_hash,
                "est_tokens": est_tokens,
                "output_bytes": output_bytes,
            }
        )
        self.cache.set(key, output)
        return AssessResult(
            stage="report",
            output=output,
            error_code=None,
            error_message=None,
            tokens_used=est_tokens,
            requests_used=1,
        )
