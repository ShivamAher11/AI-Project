"""Stage 1 function summarization: deterministic selection, bounded context, validation.

Builds a per-function AI prompt from persisted normalized analysis evidence,
selects functions deterministically (SPEC §26), validates model output strictly
(ai/schemas/validate.py), and caches validated results (ai/cache.py).

No raw binary or full artifact is ever sent to the model. Only bounded snippets
and metadata for the current function are included.

Rate limiting:
- LLM_RPM caps requests per minute.
- LLM_TPM_LIMIT caps output tokens per minute.
- MAX_OUTPUT_TOKENS_PER_ANALYSIS caps total output tokens per analysis.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from pathlib import Path
from typing import Any

from ai.cache import AICache, cache_key
from ai.provider import AIConfigurationError, AIProviderError, MockProvider
from ai.schemas.validate import SchemaValidationError, validate_function_summary

FUNC_MAX_CHARS = int(os.getenv("FUNC_MAX_CHARS", "12000"))
FUNC_AI_K_DEFAULT = int(os.getenv("FUNC_AI_K", "50"))
FUNC_AI_K_LOW_BUDGET = int(os.getenv("FUNC_AI_K_LOW_BUDGET", "20"))
PROMPT_VERSION = "1.0"
OUTPUT_SCHEMA_VERSION = "1.0"
MAX_REPAIRS = 2
MAX_OUTPUT_TOKENS_PER_CALL = 1500
MAX_OUTPUT_TOKENS_PER_ANALYSIS = 60000
LLM_TPM_LIMIT = int(os.getenv("LLM_TPM_LIMIT", "30000"))
LLM_RPM = int(os.getenv("LLM_RPM", "60"))
LOW_BUDGET = os.getenv("LOW_BUDGET", "").strip().lower() in {"1", "true", "yes", "on"}

PROMPT_PATH = Path(__file__).resolve().parents[1] / "ai" / "prompts_v1.0" / "func.json"


def load_func_prompt() -> dict[str, Any]:
    return json.loads(PROMPT_PATH.read_text(encoding="utf-8"))


class SummarizerError(RuntimeError):
    """Raised when Stage 1 cannot produce a usable summary."""


def _norm(value: float, maximum: float) -> float:
    if maximum <= 0:
        return 0.0
    return max(0.0, min(1.0, value / maximum))


def select_functions(
    functions: list[dict[str, Any]],
    *,
    signal_counts: dict[str, int],
    suspicious_api_counts: dict[str, int] | None = None,
    string_counts: dict[str, int] | None = None,
    entry_point: str | None,
    k: int = FUNC_AI_K_DEFAULT,
    low_budget: bool = False,
    est_input_chars: int = 0,
) -> list[str]:
    """Return function IDs ordered by descending deterministic rank, top K.

    Implements SPEC §26 ranking:
    score = 3*rule_hits + 2*suspicious_api + centrality + entry_reachable
            + strings_bonus + log(size)

    Each heterogeneous signal is normalized to [0,1] first:
      centrality ∈ [0,1]
      rule_hits ∈ [0,1] via min(hits/5, 1)
      suspicious_api ∈ [0,1] via min(count/5, 1)
      entry_reachable ∈ {0, 1}
      strings_bonus ∈ [0,1] via min(count/5, 1)
      log(size) scaled/clipped to [0,1]

    Ties break by function address ascending.
    """
    if k < 1:
        k = 1
    if low_budget:
        k = min(k, FUNC_AI_K_LOW_BUDGET)

    if suspicious_api_counts is None:
        suspicious_api_counts = {}
    if string_counts is None:
        string_counts = {}

    rule_hits = [signal_counts.get(f["id"], 0) for f in functions]
    norm_rule = [min(h / 5.0, 1.0) for h in rule_hits]

    suspicious = [suspicious_api_counts.get(f["id"], 0) for f in functions]
    norm_suspicious = [min(c / 5.0, 1.0) for c in suspicious]

    strings_bonus = [min(string_counts.get(f["id"], 0) / 5.0, 1.0) for f in functions]

    sizes = [int(f.get("size") or 0) for f in functions]
    max_log = math.log1p(max(sizes)) if sizes else 0.0
    max_log = max_log if max_log > 0 else 1.0
    norm_log = [
        math.log1p(int(f.get("size") or 0)) / max_log for f in functions
    ]

    centralities = [float(f.get("centrality") or 0.0) for f in functions]
    max_centrality = max(centralities) if centralities else 0.0
    max_centrality = max_centrality if max_centrality > 0 else 1.0

    scored = []
    for f, nr, ns, nb, nl in zip(functions, norm_rule, norm_suspicious, strings_bonus, norm_log):
        fid = f["id"]
        entry_reachable = (
            1.0 if entry_point and f.get("address") == entry_point else 0.0
        )
        score = (
            3.0 * nr
            + 2.0 * ns
            + (float(f.get("centrality") or 0.0) / max_centrality)
            + entry_reachable
            + nb
            + nl
        )
        addr = int(f["address"], 16) if f.get("address", "").startswith("0x") else 0
        scored.append((score, addr, fid))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [fid for _, _, fid in scored[:k]]


def _signal_counts_for_functions(normalized: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hit in normalized.get("rule_hits", []):
        for fid in hit.get("function_ids", []):
            counts[fid] = counts.get(fid, 0) + 1
    return counts


def _relevant_imports(normalized: dict, fid: str) -> list[dict[str, Any]]:
    """Imports directly called by this function (import edges)."""
    import_map = {
        imp.get("name"): imp for imp in normalized.get("imports", [])
    }
    result: list[dict[str, Any]] = []
    for hit in normalized.get("rule_hits", []):
        if fid in hit.get("function_ids", []):
            for ref in hit.get("evidence_refs", []) or []:
                if ref.startswith("I-"):
                    imp = import_map.get(ref[2:])
                    if imp:
                        result.append(imp)
    return result


def _string_ref(row: dict) -> str:
    key = json.dumps([row["offset"], row["value"]], separators=(",", ":"))
    return "STR-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _relevant_strings(normalized: dict, fid: str) -> list[dict[str, Any]]:
    """Strings referenced in evidence for this function via rule hits/signals."""
    string_map = {s.get("offset"): s for s in normalized.get("strings", [])}
    result: list[dict[str, Any]] = []
    for hit in normalized.get("rule_hits", []):
        if fid in hit.get("function_ids", []):
            for ref in hit.get("evidence_refs", []) or []:
                if ref.startswith("STR-"):
                    # STR- ids are hashes; match by value substring or index.
                    for s in normalized.get("strings", []):
                        if s.get("offset") == ref[4:]:
                            result.append(s)
                            break
    return result


def _evidence_ids_for_function(normalized: dict, fid: str) -> set[str]:
    ids: set[str] = set()
    for hit in normalized.get("rule_hits", []):
        if fid in hit.get("function_ids", []):
            ids.update(hit.get("evidence_refs", []) or [])
    return ids


def _suspicious_api_counts(normalized: dict) -> dict[str, int]:
    """Count suspicious API usage per function via import edges."""
    counts: dict[str, int] = {}
    for hit in normalized.get("rule_hits", []):
        if hit.get("absorbed"):
            continue
        for fid in hit.get("function_ids", []):
            counts[fid] = counts.get(fid, 0) + 1
    return counts


def _string_counts(normalized: dict) -> dict[str, int]:
    """Count strings per function via string evidence refs."""
    counts: dict[str, int] = {}
    for hit in normalized.get("rule_hits", []):
        if hit.get("absorbed"):
            continue
        for fid in hit.get("function_ids", []):
            counts[fid] = counts.get(fid, 0) + 1
    return counts


def build_function_context(
    normalized: dict,
    fid: str,
    *,
    analysis_id: str,
    input_hash: str,
) -> dict[str, Any]:
    """Build bounded, function-scoped AI input evidence for one function."""
    function = next(
        (f for f in normalized.get("functions", []) if f["id"] == fid), None
    )
    if function is None:
        raise ValueError(f"Function {fid} not found in analysis.")

    decomp = function.get("decompiled_excerpt") or ""
    assembly = function.get("assembly_excerpt") or ""

    context_chars = len(decomp) + len(assembly)
    max_decomp_chars = FUNC_MAX_CHARS
    if context_chars > max_decomp_chars:
        # Drop assembly first, then decompilation tail.
        assembly = ""
        decomp = decomp[:max_decomp_chars]

    return {
        "analysis_id": analysis_id,
        "input_hash": input_hash,
        "function": {
            "id": function["id"],
            "address": function.get("address", ""),
            "name": function.get("name", ""),
            "signature": function.get("signature", ""),
            "size": function.get("size", 0),
            "decompiler_status": function.get("decompiler_status", ""),
            "centrality": function.get("centrality", 0.0),
        },
        "decompilation_excerpt": decomp,
        "assembly_excerpt": assembly,
        "rule_hits": _relevant_imports(normalized, fid),
        "imports": _relevant_imports(normalized, fid),
        "strings": _relevant_strings(normalized, fid),
        "evidence_ids": sorted(_evidence_ids_for_function(normalized, fid)),
    }


def _render_context(context: dict[str, Any]) -> str:
    """Render context as bounded JSON text for the model."""
    return json.dumps(context, ensure_ascii=True, separators=(",", ":"))


class Stage1Summarizer:
    """Orchestrates Stage 1: select, build context, call model, validate, cache."""

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

    def summarize_analysis(
        self,
        normalized: dict,
        *,
        k: int = FUNC_AI_K_DEFAULT,
        low_budget: bool = False,
        est_input_chars: int = 0,
    ) -> dict[str, dict[str, Any] | None]:
        """Return {function_id: validated summary or None} for selected functions.

        Applies the SPEC §26 budget rules:
        - Default K=50, reduced to K=20 when est_input_chars > 120_000,
          LOW_BUDGET is set, or a prior 429 was observed.
        - If K=20 still exceeds the character budget, mark AI DEGRADED
          (return empty dict) rather than sending oversized requests.
        """
        analysis_id = normalized["analysis_id"]
        input_hash = normalized.get("provenance", {}).get("input_hash", "")
        functions = normalized.get("functions", [])
        if not functions:
            return {}

        signal_counts = _signal_counts_for_functions(normalized)
        suspicious_api_counts = _suspicious_api_counts(normalized)
        string_counts = _string_counts(normalized)
        entry_point = normalized.get("file", {}).get("entry_point")

        # Budget rule: reduce K to 20 when over budget.
        reduced_k = k
        k_reduced = False
        if est_input_chars > 120000 or low_budget or LOW_BUDGET:
            reduced_k = min(k, FUNC_AI_K_LOW_BUDGET)
            k_reduced = True

        selected = select_functions(
            functions,
            signal_counts=signal_counts,
            suspicious_api_counts=suspicious_api_counts,
            string_counts=string_counts,
            entry_point=entry_point,
            k=reduced_k,
            low_budget=k_reduced,
            est_input_chars=est_input_chars,
        )

        results: dict[str, dict[str, Any] | None] = {}
        for fid in selected:
            if self.tokens_used >= MAX_OUTPUT_TOKENS_PER_ANALYSIS:
                break
            summary = self._summarize_one(
                normalized, fid, analysis_id, input_hash, k_reduced
            )
            results[fid] = summary
        return results

    def summarize_function(
        self, normalized: dict, function_id: str
    ) -> dict[str, Any] | None:
        """Summarize exactly one requested function for an explicit user action."""
        if not any(row.get("id") == function_id for row in normalized.get("functions", [])):
            raise ValueError("Function does not belong to this analysis.")
        analysis_id = normalized["analysis_id"]
        input_hash = normalized.get("provenance", {}).get("input_hash", "")
        return self._summarize_one(
            normalized, function_id, analysis_id, input_hash, False
        )

    def _summarize_one(
        self,
        normalized: dict,
        fid: str,
        analysis_id: str,
        input_hash: str,
        k_reduced: bool,
    ) -> dict[str, Any] | None:
        context = build_function_context(
            normalized, fid, analysis_id=analysis_id, input_hash=input_hash
        )
        rendered = _render_context(context)
        evidence_ids = set(context["evidence_ids"])
        function_ids = {f["id"] for f in normalized.get("functions", [])}

        model_name = "mock"
        config = getattr(self.provider, "config", None)
        if config is not None:
            model_name = getattr(config, "model", "mock") or "mock"

        key = cache_key(
            model=model_name,
            prompt_version=PROMPT_VERSION,
            schema_version=OUTPUT_SCHEMA_VERSION,
            input_hash=input_hash + ":" + fid,
        )
        cached = self.cache.get(key)
        if cached is not None:
            return cached

        prompt = load_func_prompt()
        summary = self._call_with_repair(
            context=context,
            evidence_ids=evidence_ids,
            function_ids=function_ids,
            fid=fid,
            prompt=prompt,
            model_name=model_name,
            input_hash=input_hash,
            k_reduced=k_reduced,
        )
        if summary is not None:
            self.cache.set(key, summary)
        return summary

    def _call_with_repair(
        self,
        *,
        context: dict[str, Any],
        evidence_ids: set[str],
        function_ids: set[str],
        fid: str,
        prompt: dict[str, Any],
        model_name: str,
        input_hash: str,
        k_reduced: bool,
    ) -> dict[str, Any] | None:
        system_prompt = prompt["system"]
        template = prompt["user_template"]
        rendered_context = json.dumps(context, ensure_ascii=True, separators=(",", ":"))
        function = context["function"]
        last_error = ""
        for attempt in range(self.max_repairs + 1):
            user_prompt = template.format(
                function_id=function["id"],
                address=function.get("address", ""),
                name=function.get("name", ""),
                signature=function.get("signature", "") or "",
                size=function.get("size", 0),
                decompiler_status=function.get("decompiler_status", ""),
                analysis_id=context["analysis_id"],
                input_hash=context["input_hash"],
                rule_hits=json.dumps(context["rule_hits"], ensure_ascii=True),
                imports=json.dumps(context["imports"], ensure_ascii=True),
                strings=json.dumps(context["strings"], ensure_ascii=True),
                evidence=rendered_context,
            )
            est_tokens = len(rendered_context) // 4
            try:
                self._check_rate_limits(est_tokens)
            except AIProviderError as exc:
                last_error = str(exc)
                return None
            try:
                raw = self.provider.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=MAX_OUTPUT_TOKENS_PER_CALL,
                    response_format={"type": "json_object"},
                )
            except AIConfigurationError as exc:
                # AI disabled: keep deterministic results, mark degraded externally.
                last_error = str(exc)
                return None
            except AIProviderError as exc:
                last_error = str(exc)
                if (
                    "429" in str(exc)
                    and self.tokens_used < MAX_OUTPUT_TOKENS_PER_ANALYSIS
                ):
                    continue
                return None
            except (ValueError, KeyError, TypeError) as exc:
                last_error = f"unparseable model output: {exc}"
                continue
            try:
                validate_function_summary(
                    raw, function_ids=function_ids, evidence_ids=evidence_ids
                )
            except SchemaValidationError as exc:
                last_error = str(exc)
                if attempt < self.max_repairs:
                    continue
                return None
            # Track token usage conservatively: count rendered prompt + output.
            est_tokens = len(rendered_context) // 4 + len(json.dumps(raw)) // 4
            self.tokens_used += est_tokens
            self.requests_used += 1
            self._record_call(est_tokens)
            self.calls_log.append(
                {
                    "function_id": fid,
                    "input_hash": input_hash,
                    "k_reduced": k_reduced,
                    "est_tokens": est_tokens,
                }
            )
            return raw
        return None
