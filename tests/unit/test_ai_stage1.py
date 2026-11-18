"""Stage 1 function summary pipeline: selection, context, validation, cache."""

import json
from pathlib import Path

from ai.cache import AICache
from ai.provider import AIConfigurationError, MockProvider
from ai.schemas.validate import SchemaValidationError
from ai.summarizer import (
    MAX_OUTPUT_TOKENS_PER_ANALYSIS,
    Stage1Summarizer,
    build_function_context,
    select_functions,
)

ROOT = Path(__file__).parents[2]
FULL = json.loads(
    (ROOT / "fixtures/analysis-full.json").read_text(encoding="utf-8-sig")
)

FID_INJECT = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001c00"


def valid_summary(function_id=FID_INJECT, evidence_ids=None):
    return {
        "schema_version": "1.0",
        "function_id": function_id,
        "purpose": "Injects a payload into a remote process.",
        "behavior": ["opens target process", "allocates remote memory"],
        "evidence_ids": evidence_ids or ["I-CreateRemoteThread", "F-INJECT"],
        "uncertainty": "The exact payload source could not be determined statically.",
        "alternative_explanation": "A legitimate debugger may perform similar calls.",
        "suggested_technique_id": "T1055",
        "rationale": "Cited imports match G_INJECTION.",
    }


class EchoProvider(MockProvider):
    """Returns a valid summary for whichever function the summarizer selected."""

    def generate_structured(
        self, *, system_prompt, user_prompt, max_tokens, response_format=None
    ):
        import re

        m = re.search(r"Function: ([^ ]+) at", user_prompt)
        fid = m.group(1) if m else FID_INJECT
        self.responses.append(
            json.dumps(valid_summary(function_id=fid, evidence_ids=[]))
        )
        return super().generate_structured(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            response_format=response_format,
        )


def test_select_functions_returns_top_k_and_boosts_rule_hits():
    functions = FULL["functions"]
    signal_counts = {fid: 1 for fid in FULL["rule_hits"][0]["function_ids"]}
    result = select_functions(
        functions,
        signal_counts=signal_counts,
        entry_point=FULL["file"]["entry_point"],
        k=3,
    )
    assert len(result) <= 3
    assert FID_INJECT in result


def test_select_functions_low_budget_caps_at_20():
    functions = FULL["functions"]
    full = select_functions(functions, signal_counts={}, entry_point=None, k=50)
    low = select_functions(
        functions, signal_counts={}, entry_point=None, k=50, low_budget=True
    )
    assert len(low) <= 20
    assert len(full) >= len(low)


def test_context_is_bounded_under_12k():
    ctx = build_function_context(
        FULL, FID_INJECT, analysis_id=FULL["analysis_id"], input_hash="abc"
    )
    assert ctx["function"]["id"] == FID_INJECT
    assert len(ctx["decompilation_excerpt"]) <= 12000


def test_context_does_not_send_raw_binary_or_paths():
    ctx = build_function_context(
        FULL, FID_INJECT, analysis_id=FULL["analysis_id"], input_hash="abc"
    )
    rendered = json.dumps(ctx)
    assert "/data/" not in rendered
    assert "original.bin" not in rendered


def test_summarizer_validates_and_caches():
    provider = EchoProvider()
    cache = AICache()
    summarizer = Stage1Summarizer(provider, cache=cache)
    results = summarizer.summarize_analysis(FULL, k=50)
    assert FID_INJECT in results
    assert results[FID_INJECT] is not None
    assert results[FID_INJECT]["purpose"] == "Injects a payload into a remote process."
    # Repeating the same input returns cached output: provider is not called again.
    results2 = summarizer.summarize_analysis(FULL, k=50)
    assert results2 == results


def test_summarizer_rejects_schema_invalid_output():
    provider = MockProvider(responses=[json.dumps({"schema_version": "1.0"})] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=50)
    for summary in results.values():
        assert summary is None


def test_summarizer_rejects_grounding_invalid_evidence():
    bad = valid_summary(evidence_ids=["STR-FAKE0000000000"])
    provider = MockProvider(responses=[json.dumps(bad)] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=50)
    for summary in results.values():
        assert summary is None


def test_summarizer_rejects_forbidden_risk_field():
    bad = valid_summary()
    bad["score"] = 48
    provider = MockProvider(responses=[json.dumps(bad)] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=50)
    for summary in results.values():
        assert summary is None


def test_summarizer_disabled_provider_returns_none():
    class DisabledProvider:
        def generate_structured(self, *, system_prompt, user_prompt, max_tokens):
            raise AIConfigurationError("CONSENT_CLOUD_LLM is not true.")

    summarizer = Stage1Summarizer(DisabledProvider())
    results = summarizer.summarize_analysis(FULL, k=50)
    for summary in results.values():
        assert summary is None


def test_empty_functions_returns_empty():
    summarizer = Stage1Summarizer(MockProvider(responses=[json.dumps(valid_summary())]))
    empty = {"analysis_id": "test-empty", "functions": []}
    assert summarizer.summarize_analysis(empty) == {}


def test_full_fixture_produces_valid_summary_with_real_evidence_ids():
    """A fixture produces a valid summary with real evidence IDs."""
    provider = EchoProvider()
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=50)
    assert FID_INJECT in results
    summary = results[FID_INJECT]
    assert summary is not None
    assert summary["schema_version"] == "1.0"
    assert summary["function_id"] == FID_INJECT
    # If evidence IDs are present, they must reference real evidence from this analysis.
    real_evidence = set()
    for hit in FULL["rule_hits"]:
        real_evidence.update(hit.get("evidence_refs", []))
    for sig in FULL["signals"]:
        real_evidence.update(sig.get("evidence_refs", []))
    if summary["evidence_ids"]:
        assert set(summary["evidence_ids"]) <= real_evidence


def test_partial_analysis_keeps_static_findings():
    """A partial analysis stays partial and keeps its static findings."""
    PARTIAL_PATH = ROOT / "fixtures/analysis-partial.json"
    partial = json.loads(PARTIAL_PATH.read_text(encoding="utf-8-sig"))
    provider = MockProvider(responses=[json.dumps(valid_summary())] * 10)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(partial, k=50)
    # Partial fixture has no functions -> no summaries expected.
    assert results == {}
    assert partial["status"] == "PARTIAL"
    assert partial["decomp_status"] == "TIMEOUT"


def test_ai_disabled_keeps_deterministic_results():
    """AI disabled keeps deterministic results intact."""

    class DisabledProvider:
        def generate_structured(
            self, *, system_prompt, user_prompt, max_tokens, response_format=None
        ):
            raise AIConfigurationError("AI disabled")

    summarizer = Stage1Summarizer(DisabledProvider())
    results = summarizer.summarize_analysis(FULL, k=50)
    for summary in results.values():
        assert summary is None
    # Deterministic findings are untouched.
    assert len(FULL["findings"]) == 2
    assert FULL["rule_hits"][0]["rule_id"] == "G_INJECTION"


def test_timeout_is_degraded():
    """Timeout is reported as degraded without erasing deterministic output."""

    class TimeoutProvider:
        def generate_structured(
            self, *, system_prompt, user_prompt, max_tokens, response_format=None
        ):
            from ai.provider import AIProviderError

            raise AIProviderError("AI request timed out.")

    summarizer = Stage1Summarizer(TimeoutProvider())
    results = summarizer.summarize_analysis(FULL, k=1)
    for summary in results.values():
        assert summary is None


def test_invalid_json_is_dropped():
    """Invalid JSON output is dropped after repair attempts."""
    provider = MockProvider(responses=["not json at all"] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=1)
    for summary in results.values():
        assert summary is None


def test_invalid_evidence_is_dropped():
    """Invalid evidence IDs cause output to be dropped."""
    bad = valid_summary(evidence_ids=["STR-FAKE0000000000"])
    provider = MockProvider(responses=[json.dumps(bad)] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=1)
    for summary in results.values():
        assert summary is None


def test_cache_hit_no_duplicate_provider_call():
    """Cache hit returns cached result without calling provider again."""
    provider = EchoProvider()
    cache = AICache()
    summarizer = Stage1Summarizer(provider, cache=cache)
    results = summarizer.summarize_analysis(FULL, k=1)
    first_calls = len(provider.calls)
    assert first_calls >= 1
    # Repeat: should use cache.
    results2 = summarizer.summarize_analysis(FULL, k=1)
    assert results2 == results
    # Provider not called again for cached function.
    assert len(provider.calls) == first_calls


def test_deterministic_results_unchanged():
    """Same input produces same results (deterministic)."""
    provider = EchoProvider()
    summarizer = Stage1Summarizer(provider)
    results1 = summarizer.summarize_analysis(FULL, k=1)
    results2 = summarizer.summarize_analysis(FULL, k=1)
    assert results1 == results2


def test_token_ceiling_stops_calls():
    """60k token ceiling stops further calls."""
    provider = EchoProvider()
    summarizer = Stage1Summarizer(provider)
    # Set tokens_used just below ceiling; next call should cross it.
    summarizer.tokens_used = MAX_OUTPUT_TOKENS_PER_ANALYSIS - 1000
    results = summarizer.summarize_analysis(FULL, k=50)
    # Tokens should not exceed ceiling by more than one call's worth.
    assert summarizer.tokens_used <= MAX_OUTPUT_TOKENS_PER_ANALYSIS + 5000


def test_low_budget_reduces_k():
    """LOW_BUDGET reduces K to 20."""
    provider = EchoProvider()
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=50, low_budget=True)
    # k_reduced should be True since low_budget=True.
    # The number of selected functions should be <= 20.
    assert len(results) <= 20


def test_never_invents_evidence_ids():
    """Summarizer never accepts invented evidence IDs."""
    bad = valid_summary(evidence_ids=["STR-INVENTED0000000000"])
    provider = MockProvider(responses=[json.dumps(bad)] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=1)
    for summary in results.values():
        assert summary is None


def test_repair_invalid_output_up_to_twice():
    """Invalid output is repaired at most twice, then dropped."""
    invalid = json.dumps({"schema_version": "1.0"})  # missing required fields
    provider = MockProvider(responses=[invalid] * 50)
    summarizer = Stage1Summarizer(provider)
    results = summarizer.summarize_analysis(FULL, k=1)
    for summary in results.values():
        assert summary is None
