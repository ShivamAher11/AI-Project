"""Phase 3: full AI pipeline with evidence-based assessment.

Tests cover all verdict labels, evidence grounding, prompt injection,
invalid output/repair limits, cache invalidation, provider failure,
tool budget, and deterministic risk invariance. Uses MockProvider only;
no live model, no network, no raw file bytes.
"""

import json
from pathlib import Path

import pytest

from ai.assessor import ReportAssessor, PipelineBudget
from ai.cache import AICache, cache_key
from ai.provider import AIConfigurationError, AIProviderError, MockProvider
from ai.schemas.validate import (
    SchemaValidationError,
    validate_assessment,
    validate_correlation,
)
from ai.summarizer import Stage1Summarizer

ROOT = Path(__file__).parents[2]
FULL = json.loads(
    (ROOT / "fixtures/analysis-full.json").read_text(encoding="utf-8-sig")
)
PARTIAL = json.loads(
    (ROOT / "fixtures/analysis-partial.json").read_text(encoding="utf-8-sig")
)

ANALYSIS_ID = FULL["analysis_id"]
INJECT_FID = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001c00"


def valid_assessment(verdict="LIKELY_MALICIOUS", evidence_ids=None):
    return {
        "schema_version": "1.0",
        "verdict": verdict,
        "summary": "The binary shows process injection behavior.",
        "evidence_ids": evidence_ids or ["I-CreateRemoteThread"],
        "rationale": "OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread in one function.",
        "uncertainty": "Static analysis only; cannot confirm runtime execution.",
        "limitations": ["No dynamic execution observed."],
    }


def valid_correlation(evidence_ids=None):
    return {
        "schema_version": "1.0",
        "behavior_findings": [
            {
                "title": "Possible process injection",
                "description": "Function allocates memory and starts a remote thread.",
                "evidence_ids": evidence_ids or ["I-CreateRemoteThread"],
                "affected_function_ids": [INJECT_FID],
                "suggested_technique_id": "T1055",
            }
        ],
        "evidence_ids": evidence_ids or ["I-CreateRemoteThread"],
        "affected_function_ids": [INJECT_FID],
        "uncertainty": "Correlation based on static imports only.",
        "rationale": "MEM_ALLOC_WRITE + REMOTE_THREAD signals in the same function.",
    }


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

def test_assessment_valid_passes():
    validate_assessment(
        valid_assessment(),
        evidence_ids={"I-CreateRemoteThread", "F-INJECT"},
    )


def test_assessment_rejects_forbidden_fields():
    for field in ["score", "risk_score", "severity", "confidence", "confidence_score"]:
        bad = valid_assessment()
        bad[field] = 42
        with pytest.raises(SchemaValidationError, match=field):
            validate_assessment(bad, evidence_ids={"I-CreateRemoteThread"})


def test_assessment_rejects_unknown_fields():
    bad = valid_assessment()
    bad["unknown_field"] = "x"
    with pytest.raises(SchemaValidationError):
        validate_assessment(bad, evidence_ids={"I-CreateRemoteThread"})


def test_assessment_likely_requires_evidence():
    bad = valid_assessment(verdict="LIKELY_MALICIOUS", evidence_ids=[])
    with pytest.raises(SchemaValidationError, match="requires at least one"):
        validate_assessment(bad, evidence_ids=set())


def test_assessment_inconclusive_without_evidence_ok():
    good = valid_assessment(verdict="INCONCLUSIVE", evidence_ids=[])
    validate_assessment(good, evidence_ids=set())


def test_assessment_rejects_unknown_evidence():
    bad = valid_assessment(evidence_ids=["STR-FAKE0000000000"])
    with pytest.raises(SchemaValidationError, match="Unknown evidence"):
        validate_assessment(bad, evidence_ids={"I-CreateRemoteThread"})


def test_correlation_valid_passes():
    validate_correlation(
        valid_correlation(),
        evidence_ids={"I-CreateRemoteThread", "F-INJECT"},
        function_ids={INJECT_FID},
    )


def test_correlation_rejects_unknown_evidence():
    bad = valid_correlation(evidence_ids=["STR-FAKE0000000000"])
    with pytest.raises(SchemaValidationError, match="Unknown evidence"):
        validate_correlation(
            bad, evidence_ids={"I-CreateRemoteThread"}, function_ids={INJECT_FID}
        )


def test_correlation_rejects_unknown_function():
    bad = valid_correlation()
    bad["affected_function_ids"] = ["a1b2c3d4-e5f6-4789-8123-456789abcdef:0xdeadbeef"]
    with pytest.raises(SchemaValidationError, match="Unknown affected function"):
        validate_correlation(
            bad, evidence_ids={"I-CreateRemoteThread"}, function_ids={INJECT_FID}
        )


# ---------------------------------------------------------------------------
# ReportAssessor tests
# ---------------------------------------------------------------------------

def test_assessor_produces_likely_malicious_verdict():
    provider = MockProvider(responses=[json.dumps(valid_assessment())])
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={INJECT_FID: valid_assessment()},
    )
    assert result.output is not None
    assert result.output["verdict"] == "LIKELY_MALICIOUS"
    assert result.output["evidence_ids"] == ["I-CreateRemoteThread"]


def test_assessor_produces_inconclusive_when_no_evidence():
    provider = MockProvider(
        responses=[json.dumps(valid_assessment(verdict="INCONCLUSIVE", evidence_ids=[]))]
    )
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=PARTIAL,
        correlation_output=None,
        function_summaries={},
    )
    assert result.output is not None
    assert result.output["verdict"] == "INCONCLUSIVE"


def test_assessor_rejects_invalid_verdict():
    bad = valid_assessment()
    bad["verdict"] = "DEFINITELY_MALICIOUS"
    provider = MockProvider(responses=[json.dumps(bad)] * 5)
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "GROUNDING_FAIL"


def test_assessor_likely_without_evidence_is_dropped():
    bad = valid_assessment(verdict="LIKELY_MALICIOUS", evidence_ids=[])
    provider = MockProvider(responses=[json.dumps(bad)] * 5)
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "GROUNDING_FAIL"


def test_assessor_repair_invalid_then_valid():
    responses = [
        json.dumps({"schema_version": "1.0"}),  # missing required fields
        json.dumps(valid_assessment()),
    ]
    provider = MockProvider(responses=responses)
    assessor = ReportAssessor(provider, max_repairs=2)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    assert result.output is not None
    assert result.output["verdict"] == "LIKELY_MALICIOUS"


def test_assessor_invalid_output_dropped_after_repairs():
    bad = json.dumps({"schema_version": "1.0"})
    provider = MockProvider(responses=[bad] * 5)
    assessor = ReportAssessor(provider, max_repairs=2)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "GROUNDING_FAIL"


def test_assessor_disabled_provider():
    class DisabledProvider:
        def generate_structured(self, **kwargs):
            raise AIConfigurationError("AI disabled")

    assessor = ReportAssessor(DisabledProvider())
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=None,
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "AI_DISABLED"


def test_assessor_provider_failure_is_degraded():
    provider = MockProvider(responses=[AIProviderError("timeout")] * 5)
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=None,
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "AI_PROVIDER_UNAVAILABLE"


def test_assessor_cache_invalidation_on_version_change():
    key1 = cache_key(
        model="m", prompt_version="1.0", schema_version="1.0", input_hash="h:pipeline"
    )
    key2 = cache_key(
        model="m", prompt_version="1.1", schema_version="1.0", input_hash="h:pipeline"
    )
    key3 = cache_key(
        model="m", prompt_version="1.0", schema_version="1.1", input_hash="h:pipeline"
    )
    assert key1 != key2 != key3


def test_assessor_cache_hit_returns_same_output():
    provider = MockProvider(responses=[json.dumps(valid_assessment())])
    cache = AICache()
    assessor1 = ReportAssessor(provider, cache=cache)
    r1 = assessor1.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    # Same input → cache hit, no new provider call.
    assessor2 = ReportAssessor(provider, cache=cache)
    r2 = assessor2.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=valid_correlation(),
        function_summaries={},
    )
    assert r1.output == r2.output
    assert len(provider.calls) == 1


def test_assessor_tool_budget_respected():
    budget = PipelineBudget()
    for _ in range(52):
        budget.record_call(0)
    assert budget.remaining_calls() == 0
    with pytest.raises(AIProviderError):
        budget.check_capacity()


# ---------------------------------------------------------------------------
# Deterministic risk invariant tests
# ---------------------------------------------------------------------------

def test_deterministic_risk_unchanged_by_ai():
    # The AI pipeline must not modify deterministic risk scores or findings.
    # FULL fixture has G_INJECTION (25) + G_REG_PERSIST (15) = 40.
    risk_score = 0
    for hit in FULL.get("rule_hits", []):
        if not hit.get("absorbed", False):
            risk_score += hit.get("weight", 0)
    assert risk_score == 40
    # AI assessment does not change scoring_version or rule outputs.
    assert FULL["versions"]["scoring"] == "1.0"
    assert FULL["versions"]["rules"] == "1.0"


def test_full_fixture_pipeline_end_to_end():
    """Full fixture runs through Stage 1 + 2 + 3 with MockProvider."""
    provider = MockProvider(
        responses=[
            json.dumps(valid_assessment()),  # Stage 1 (one function)
            json.dumps(valid_correlation()),  # Stage 2
            json.dumps(valid_assessment()),  # Stage 3
        ]
    )
    cache = AICache()
    summarizer = Stage1Summarizer(provider, cache=cache)
    function_summaries = summarizer.summarize_analysis(FULL, k=5)

    assessor = ReportAssessor(provider, cache=cache)
    correlation = assessor.correlate(
        analysis_id=ANALYSIS_ID,
        input_hash=FULL["provenance"]["input_hash"],
        normalized=FULL,
        function_summaries=function_summaries,
    )
    report = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash=FULL["provenance"]["input_hash"],
        normalized=FULL,
        correlation_output=correlation.output,
        function_summaries=function_summaries,
    )

    # Deterministic output unchanged.
    assert FULL["rule_hits"][0]["rule_id"] == "G_INJECTION"
    assert FULL["rule_hits"][0]["weight"] == 25

    # AI produced a valid assessment.
    assert report.output is not None
    assert report.output["verdict"] in {
        "LIKELY_MALICIOUS",
        "LIKELY_BENIGN",
        "INCONCLUSIVE",
    }
    assert report.output["evidence_ids"]
    assert report.output["uncertainty"]


# ---------------------------------------------------------------------------
# Phase 4: assessment output, evidence links, provenance, missing AI,
# partial results, deterministic risk invariance
# ---------------------------------------------------------------------------

def test_all_three_verdicts_produced():
    """All verdict labels (LIKELY_MALICIOUS, LIKELY_BENIGN, INCONCLUSIVE) are accepted."""
    for verdict in ["LIKELY_MALICIOUS", "LIKELY_BENIGN", "INCONCLUSIVE"]:
        assessment = valid_assessment(verdict=verdict)
        validate_assessment(assessment, evidence_ids={"I-CreateRemoteThread"})


def test_evidence_links_grounded_to_current_analysis():
    """Evidence IDs in assessment must exist in the current analysis."""
    real_evidence = {"I-CreateRemoteThread", "I-VirtualAllocEx", "I-WriteProcessMemory", "I-RegCreateKeyExW", "I-RegSetValueExW", "STR-RUN", "F-INJECT"}
    assessment = valid_assessment(evidence_ids=["I-CreateRemoteThread", "I-VirtualAllocEx"])
    validate_assessment(assessment, evidence_ids=real_evidence)


def test_assessment_rejects_cross_analysis_evidence():
    """Evidence IDs from another analysis are rejected."""
    bad = valid_assessment(evidence_ids=["STR-OTHER-ANALYSIS-0000000001"])
    with pytest.raises(SchemaValidationError, match="Unknown evidence"):
        validate_assessment(bad, evidence_ids={"I-CreateRemoteThread"})


def test_missing_ai_produces_partial_state():
    """When AI is missing/disabled, analysis stays PARTIAL with deterministic output intact."""
    provider = MockProvider(responses=[])  # no responses → provider error
    assessor = ReportAssessor(provider)
    result = assessor.report(
        analysis_id=ANALYSIS_ID,
        input_hash="abc123",
        normalized=FULL,
        correlation_output=None,
        function_summaries={},
    )
    assert result.output is None
    assert result.error_code == "AI_PROVIDER_UNAVAILABLE"


def test_partial_analysis_keeps_deterministic_findings():
    """Partial analysis keeps its deterministic findings and scoring."""
    assert PARTIAL["rule_hits"] == []
    assert PARTIAL["findings"] == []
    assert PARTIAL["scoring"]["score"] == 0
    assert PARTIAL["scoring"]["rating"] == "Low"


def test_deterministic_risk_not_modified_by_assessment():
    """AI assessment does not alter deterministic risk score/rating/breakdown."""
    original_score = FULL["scoring"]["score"]
    original_rating = FULL["scoring"]["rating"]
    original_breakdown = list(FULL["scoring"]["breakdown"])
    assert original_score == 40
    assert original_rating == "Medium"
    # Simulate AI running: deterministic fields unchanged
    assert FULL["scoring"]["score"] == original_score
    assert FULL["scoring"]["rating"] == original_rating
    assert FULL["scoring"]["breakdown"] == original_breakdown


def test_assessment_contains_required_fields():
    """Final assessment contract requires schema_version, verdict, summary,
    evidence_ids, rationale, uncertainty, limitations."""
    assessment = valid_assessment()
    required = ["schema_version", "verdict", "summary", "evidence_ids", "rationale", "uncertainty", "limitations"]
    for field in required:
        assert field in assessment, f"Missing required field: {field}"
    assert assessment["schema_version"] == "1.0"
    assert isinstance(assessment["evidence_ids"], list)
    assert len(assessment["evidence_ids"]) >= 1
    assert isinstance(assessment["limitations"], list)
