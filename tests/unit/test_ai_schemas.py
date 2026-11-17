"""Strict function-summary schema and grounding validation (Phase 1)."""

import pytest

from ai.schemas.validate import SchemaValidationError, validate_function_summary

FUNC_ID = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001c00"
EVIDENCE_IDS = {"I-CreateRemoteThread", "F-INJECT"}


def _summary(**overrides):
    base = {
        "schema_version": "1.0",
        "function_id": FUNC_ID,
        "purpose": "Injects a payload into a remote process.",
        "behavior": ["opens target process", "allocates remote memory"],
        "evidence_ids": ["I-CreateRemoteThread", "F-INJECT"],
        "uncertainty": "The exact payload source could not be determined from static text alone.",
        "alternative_explanation": "A legitimate debugger or injection tool may perform similar calls.",
        "rationale": "Cited imports match the deterministic G_INJECTION rule hit.",
    }
    base.update(overrides)
    return base


def test_valid_summary_passes():
    validate_function_summary(
        _summary(), function_ids={FUNC_ID}, evidence_ids=EVIDENCE_IDS
    )


def test_rejects_forbidden_numeric_risk_fields():
    for field in ["score", "risk_score", "severity", "confidence", "confidence_score"]:
        with pytest.raises(SchemaValidationError, match="Forbidden"):
            validate_function_summary(
                _summary(**{field: "high"}),
                function_ids={FUNC_ID},
                evidence_ids=EVIDENCE_IDS,
            )


def test_rejects_unknown_fields():
    with pytest.raises(SchemaValidationError):
        validate_function_summary(
            _summary(extra_field="nope"),
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_rejects_missing_required_field():
    with pytest.raises(SchemaValidationError):
        validate_function_summary(
            {k: v for k, v in _summary().items() if k != "uncertainty"},
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_rejects_wrong_types():
    with pytest.raises(SchemaValidationError):
        validate_function_summary(
            _summary(behavior="not a list"),
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_rejects_invalid_function_id():
    with pytest.raises(SchemaValidationError, match="not found"):
        validate_function_summary(
            _summary(
                function_id="a1b2c3d4-e5f6-4789-8123-456789abcdef:0xdeadbeef"
            ),
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_rejects_unknown_evidence_id():
    with pytest.raises(SchemaValidationError, match="Unknown evidence"):
        validate_function_summary(
            _summary(
                evidence_ids=["I-CreateRemoteThread", "STR-FAKE0000000000"]
            ),
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_rejects_non_object_output():
    with pytest.raises(SchemaValidationError):
        validate_function_summary(
            "not an object",
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )


def test_suggested_technique_id_optional_and_string_only():
    validate_function_summary(
        _summary(suggested_technique_id="T1055"),
        function_ids={FUNC_ID},
        evidence_ids=EVIDENCE_IDS,
    )
    validate_function_summary(
        _summary(),
        function_ids={FUNC_ID},
        evidence_ids=EVIDENCE_IDS,
    )
    with pytest.raises(SchemaValidationError):
        validate_function_summary(
            _summary(suggested_technique_id=123),
            function_ids={FUNC_ID},
            evidence_ids=EVIDENCE_IDS,
        )
