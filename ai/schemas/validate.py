"""Strict validation of AI-structured outputs against versioned JSON Schemas.

All schemas live in ai/schemas/ and are versioned. Unknown fields, forbidden
numeric risk fields, and bad types are rejected. Every evidence ID and
function ID must exist in the supplied analysis evidence/function sets.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parent


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


FUNCTION_SCHEMA = _load_schema("function_summary_v1_0.json")
CORRELATION_SCHEMA = _load_schema("correlation_v1_0.json")
ASSESSMENT_SCHEMA = _load_schema("report_assessment_v1_0.json")

# Forbidden fields the model must never emit; validators reject unknown fields
# via additionalProperties:false, but we also surface a clearer message here.
_FORBIDDEN_FIELDS = {
    "score",
    "risk_score",
    "severity",
    "confidence",
    "confidence_score",
    "verdict",
    "family",
    "malware",
}


class SchemaValidationError(ValueError):
    """The model output failed strict schema or grounding validation."""


def _validate_forbidden(output: dict, *, allowed_fields: set[str] | None = None) -> None:
    forbidden = sorted((set(output) & _FORBIDDEN_FIELDS) - (allowed_fields or set()))
    if forbidden:
        raise SchemaValidationError(
            "Forbidden field(s) present: " + ", ".join(forbidden)
        )


def _validate_schema(output: dict, validator: Draft202012Validator) -> None:
    errors = sorted(validator.iter_errors(output), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in e.path) or 'root'}: {e.message}"
            for e in errors[:10]
        )
        raise SchemaValidationError("Schema violation: " + detail)


def validate_function_summary(
    output: dict, *, function_ids: set[str], evidence_ids: set[str]
) -> None:
    """Validate a Stage 1 function summary against schema v1.0 and grounding.

    Raises SchemaValidationError on any violation.
    """
    if not isinstance(output, dict):
        raise SchemaValidationError("Model output is not a JSON object.")

    _validate_forbidden(output)
    _validate_schema(output, Draft202012Validator(FUNCTION_SCHEMA))

    function_id = output.get("function_id")
    if function_id not in function_ids:
        raise SchemaValidationError(
            f"function_id {function_id!r} not found in this analysis."
        )

    returned_evidence = output.get("evidence_ids", [])
    if not isinstance(returned_evidence, list):
        raise SchemaValidationError("evidence_ids must be a list of strings.")
    unknown_evidence = sorted(set(returned_evidence) - evidence_ids)
    if unknown_evidence:
        raise SchemaValidationError(
            "Unknown evidence id(s): " + ", ".join(unknown_evidence)
        )

    suggested = output.get("suggested_technique_id")
    if suggested is not None and not isinstance(suggested, str):
        raise SchemaValidationError(
            "suggested_technique_id must be a string or absent."
        )


def validate_correlation(
    output: dict, *, evidence_ids: set[str], function_ids: set[str]
) -> None:
    """Validate a Stage 2 correlation output against schema v1.0 and grounding.

    Raises SchemaValidationError on any violation.
    """
    if not isinstance(output, dict):
        raise SchemaValidationError("Model output is not a JSON object.")

    _validate_forbidden(output)
    _validate_schema(output, Draft202012Validator(CORRELATION_SCHEMA))

    returned_evidence = output.get("evidence_ids", [])
    if not isinstance(returned_evidence, list):
        raise SchemaValidationError("evidence_ids must be a list of strings.")
    unknown_evidence = sorted(set(returned_evidence) - evidence_ids)
    if unknown_evidence:
        raise SchemaValidationError(
            "Unknown evidence id(s): " + ", ".join(unknown_evidence)
        )

    affected = output.get("affected_function_ids", [])
    if not isinstance(affected, list):
        raise SchemaValidationError("affected_function_ids must be a list of strings.")
    unknown_functions = sorted(set(affected) - function_ids)
    if unknown_functions:
        raise SchemaValidationError(
            "Unknown affected function id(s): " + ", ".join(unknown_functions)
        )

    for finding in output.get("behavior_findings", []):
        fev = finding.get("evidence_ids", [])
        if not isinstance(fev, list):
            raise SchemaValidationError("behavior finding evidence_ids must be a list of strings.")
        unknown_fev = sorted(set(fev) - evidence_ids)
        if unknown_fev:
            raise SchemaValidationError(
                "Unknown behavior finding evidence id(s): " + ", ".join(unknown_fev)
            )
        ffn = finding.get("affected_function_ids", [])
        if not isinstance(ffn, list):
            raise SchemaValidationError("behavior finding affected_function_ids must be a list of strings.")
        unknown_ffn = sorted(set(ffn) - function_ids)
        if unknown_ffn:
            raise SchemaValidationError(
                "Unknown behavior finding affected function id(s): "
                + ", ".join(unknown_ffn)
            )


def validate_assessment(
    output: dict, *, evidence_ids: set[str]
) -> None:
    """Validate a Stage 3 report assessment against schema v1.0 and grounding.

    Raises SchemaValidationError on any violation.

    Likely verdicts require at least one valid evidence ID. INCONCLUSIVE is
    required when evidence is absent or insufficient.
    """
    if not isinstance(output, dict):
        raise SchemaValidationError("Model output is not a JSON object.")

    _validate_forbidden(output, allowed_fields={"verdict"})
    _validate_schema(output, Draft202012Validator(ASSESSMENT_SCHEMA))

    verdict = output.get("verdict")
    if verdict not in {"LIKELY_MALICIOUS", "LIKELY_BENIGN", "INCONCLUSIVE"}:
        raise SchemaValidationError("verdict must be one of the allowed enum values.")

    returned_evidence = output.get("evidence_ids", [])
    if not isinstance(returned_evidence, list):
        raise SchemaValidationError("evidence_ids must be a list of strings.")
    unknown_evidence = sorted(set(returned_evidence) - evidence_ids)
    if unknown_evidence:
        raise SchemaValidationError(
            "Unknown evidence id(s): " + ", ".join(unknown_evidence)
        )

    # Likely verdicts require at least one valid evidence ID.
    if verdict in {"LIKELY_MALICIOUS", "LIKELY_BENIGN"} and not returned_evidence:
        raise SchemaValidationError(
            f"{verdict} requires at least one valid evidence ID."
        )
