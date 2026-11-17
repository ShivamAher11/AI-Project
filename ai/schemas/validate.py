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


def validate_function_summary(
    output: dict, *, function_ids: set[str], evidence_ids: set[str]
) -> None:
    """Validate a Stage 1 function summary against schema v1.0 and grounding.

    Raises SchemaValidationError on any violation.
    """
    if not isinstance(output, dict):
        raise SchemaValidationError("Model output is not a JSON object.")

    forbidden = sorted(set(output) & _FORBIDDEN_FIELDS)
    if forbidden:
        raise SchemaValidationError(
            "Forbidden field(s) present: " + ", ".join(forbidden)
        )

    validator = Draft202012Validator(FUNCTION_SCHEMA)
    errors = sorted(validator.iter_errors(output), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in e.path) or 'root'}: {e.message}"
            for e in errors[:10]
        )
        raise SchemaValidationError("Schema violation: " + detail)

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
        raise SchemaValidationError("suggested_technique_id must be a string or absent.")
