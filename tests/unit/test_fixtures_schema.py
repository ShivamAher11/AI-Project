import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def _project_root() -> Path:
    candidates = [Path(__file__).parents[2], Path("/")]
    for root in candidates:
        if (root / "shared/analysis_schema_v1.0.json").is_file():
            return root
    raise FileNotFoundError("shared/analysis_schema_v1.0.json not found")


def test_both_fixtures_validate_against_normalized_schema():
    root = _project_root()
    schema = json.loads((root / "shared/analysis_schema_v1.0.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for fixture_name in ("analysis-full.json", "analysis-partial.json"):
        fixture = json.loads((root / "fixtures" / fixture_name).read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(fixture), key=lambda error: list(error.path))
        assert errors == [], f"{fixture_name}: " + "; ".join(error.message for error in errors)

    partial = json.loads((root / "fixtures/analysis-partial.json").read_text(encoding="utf-8"))
    assert partial["decomp_status"] == "TIMEOUT"
    assert partial["functions"] == []
