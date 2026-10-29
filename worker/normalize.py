"""Canonical normalized JSON v1.0 generation and validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "shared" / "analysis_schema_v1.0.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


class NormalizationError(ValueError):
    pass


def _addr_sort(record: dict, key: str) -> tuple:
    value = record.get(key)
    return (value is None, int(value, 16) if value else 0)


def normalize_analysis(static: dict, analysis_id: str, *, created_at: datetime | None = None) -> dict:
    created_at = created_at or datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    sections = sorted(static["sections"], key=lambda row: (_addr_sort(row, "vaddr"), row["name"]))
    imports_by_key: dict[tuple[str, str], dict] = {}
    for row in static["imports"]:
        key = (row["library"].casefold(), row["name"].casefold())
        previous = imports_by_key.get(key)
        if previous is None or (previous["address"] is None and row["address"] is not None):
            imports_by_key[key] = row
    imports = sorted(imports_by_key.values(), key=lambda row: (_addr_sort(row, "address"),
                                                                row["library"].casefold(), row["name"].casefold()))
    exports = sorted(static["exports"], key=lambda row: (_addr_sort(row, "address"), row["ordinal"] or 0,
                                                          row["name"]))
    strings = sorted(static["strings"], key=lambda row: (_addr_sort(row, "offset"), row["encoding"], row["value"]))
    normalized = {
        "schema_version": "1.0",
        "analysis_id": str(UUID(analysis_id)),
        "sha256": static["sha256"],
        "md5": static["md5"],
        "status": "PARTIAL",
        "decomp_status": "NOT_RUN",
        "strings_truncated": bool(static["strings_truncated"]),
        "possible_packing": bool(static["possible_packing"]),
        "packing_note": static["packing_note"],
        "file": {
            "original_filename": static["original_filename"] or "upload",
            "size": static["size"],
            "format": static["format"],
            "arch": static["arch"],
            "bitness": static["bitness"],
            "endian": static["endian"],
            "entry_point": static["entry_point"],
            "extension_mismatch": static["extension_mismatch"],
        },
        "toolchain": {"ghidra": "NOT_RUN", "jdk": "NOT_RUN", "lief": "1.0.0", "capstone": "NOT_RUN"},
        "versions": {"scoring": "1.0", "rules": "1.0", "prompts": "1.0"},
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "functions": [],
        "edges": [],
        "signals": [],
        "rule_hits": [],
        "findings": [],
        "provenance": {
            "input_hash": static["sha256"],
            "created_at": created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        raise NormalizationError("Normalized analysis did not match schema v1.0.")
    return normalized


def serialize_normalized(normalized: dict) -> bytes:
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        raise NormalizationError("Normalized analysis did not match schema v1.0.")
    return (json.dumps(normalized, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def validate_normalized(normalized: dict) -> None:
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path)
        raise NormalizationError(f"Normalized analysis schema validation failed at {path or '<root>'}.")
