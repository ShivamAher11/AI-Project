"""AI input boundary adapter tests using full and partial fixtures.

No Ghidra, ngrok, or live model is required.
"""

import json
from pathlib import Path

import pytest

from ai.input_adapter import (
    build_function_input,
    list_eligible_functions,
    summary_of_input,
)

ROOT = Path(__file__).parents[2]
FULL = json.loads(
    (ROOT / "fixtures/analysis-full.json").read_text(encoding="utf-8-sig")
)
PARTIAL = json.loads(
    (ROOT / "fixtures/analysis-partial.json").read_text(encoding="utf-8-sig")
)

INJECT_FID = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001c00"
REG_FID = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001d00"
MISSING_FID = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001dead"


def test_full_fixture_adapter_returns_function_input():
    result = build_function_input(FULL, INJECT_FID)

    assert result["analysis_id"] == FULL["analysis_id"]
    assert result["source"] == "fixture"
    assert result["function_id"] == INJECT_FID
    assert result["function"]["id"] == INJECT_FID
    assert result["function"]["name"] == "FUN_140001c00"
    assert result["function"]["decompiler_status"] == "ok"
    assert result["error"] is None

    # Import edges resolved to import records.
    import_names = {imp["name"] for imp in result["imports"]}
    assert import_names == {
        "OpenProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }

    # Graph edges captured.
    assert any(
        c["caller"] == "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001b00"
        for c in result["graph"]["callers"]
    )
    assert result["graph"]["imports"] == [
        "OpenProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]

    # Evidence IDs from signals/rule hits.
    assert result["evidence_ids"]
    assert "I-CreateRemoteThread" in result["evidence_ids"]
    assert "I-VirtualAllocEx" in result["evidence_ids"]
    assert "I-WriteProcessMemory" in result["evidence_ids"]
    assert "I-OpenProcess" in result["evidence_ids"]

    # Strings are returned in full (bounded by the normalized schema).
    assert len(result["strings"]) == 3
    assert any(
        s["value"] == "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        for s in result["strings"]
    )

    # Decompilation present for the inject function.
    assert result["decompilation_excerpt"] is not None
    assert "VirtualAllocEx" in result["decompilation_excerpt"]

    # Rule hits and findings involving the function.
    assert any(h["rule_id"] == "G_INJECTION" for h in result["rule_hits"])
    assert any(f["group_id"] == "G_INJECTION" for f in result["findings"])

    # Input hash carried through.
    assert result["input_hash"] == FULL["provenance"]["input_hash"]

    # Safe logging summary excludes raw decompilation.
    summ = summary_of_input(result)
    assert "decompilation_excerpt" not in json.dumps(summ)
    assert summ["has_decompilation"] is True


def test_partial_fixture_adapter_returns_empty_functions():
    funcs = list_eligible_functions(PARTIAL)
    assert funcs == []

    result = build_function_input(PARTIAL, MISSING_FID)
    assert result["function"] is None
    assert result["error"] is not None
    assert result["imports"] == []
    assert result["strings"] == []
    assert result["evidence_ids"] == []
    assert result["graph"] == {"callers": [], "callees": [], "imports": []}
    assert result["decompilation_excerpt"] is None
    assert result["rule_hits"] == []
    assert result["findings"] == []
    assert result["source"] == "none"


def test_main_function_without_decompilation_has_null_excerpt():
    main_fid = "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001000"
    result = build_function_input(FULL, main_fid)
    assert result["function"]["name"] == "main"
    # main has null decompiled_excerpt in the fixture.
    assert result["decompilation_excerpt"] is None
    assert result["error"] is None


def test_missing_decompilation_and_missing_evidence_not_fabricated():
    reg_result = build_function_input(FULL, REG_FID)
    assert reg_result["function"]["name"] == "FUN_140001d00"
    # Reg function has null decompiled_excerpt.
    assert reg_result["decompilation_excerpt"] is None
    # Evidence IDs are only those actually referenced; none fabricated.
    assert all(
        eid.startswith(("I-", "STR-", "F-")) for eid in reg_result["evidence_ids"]
    )


def test_unknown_function_returns_error_without_crash():
    result = build_function_input(FULL, MISSING_FID)
    assert result["function"] is None
    assert result["function_id"] == MISSING_FID
    assert "not found" in result["error"]
    assert result["source"] == "fixture"
    assert result["decompilation_excerpt"] is None


def test_list_eligible_functions_full_fixture():
    funcs = list_eligible_functions(FULL)
    assert len(funcs) == 15
    assert funcs[0] == "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001000"
    assert funcs[-1] == "a1b2c3d4-e5f6-4789-8123-456789abcdef:0x140001e00"
    assert INJECT_FID in funcs
