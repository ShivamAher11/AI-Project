"""Deterministic Stage 1 function ranking and bounded context (Phase 1/2)."""

from ai.summarizer import build_function_context, select_functions

FUNC_ID = "a1b2c3d4-e5f6-4789-8123-456789abcdef"


def _func(fid, address, size=100, centrality=0.5):
    return {
        "id": f"{FUNC_ID}:{address}",
        "address": address,
        "name": f"fn_{address}",
        "signature": None,
        "size": size,
        "decompiler_status": "ok",
        "assembly_excerpt": None,
        "decompiled_excerpt": None,
        "artifact": None,
        "centrality": centrality,
    }


def _normalized(functions, rule_hits=None):
    return {
        "analysis_id": FUNC_ID,
        "provenance": {"input_hash": "abc" * 22},
        "file": {"entry_point": "0x140001000"},
        "functions": functions,
        "rule_hits": rule_hits or [],
        "signals": [],
        "strings": [],
        "imports": [],
        "edges": [],
    }


def test_ranking_top_k_and_tiebreak_by_address():
    functions = [
        _func("a", "0x140001000", size=100, centrality=0.5),
        _func("b", "0x140001100", size=100, centrality=0.5),
        _func("c", "0x140001200", size=100, centrality=0.5),
    ]
    result = select_functions(functions, signal_counts={}, entry_point=None, k=2)
    assert len(result) == 2
    assert result == [f"{FUNC_ID}:0x140001000", f"{FUNC_ID}:0x140001100"]


def test_ranking_rule_hits_boost():
    functions = [
        _func("a", "0x140001000", size=10, centrality=0.0),
        _func("b", "0x140001100", size=10, centrality=0.0),
    ]
    hits = [{"rule_id": "R1", "function_ids": [f"{FUNC_ID}:0x140001100"], "weight": 5}]
    result = select_functions(
        functions, signal_counts={f"{FUNC_ID}:0x140001100": 1}, entry_point=None, k=2
    )
    assert result[0] == f"{FUNC_ID}:0x140001100"


def test_ranking_entry_point_boost():
    functions = [
        _func("a", "0x140001000", size=10, centrality=0.0),
        _func("b", "0x140001100", size=10, centrality=0.0),
    ]
    result = select_functions(
        functions,
        signal_counts={},
        entry_point="0x140001100",
        k=2,
    )
    assert result[0] == f"{FUNC_ID}:0x140001100"


def test_low_budget_reduces_k_to_20():
    functions = [_func(f"n{i}", f"0x140001{i:03x}", size=10) for i in range(50)]
    result = select_functions(
        functions, signal_counts={}, entry_point=None, k=50, low_budget=True
    )
    assert len(result) <= 20


def test_context_is_bounded_and_drops_asm_first():
    functions = [_func("a", "0x140001000", size=100)]
    norm = _normalized(functions)
    norm["functions"][0]["decompiled_excerpt"] = "x" * 20000
    norm["functions"][0]["assembly_excerpt"] = "asm" * 5000
    ctx = build_function_context(
        norm, f"{FUNC_ID}:0x140001000", analysis_id="x", input_hash="h"
    )
    assert len(ctx["decompilation_excerpt"]) <= 12000
    assert "assembly_excerpt" not in ctx
