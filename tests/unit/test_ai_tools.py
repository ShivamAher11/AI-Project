"""Typed static-analysis tool allowlist: validation, budget, and boundaries.

No live model, no network, no raw file bytes. Tests exercise the allowlist
directly and through the internal API endpoint.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai.tools import (
    StaticToolExecutor,
    ToolArgumentError,
    ToolBudget,
    ToolBudgetExceeded,
    ToolNotAllowed,
    ToolNotFound,
    _validate_args,
    MAX_TOOL_CALLS_PER_ANALYSIS,
)
from backend.app.db import new_session
from backend.app.main import app
from backend.app.models import Analysis

ROOT = Path(__file__).parents[2]
FULL = json.loads(
    (ROOT / "fixtures/analysis-full.json").read_text(encoding="utf-8-sig")
)
ANALYSIS_ID = FULL["analysis_id"]


# ---------------------------------------------------------------------------
# Validation unit tests (no DB required)
# ---------------------------------------------------------------------------

def test_allowlist_contains_only_static_tools():
    from ai.tools import _TOOLS

    expected = {
        "analysis.metadata",
        "analysis.strings",
        "analysis.functions",
        "analysis.function_detail",
        "analysis.findings",
        "analysis.imports",
    }
    assert _TOOLS == expected


def test_validate_args_known_tool_with_defaults():
    args = _validate_args("analysis.metadata", {"analysis_id": ANALYSIS_ID})
    assert args["analysis_id"] == ANALYSIS_ID


def test_validate_args_unknown_tool_rejected():
    with pytest.raises(ToolNotAllowed):
        _validate_args("shell.exec", {})


def test_validate_args_unknown_argument_rejected():
    with pytest.raises(ToolArgumentError):
        _validate_args(
            "analysis.metadata", {"analysis_id": ANALYSIS_ID, "evil": "x"}
        )


def test_validate_args_missing_required_rejected():
    with pytest.raises(ToolArgumentError):
        _validate_args("analysis.metadata", {})


def test_validate_args_bad_function_id_rejected():
    with pytest.raises(ToolArgumentError):
        _validate_args(
            "analysis.function_detail",
            {"analysis_id": ANALYSIS_ID, "function_id": "not-a-fid"},
        )


def test_validate_args_limit_clamped_to_max():
    args = _validate_args(
        "analysis.strings", {"analysis_id": ANALYSIS_ID, "limit": 9999}
    )
    assert args["limit"] == 50


def test_validate_args_limit_floor_is_one():
    args = _validate_args(
        "analysis.strings", {"analysis_id": ANALYSIS_ID, "limit": 0}
    )
    assert args["limit"] == 1


def test_validate_args_invalid_analysis_id_rejected():
    with pytest.raises(ToolArgumentError):
        _validate_args("analysis.metadata", {"analysis_id": "not-a-uuid"})


# ---------------------------------------------------------------------------
# Budget unit tests (no DB required)
# ---------------------------------------------------------------------------

def test_budget_tracks_calls_and_output_bytes():
    from ai.tools import ToolCall

    budget = ToolBudget()
    budget.record(
        ToolCall(
            name="analysis.metadata",
            arguments={},
            output_bytes=100,
            ok=True,
        )
    )
    assert budget.calls == 1
    assert budget.output_bytes == 100
    assert budget.remaining_calls() == MAX_TOOL_CALLS_PER_ANALYSIS - 1


def test_budget_check_capacity_blocks_at_limit():
    budget = ToolBudget()
    from ai.tools import ToolCall

    for _ in range(MAX_TOOL_CALLS_PER_ANALYSIS):
        budget.record(
            ToolCall(
                name="analysis.metadata",
                arguments={},
                output_bytes=0,
                ok=True,
            )
        )
    with pytest.raises(ToolBudgetExceeded):
        budget.check_capacity()


# ---------------------------------------------------------------------------
# Executor tests
# ---------------------------------------------------------------------------

def test_executor_rejects_bad_analysis_id():
    with pytest.raises(ToolArgumentError):
        StaticToolExecutor("not-a-uuid")


# ---------------------------------------------------------------------------
# API endpoint tests (TestClient + real PostgreSQL via app)
# ---------------------------------------------------------------------------

def _token_headers():
    return {"X-Pipeline-AI-Token": "t" * 32}


def _insert_analysis(session, analysis_id, status="COMPLETED"):
    row = Analysis(
        id=analysis_id,
        status=status,
        stage=status,
        progress=100,
        original_filename="sample.exe",
        sha256="a" * 64,
        md5="b" * 32,
        file_size=100,
        format="pe",
        arch="x64",
        bitness=64,
        endian="le",
        entry_point="0x140001000",
        extension_mismatch=False,
        strings_truncated=False,
        possible_packing=False,
        toolchain={"lief": "1.0.0"},
        scoring_version="1.0",
        rule_set_version="1.0",
        schema_version="1.0",
        decomp_status="OK",
        ai_status="NOT_RUN",
        created_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        ghidra_source="none",
    )
    session.add(row)
    session.commit()
    return str(analysis_id)


def test_tool_endpoint_requires_pipeline_token(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    analysis_id = uuid.uuid4()
    with TestClient(app) as client:
        with new_session() as session:
            _insert_analysis(session, analysis_id)
        resp = client.post(
            f"/ai/internal/analyses/{analysis_id}/tool",
            json={"tool": "analysis.metadata", "arguments": {"analysis_id": str(analysis_id)}},
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "PIPELINE_AI_FORBIDDEN"


def test_tool_endpoint_unknown_tool_rejected(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    analysis_id = uuid.uuid4()
    with TestClient(app) as client:
        with new_session() as session:
            _insert_analysis(session, analysis_id)
        resp = client.post(
            f"/ai/internal/analyses/{analysis_id}/tool",
            headers=_token_headers(),
            json={"tool": "shell.exec", "arguments": {}},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "TOOL_NOT_ALLOWED"


def test_tool_endpoint_invalid_argument_rejected(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    analysis_id = uuid.uuid4()
    with TestClient(app) as client:
        with new_session() as session:
            _insert_analysis(session, analysis_id)
        resp = client.post(
            f"/ai/internal/analyses/{analysis_id}/tool",
            headers=_token_headers(),
            json={
                "tool": "analysis.metadata",
                "arguments": {"analysis_id": "not-a-uuid"},
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "INVALID_ARGUMENT"


def test_tool_endpoint_unknown_analysis_404(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    with TestClient(app) as client:
        resp = client.post(
            f"/ai/internal/analyses/{uuid.uuid4()}/tool",
            headers=_token_headers(),
            json={
                "tool": "analysis.metadata",
                "arguments": {"analysis_id": str(uuid.uuid4())},
            },
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"


def test_tool_endpoint_budget_exceeded_429(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    import ai.tools as tools_mod

    orig = ToolBudget.check_capacity
    ToolBudget.check_capacity = lambda self: (_ for _ in ()).throw(
        ToolBudgetExceeded("budget exhausted")
    )
    try:
        analysis_id = uuid.uuid4()
        with TestClient(app) as client:
            with new_session() as session:
                _insert_analysis(session, analysis_id)
            resp = client.post(
                f"/ai/internal/analyses/{analysis_id}/tool",
                headers=_token_headers(),
                json={
                    "tool": "analysis.metadata",
                    "arguments": {"analysis_id": str(analysis_id)},
                },
            )
        assert resp.status_code == 429
        assert resp.json()["error"]["code"] == "TOOL_BUDGET_EXCEEDED"
    finally:
        ToolBudget.check_capacity = orig


def test_tool_metadata_valid_with_fixture_db(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    analysis_id = uuid.uuid4()
    with TestClient(app) as client:
        with new_session() as session:
            _insert_analysis(session, analysis_id)
        resp = client.post(
            f"/ai/internal/analyses/{analysis_id}/tool",
            headers=_token_headers(),
            json={
                "tool": "analysis.metadata",
                "arguments": {"analysis_id": str(analysis_id)},
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["tool"] == "analysis.metadata"
        assert body["result"]["analysis_id"] == str(analysis_id)
        assert body["result"]["format"] == "pe"
        assert body["budget"]["calls"] == 1
        assert body["budget"]["calls_remaining"] == MAX_TOOL_CALLS_PER_ANALYSIS - 1


def test_tool_function_detail_unknown_fid_404(monkeypatch):
    monkeypatch.setenv("PIPELINE_AI_INTERNAL_TOKEN", "t" * 32)
    analysis_id = uuid.uuid4()
    with TestClient(app) as client:
        with new_session() as session:
            _insert_analysis(session, analysis_id)
        resp = client.post(
            f"/ai/internal/analyses/{analysis_id}/tool",
            headers=_token_headers(),
            json={
                "tool": "analysis.function_detail",
                "arguments": {
                    "analysis_id": str(analysis_id),
                    "function_id": f"{analysis_id}:0xdeadbeef",
                },
            },
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "NOT_FOUND"
