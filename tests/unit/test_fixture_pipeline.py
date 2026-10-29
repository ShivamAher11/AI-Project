import json
import os
from datetime import datetime, timezone
from pathlib import Path
import pytest

from worker.ghidra_runner import GhidraRunner
from worker.normalize import calculate_centrality, normalize_analysis, serialize_normalized
from app.db import new_session
from app.models import Analysis, Section
from worker.tasks import _persist_functions, _persist_static_metadata
from sqlalchemy import select
import uuid


ROOT = Path(__file__).parents[2]
ANALYSIS_ID = "a1b2c3d4-e5f6-4789-8123-456789abcdef"


def _static():
    fixture = json.loads((ROOT / "fixtures/analysis-full.json").read_text(encoding="utf-8-sig"))
    return {
        "sha256": fixture["sha256"], "md5": fixture["md5"], "size": fixture["file"]["size"],
        "original_filename": fixture["file"]["original_filename"], "format": fixture["file"]["format"],
        "arch": fixture["file"]["arch"], "bitness": fixture["file"]["bitness"],
        "endian": fixture["file"]["endian"], "entry_point": fixture["file"]["entry_point"],
        "extension_mismatch": False, "strings_truncated": False, "possible_packing": False,
        "packing_note": None, "sections": fixture["sections"], "imports": fixture["imports"],
        "exports": fixture["exports"], "strings": fixture["strings"],
    }


def test_pagerank_uses_only_direct_edges_and_normalizes():
    edges = [
        {"caller": "a", "callee": "b", "type": "direct"},
        {"caller": "b", "callee": "c", "type": "direct"},
        {"caller": "c", "callee": "a", "type": "indirect"},
        {"caller": "c", "callee": "external", "type": "import"},
    ]
    values = calculate_centrality(["a", "b", "c"], edges)
    direct_only = calculate_centrality(["a", "b", "c"], edges[:2])
    assert values == direct_only
    assert values == pytest.approx({"a": 0.388727334987, "b": 0.719146851808, "c": 1.0})


def test_fixture_runner_normalizes_and_roundtrips_deterministically(tmp_path):
    result = GhidraRunner(fixture_root=ROOT / "fixtures").run(ANALYSIS_ID, "hello_pe_x64.exe")
    assert result["source"] == "fixture"
    normalized = normalize_analysis(
        _static(), ANALYSIS_ID, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ghidra_result=result, data_root=str(tmp_path),
    )
    again = normalize_analysis(
        _static(), ANALYSIS_ID, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ghidra_result=result, data_root=str(tmp_path),
    )
    assert serialize_normalized(normalized) == serialize_normalized(again)
    assert normalized["source"] == "fixture"
    assert len(normalized["functions"]) == 2
    assert normalized["edges"][0]["caller"].startswith(ANALYSIS_ID + ":")
    assert all(0 <= fn["centrality"] <= 1 for fn in normalized["functions"])
    artifact = tmp_path / "artifacts" / ANALYSIS_ID / "funcs" / "140001000.c"
    assert artifact.read_text(encoding="utf-8").startswith("int main")
    assert normalized["functions"][0]["artifact"]["size"] == artifact.stat().st_size


def test_partial_result_keeps_static_metadata_and_has_no_fake_functions(tmp_path):
    static = _static()
    normalized = normalize_analysis(static, ANALYSIS_ID, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                                    ghidra_result={"source": "none", "functions": [], "edges": []},
                                    data_root=str(tmp_path))
    assert normalized["status"] == "PARTIAL"
    assert normalized["source"] == "none"
    assert normalized["sections"] == static["sections"]
    assert normalized["imports"]
    assert normalized["functions"] == []


def test_partial_pipeline_keeps_already_persisted_static_rows():
    if not os.getenv("DATABASE_URL"):
        import pytest
        pytest.skip("DATABASE_URL is required for the PostgreSQL persistence check")
    analysis_id = str(uuid.uuid4())
    static = _static()
    with new_session() as session:
        session.add(Analysis(
            id=uuid.UUID(analysis_id), status="STATIC_ANALYSIS", stage="STATIC_ANALYSIS", progress=15,
            original_filename="fixture.exe", sha256=static["sha256"], md5=static["md5"], file_size=static["size"],
            format="pe", arch="x64", bitness=64, entry_point=static["entry_point"], toolchain={},
            decomp_status="NOT_RUN", ai_status="NOT_RUN",
        ))
        session.commit()
    _persist_static_metadata(analysis_id, static)
    _persist_functions(analysis_id, {"source": "none", "functions": [], "edges": []})
    with new_session() as session:
        analysis = session.get(Analysis, uuid.UUID(analysis_id))
        analysis.status = "PARTIAL"
        analysis.stage = "PARTIAL"
        assert session.scalar(select(Section).where(Section.analysis_id == uuid.UUID(analysis_id))) is not None
        session.commit()
        session.delete(analysis)
        session.commit()
