import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from app.db import Base, create_engine_from_url
from app.models import (
    AIRun,
    Analysis,
    AttackMapping,
    CallEdge,
    Evidence,
    Finding,
    Function,
    ImportSymbol,
    Section,
    Signal,
    StringRecord,
)


@pytest.fixture(scope="module")
def engine():
    database_url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        pytest.skip("Set TEST_DATABASE_URL or DATABASE_URL to a PostgreSQL test database")
    test_engine = create_engine_from_url(database_url)
    Base.metadata.create_all(test_engine)
    yield test_engine
    test_engine.dispose()


def test_all_spec_tables_are_mapped():
    expected = {
        "analyses", "sections", "import_symbols", "string_records", "functions",
        "call_edges", "signals", "findings", "evidence", "attack_mappings", "ai_runs",
    }
    assert set(Base.metadata.tables) == expected
    for table in Base.metadata.tables.values():
        assert table.indexes or table.primary_key, f"{table.name} has no index or primary-key index"
        for foreign_key in table.foreign_keys:
            assert foreign_key.ondelete == "CASCADE", f"{table.name}.{foreign_key.parent.name} must cascade"
    named_checks = {constraint.name for table in Base.metadata.tables.values() for constraint in table.constraints if constraint.name}
    assert {"ck_analyses_status", "ck_call_edges_type", "ck_findings_severity", "ck_findings_confidence", "ck_evidence_source_type"} <= named_checks


def test_migrated_tables_exist(engine):
    expected = set(Base.metadata.tables)
    assert expected <= set(inspect(engine).get_table_names())


def test_analysis_delete_cascades_to_every_child_table(engine):
    analysis_id = uuid.uuid4()
    function_id = f"{analysis_id}:0x1000"
    finding_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    with Session(engine) as session:
        analysis = Analysis(
            id=analysis_id, status="COMPLETED", stage="COMPLETED", progress=100,
            original_filename="fixture.exe", sha256="a" * 64, md5="b" * 32,
            file_size=512, format="pe", arch="x64", bitness=64,
            toolchain={"ghidra": "fixture"}, decomp_status="OK", ai_status="DISABLED",
        )
        session.add(analysis)
        session.flush()
        session.add_all([
            Section(analysis_id=analysis_id, name=".text", vaddr="0x1000", vsize=16, raw_size=16, perms="R-X", entropy=4.0),
            ImportSymbol(analysis_id=analysis_id, library="kernel32.dll", name="OpenProcess", category="process"),
            StringRecord(analysis_id=analysis_id, offset="0x2000", encoding="utf-8", value="Run", length=3),
            Function(id=function_id, analysis_id=analysis_id, address="0x1000", name="entry", size=16, decompiler_status="ok"),
            Signal(id="S-test", analysis_id=analysis_id, rule_id="TEST", function_ids=[function_id], evidence_refs=[str(evidence_id)]),
            Finding(id=finding_id, analysis_id=analysis_id, type="test", title="Test finding", severity="low", confidence="low", confidence_score=0.3, description="Static test fixture", score_contribution=1),
            AIRun(id=uuid.uuid4(), analysis_id=analysis_id, stage="func", model="mock", prompt_version="1.0", input_hash="c" * 64, output_schema_version="1.0", started_at=datetime.now(timezone.utc), status="COMPLETED"),
        ])
        session.flush()
        session.add_all([
            CallEdge(analysis_id=analysis_id, caller_id=function_id, callee_id="kernel32.dll!OpenProcess", edge_type="import"),
            Evidence(id=evidence_id, analysis_id=analysis_id, finding_id=finding_id, evidence_type="import", source_type="import", source_id="1", excerpt="OpenProcess"),
            AttackMapping(finding_id=finding_id, technique_id="T1055", technique_name="Process Injection", confidence="low", confidence_score=0.3, rationale="Fixture test"),
        ])
        session.commit()

        session.delete(analysis)
        session.commit()

        for model in (Section, ImportSymbol, StringRecord, Function, CallEdge, Signal, Finding, Evidence, AttackMapping, AIRun):
            remaining = session.scalar(select(func.count()).select_from(model).where(model.analysis_id == analysis_id)) if model is not AttackMapping else session.scalar(
                select(func.count()).select_from(AttackMapping).where(AttackMapping.finding_id == finding_id)
            )
            assert remaining == 0, f"{model.__tablename__} rows remained after cascade delete"
