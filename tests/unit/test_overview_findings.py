import uuid

from fastapi.testclient import TestClient

from app.db import Base, get_engine, new_session
from app.main import app
from app.models import Analysis, AttackMapping, Evidence, Finding


def test_overview_findings_scores_and_404():
    Base.metadata.create_all(bind=get_engine())
    # Let the app lifespan apply the production migration path before inserting fixtures.
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
    created = []
    with new_session() as session:
        for name, score, group, title, technique in [
            ("persist_reg.exe", 18, "G_REG_PERSIST", "Registry Run-key persistence", "T1547.001"),
            ("inject_pattern.exe", 28, "G_INJECTION", "Possible process injection", "T1055"),
        ]:
            analysis_id = uuid.uuid4()
            created.append(analysis_id)
            analysis = Analysis(id=analysis_id, status="COMPLETED", stage="COMPLETED", progress=100,
                original_filename=name, sha256=uuid.uuid4().hex * 2, md5=uuid.uuid4().hex,
                file_size=2048, format="pe", arch="x86_64", bitness=64, endian="le",
                extension_mismatch=False, strings_truncated=False, possible_packing=False,
                toolchain={}, scoring_version="1.0", rule_set_version="1.0", risk_score=score,
                risk_rating="Low", scoring_breakdown=[{"title": group, "weight": score}],
                schema_version="1.0", decomp_status="OK", ai_status="NOT_RUN", ghidra_source="fixture")
            finding = Finding(analysis_id=analysis_id, type=group, title=title, severity="high",
                confidence="high", confidence_score=0.9, description="Observed API sequence.",
                interpretation=None, alternative="May have a legitimate software purpose.",
                score_contribution=score, group_id=group, signal_ids=[], status="active")
            session.add_all([analysis, finding])
            session.flush()
            session.add(Evidence(analysis_id=analysis_id, finding_id=finding.id,
                evidence_type="api", source_type="import", source_id="CreateRemoteThread",
                excerpt="CreateRemoteThread", offset_or_address="0x140001000", reason="Rule evidence."))
            session.add(AttackMapping(finding_id=finding.id, technique_id=technique,
                technique_name="Process Injection" if technique == "T1055" else "Registry Run",
                confidence="high", confidence_score=0.9, rationale="Rule-derived match."))
        session.commit()

    try:
        with TestClient(app) as client:
            for analysis_id, expected in zip(created, (18, 28)):
                overview = client.get(f"/api/v1/analyses/{analysis_id}/overview")
                assert overview.status_code == 200
                assert overview.json()["risk"]["score"] == expected
                assert len(overview.json()["top_findings"]) == 1
                findings = client.get(f"/api/v1/analyses/{analysis_id}/findings")
                assert findings.status_code == 200
                cards = findings.json()["items"]
                assert cards and all(card["evidence"] for card in cards if card["severity"] == "High")
                assert cards[0]["attack_mappings"][0]["technique_id"] in {"T1547.001", "T1055"}

            missing = client.get(f"/api/v1/analyses/{uuid.uuid4()}/overview")
            assert missing.status_code == 404
            assert missing.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"
            assert missing.json()["error"]["request_id"]
            missing_findings = client.get(f"/api/v1/analyses/{uuid.uuid4()}/findings")
            assert missing_findings.status_code == 404
    finally:
        with new_session() as session:
            for analysis_id in created:
                row = session.get(Analysis, analysis_id)
                if row:
                    session.delete(row)
            session.commit()
