import logging
import os
import threading
import time
from datetime import datetime, timezone
from uuid import UUID

from celery.utils.log import get_task_logger
from sqlalchemy import select

from app.celery_app import celery_app
from app.db import new_session
from app.models import Analysis
from app.state_machine import InvalidStateTransition, transition_analysis
from app.storage import artifact_dir_path, remove_temporary_artifacts, resolve_under

logger = get_task_logger(__name__)
PLACEHOLDER_DELAY_S = float(os.getenv("PLACEHOLDER_STAGE_DELAY_S", "0.35"))
PIPELINE_STAGES = [
    ("VALIDATING", 5),
    ("STATIC_ANALYSIS", 15),
    ("RE_ANALYSIS", 35),
    ("NORMALIZING", 50),
    ("DETECTION", 65),
    ("AI_ANALYSIS", 78),
    ("REPORTING", 88),
]


def _touch_heartbeat(analysis_id: str) -> None:
    with new_session() as session:
        analysis = session.get(Analysis, UUID(analysis_id))
        if analysis is not None and analysis.status not in {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}:
            analysis.heartbeat_at = datetime.now(timezone.utc)
            session.commit()


def _heartbeat_loop(analysis_id: str, stop: threading.Event) -> None:
    while not stop.wait(30):
        try:
            _touch_heartbeat(analysis_id)
        except Exception:
            logger.warning("analysis_heartbeat_update_failed")


def _enter_stage(analysis_id: str, stage: str, progress: int) -> None:
    with new_session() as session:
        analysis = session.scalar(select(Analysis).where(Analysis.id == UUID(analysis_id)).with_for_update())
        if analysis is None or analysis.status in {"CANCELLED", "FAILED", "COMPLETED", "PARTIAL"}:
            return
        try:
            transition_analysis(analysis, stage, progress)
        except InvalidStateTransition:
            if analysis.status not in {"CANCELLED", "FAILED", "COMPLETED", "PARTIAL"}:
                raise
        session.commit()


@celery_app.task(bind=True, name="worker.tasks.analyze", ignore_result=True)
def analyze(self, analysis_id: str):
    stop_heartbeat = threading.Event()
    heartbeat = threading.Thread(target=_heartbeat_loop, args=(analysis_id, stop_heartbeat), daemon=True)
    data_root = os.getenv("DATA_ROOT", "/data")
    analysis_uuid = UUID(analysis_id)
    heartbeat.start()
    try:
        with new_session() as session:
            analysis = session.get(Analysis, analysis_uuid)
            if analysis is None or analysis.status == "CANCELLED":
                return {"id": analysis_id, "status": "CANCELLED"}
            analysis.heartbeat_at = datetime.now(timezone.utc)
            session.commit()

        # TODO(spec §6): replace this placeholder pipeline with bounded static extraction.
        temp_dir = resolve_under(artifact_dir_path(data_root, analysis_id), "tmp")
        temp_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for stage, progress in PIPELINE_STAGES:
            _enter_stage(analysis_id, stage, progress)
            with new_session() as session:
                current = session.get(Analysis, analysis_uuid)
                if current is None or current.status == "CANCELLED":
                    return {"id": analysis_id, "status": "CANCELLED"}
            time.sleep(PLACEHOLDER_DELAY_S)

        with new_session() as session:
            analysis = session.scalar(select(Analysis).where(Analysis.id == analysis_uuid).with_for_update())
            if analysis is None or analysis.status == "CANCELLED":
                return {"id": analysis_id, "status": "CANCELLED"}
            transition_analysis(analysis, "PARTIAL", 95)
            analysis.decomp_status = "NOT_RUN"
            analysis.ai_status = "DISABLED"
            analysis.error_code = "PIPELINE_STUBBED"
            analysis.error_message = "Pipeline stages are placeholders; no binary analysis was performed."
            session.commit()
        return {"id": analysis_id, "status": "PARTIAL"}
    except Exception:
        logger.error("analysis_pipeline_failed")
        try:
            with new_session() as session:
                analysis = session.scalar(select(Analysis).where(Analysis.id == analysis_uuid).with_for_update())
                if analysis is not None and analysis.status not in {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}:
                    transition_analysis(analysis, "FAILED")
                    analysis.error_code = "INTERNAL_ERROR"
                    analysis.error_message = "Analysis could not be completed. Re-upload to try again."
                    session.commit()
        except Exception:
            logger.error("analysis_failure_state_update_failed")
        return {"id": analysis_id, "status": "FAILED"}
    finally:
        stop_heartbeat.set()
        heartbeat.join(timeout=1)
        try:
            remove_temporary_artifacts(data_root, analysis_id)
        except Exception:
            logger.warning("analysis_temporary_file_cleanup_failed")
