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
from app.models import Analysis, ExportSymbol, ImportSymbol, Section, StringRecord
from app.state_machine import InvalidStateTransition, transition_analysis
from app.storage import artifact_dir_path, remove_temporary_artifacts, resolve_under, upload_file_path
from worker.lief_extract import InvalidBinary, UnsupportedArchitecture, extract_pe, load_import_categories
from worker.normalize import NormalizationError, normalize_analysis, serialize_normalized

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


def _mark_failed(analysis_id: str, code: str, message: str) -> None:
    with new_session() as session:
        analysis = session.scalar(select(Analysis).where(Analysis.id == UUID(analysis_id)).with_for_update())
        if analysis is not None and analysis.status not in {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}:
            transition_analysis(analysis, "FAILED")
            analysis.error_code = code
            analysis.error_message = message
            session.commit()


def _persist_static_metadata(analysis_id: str, static: dict) -> None:
    analysis_uuid = UUID(analysis_id)
    with new_session() as session:
        analysis = session.scalar(select(Analysis).where(Analysis.id == analysis_uuid).with_for_update())
        if analysis is None or analysis.status in {"CANCELLED", "FAILED"}:
            return
        analysis.sha256 = static["sha256"]
        analysis.md5 = static["md5"]
        analysis.file_size = static["size"]
        analysis.format = static["format"]
        analysis.arch = static["arch"]
        analysis.bitness = static["bitness"]
        analysis.endian = static["endian"]
        analysis.entry_point = static["entry_point"]
        analysis.extension_mismatch = static["extension_mismatch"]
        analysis.strings_truncated = static["strings_truncated"]
        analysis.possible_packing = static["possible_packing"]
        analysis.toolchain = {**analysis.toolchain, "lief": "1.0.0"}
        for row in static["sections"]:
            session.add(Section(analysis_id=analysis_uuid, **row))
        for row in static["imports"]:
            session.add(ImportSymbol(analysis_id=analysis_uuid, **row))
        for row in static["exports"]:
            session.add(ExportSymbol(analysis_id=analysis_uuid, **row))
        for row in static["strings"]:
            session.add(StringRecord(analysis_id=analysis_uuid, **row))
        session.commit()


def _write_normalized(data_root: str, analysis_id: str, normalized: dict) -> None:
    artifact_dir = artifact_dir_path(data_root, analysis_id)
    artifact_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = resolve_under(artifact_dir, "normalized.json")
    temp_path = resolve_under(artifact_dir, f".normalized-{analysis_id}.tmp")
    content = serialize_normalized(normalized)
    try:
        with temp_path.open("xb") as stream:
            os.chmod(temp_path, 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target)
        os.chmod(target, 0o600)
    finally:
        temp_path.unlink(missing_ok=True)


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

        # TODO(spec §6): replace the bounded PE x64 path with the full static toolchain.
        analysis_artifacts = artifact_dir_path(data_root, analysis_id)
        analysis_artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(analysis_artifacts, 0o700)
        temp_dir = resolve_under(analysis_artifacts, "tmp")
        temp_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _enter_stage(analysis_id, "VALIDATING", 5)
        with new_session() as session:
            current = session.get(Analysis, analysis_uuid)
            if current is None or current.status == "CANCELLED":
                return {"id": analysis_id, "status": "CANCELLED"}

        _enter_stage(analysis_id, "STATIC_ANALYSIS", 15)
        with new_session() as session:
            current = session.get(Analysis, analysis_uuid)
            if current is None or current.status == "CANCELLED":
                return {"id": analysis_id, "status": "CANCELLED"}
            original_filename = current.original_filename
            extension_mismatch = current.extension_mismatch
        upload_path = upload_file_path(data_root, analysis_id)
        static = extract_pe(
            upload_path,
            original_filename=original_filename,
            extension_mismatch=extension_mismatch,
            categories=load_import_categories(),
        )
        _persist_static_metadata(analysis_id, static)
        time.sleep(PLACEHOLDER_DELAY_S)

        # TODO(spec §14): Ghidra re-analysis is a later optional pipeline step.
        _enter_stage(analysis_id, "RE_ANALYSIS", 35)
        time.sleep(PLACEHOLDER_DELAY_S)

        _enter_stage(analysis_id, "NORMALIZING", 50)
        with new_session() as session:
            current = session.get(Analysis, analysis_uuid)
            if current is None or current.status == "CANCELLED":
                return {"id": analysis_id, "status": "CANCELLED"}
            created_at = current.created_at
        normalized = normalize_analysis(static, analysis_id, created_at=created_at)
        _write_normalized(data_root, analysis_id, normalized)

        for stage, progress in PIPELINE_STAGES[4:]:
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
            analysis.error_message = "PE x64 static metadata was extracted; Ghidra, detection, and AI stages remain placeholders."
            session.commit()
        return {"id": analysis_id, "status": "PARTIAL"}
    except UnsupportedArchitecture as exc:
        _mark_failed(analysis_id, "UNSUPPORTED_ARCHITECTURE", str(exc))
        return {"id": analysis_id, "status": "FAILED"}
    except InvalidBinary:
        _mark_failed(analysis_id, "INVALID_BINARY", "The uploaded file could not be parsed as a valid PE binary.")
        return {"id": analysis_id, "status": "FAILED"}
    except NormalizationError:
        _mark_failed(analysis_id, "INTERNAL_ERROR", "Analysis output could not be validated. Please re-upload later.")
        return {"id": analysis_id, "status": "FAILED"}
    except Exception:
        logger.error("analysis_pipeline_failed")
        try:
            _mark_failed(analysis_id, "INTERNAL_ERROR", "Analysis could not be completed. Re-upload to try again.")
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
