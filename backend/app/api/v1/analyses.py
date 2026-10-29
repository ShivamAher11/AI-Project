import hashlib
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ...celery_app import celery_app
from ...db import new_session
from ...models import Analysis
from ...sse import analysis_event_stream, event_response, store_terminal_tombstone
from ...state_machine import TERMINAL_STATES, transition_analysis
from ...storage import (
    UnsafeStoragePath,
    create_upload_directory,
    remove_analysis_files,
    upload_file_path,
)

router = APIRouter()
MAX_FILE_MB = max(1, min(100, int(os.getenv("MAX_FILE_MB", "100"))))
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
CONTENT_LENGTH_OVERHEAD = 64 * 1024
CHUNK_BYTES = 64 * 1024
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"


class UploadTooLarge(Exception):
    pass


def _problem(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


async def _stream_upload(upload: UploadFile, target: Path, max_bytes: int) -> tuple[int, str, str, bytes]:
    """Copy the multipart file in bounded chunks; never use the client name as a path."""
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    size = 0
    prefix = bytearray()
    try:
        with os.fdopen(descriptor, "wb") as output:
            while True:
                chunk = await upload.read(CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise UploadTooLarge
                if len(prefix) < 4:
                    prefix.extend(chunk[: 4 - len(prefix)])
                sha256.update(chunk)
                md5.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        return size, sha256.hexdigest(), md5.hexdigest(), bytes(prefix)
    except BaseException:
        try:
            target.unlink(missing_ok=True)
        finally:
            raise


def _detect_format(prefix: bytes) -> str | None:
    if prefix.startswith(PE_MAGIC):
        return "pe"
    if prefix.startswith(ELF_MAGIC):
        return "elf"
    return None


def _extension_mismatch(filename: str, binary_format: str) -> bool:
    extension = os.path.splitext(filename)[1].lower()
    if binary_format == "pe":
        return bool(extension and extension not in {".exe", ".dll"})
    return bool(extension and extension not in {".elf", ".so"})


def _content_length_too_large(value: str | None, max_bytes: int) -> bool:
    if value is None:
        return False
    try:
        length = int(value)
    except ValueError:
        raise _problem(400, "INVALID_CONTENT_LENGTH", "Invalid Content-Length header.")
    return length > max_bytes + CONTENT_LENGTH_OVERHEAD


def _get_analysis(session: Session, analysis_id: uuid.UUID) -> Analysis:
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise _problem(404, "ANALYSIS_NOT_FOUND", "Analysis not found.")
    return analysis


@router.post(
    "",
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {"file": {"type": "string", "format": "binary"}},
                    }
                }
            },
        }
    },
)
async def create_analysis(request: Request):
    max_bytes = MAX_FILE_BYTES
    if _content_length_too_large(request.headers.get("content-length"), max_bytes):
        raise _problem(413, "PAYLOAD_TOO_LARGE", f"File too large. Max {MAX_FILE_MB} MB.")

    # TODO(spec §12): raw-body ASGI receive counting is deferred; ingress and this file stream counter bound uploads.
    try:
        form = await request.form()
    except Exception:
        raise _problem(400, "INVALID_MULTIPART", "Could not read the multipart upload.")
    file = form.get("file")
    if not isinstance(file, UploadFile):
        raise _problem(422, "VALIDATION_ERROR", "A multipart file field is required.")

    analysis_id = uuid.uuid4()
    data_root = os.getenv("DATA_ROOT", "/data")
    try:
        create_upload_directory(data_root, str(analysis_id))
        target = upload_file_path(data_root, str(analysis_id))
        size, sha256, md5, prefix = await _stream_upload(file, target, max_bytes)
    except UploadTooLarge:
        remove_analysis_files(data_root, str(analysis_id))
        raise _problem(413, "PAYLOAD_TOO_LARGE", f"File too large. Max {MAX_FILE_MB} MB.")
    except Exception:
        remove_analysis_files(data_root, str(analysis_id))
        raise
    finally:
        await file.close()

    if size == 0:
        remove_analysis_files(data_root, str(analysis_id))
        raise _problem(400, "EMPTY_FILE", "Uploaded file is empty.")

    binary_format = _detect_format(prefix)
    if binary_format is None:
        remove_analysis_files(data_root, str(analysis_id))
        raise _problem(400, "UNSUPPORTED_FORMAT", "Unsupported or invalid binary. Upload a valid PE or ELF.")

    original_filename = (file.filename or "upload").replace("\x00", "")[:255]
    mismatch = _extension_mismatch(original_filename, binary_format)
    now = datetime.now(timezone.utc)
    try:
        with new_session() as session:
            prior_ids = list(
                session.scalars(
                    select(Analysis.id)
                    .where(Analysis.sha256 == sha256)
                    .order_by(Analysis.created_at.asc(), Analysis.id.asc())
                )
            )
            analysis = Analysis(
                id=analysis_id,
                status="CREATED",
                stage="CREATED",
                progress=0,
                original_filename=original_filename,
                sha256=sha256,
                md5=md5,
                file_size=size,
                format=binary_format,
                arch="unknown",
                bitness=None,
                entry_point=None,
                toolchain={"ghidra": "NOT_RUN", "jdk": "NOT_RUN", "lief": "NOT_RUN", "capstone": "NOT_RUN"},
                scoring_version="1.0",
                rule_set_version="1.0",
                schema_version="1.0",
                decomp_status="NOT_RUN",
                ai_status="NOT_RUN",
                created_at=now,
                heartbeat_at=now,
            )
            session.add(analysis)
            session.commit()
    except Exception:
        remove_analysis_files(data_root, str(analysis_id))
        raise

    response_status = "CREATED"
    try:
        celery_app.send_task("worker.tasks.analyze", args=[str(analysis_id)], task_id=str(analysis_id), queue="analyses")
    except Exception:
        with new_session() as session:
            failed = session.get(Analysis, analysis_id)
            if failed is not None:
                transition_analysis(failed, "FAILED")
                failed.error_code = "QUEUE_UNAVAILABLE"
                failed.error_message = "The analysis queue is unavailable. Try again shortly."
                session.commit()
                response_status = "FAILED"

    return {
        "id": str(analysis_id),
        "status": response_status,
        "extension_mismatch": mismatch,
        "prior_analysis_ids": [str(item) for item in prior_ids],
    }


@router.get("/{analysis_id}/status")
def analysis_status(analysis_id: uuid.UUID):
    with new_session() as session:
        analysis = _get_analysis(session, analysis_id)
        error = None
        if analysis.error_code:
            error = {"code": analysis.error_code, "message": analysis.error_message}
        return {
            "id": str(analysis.id),
            "status": analysis.status,
            "stage": analysis.stage,
            "progress": analysis.progress,
            "decomp_status": analysis.decomp_status,
            "ai_status": analysis.ai_status,
            "error": error,
        }


@router.get("/{analysis_id}/events")
def analysis_events(analysis_id: uuid.UUID):
    with new_session() as session:
        _get_analysis(session, analysis_id)
    return event_response(analysis_event_stream(str(analysis_id)))


@router.delete("/{analysis_id}", status_code=202)
def delete_analysis(analysis_id: uuid.UUID):
    data_root = os.getenv("DATA_ROOT", "/data")
    with new_session() as session:
        analysis = _get_analysis(session, analysis_id)
        if analysis.status not in TERMINAL_STATES:
            try:
                celery_app.control.revoke(str(analysis_id), terminate=True, signal="SIGTERM")
            except Exception:
                pass
            transition_analysis(analysis, "CANCELLED")
            session.commit()
            try:
                store_terminal_tombstone(str(analysis_id), "cancelled", {"id": str(analysis_id)})
            except Exception:
                pass
        try:
            remove_analysis_files(data_root, str(analysis_id))
        except OSError:
            pass
        session.delete(analysis)
        session.commit()
    return {"deleted": True}
