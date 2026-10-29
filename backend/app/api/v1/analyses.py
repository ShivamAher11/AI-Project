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
from ...models import (Analysis, AttackMapping, CallEdge, Evidence, ExportSymbol, Finding, Function,
                       ImportSymbol, Section, StringRecord)
from ...sse import analysis_event_stream, event_response, store_terminal_tombstone
from ...state_machine import TERMINAL_STATES, transition_analysis
from ...storage import (
    UnsafeStoragePath,
    create_upload_directory,
    remove_analysis_files,
    upload_file_path,
    function_artifact_path,
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


def _address_order(value: str | None) -> tuple[bool, int]:
    return (value is None, int(value, 16) if value else 0)


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
                endian="le",
                extension_mismatch=mismatch,
                strings_truncated=False,
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


@router.get("/{analysis_id}/static")
def analysis_static_metadata(analysis_id: uuid.UUID):
    """Return persisted LIEF metadata as soon as the static-analysis stage ingests it."""
    with new_session() as session:
        analysis = _get_analysis(session, analysis_id)
        sections = list(session.scalars(select(Section).where(Section.analysis_id == analysis_id)))
        imports = list(session.scalars(select(ImportSymbol).where(ImportSymbol.analysis_id == analysis_id)))
        exports = list(session.scalars(select(ExportSymbol).where(ExportSymbol.analysis_id == analysis_id)))
        strings = list(session.scalars(select(StringRecord).where(StringRecord.analysis_id == analysis_id)))
        functions = list(session.scalars(select(Function).where(Function.analysis_id == analysis_id)))
        edges = list(session.scalars(select(CallEdge).where(CallEdge.analysis_id == analysis_id)))
        return {
            "id": str(analysis.id),
            "status": analysis.status,
            "stage": analysis.stage,
            "source": analysis.ghidra_source,
            "source_label": "source: fixture" if analysis.ghidra_source == "fixture" else f"source: {analysis.ghidra_source}",
            "scoring": {"score": analysis.risk_score, "rating": analysis.risk_rating,
                        "scoring_version": analysis.scoring_version, "rule_set_version": analysis.rule_set_version,
                        "input_hash": analysis.scoring_input_hash, "breakdown": analysis.scoring_breakdown or []},
            "static_available": bool(sections or imports or exports or strings or analysis.arch != "unknown"),
            "file": {
                "sha256": analysis.sha256,
                "md5": analysis.md5,
                "size": analysis.file_size,
                "format": analysis.format,
                "arch": analysis.arch,
                "bitness": analysis.bitness,
                "endian": analysis.endian,
                "entry_point": analysis.entry_point,
                "extension_mismatch": analysis.extension_mismatch,
                "strings_truncated": analysis.strings_truncated,
            },
            "strings_truncated": analysis.strings_truncated,
            "possible_packing": analysis.possible_packing,
            "packing_note": "possible packing - heuristic, not proof" if analysis.possible_packing else None,
            "sections": [
                {"name": row.name, "vaddr": row.vaddr, "vsize": row.vsize, "raw_size": row.raw_size,
                 "perms": row.perms, "entropy": row.entropy}
                for row in sorted(sections, key=lambda item: (_address_order(item.vaddr), item.name))
            ],
            "imports": [
                {"library": row.library, "name": row.name, "ordinal": row.ordinal, "address": row.address,
                 "category": row.category}
                for row in sorted(imports, key=lambda item: (_address_order(item.address), item.library, item.name))
            ],
            "exports": [
                {"name": row.name, "address": row.address, "ordinal": row.ordinal}
                for row in sorted(exports, key=lambda item: (_address_order(item.address), item.ordinal or 0, item.name))
            ],
            "strings": [
                {"offset": row.offset, "encoding": row.encoding, "value": row.value,
                 "length": row.length, "category": row.category}
                for row in sorted(strings, key=lambda item: (_address_order(item.offset), item.encoding, item.value))
            ],
            "functions": [
                {"id": row.id, "address": row.address, "name": row.name, "size": row.size,
                 "decompiler_status": row.decompiler_status, "decompiled_excerpt": row.decompiled_excerpt,
                 "centrality": row.centrality, "artifact_available": bool(row.artifact_path)}
                for row in sorted(functions, key=lambda item: int(item.address, 16))
            ],
            "edges": [{"caller": row.caller_id, "callee": row.callee_id, "type": row.edge_type}
                      for row in sorted(edges, key=lambda item: (item.caller_id, item.callee_id, item.edge_type))],
        }


@router.get("/{analysis_id}/findings")
def analysis_findings(analysis_id: uuid.UUID):
    with new_session() as session:
        _get_analysis(session, analysis_id)
        rows = list(session.scalars(select(Finding).where(Finding.analysis_id == analysis_id)))
        result = []
        for row in sorted(rows, key=lambda item: (-item.score_contribution, item.group_id or item.type, str(item.id))):
            evidence = sorted(session.scalars(select(Evidence).where(Evidence.finding_id == row.id)),
                              key=lambda item: (item.source_type, item.source_id, str(item.id)))
            mappings = sorted(session.scalars(select(AttackMapping).where(AttackMapping.finding_id == row.id)),
                              key=lambda item: item.technique_id)
            result.append({"id": str(row.id), "type": row.type, "group_id": row.group_id, "title": row.title,
                "severity": row.severity, "confidence": row.confidence, "confidence_score": row.confidence_score,
                "description": row.description, "interpretation": row.interpretation, "alternative": row.alternative,
                "score_contribution": row.score_contribution, "signal_ids": row.signal_ids,
                "evidence": [{"id": str(item.id), "source_type": item.source_type, "source_id": item.source_id,
                    "excerpt": item.excerpt, "offset_or_address": item.offset_or_address, "reason": item.reason}
                    for item in evidence],
                "attack_mappings": [{"technique_id": item.technique_id, "technique_name": item.technique_name,
                    "confidence": item.confidence, "confidence_score": item.confidence_score,
                    "label": "Likely" if item.confidence_score >= 0.8 else "Possible" if item.confidence_score >= 0.5 else None,
                    "display": item.confidence_score >= 0.5, "rationale": item.rationale} for item in mappings]})
        return {"items": result}


@router.get("/{analysis_id}/functions")
def analysis_functions(analysis_id: uuid.UUID):
    with new_session() as session:
        _get_analysis(session, analysis_id)
        rows = list(session.scalars(select(Function).where(Function.analysis_id == analysis_id)))
        return {"items": [{"id": row.id, "address": row.address, "name": row.name,
                            "centrality": row.centrality, "decompiler_status": row.decompiler_status,
                            "decompiled_excerpt": row.decompiled_excerpt,
                            "artifact_available": bool(row.artifact_path)}
                           for row in sorted(rows, key=lambda item: int(item.address, 16))], "next_cursor": None}


@router.get("/{analysis_id}/functions/{fid}")
def analysis_function_detail(analysis_id: uuid.UUID, fid: str, load_full: bool = False):
    with new_session() as session:
        _get_analysis(session, analysis_id)
        row = session.get(Function, fid)
        if row is None or row.analysis_id != analysis_id:
            raise _problem(404, "FUNCTION_NOT_FOUND", "Function not found.")
        result = {"id": row.id, "address": row.address, "name": row.name,
                  "centrality": row.centrality, "decompiler_status": row.decompiler_status,
                  "decompiled_excerpt": row.decompiled_excerpt, "artifact_available": bool(row.artifact_path)}
        if load_full and row.artifact_path:
            try:
                path = function_artifact_path(os.getenv("DATA_ROOT", "/data"), str(analysis_id), fid)
                with path.open("rb") as stream:
                    content = stream.read(500_001)
            except (UnsafeStoragePath, OSError):
                raise _problem(404, "FUNCTION_ARTIFACT_NOT_FOUND", "Full decompilation artifact not found.")
            result["decompiled_full"] = content[:500_000].decode("utf-8", errors="replace")
            result["artifact_truncated"] = row.artifact_size is not None and row.artifact_size > 500_000
        return result


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
