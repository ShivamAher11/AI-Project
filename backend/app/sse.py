import asyncio
import json
import os
import time
from collections.abc import AsyncIterator
from uuid import UUID

from fastapi.responses import StreamingResponse
from redis import Redis

from .db import new_session
from .models import Analysis

TERMINAL_EVENT = {
    "COMPLETED": "completed",
    "PARTIAL": "partial",
    "FAILED": "failed",
    "CANCELLED": "cancelled",
}


def _read_analysis(analysis_id: str) -> dict | None:
    with new_session() as session:
        row = session.get(Analysis, UUID(analysis_id))
        if row is None:
            return None
        return {
            "id": str(row.id),
            "status": row.status,
            "stage": row.stage,
            "progress": row.progress,
            "error_code": row.error_code,
            "error_message": row.error_message,
        }


def _redis_terminal(analysis_id: str) -> dict | None:
    try:
        value = Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True).get(
            f"analysis-terminal:{analysis_id}"
        )
        return json.loads(value) if value else None
    except Exception:
        return None


def _format_event(name: str, payload: dict, seq: int) -> str:
    return f"id: {seq}\nevent: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


def _terminal_event(snapshot: dict) -> tuple[str, dict]:
    state = snapshot["status"]
    name = TERMINAL_EVENT[state]
    if state == "PARTIAL":
        return name, {
            "reason": snapshot.get("error_message") or "Analysis completed with limited results.",
            "available": [],
        }
    if state == "FAILED":
        return name, {"code": snapshot.get("error_code") or "ANALYSIS_FAILED", "message": snapshot.get("error_message") or "Analysis failed."}
    if state == "CANCELLED":
        return name, {"id": snapshot["id"]}
    return name, {"id": snapshot["id"], "status": state}


async def analysis_event_stream(analysis_id: str) -> AsyncIterator[str]:
    # TODO(spec §19): Last-Event-ID replay is deferred for the solo MVP.
    seq = 0
    snapshot = _read_analysis(analysis_id)
    if snapshot is None:
        tombstone = _redis_terminal(analysis_id)
        if tombstone:
            yield _format_event("connected", {"id": analysis_id, "status": "CANCELLED", "stage": "CANCELLED", "progress": 0}, seq := seq + 1)
            yield _format_event(tombstone["event"], tombstone["data"], seq := seq + 1)
        return

    yield _format_event(
        "connected",
        {"id": snapshot["id"], "status": snapshot["status"], "stage": snapshot["stage"], "progress": snapshot["progress"]},
        seq := seq + 1,
    )
    if snapshot["status"] in TERMINAL_EVENT:
        name, data = _terminal_event(snapshot)
        yield _format_event(name, data, seq := seq + 1)
        return

    yield _format_event("stage_change", {"stage": snapshot["stage"], "progress": snapshot["progress"]}, seq := seq + 1)
    yield _format_event("progress", {"stage": snapshot["stage"], "progress": snapshot["progress"], "detail": "Current analysis stage."}, seq := seq + 1)
    last_stage = snapshot["stage"]
    last_progress = snapshot["progress"]
    last_ping = time.monotonic()

    while True:
        await asyncio.sleep(0.1)
        current = _read_analysis(analysis_id)
        if current is None:
            tombstone = _redis_terminal(analysis_id)
            if tombstone:
                yield _format_event(tombstone["event"], tombstone["data"], seq := seq + 1)
            return

        if current["stage"] != last_stage:
            yield _format_event("stage_change", {"stage": current["stage"], "progress": current["progress"]}, seq := seq + 1)
            last_stage = current["stage"]
        if current["progress"] != last_progress:
            yield _format_event(
                "progress",
                {"stage": current["stage"], "progress": current["progress"], "detail": "Stage progress updated."},
                seq := seq + 1,
            )
            last_progress = current["progress"]

        if current["status"] in TERMINAL_EVENT:
            name, data = _terminal_event(current)
            yield _format_event(name, data, seq := seq + 1)
            return

        if time.monotonic() - last_ping >= 15:
            yield ":ping\n\n"
            last_ping = time.monotonic()


def event_response(iterator: AsyncIterator[str]) -> StreamingResponse:
    return StreamingResponse(
        iterator,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def store_terminal_tombstone(analysis_id: str, event_name: str, data: dict) -> None:
    client = Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    client.setex(
        f"analysis-terminal:{analysis_id}",
        60,
        json.dumps({"event": event_name, "data": data}, separators=(",", ":")),
    )
