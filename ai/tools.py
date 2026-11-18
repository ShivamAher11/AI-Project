"""Typed, allow-listed static-analysis tools the model may request.

Tools run only in the API process and read only persisted, bounded static
evidence from PostgreSQL. They never receive raw file bytes, upload paths,
shell access, network access, or arbitrary SQL. All output is treated as
untrusted evidence and is bounded in size before it reaches the model.

The allowlist is intentionally small:
  analysis.metadata   bounded analysis/file metadata
  analysis.strings    bounded printable-string records with offsets
  analysis.functions  bounded function list
  analysis.function_detail bounded detail for one function ID
  analysis.findings   bounded findings with evidence refs
  analysis.imports    bounded import records

Every tool call counts against the per-analysis budget (52 calls and the
60,000-output-token ceiling from SPEC §49). Unknown tools and unknown/invalid
arguments are rejected before any work is done.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.db import new_session
from app.models import (
    Analysis,
    CallEdge,
    Evidence,
    Finding,
    Function,
    ImportSymbol,
    Signal,
    StringRecord,
)

# SPEC §49 ceilings.
MAX_TOOL_CALLS_PER_ANALYSIS = 52
MAX_OUTPUT_BYTES_PER_ANALYSIS = 60_000 * 4  # conservative 4 bytes/token proxy
MAX_OUTPUT_BYTES_PER_CALL = 8_000
MAX_STRINGS_PER_CALL = 50
MAX_STRING_VALUE_CHARS = 500
MAX_FINDINGS_PER_CALL = 20
MAX_FUNCTIONS_PER_CALL = 40
MAX_IMPORTS_PER_CALL = 40

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_FID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}:0x[0-9a-f]+$")


class ToolBudgetExceeded(RuntimeError):
    """The per-analysis tool budget is exhausted."""


class ToolNotAllowed(RuntimeError):
    """The requested tool is not on the allowlist."""


class ToolArgumentError(RuntimeError):
    """The tool arguments failed validation."""


class ToolNotFound(RuntimeError):
    """The referenced analysis or evidence item does not exist."""


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    output_bytes: int = 0
    ok: bool = True
    error: str | None = None


@dataclass
class ToolBudget:
    calls: int = 0
    output_bytes: int = 0
    calls_log: list[dict[str, Any]] = field(default_factory=list)

    def remaining_calls(self) -> int:
        return max(0, MAX_TOOL_CALLS_PER_ANALYSIS - self.calls)

    def record(self, call: ToolCall) -> None:
        self.calls += 1
        self.output_bytes += call.output_bytes
        self.calls_log.append(
            {
                "tool": call.name,
                "output_bytes": call.output_bytes,
                "ok": call.ok,
                "error": call.error,
            }
        )

    def check_capacity(self) -> None:
        if self.calls >= MAX_TOOL_CALLS_PER_ANALYSIS:
            raise ToolBudgetExceeded(
                f"Tool call budget exhausted ({MAX_TOOL_CALLS_PER_ANALYSIS} calls)."
            )
        if self.output_bytes >= MAX_OUTPUT_BYTES_PER_ANALYSIS:
            raise ToolBudgetExceeded(
                f"Tool output budget exhausted ({MAX_OUTPUT_BYTES_PER_ANALYSIS} bytes)."
            )


# ---------------------------------------------------------------------------
# Argument validation helpers
# ---------------------------------------------------------------------------

def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolArgumentError(f"{field_name} must be a non-empty string.")
    return value


def _require_analysis_id(value: Any) -> UUID:
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ToolArgumentError("analysis_id must be a valid UUID.") from exc


def _require_fid(value: Any) -> str:
    fid = _require_str(value, "function_id")
    if not _FID_PATTERN.match(fid):
        raise ToolArgumentError("function_id must match <uuid>:0x<hex>.")
    return fid


def _bounded_int(
    value: Any, default: int, minimum: int, maximum: int
) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError) as exc:
        raise ToolArgumentError("Limit must be an integer.") from exc
    return max(minimum, min(maximum, parsed))


def _validate_args(
    tool: str, arguments: dict[str, Any] | None
) -> dict[str, Any]:
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ToolArgumentError("Tool arguments must be a JSON object.")
    known = _TOOL_ARGS.get(tool)
    if known is None:
        raise ToolNotAllowed(f"Unknown tool: {tool}")
    for key in arguments:
        if key not in known["allowed"]:
            raise ToolArgumentError(f"Unknown argument '{key}' for {tool}.")
    result: dict[str, Any] = {}
    for key, spec in known["schema"].items():
        required = bool(spec.get("required", False))
        default = spec.get("default")
        if key not in arguments or arguments[key] is None:
            if required:
                raise ToolArgumentError(
                    f"Missing required argument '{key}' for {tool}."
                )
            result[key] = default
            continue
        value = arguments[key]
        if spec["type"] == "string":
            result[key] = _require_str(value, key)
        elif spec["type"] == "integer":
            result[key] = _bounded_int(
                value,
                default,
                int(spec.get("minimum", 0)),
                int(spec.get("maximum", 1000)),
            )
        elif spec["type"] == "boolean":
            if not isinstance(value, bool):
                raise ToolArgumentError(f"{key} must be a boolean.")
            result[key] = value
    return result


# Tool name -> {"allowed": [arg names], "schema": {arg: {...}}}
_TOOL_ARGS: dict[str, dict[str, Any]] = {
    "analysis.metadata": {
        "allowed": ["analysis_id"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
        },
    },
    "analysis.strings": {
        "allowed": ["analysis_id", "limit", "offset_hex"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
            "limit": {
                "type": "integer",
                "required": False,
                "default": 20,
                "minimum": 1,
                "maximum": MAX_STRINGS_PER_CALL,
            },
            "offset_hex": {"type": "string", "required": False, "default": ""},
        },
    },
    "analysis.functions": {
        "allowed": ["analysis_id", "limit"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
            "limit": {
                "type": "integer",
                "required": False,
                "default": 20,
                "minimum": 1,
                "maximum": MAX_FUNCTIONS_PER_CALL,
            },
        },
    },
    "analysis.function_detail": {
        "allowed": ["analysis_id", "function_id"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
            "function_id": {"type": "string", "required": True},
        },
    },
    "analysis.findings": {
        "allowed": ["analysis_id", "limit"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
            "limit": {
                "type": "integer",
                "required": False,
                "default": 10,
                "minimum": 1,
                "maximum": MAX_FINDINGS_PER_CALL,
            },
        },
    },
    "analysis.imports": {
        "allowed": ["analysis_id", "limit"],
        "schema": {
            "analysis_id": {"type": "string", "required": True},
            "limit": {
                "type": "integer",
                "required": False,
                "default": 20,
                "minimum": 1,
                "maximum": MAX_IMPORTS_PER_CALL,
            },
        },
    },
}

_TOOLS = frozenset(_TOOL_ARGS)


# ---------------------------------------------------------------------------
# Output bounding
# ---------------------------------------------------------------------------

def _safe(value: Any, limit: int) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value[:limit]
    return value


def _serialize_bounded(obj: Any, max_bytes: int) -> bytes:
    serialized = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    data = serialized.encode("utf-8")
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data


def _check_evidence_ids(session, analysis_id: UUID, ids: list[str]) -> None:
    """Validate that every evidence id exists in this analysis."""
    if not ids:
        return
    rows = session.scalars(
        select(Evidence.id).where(
            Evidence.analysis_id == analysis_id, Evidence.id.in_(ids)
        )
    )
    found = {str(row) for row in rows}
    missing = sorted(set(ids) - found)
    if missing:
        raise ToolNotFound(f"Unknown evidence id(s): {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def _handle_metadata(session, analysis_id: UUID, args: dict[str, Any]) -> dict[str, Any]:
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise ToolNotFound("Analysis not found.")
    return {
        "analysis_id": str(analysis.id),
        "original_filename": _safe(analysis.original_filename, 128),
        "sha256": analysis.sha256,
        "md5": analysis.md5,
        "file_size": analysis.file_size,
        "format": analysis.format,
        "arch": analysis.arch,
        "bitness": analysis.bitness,
        "endian": analysis.endian,
        "entry_point": analysis.entry_point,
        "extension_mismatch": analysis.extension_mismatch,
        "status": analysis.status,
        "decomp_status": analysis.decomp_status,
        "ai_status": analysis.ai_status,
        "source": analysis.ghidra_source,
        "risk_score": analysis.risk_score,
        "risk_rating": analysis.risk_rating,
        "scoring_version": analysis.scoring_version,
        "rule_set_version": analysis.rule_set_version,
        "strings_truncated": analysis.strings_truncated,
        "possible_packing": analysis.possible_packing,
    }


def _handle_strings(session, analysis_id: UUID, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    offset_hex = str(args.get("offset_hex") or "")
    query = (
        select(StringRecord)
        .where(StringRecord.analysis_id == analysis_id)
        .order_by(StringRecord.offset.asc())
    )
    if offset_hex:
        query = query.where(StringRecord.offset >= offset_hex)
    rows = list(session.scalars(query.limit(limit)))
    return {
        "analysis_id": str(analysis_id),
        "strings": [
            {
                "offset": row.offset,
                "encoding": row.encoding,
                "value": _safe(row.value, MAX_STRING_VALUE_CHARS),
                "length": row.length,
                "category": row.category,
            }
            for row in rows
        ],
        "returned": len(rows),
        "limit": limit,
    }


def _handle_functions(session, analysis_id: UUID, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    rows = list(
        session.scalars(
            select(Function)
            .where(Function.analysis_id == analysis_id)
            .order_by(Function.address.asc())
            .limit(limit)
        )
    )
    return {
        "analysis_id": str(analysis_id),
        "functions": [
            {
                "id": row.id,
                "address": row.address,
                "name": row.name,
                "size": row.size,
                "decompiler_status": row.decompiler_status,
                "centrality": row.centrality,
                "artifact_available": bool(row.artifact_path),
            }
            for row in rows
        ],
        "returned": len(rows),
        "limit": limit,
    }


def _handle_function_detail(
    session, analysis_id: UUID, args: dict[str, Any]
) -> dict[str, Any]:
    fid = _require_fid(args.get("function_id"))
    row = session.get(Function, fid)
    if row is None or row.analysis_id != analysis_id:
        raise ToolNotFound("Function not found in this analysis.")
    edges = list(
        session.scalars(
            select(CallEdge).where(
                (CallEdge.caller_id == fid) | (CallEdge.callee_id == fid)
            ).limit(20)
        )
    )
    evidence_ids: list[str] = []
    for sig in session.scalars(select(Signal).where(Signal.analysis_id == analysis_id)):
        fids = sig.function_ids or []
        if fid in fids:
            evidence_ids.extend(sig.evidence_refs or [])
    _check_evidence_ids(session, analysis_id, evidence_ids)
    excerpt = _safe(row.decompiled_excerpt, MAX_STRING_VALUE_CHARS * 2)
    assembly = _safe(row.assembly_excerpt, MAX_STRING_VALUE_CHARS * 2)
    return {
        "function_id": fid,
        "address": row.address,
        "name": row.name,
        "signature": row.signature,
        "size": row.size,
        "decompiler_status": row.decompiler_status,
        "centrality": row.centrality,
        "decompiled_excerpt": excerpt,
        "assembly_excerpt": assembly,
        "artifact_available": bool(row.artifact_path),
        "calls": [
            {"caller": e.caller_id, "callee": e.callee_id, "type": e.edge_type}
            for e in edges
        ],
        "evidence_ids": sorted(set(evidence_ids)),
    }


def _handle_findings(session, analysis_id: UUID, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 10))
    rows = list(
        session.scalars(
            select(Finding)
            .where(Finding.analysis_id == analysis_id)
            .order_by(
                Finding.score_contribution.desc().nullslast(), Finding.id.asc()
            )
            .limit(limit)
        )
    )
    result_findings = []
    for row in rows:
        evidence_rows = list(
            session.scalars(
                select(Evidence)
                .where(Evidence.finding_id == row.id)
                .order_by(Evidence.id.asc())
                .limit(4)
            )
        )
        result_findings.append(
            {
                "finding_id": str(row.id),
                "group_id": row.group_id,
                "title": _safe(row.title, 200),
                "severity": row.severity,
                "confidence": row.confidence,
                "score_contribution": row.score_contribution,
                "description": _safe(row.description, 800),
                "evidence_ids": [str(e.id) for e in evidence_rows],
            }
        )
    return {
        "analysis_id": str(analysis_id),
        "findings": result_findings,
        "returned": len(result_findings),
        "limit": limit,
    }


def _handle_imports(session, analysis_id: UUID, args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    rows = list(
        session.scalars(
            select(ImportSymbol)
            .where(ImportSymbol.analysis_id == analysis_id)
            .order_by(ImportSymbol.name.asc())
            .limit(limit)
        )
    )
    return {
        "analysis_id": str(analysis_id),
        "imports": [
            {
                "library": _safe(row.library, 100),
                "name": _safe(row.name, 120),
                "ordinal": row.ordinal,
                "address": row.address,
                "category": row.category,
            }
            for row in rows
        ],
        "returned": len(rows),
        "limit": limit,
    }


_HANDLERS = {
    "analysis.metadata": _handle_metadata,
    "analysis.strings": _handle_strings,
    "analysis.functions": _handle_functions,
    "analysis.function_detail": _handle_function_detail,
    "analysis.findings": _handle_findings,
    "analysis.imports": _handle_imports,
}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class StaticToolExecutor:
    """Executes one allow-listed static-analysis tool call under budget."""

    def __init__(self, analysis_id: str, budget: ToolBudget | None = None) -> None:
        try:
            self.analysis_id = UUID(analysis_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ToolArgumentError("analysis_id must be a valid UUID.") from exc
        self.budget = budget or ToolBudget()

    def call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if tool not in _TOOLS:
            raise ToolNotAllowed(f"Unknown or disallowed tool: {tool}")
        self.budget.check_capacity()
        args = _validate_args(tool, arguments)
        with new_session() as session:
            analysis = session.get(Analysis, self.analysis_id)
            if analysis is None:
                raise ToolNotFound("Analysis not found.")
            handler = _HANDLERS[tool]
            result = handler(session, self.analysis_id, args)
        output_bytes = len(_serialize_bounded(result, MAX_OUTPUT_BYTES_PER_CALL))
        call = ToolCall(name=tool, arguments=args, output_bytes=output_bytes, ok=True)
        self.budget.record(call)
        return result
