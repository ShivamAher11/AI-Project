"""Canonical normalized JSON v1.0 generation and validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
import hashlib

import networkx as nx

from jsonschema import Draft202012Validator, FormatChecker

from app.storage import UnsafeStoragePath, function_artifact_path


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "shared" / "analysis_schema_v1.0.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


class NormalizationError(ValueError):
    pass


def _addr_sort(record: dict, key: str) -> tuple:
    value = record.get(key)
    return (value is None, int(value, 16) if value else 0)


def calculate_centrality(function_ids: list[str], edges: list[dict]) -> dict[str, float]:
    """PageRank on direct calls only, scaled so the strongest node is 1.0."""
    graph = nx.DiGraph()
    graph.add_nodes_from(function_ids)
    graph.add_edges_from((edge["caller"], edge["callee"]) for edge in edges if edge["type"] == "direct")
    if graph.number_of_edges() == 0:
        return {node: 0.0 for node in graph.nodes}
    values = nx.pagerank(graph, weight=None)
    maximum = max(values.values(), default=0.0)
    return {node: (value / maximum if maximum else 0.0) for node, value in values.items()}


def normalize_analysis(static: dict, analysis_id: str, *, created_at: datetime | None = None,
                       ghidra_result: dict | None = None, data_root: str = "/data") -> dict:
    created_at = created_at or datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    sections = sorted(static["sections"], key=lambda row: (_addr_sort(row, "vaddr"), row["name"]))
    imports_by_key: dict[tuple[str, str], dict] = {}
    for row in static["imports"]:
        key = (row["library"].casefold(), row["name"].casefold())
        previous = imports_by_key.get(key)
        if previous is None or (previous["address"] is None and row["address"] is not None):
            imports_by_key[key] = row
    imports = sorted(imports_by_key.values(), key=lambda row: (_addr_sort(row, "address"),
                                                                row["library"].casefold(), row["name"].casefold()))
    exports = sorted(static["exports"], key=lambda row: (_addr_sort(row, "address"), row["ordinal"] or 0,
                                                          row["name"]))
    strings = sorted(static["strings"], key=lambda row: (_addr_sort(row, "offset"), row["encoding"], row["value"]))
    ghidra_result = ghidra_result or {"source": "none", "functions": [], "edges": []}
    source = ghidra_result.get("source", "none")
    if source not in {"fixture", "real", "none"}:
        raise NormalizationError("Invalid decompilation source.")
    id_prefix = str(UUID(analysis_id))
    address_to_id: dict[str, str] = {}
    prepared_functions = []
    for raw in ghidra_result.get("functions", []):
        address = str(raw.get("address", "")).lower()
        if not address.startswith("0x") or not address[2:] or any(char not in "0123456789abcdef" for char in address[2:]):
            raise NormalizationError("Invalid function address.")
        fid = f"{id_prefix}:{address}"
        address_to_id[address] = fid
        full_text = raw.get("decompiled_code", raw.get("decompiled_excerpt"))
        if not isinstance(full_text, str) or not full_text:
            full_text = None
        artifact = None
        excerpt = full_text[:12000] if full_text is not None else None
        if full_text is not None and str(raw.get("decompiler_status", "ok")).lower() == "ok":
            try:
                path = function_artifact_path(data_root, analysis_id, fid)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                content = full_text.encode("utf-8")
                path.write_bytes(content)
                path.chmod(0o600)
                artifact = {"path": f"funcs/{address[2:]}.c", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
            except (OSError, UnsafeStoragePath) as exc:
                raise NormalizationError("Could not safely store decompilation artifact.") from exc
        prepared_functions.append({
            "id": fid, "address": address, "name": str(raw.get("name") or f"FUN_{address[2:]}"),
            "signature": raw.get("signature"), "size": max(0, int(raw.get("size", 0))),
            "decompiler_status": "ok" if str(raw.get("decompiler_status", "ok")).lower() == "ok" else "failed",
            "assembly_excerpt": raw.get("assembly_excerpt"), "decompiled_excerpt": excerpt,
            "artifact": artifact,
        })
    prepared_functions.sort(key=lambda row: int(row["address"], 16))
    prepared_edges = []
    for raw in ghidra_result.get("edges", []):
        edge_type = raw.get("type")
        if edge_type not in {"direct", "indirect", "import"}:
            raise NormalizationError("Invalid call edge type.")
        def endpoint(value: str, *, caller: bool = False) -> str:
            value = str(value).lower()
            if value in address_to_id:
                return address_to_id[value]
            if value.startswith(f"{id_prefix}:0x") and value.split(":", 1)[1] in address_to_id:
                return value
            if not caller and edge_type == "import":
                return value
            raise NormalizationError("Call edge refers to an unknown function.")
        prepared_edges.append({"caller": endpoint(raw.get("caller", ""), caller=True),
                               "callee": endpoint(raw.get("callee", "")), "type": edge_type})
    prepared_edges.sort(key=lambda row: (row["caller"], row["callee"], row["type"]))
    centrality = calculate_centrality([row["id"] for row in prepared_functions], prepared_edges)
    for row in prepared_functions:
        row["centrality"] = round(centrality[row["id"]], 12)

    normalized = {
        "schema_version": "1.0",
        "analysis_id": str(UUID(analysis_id)),
        "sha256": static["sha256"],
        "md5": static["md5"],
        "status": "PARTIAL",
        "decomp_status": "OK" if source == "fixture" and ghidra_result.get("functions") else "NOT_RUN",
        "source": source,
        "strings_truncated": bool(static["strings_truncated"]),
        "possible_packing": bool(static["possible_packing"]),
        "packing_note": static["packing_note"],
        "file": {
            "original_filename": static["original_filename"] or "upload",
            "size": static["size"],
            "format": static["format"],
            "arch": static["arch"],
            "bitness": static["bitness"],
            "endian": static["endian"],
            "entry_point": static["entry_point"],
            "extension_mismatch": static["extension_mismatch"],
        },
        "toolchain": {"ghidra": "NOT_RUN", "jdk": "NOT_RUN", "lief": "1.0.0", "capstone": "NOT_RUN"},
        "versions": {"scoring": "1.0", "rules": "1.0", "prompts": "1.0"},
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "functions": prepared_functions,
        "edges": prepared_edges,
        "signals": [],
        "rule_hits": [],
        "findings": [],
        "provenance": {
            "input_hash": static["sha256"],
            "created_at": created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        raise NormalizationError("Normalized analysis did not match schema v1.0.")
    return normalized


def serialize_normalized(normalized: dict) -> bytes:
    normalized = {key: value for key, value in normalized.items() if not key.startswith("_")}
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        raise NormalizationError("Normalized analysis did not match schema v1.0.")
    return (json.dumps(normalized, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def validate_normalized(normalized: dict) -> None:
    normalized = {key: value for key, value in normalized.items() if not key.startswith("_")}
    errors = sorted(VALIDATOR.iter_errors(normalized), key=lambda err: list(err.absolute_path))
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path)
        raise NormalizationError(f"Normalized analysis schema validation failed at {path or '<root>'}.")
