"""AI input boundary adapter.

Produces bounded, fixture-safe AI input from a normalized analysis dict
(schema v1.0). No model calls are made here. The adapter exposes only the
data the model may consume: function metadata, relevant imports/strings,
evidence IDs, graph edges, findings, and rule hits. Raw binaries, artifact
paths, and full decompilation artifacts are never included.

Fixture provenance (``source``) is carried through so AI code can label
results as fixture-derived when required.
"""

from __future__ import annotations

from typing import Any


def build_function_input(normalized: dict[str, Any], fid: str) -> dict[str, Any]:
    """Return bounded AI input for one function from a normalized analysis.

    The output is deterministic and contains only data that may be sent to
    the model. Missing decompilation and missing evidence are represented
    explicitly (null / empty) rather than fabricated.
    """
    functions = normalized.get("functions", [])
    func = next((f for f in functions if f["id"] == fid), None)
    if func is None:
        return {
            "analysis_id": normalized.get("analysis_id"),
            "source": normalized.get("source"),
            "function": None,
            "function_id": fid,
            "error": f"function {fid} not found in analysis",
            "imports": [],
            "strings": [],
            "evidence_ids": [],
            "graph": {"callers": [], "callees": [], "imports": []},
            "decompilation_excerpt": None,
            "rule_hits": [],
            "findings": [],
            "input_hash": normalized.get("provenance", {}).get("input_hash", ""),
        }

    # Graph edges touching this function.
    edges = normalized.get("edges", [])
    callers: list[dict[str, Any]] = []
    callees: list[dict[str, Any]] = []
    import_callees: list[str] = []
    for edge in edges:
        if edge.get("caller") == fid:
            callee = edge.get("callee")
            if edge.get("type") == "import":
                import_callees.append(callee)
            else:
                callees.append({"callee": callee, "type": edge.get("type")})
        elif edge.get("callee") == fid:
            callers.append({"caller": edge.get("caller"), "type": edge.get("type")})

    # Imports called by this function (by name match on import edges).
    import_map = {imp.get("name"): imp for imp in normalized.get("imports", [])}
    imports = [import_map[name] for name in import_callees if name in import_map]

    # Evidence IDs relevant to this function via signals and rule hits.
    evidence_ids: set[str] = set()
    for sig in normalized.get("signals", []):
        if fid in sig.get("function_ids", []):
            evidence_ids.update(sig.get("evidence_refs", []))
    for hit in normalized.get("rule_hits", []):
        if fid in hit.get("function_ids", []):
            evidence_ids.update(hit.get("evidence_refs", []))

    # Strings are bounded by the normalized schema (value capped at 500
    # chars per row, count capped per analysis). No raw binary or artifact
    # path is included.
    strings = list(normalized.get("strings", []))

    # Rule hits and findings involving this function.
    rule_hits = [
        h for h in normalized.get("rule_hits", []) if fid in h.get("function_ids", [])
    ]
    findings = [
        f
        for f in normalized.get("findings", [])
        if fid in _finding_function_ids(f, normalized)
    ]

    # Bounded decompilation excerpt; may be null when decompilation failed.
    decomp = func.get("decompiled_excerpt")

    return {
        "analysis_id": normalized.get("analysis_id"),
        "source": normalized.get("source"),
        "function_id": fid,
        "function": {
            "id": func["id"],
            "address": func.get("address"),
            "name": func.get("name"),
            "signature": func.get("signature"),
            "size": func.get("size"),
            "decompiler_status": func.get("decompiler_status"),
        },
        "imports": imports,
        "strings": strings,
        "evidence_ids": sorted(evidence_ids),
        "graph": {
            "callers": callers,
            "callees": callees,
            "imports": import_callees,
        },
        "decompilation_excerpt": decomp,
        "rule_hits": rule_hits,
        "findings": findings,
        "input_hash": normalized.get("provenance", {}).get("input_hash", ""),
        "error": None,
    }


def _finding_function_ids(
    finding: dict[str, Any], normalized: dict[str, Any]
) -> set[str]:
    """Return function IDs referenced by a finding via its signal IDs."""
    ids: set[str] = set()
    for sig_id in finding.get("signal_ids", []):
        for sig in normalized.get("signals", []):
            if sig.get("signal_id") == sig_id:
                ids.update(sig.get("function_ids", []))
    return ids


def list_eligible_functions(normalized: dict[str, Any]) -> list[str]:
    """Return all function IDs in the normalized analysis, in schema order."""
    return [f["id"] for f in normalized.get("functions", [])]


def summary_of_input(input_dict: dict[str, Any]) -> dict[str, Any]:
    """Return a small, safe summary of an adapter input for logging/display.

    Never includes raw decompilation text or artifact paths.
    """
    return {
        "analysis_id": input_dict.get("analysis_id"),
        "source": input_dict.get("source"),
        "function_id": input_dict.get("function_id"),
        "function_name": (input_dict.get("function") or {}).get("name"),
        "decompiler_status": (input_dict.get("function") or {}).get(
            "decompiler_status"
        ),
        "has_decompilation": input_dict.get("decompilation_excerpt") is not None,
        "import_count": len(input_dict.get("imports", [])),
        "string_count": len(input_dict.get("strings", [])),
        "evidence_count": len(input_dict.get("evidence_ids", [])),
        "rule_hit_count": len(input_dict.get("rule_hits", [])),
        "finding_count": len(input_dict.get("findings", [])),
        "error": input_dict.get("error"),
    }
