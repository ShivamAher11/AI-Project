"""Deterministic YAML rules, evidence signals, and correlation groups."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules" / "rules_v1.0"
WEIGHTS_PATH = ROOT / "rules" / "scoring_weights_v1.0.json"
RULES_VERSION = "1.0"
SCORING_VERSION = "1.0"


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    function_ids: list[str]
    evidence_refs: list[str]
    weight: int
    absorbed: bool = False
    signal_ids: tuple[str, ...] = ()
    confidence: float = 0.3
    severity: str = "low"
    title: str = ""
    description: str = ""
    alternative: str = ""
    attack: tuple[str, ...] = ()


class AnalysisCtx:
    """Detector seam: groups are prequalified with direct-call-only context."""
    def __init__(self, group_hits: list[RuleHit]):
        self._group_hits = group_hits

    def group_hits(self, group_id: str) -> list[RuleHit]:
        return [hit for hit in self._group_hits if hit.rule_id == group_id]


def load_rules() -> list[dict]:
    loaded = [yaml.safe_load(path.read_text(encoding="utf-8")) for path in sorted(RULES_DIR.glob("*.yaml"))]
    required = {"id", "name", "category", "severity", "weight", "attack_technique", "apis", "strings", "regex", "detector", "description", "fp_note"}
    ids = set()
    for rule in loaded:
        if not isinstance(rule, dict) or set(rule) != required or rule["id"] in ids:
            raise ValueError("Rule catalog schema is invalid.")
        ids.add(rule["id"])
        if rule["severity"] not in {"low", "medium", "high", "critical"} or not isinstance(rule["weight"], int) or rule["weight"] < 0:
            raise ValueError("Rule severity or weight is invalid.")
        if rule["detector"] is not None and rule["detector"] not in {
            "rules.detectors.injection:detect", "rules.detectors.registry_persist:detect",
            "rules.detectors.download:detect", "rules.detectors.antianalysis:detect",
        }:
            raise ValueError("Rule catalog references an unsupported Python detector.")
        if not isinstance(rule["apis"], list) or not isinstance(rule["strings"], list) or not isinstance(rule["regex"], list):
            raise ValueError("Rule match lists must be arrays.")
        for pattern in rule["regex"]:
            re.compile(pattern, re.IGNORECASE)
    if len(loaded) != 20:
        raise ValueError("Rule catalog must contain exactly 20 indicator rules.")
    return loaded


def _distance_map(edges: list[dict]) -> dict[str, dict[str, int]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge["type"] == "direct":
            graph[edge["caller"]].add(edge["callee"])
            graph[edge["callee"]].add(edge["caller"])
    result: dict[str, dict[str, int]] = {}
    for start in graph:
        distances, queue = {start: 0}, deque([start])
        while queue:
            node = queue.popleft()
            for neighbor in graph[node]:
                if neighbor not in distances:
                    distances[neighbor] = distances[node] + 1
                    queue.append(neighbor)
        result[start] = distances
    return result


def _nearest_functions(function_sets: list[set[str]], distances: dict[str, dict[str, int]], limit: int) -> bool:
    if any(left & right for i, left in enumerate(function_sets) for right in function_sets[i + 1:]):
        return True
    for i, left in enumerate(function_sets):
        for right in function_sets[i + 1:]:
            if any(distances.get(a, {}).get(b, limit + 1) <= limit for a in left for b in right):
                return True
    return False


def _make_evidence(normalized: dict) -> tuple[dict, dict[str, list[str]]]:
    catalog: dict[str, dict] = {}
    functions_by_api: dict[str, set[str]] = defaultdict(set)
    imports_by_name: dict[str, list[str]] = defaultdict(list)
    for row in normalized["imports"]:
        key = json.dumps([row.get("library"), row["name"], row.get("address")], separators=(",", ":"), ensure_ascii=False)
        ref = "I-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        catalog[ref] = {"source_type": "import", "source_key": [row.get("library"), row["name"], row.get("address")], "excerpt": row["name"], "offset": row.get("address"), "reason": "Imported API matched a deterministic rule."}
        imports_by_name[row["name"].casefold()].append(ref)
    for row in normalized["strings"]:
        key = json.dumps([row["offset"], row["value"]], separators=(",", ":"), ensure_ascii=False)
        ref = "STR-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        catalog[ref] = {"source_type": "string", "source_key": [row["offset"], row["value"]], "excerpt": row["value"][:500], "offset": row["offset"], "reason": "Extracted string matched a deterministic rule."}
    for row in normalized["functions"]:
        for api, refs in imports_by_name.items():
            if any(edge["type"] == "import" and edge["caller"] == row["id"] and str(edge["callee"]).casefold() == api for edge in normalized["edges"]):
                functions_by_api[api].add(row["id"])
        text = "\n".join(part or "" for part in (row.get("decompiled_excerpt"), row.get("assembly_excerpt")))
        for api, refs in imports_by_name.items():
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(api)}(?![A-Za-z0-9_])", text, re.I):
                functions_by_api[api].add(row["id"])
        if text:
            catalog[f"F:{row['id']}"] = {"source_type": "function", "source_key": row["id"], "excerpt": text[:500], "offset": row["address"], "reason": "Function text contains matching API evidence."}
    for api, refs in imports_by_name.items():
        # connect function API evidence to the exact import record
        for ref in refs:
            catalog[ref]["function_ids"] = sorted(functions_by_api[api])
    return catalog, {key: sorted(value) for key, value in functions_by_api.items()}


def _attack_allowed() -> dict[str, str]:
    return {
        "T1055": "Process Injection", "T1053": "Scheduled Task", "T1543": "Create System Process",
        "T1547.001": "Registry Run Keys / Startup Folder", "T1105": "Ingress Tool Transfer",
        "T1071.001": "Web Protocols", "T1082": "System Information Discovery",
        "T1057": "Process Discovery", "T1012": "Query Registry", "T1003": "OS Credential Dumping",
        "T1056": "Input Capture", "T1497": "Virtualization/Sandbox Evasion", "T1027": "Obfuscated Files or Information",
        "T1127": "Trusted Developer Utilities Proxy Execution", "T1218": "System Binary Proxy Execution",
    }


def detect_analysis(normalized: dict) -> dict:
    """Return normalized signals, scored hits, finding details, and evidence catalog."""
    rules = load_rules()
    weights = json.loads(WEIGHTS_PATH.read_text(encoding="utf-8"))
    evidence, functions_by_api = _make_evidence(normalized)
    distances = _distance_map(normalized["edges"])
    strings = [(f"STR{i + 1}", row["value"], row) for i, row in enumerate(normalized["strings"])]
    function_text = {row["id"]: "\n".join((row.get("decompiled_excerpt") or "", row.get("assembly_excerpt") or "")) for row in normalized["functions"]}
    signals: list[dict] = []
    raw_rules: dict[str, list[dict]] = {}
    for rule in rules:
        entries = []
        matched_apis = [api for api in rule["apis"] if any(api.casefold() == row["name"].casefold() for row in normalized["imports"])]
        for api in matched_apis:
            names = [name for name in functions_by_api if api.casefold() == name]
            refs = [ref for ref, item in evidence.items() if item["source_type"] == "import" and api.casefold() in item["excerpt"].casefold()]
            funcs = sorted({fid for name in names for fid in functions_by_api[name]})
            entries.append((funcs, refs, api))
        for ref, value, row in strings:
            if any(needle.casefold() in value.casefold() for needle in rule["strings"]):
                associated = sorted(fid for fid, text in function_text.items() if value.casefold() in text.casefold())
                entries.append((associated, [ref], value))
        if rule["id"] == "PACKED_HEURISTIC" and normalized.get("possible_packing"):
            ref = "M:packing"
            evidence[ref] = {"source_type": "metadata", "source_key": normalized["analysis_id"],
                             "excerpt": normalized.get("packing_note") or "possible packing - heuristic, not proof",
                             "offset": None, "reason": "High entropy and abnormal section heuristic."}
            entries.append(([], [ref], "packing heuristic"))
        for pattern in rule["regex"]:
            for fid, text in function_text.items():
                if re.search(pattern, text, re.I):
                    refs = [f"F:{fid}"] if f"F:{fid}" in evidence else []
                    entries.append(([fid], refs, pattern))
            for ref, value, _row in strings:
                if re.search(pattern, value, re.I):
                    associated = sorted(fid for fid, text in function_text.items() if value.casefold() in text.casefold())
                    entries.append((associated, [ref], pattern))
        # Emit one signal for each distinct rule evidence bucket.
        rule_signals = []
        for index, (funcs, refs, label) in enumerate(entries, 1):
            if not refs:
                continue
            sid = f"S-{rule['id']}-{index:02d}"
            signal = {"signal_id": sid, "rule_id": rule["id"], "function_ids": funcs, "evidence_refs": sorted(set(refs))}
            signals.append(signal); rule_signals.append(signal)
        raw_rules[rule["id"]] = rule_signals

    # Explicit signal aliases used by correlation groups, derived from YAML API matches.
    def signals_for(rule_id: str) -> list[dict]:
        return raw_rules.get(rule_id, [])
    # Map all import API signals to canonical correlation buckets; the signal itself remains rule-derived.
    api_signals = []
    alias_sets = {
        "PROC_OPEN": {"openprocess"}, "MEM_ALLOC_WRITE": {"virtualallocex", "ntallocatememory", "writeprocessmemory", "ntwritevirtualmemory"},
        "REMOTE_THREAD": {"createremotethread", "ntcreatethreadex"}, "REG_OPEN_CREATE": {"regcreatekeyexa", "regcreatekeyexw"},
        "REG_SET": {"regsetvalueexa", "regsetvalueexw"}, "NET_CONNECT": {"connect", "winsend", "winhttpconnect", "winhttpsendrequest", "httpsendrequesta", "httpsendrequestw"},
        "HTTP_API": {"winhttpopen", "winhttpconnect", "winhttpopenrequest", "winhttpsendrequest", "httpsendrequesta", "httpsendrequestw", "urldownloadtofilea", "urldownloadtofilew"},
        "FILE_WRITE": {"writefile", "createfilea", "createfilew"}, "OPEN_SCMANAGER": {"openscmanagera", "openscmanagerw"},
        "CREATE_SERVICE": {"createservicea", "createservicew"}, "SCHED_API": {"taskscheduler"}, "SCHED_CMD": {"schtasks", "/create"},
        "HOOK_API": {"setwindowshookexa", "setwindowshookexw"}, "MSG_INPUT_API": {"getasynckeystate", "getforegroundwindow"},
        "ANTI_DEBUG": {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"}, "TIMING": {"rdtsc"},
        "VM_SANDBOX": {"cpuid", "vmware", "virtualbox", "vbox", "qemu"},
    }
    alias_acc: dict[str, dict] = {}
    for signal in signals:
        refs = signal["evidence_refs"]
        matched_names = [evidence[r]["excerpt"].casefold() for r in refs if r in evidence]
        for alias, candidates in alias_sets.items():
            if any(any(candidate == name or candidate in name for candidate in candidates) for name in matched_names):
                current = alias_acc.setdefault(alias, {"signal_id": f"S-{alias}", "rule_id": alias, "function_ids": [], "evidence_refs": []})
                current["function_ids"] = sorted(set(current["function_ids"]) | set(signal["function_ids"]))
                current["evidence_refs"] = sorted(set(current["evidence_refs"]) | set(signal["evidence_refs"]))
    api_signals.extend(alias_acc[key] for key in sorted(alias_acc))
    # A nearby Run-key string strengthens, but never creates, registry persistence evidence.
    run_refs = [ref for ref, item in evidence.items() if item["source_type"] == "string" and re.search(r"\\(Run|RunOnce)$", item["excerpt"], re.I)]
    if run_refs:
        for signal in api_signals:
            if signal["rule_id"] == "REG_SET":
                signal["evidence_refs"] = sorted(set(signal["evidence_refs"]) | set(run_refs))
    url_refs = [ref for ref, item in evidence.items() if item["source_type"] == "string" and re.search(r"https?://|www\.", item["excerpt"], re.I)]
    if url_refs:
        for signal in api_signals:
            if signal["rule_id"] == "HTTP_API":
                signal["evidence_refs"] = sorted(set(signal["evidence_refs"]) | set(url_refs))
    signals.extend(api_signals)

    # Correlation groups use only direct-call distance; no import/indirect edge can bridge functions.
    groups: list[RuleHit] = []
    consumed: set[str] = set()
    aliases: dict[str, list[dict]] = defaultdict(list)
    for signal in api_signals:
        aliases[signal["rule_id"]].append(signal)
    group_specs = [
        ("G_INJECTION", ["PROC_OPEN", "MEM_ALLOC_WRITE", "REMOTE_THREAD"], 2, 3, ["T1055"], "Possible process injection", "medium"),
        ("G_DOWNLOAD", ["NET_CONNECT", "HTTP_API", "FILE_WRITE"], 2, 4, ["T1105", "T1071.001"], "Network retrieval and file write", "medium"),
        ("G_REG_PERSIST", ["REG_OPEN_CREATE", "REG_SET"], 2, 2, ["T1547.001"], "Registry Run-key persistence", "medium"),
        ("G_SERVICE_TASK", ["OPEN_SCMANAGER", "CREATE_SERVICE", "SCHED_API", "SCHED_CMD"], 2, 3, ["T1543", "T1053"], "Service or scheduled-task persistence", "medium"),
        ("G_INPUT", ["HOOK_API", "MSG_INPUT_API"], 2, 3, ["T1056"], "Input capture indicators", "medium"),
        ("G_ANTIANALYSIS", ["ANTI_DEBUG", "VM_SANDBOX", "TIMING"], 2, 3, ["T1497"], "Anti-analysis checks", "medium"),
    ]
    for group_id, keys, minimum, max_distance, attacks, title, _ in group_specs:
        if group_id == "G_SERVICE_TASK":
            paths = [(["OPEN_SCMANAGER", "CREATE_SERVICE"], ["T1543"]), (["SCHED_API", "SCHED_CMD"], ["T1053"])]
            choices = []
            for path_keys, path_attacks in paths:
                path_signals = [sig for key in path_keys for sig in aliases[key] if not (set(sig["evidence_refs"]) & consumed)]
                chosen = []
                for sig in path_signals:
                    if not chosen or _nearest_functions([set(item["function_ids"]) for item in chosen + [sig]], distances, max_distance):
                        chosen.append(sig)
                if len(chosen) >= 2:
                    choices.append((chosen, path_attacks))
            if not choices:
                continue
            selected, attacks = choices[0]
        else:
            candidates = [sig for key in keys for sig in aliases[key] if not (set(sig["evidence_refs"]) & consumed)]
            selected: list[dict] = []
            for sig in candidates:
                prior_refs = {ref for item in selected for ref in item["evidence_refs"]}
                unique_refs = sorted(set(sig["evidence_refs"]) - prior_refs - consumed)
                if not unique_refs:
                    continue
                candidate = {**sig, "evidence_refs": unique_refs}
                if not selected or _nearest_functions([set(item["function_ids"]) for item in selected + [candidate]], distances, max_distance):
                    selected.append(candidate)
        required_special = group_id != "G_INJECTION" or any(sig["rule_id"] in {"MEM_ALLOC_WRITE", "REMOTE_THREAD"} for sig in selected)
        if len(selected) >= minimum and required_special:
            refs = sorted({ref for sig in selected for ref in sig["evidence_refs"]})
            fids = sorted({fid for sig in selected for fid in sig["function_ids"]})
            run_context = any("run" in evidence.get(ref, {}).get("excerpt", "").casefold() for ref in refs)
            confidence = .9 if len(selected) >= 3 or (group_id == "G_REG_PERSIST" and run_context and len(selected) >= 2) else .65
            groups.append(RuleHit(group_id, fids, refs, int(weights["groups"][group_id]), False, tuple(sig["signal_id"] for sig in selected), confidence, "high" if confidence >= .8 else "medium", title, f"Static evidence matched {group_id} correlation criteria.", "The APIs may also occur in debugging, administration, or installer software.", tuple(attacks)))
            consumed.update(ref for sig in selected for ref in sig["evidence_refs"] if ref.startswith("I"))

    # Keep the only four Python detector entry points explicit and version-controlled.
    from rules.detectors.antianalysis import detect as detect_antianalysis
    from rules.detectors.download import detect as detect_download
    from rules.detectors.injection import detect as detect_injection
    from rules.detectors.registry_persist import detect as detect_registry_persist
    ctx = AnalysisCtx(groups)
    python_groups = (detect_injection(ctx) + detect_download(ctx) + detect_registry_persist(ctx) + detect_antianalysis(ctx))
    groups = [hit for hit in groups if hit.rule_id not in {"G_INJECTION", "G_DOWNLOAD", "G_REG_PERSIST", "G_ANTIANALYSIS"}] + python_groups

    # Rule findings: successful groups absorb their constituent solo API rule weights.
    matched_rule_ids = {rule_id for rule_id, rule_signals in raw_rules.items() if rule_signals}
    output_hits = list(groups)
    for rule in rules:
        if rule["id"] not in matched_rule_ids:
            continue
        sigs = raw_rules[rule["id"]]
        refs = sorted({ref for sig in sigs for ref in sig["evidence_refs"]})
        fids = sorted({fid for sig in sigs for fid in sig["function_ids"]})
        absorbed = any(ref in consumed for ref in refs if ref.startswith("I"))
        if rule["id"] == "MEM_ALLOC_WRITE" and any(group.rule_id == "G_INJECTION" for group in groups): absorbed = True
        if rule["id"] == "REMOTE_THREAD" and any(group.rule_id == "G_INJECTION" for group in groups): absorbed = True
        if rule["id"] in {"REGISTRY_RUN"} and any(group.rule_id == "G_REG_PERSIST" for group in groups): absorbed = True
        weight = int(weights["solo"].get(rule["id"], rule["weight"]))
        # catalog weights stay spec-owned; grouped individual indicators contribute zero.
        common_functions = set.intersection(*(set(sig["function_ids"]) for sig in sigs)) if sigs else set()
        confidence_score = .62 if len(sigs) >= 2 and common_functions else .35
        solo_attacks = tuple([rule["attack_technique"]] if rule["attack_technique"] and rule["id"] not in {"REGISTRY_RUN", "SERVICE_CREATE", "SCHED_TASK", "MEM_ALLOC_WRITE", "REMOTE_THREAD", "INPUT_CAPTURE", "ANTI_DEBUG", "VM_SANDBOX"} else ())
        output_hits.append(RuleHit(rule["id"], fids, refs, 0 if absorbed else weight, absorbed, tuple(sig["signal_id"] for sig in sigs), confidence_score, rule["severity"], rule["name"], rule["description"], rule["fp_note"], solo_attacks))

    from worker.scoring import score_hits
    scoring = score_hits(output_hits, normalized)
    details = []
    for hit in output_hits:
        if hit.absorbed or not hit.evidence_refs:
            continue
        confidence_score = hit.confidence
        confidence = "low" if confidence_score < .5 else "medium" if confidence_score < .8 else "high"
        sev = hit.severity if hit.rule_id not in {g[0] for g in group_specs} else ("high" if hit.rule_id in {"G_INJECTION", "G_INPUT", "G_SERVICE_TASK"} or (hit.rule_id == "G_REG_PERSIST" and confidence_score >= .8) else "medium")
        if hit.rule_id in {"REGISTRY_RUN", "SERVICE_CREATE", "SCHED_TASK", "INPUT_CAPTURE"}:
            sev = "medium"
        mappings = []
        for tid in hit.attack:
            if tid not in _attack_allowed():
                continue
            if tid == "T1071.001" and not any(ref.startswith("STR") and re.search(r"https?://|www\\.", evidence.get(ref, {}).get("excerpt", ""), re.I) for ref in hit.evidence_refs):
                continue
            if tid == "T1105" and hit.rule_id == "G_DOWNLOAD" and "S-FILE_WRITE" not in hit.signal_ids:
                continue
            if tid == "T1003" and not (any(ref.startswith("I") for ref in hit.evidence_refs) and any(re.search(r"OpenProcessToken|CredEnumerate|LsaEnumerate|lsass|sam\\\\", evidence.get(ref, {}).get("excerpt", ""), re.I) for ref in hit.evidence_refs)):
                continue
            mappings.append({"technique_id": tid, "technique_name": _attack_allowed()[tid], "label": "Likely" if confidence_score >= .8 else "Possible" if confidence_score >= .5 else None, "confidence": confidence,
                             "confidence_score": confidence_score, "rationale": f"Rule-derived candidate from {hit.rule_id}."})
        details.append({"rule_id": hit.rule_id, "title": hit.title or hit.rule_id, "severity": sev, "confidence": confidence,
                        "confidence_score": confidence_score, "description": "Behaviorally suspicious static indicators: " + (hit.description or hit.title),
                        "interpretation": "Deterministic rule interpretation; heuristic, not verdict.", "alternative": hit.alternative,
                        "weight": hit.weight, "group_id": hit.rule_id if hit.rule_id.startswith("G_") else None,
                        "signal_ids": list(hit.signal_ids), "evidence_refs": hit.evidence_refs, "attack_mappings": mappings})
    return {"signals": signals, "hits": output_hits, "findings": details, "evidence": evidence, "scoring": scoring}
