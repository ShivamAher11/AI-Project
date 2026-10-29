import copy
import json
from pathlib import Path

import pytest

from worker.rules.engine import RuleHit, detect_analysis, load_rules
from worker.scoring import risk_band, score_hits


def sample(import_names=(), strings=(), *, function_text="", possible_packing=False):
    analysis_id = "a1b2c3d4-e5f6-4789-8123-456789abcdef"
    fid = f"{analysis_id}:0x140001000"
    imports = [{"library": "test.dll", "name": name, "ordinal": None, "address": f"0x{i+1:x}", "category": "other"}
               for i, name in enumerate(import_names)]
    functions = ([{"id": fid, "address": "0x140001000", "name": "entry", "decompiled_excerpt": function_text,
                   "assembly_excerpt": None}] if function_text else [])
    edges = [{"caller": fid, "callee": row["name"], "type": "import"} for row in imports] if functions else []
    return {"analysis_id": analysis_id, "imports": imports,
            "strings": [{"offset": f"0x{i+100:x}", "value": value} for i, value in enumerate(strings)],
            "functions": functions, "edges": edges, "possible_packing": possible_packing}


@pytest.mark.parametrize("rule", load_rules(), ids=lambda rule: rule["id"])
def test_each_rule_has_positive_and_negative_match(rule):
    if rule["apis"]:
        positive = sample([rule["apis"][0]])
    elif rule["strings"]:
        positive = sample(strings=[rule["strings"][0]])
    else:
        positive = sample(possible_packing=True)
    positive_ids = {hit.rule_id for hit in detect_analysis(positive)["hits"]}
    assert rule["id"] in positive_ids
    negative = sample()
    negative_ids = {hit.rule_id for hit in detect_analysis(negative)["hits"]}
    assert rule["id"] not in negative_ids


def test_injection_same_function_is_one_group_finding_and_absorbs_solos():
    names = ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    text = "OpenProcess(); VirtualAllocEx(); WriteProcessMemory(); CreateRemoteThread();"
    result = detect_analysis(sample(names, function_text=text))
    injection = [finding for finding in result["findings"] if finding["rule_id"] == "G_INJECTION"]
    assert len(injection) == 1
    assert injection[0]["weight"] == 25
    assert result["scoring"]["score"] == 25
    assert [item["technique_id"] for item in injection[0]["attack_mappings"]] == ["T1055"]
    assert any(hit.rule_id == "MEM_ALLOC_WRITE" and hit.absorbed for hit in result["hits"])
    assert any(hit.rule_id == "REMOTE_THREAD" and hit.absorbed for hit in result["hits"])


def test_registry_run_group_maps_t1547_001():
    result = detect_analysis(sample(["RegCreateKeyExW", "RegSetValueExW"],
        [r"Software\Microsoft\Windows\CurrentVersion\Run"],
        function_text="RegCreateKeyExW(); RegSetValueExW();"))
    finding = next(item for item in result["findings"] if item["rule_id"] == "G_REG_PERSIST")
    assert finding["weight"] == 15
    assert "T1547.001" in [item["technique_id"] for item in finding["attack_mappings"]]
    assert finding["confidence"] == "high"
    assert result["scoring"]["score"] == 15


def test_lone_remote_memory_indicator_uses_small_solo_weight():
    result = detect_analysis(sample(["VirtualAllocEx"], function_text="VirtualAllocEx();"))
    hit = next(hit for hit in result["hits"] if hit.rule_id == "MEM_ALLOC_WRITE")
    assert hit.weight == 3 and hit.absorbed is False
    assert result["scoring"]["score"] == 3
    assert result["scoring"]["rating"] == "Low"


def test_benign_fixture_has_no_high_finding():
    result = detect_analysis(sample(["ExitProcess", "GetCurrentProcessId"], function_text="ExitProcess(0);"))
    assert not [finding for finding in result["findings"] if finding["severity"] in {"high", "critical"}]


def test_scoring_is_stable_and_48_is_medium():
    hits = [RuleHit("G_INJECTION", [], ["I1"], 25), RuleHit("G_REG_PERSIST", [], ["I2"], 15),
            RuleHit("PROC_CREATE", [], ["I3"], 5), RuleHit("MEM_ALLOC_WRITE", [], ["I4"], 3)]
    first = score_hits(hits, {})
    second = score_hits(copy.deepcopy(hits), {})
    assert first == second
    assert first["score"] == 48
    assert first["rating"] == "Medium"
    assert risk_band(30) == "Low" and risk_band(60) == "Medium" and risk_band(80) == "High" and risk_band(81) == "Critical"
    assert [item["rule_id"] for item in first["breakdown"]] == ["G_INJECTION", "G_REG_PERSIST", "PROC_CREATE", "MEM_ALLOC_WRITE"]


def test_full_normalized_fixture_correlates_one_injection_and_registry():
    full = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "analysis-full.json").read_text(encoding="utf-8"))
    result = detect_analysis(full)
    groups = [finding["rule_id"] for finding in result["findings"] if finding["rule_id"].startswith("G_")]
    assert groups.count("G_INJECTION") == 1
    assert groups.count("G_REG_PERSIST") == 1


def test_detection_output_fits_normalized_schema_and_is_byte_stable():
    from worker.normalize import serialize_normalized, validate_normalized
    from uuid import UUID, uuid5
    full = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "analysis-full.json").read_text(encoding="utf-8"))

    def completed_payload():
        result = detect_analysis(full)
        data = copy.deepcopy(full)
        data["signals"] = result["signals"]
        data["rule_hits"] = [{"rule_id": hit.rule_id, "function_ids": hit.function_ids, "evidence_refs": hit.evidence_refs,
            "weight": hit.weight, "absorbed": hit.absorbed, "signal_ids": list(hit.signal_ids)} for hit in result["hits"]]
        data["findings"] = [{"finding_id": str(uuid5(UUID(data["analysis_id"]), finding["rule_id"])), "group_id": finding["group_id"],
            "signal_ids": finding["signal_ids"], "weight": finding["weight"]} for finding in result["findings"]]
        data["scoring"] = result["scoring"]
        return data

    first, second = completed_payload(), completed_payload()
    validate_normalized(first)
    assert serialize_normalized(first) == serialize_normalized(second)

