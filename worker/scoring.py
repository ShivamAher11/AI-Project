"""Versioned, stable risk scoring for deterministic rule findings."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from worker.rules.engine import RuleHit, RULES_VERSION, SCORING_VERSION, WEIGHTS_PATH


def risk_band(score: int) -> str:
    if score <= 30: return "Low"
    if score <= 60: return "Medium"
    if score <= 80: return "High"
    return "Critical"


def score_hits(hits: list[RuleHit], normalized: dict) -> dict:
    active = sorted((hit for hit in hits if not hit.absorbed and hit.weight > 0), key=lambda hit: (-hit.weight, hit.rule_id))
    score = min(100, sum(hit.weight for hit in active))
    evidence_ids = sorted({ref for hit in hits for ref in hit.evidence_refs})
    input_hash = hashlib.sha256("\n".join(evidence_ids).encode("utf-8")).hexdigest()
    return {
        "score": score, "rating": risk_band(score),
        "scoring_version": SCORING_VERSION, "rule_set_version": RULES_VERSION, "input_hash": input_hash,
        "breakdown": [{"rule_id": hit.rule_id, "title": hit.title or hit.rule_id, "weight": hit.weight} for hit in active],
    }
