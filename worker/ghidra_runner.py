"""Fixture-backed decompilation output; real Ghidra is a later project part."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID


ROOT = Path(__file__).resolve().parents[1]
CORPUS_FIXTURES = {
    "hello_pe_x64.exe": "hello_pe_x64",
    "persist_reg.exe": "persist_reg",
    "inject_pattern.exe": "inject_pattern",
}


class GhidraRunner:
    def __init__(self, mode: str | None = None, fixture_root: Path | None = None):
        self.mode = (mode or os.getenv("GHIDRA_MODE", "fixture")).lower()
        self.fixture_root = fixture_root or ROOT / "fixtures"

    def run(self, analysis_id: str, original_filename: str) -> dict:
        # Never join a client filename to a filesystem path. Only this fixed allowlist
        # selects corpus fixture directories; all other names use the generic fixture.
        UUID(analysis_id)
        if self.mode == "real":
            # TODO(spec §14): implement and prove the isolated headless Ghidra runner in Prompt 11.
            raise NotImplementedError("Real Ghidra mode is deferred to Prompt 11.")
        if self.mode != "fixture":
            raise ValueError("GHIDRA_MODE must be fixture or real")

        corpus_key = CORPUS_FIXTURES.get(Path(original_filename).name.lower())
        if corpus_key:
            directory = self.fixture_root / "ghidra_out" / corpus_key
            functions = json.loads((directory / "funcs.json").read_text(encoding="utf-8"))["functions"]
            edges = json.loads((directory / "edges.json").read_text(encoding="utf-8"))["edges"]
        else:
            generic = json.loads((self.fixture_root / "analysis-full.json").read_text(encoding="utf-8"))
            functions, edges = generic["functions"], generic["edges"]
        return {"source": "fixture", "functions": functions, "edges": edges}
