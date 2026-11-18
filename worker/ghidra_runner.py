"""Run Ghidra headlessly and return its structured static-analysis output."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
CORPUS_FIXTURES = {
    "hello_pe_x64.exe": "hello_pe_x64",
    "persist_reg.exe": "persist_reg",
    "inject_pattern.exe": "inject_pattern",
}


class GhidraExecutionError(RuntimeError):
    """Raised when Ghidra cannot be started or returns invalid output."""


class GhidraRunner:
    def __init__(
        self,
        mode: str | None = None,
        fixture_root: Path | None = None,
        *,
        ghidra_home: Path | None = None,
        headless_path: Path | None = None,
        timeout_seconds: int | None = None,
    ):
        self.mode = (mode or os.getenv("GHIDRA_MODE", "real")).lower()
        self.fixture_root = fixture_root or ROOT / "fixtures"
        configured_home = ghidra_home or os.getenv("GHIDRA_HOME")
        self.ghidra_home = Path(configured_home) if configured_home else None
        configured_headless = headless_path or os.getenv("GHIDRA_HEADLESS_PATH")
        self.headless_path = Path(configured_headless) if configured_headless else None
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else int(os.getenv("GHIDRA_TIMEOUT_SECONDS", "900"))
        )

    def run(
        self,
        analysis_id: str,
        original_filename: str,
        *,
        binary_path: Path | None = None,
        work_dir: Path | None = None,
    ) -> dict:
        analysis_uuid = UUID(analysis_id)
        if self.mode == "fixture":
            return self._run_fixture(original_filename)
        if self.mode != "real":
            raise ValueError("GHIDRA_MODE must be fixture or real")
        if binary_path is None or work_dir is None:
            raise GhidraExecutionError(
                "Real Ghidra mode requires an input binary and analysis work directory."
            )

        binary_path = Path(binary_path).resolve()
        work_dir = Path(work_dir).resolve()
        if not binary_path.is_file():
            raise GhidraExecutionError(
                "The uploaded binary is unavailable for Ghidra analysis."
            )
        if self.timeout_seconds <= 0:
            raise ValueError("GHIDRA_TIMEOUT_SECONDS must be a positive integer")

        headless = self._find_headless()
        scripts_dir = ROOT / "ghidra_scripts"
        if not (scripts_dir / "Export.java").is_file():
            raise GhidraExecutionError("The Ghidra Export.java script is missing.")

        work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(
                prefix="ghidra-", dir=work_dir
            ) as temporary:
                temp_dir = Path(temporary)
                project_dir = temp_dir / "project"
                project_dir.mkdir()
                output_path = temp_dir / "ghidra-output.json"
                stdout_path = temp_dir / "ghidra.stdout.log"
                stderr_path = temp_dir / "ghidra.stderr.log"
                command = [
                    str(headless),
                    str(project_dir),
                    f"analysis_{analysis_uuid.hex}",
                    "-import",
                    str(binary_path),
                    "-scriptPath",
                    str(scripts_dir),
                    "-postScript",
                    "Export.java",
                    str(output_path),
                    "-deleteProject",
                ]
                try:
                    with stdout_path.open("wb") as stdout_log, stderr_path.open(
                        "wb"
                    ) as stderr_log:
                        completed = subprocess.run(
                            command,
                            check=False,
                            stdout=stdout_log,
                            stderr=stderr_log,
                            timeout=self.timeout_seconds,
                            cwd=temp_dir,
                            env=os.environ.copy(),
                        )
                except subprocess.TimeoutExpired:
                    return self._empty_result("TIMEOUT")
                if completed.returncode != 0:
                    raise GhidraExecutionError(
                        self._failure_message(
                            f"Ghidra headless analysis exited with status {completed.returncode}.",
                            stdout_path,
                            stderr_path,
                        )
                    )
                if not output_path.is_file():
                    raise GhidraExecutionError(
                        self._failure_message(
                            "Ghidra completed without producing its JSON export.",
                            stdout_path,
                            stderr_path,
                        )
                    )
                try:
                    exported = json.loads(output_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise GhidraExecutionError(
                        "Ghidra produced an invalid JSON export."
                    ) from exc
        except OSError as exc:
            raise GhidraExecutionError(
                "Could not run the Ghidra headless analyzer."
            ) from exc

        if (
            not isinstance(exported, dict)
            or not isinstance(exported.get("functions"), list)
            or not isinstance(exported.get("edges"), list)
        ):
            raise GhidraExecutionError(
                "Ghidra JSON export is missing functions or edges."
            )
        return {
            "source": "real",
            "decomp_status": "OK",
            "functions": exported["functions"],
            "edges": exported["edges"],
            "toolchain": self._toolchain_versions(),
        }

    def _run_fixture(self, original_filename: str) -> dict:
        corpus_key = CORPUS_FIXTURES.get(Path(original_filename).name.lower())
        if corpus_key:
            directory = self.fixture_root / "ghidra_out" / corpus_key
            functions = json.loads(
                (directory / "funcs.json").read_text(encoding="utf-8")
            )["functions"]
            edges = json.loads((directory / "edges.json").read_text(encoding="utf-8"))[
                "edges"
            ]
        else:
            generic = json.loads(
                (self.fixture_root / "analysis-full.json").read_text(encoding="utf-8")
            )
            functions, edges = generic["functions"], generic["edges"]
        return {
            "source": "fixture",
            "decomp_status": "OK" if functions else "NOT_RUN",
            "functions": functions,
            "edges": edges,
            "toolchain": {"ghidra": "fixture", "jdk": "fixture"},
        }

    def _find_headless(self) -> Path:
        if self.headless_path is not None:
            candidates = [self.headless_path]
        else:
            candidates = []
            if self.ghidra_home is not None:
                candidates.append(self.ghidra_home / "support" / "analyzeHeadless")
            path_command = shutil.which("analyzeHeadless")
            if path_command:
                candidates.append(Path(path_command))
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        raise GhidraExecutionError(
            "Ghidra headless analyzer was not found; configure GHIDRA_HOME or GHIDRA_HEADLESS_PATH."
        )

    def _toolchain_versions(self) -> dict[str, str]:
        return {
            "ghidra": os.getenv("GHIDRA_VERSION", "unknown"),
            "jdk": os.getenv("JAVA_VERSION", "unknown"),
        }

    @staticmethod
    def _failure_message(message: str, stdout_path: Path, stderr_path: Path) -> str:
        """Attach bounded headless diagnostics to failures without buffering all output."""
        diagnostic_limit = 4000
        diagnostics = []
        for label, path in (("stderr", stderr_path), ("stdout", stdout_path)):
            try:
                with path.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    stream.seek(max(0, size - diagnostic_limit))
                    tail = stream.read(diagnostic_limit).decode("utf-8", errors="replace").strip()
            except OSError:
                continue
            if tail:
                diagnostics.append(f"{label} tail:\n{tail}")
        if not diagnostics:
            return message
        return f"{message} Ghidra diagnostics (last {diagnostic_limit} bytes per stream):\n" + "\n".join(diagnostics)

    def _empty_result(self, status: str) -> dict:
        return {
            "source": "none",
            "decomp_status": status,
            "functions": [],
            "edges": [],
            "toolchain": self._toolchain_versions(),
        }
