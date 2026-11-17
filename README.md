# AI-Assisted Reverse Engineering Assistant

Evidence-first assistant for static reverse engineering. It analyzes uploaded binaries without executing them and presents deterministic, evidence-backed findings with optional AI explanations.

## Status

The worker statically extracts PE x64 metadata with pinned LIEF, and includes a real Ghidra headless runner that exports function names, addresses, decompiled pseudocode, assembly, and direct call edges before normalization and deterministic detection. The worker image includes Ghidra 12.1.3 and JDK 21. AI analysis remains disabled, so pipeline results are still marked `PARTIAL`. See `docs/SPEC.md` and `AGENTS.md` for the product contract and permanent project rules.

## Requirements

- Python 3.12
- Node.js (version to be pinned during frontend setup)
- Docker Compose for the full stack

## Configuration

Copy `.env.example` to `.env` and set local values as needed. Cloud LLM access is disabled by default; never enable it without explicit consent.

## Run

From the repository root, start the stack:

```powershell
docker compose up --build
```

The API is available at `http://localhost:8000`; verify it with:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

To run unit tests against the Compose PostgreSQL database from another terminal:

```powershell
docker compose exec api pytest -p no:cacheprovider /tests/unit -q
docker compose exec -T worker pytest -p no:cacheprovider /app/tests/worker -q
```

Build the three owned synthetic PE x64 samples (compilation only; the programs are never run by the project):

```powershell
./evaluation/build-corpus.ps1
```

The outputs go to ignored `evaluation/build/`. Upload the benign sample with:

```powershell
$upload = curl.exe -sS -F "file=@evaluation/build/hello_pe_x64.exe;type=application/octet-stream" http://localhost:8000/api/v1/analyses
$upload
$id = ($upload | ConvertFrom-Json).id
curl.exe -sS -N "http://localhost:8000/api/v1/analyses/$id/events"
curl.exe -sS "http://localhost:8000/api/v1/analyses/$id/static"
curl.exe -sS -X DELETE "http://localhost:8000/api/v1/analyses/$id"
```

To exercise upload, SSE, and deletion in PowerShell, create a tiny fake PE header and run:

```powershell
python -c "from pathlib import Path; Path('tiny-pe.exe').write_bytes(b'MZ' + bytes(126))"
$upload = curl.exe -sS -F "file=@tiny-pe.exe;type=application/octet-stream" http://localhost:8000/api/v1/analyses
$upload
$id = ($upload | ConvertFrom-Json).id
curl.exe -sS -N "http://localhost:8000/api/v1/analyses/$id/events"
curl.exe -sS -X DELETE "http://localhost:8000/api/v1/analyses/$id"
Remove-Item -LiteralPath tiny-pe.exe
```

Stop the stack with `docker compose down` (named volumes are retained).

## Ghidra

The Compose worker defaults to `GHIDRA_MODE=real`, using the installed headless toolchain. Set `GHIDRA_MODE=fixture` to use checked-in fixtures for tests. `GHIDRA_TIMEOUT_SECONDS` controls the real analyzer timeout (default: 900 seconds). Fixture results remain labeled as fixture output.

## Development

Add tests with each feature and preserve the static-only, evidence-first boundary. Uploaded binaries are imported for static analysis only and are never executed by the application.
