# AI-Assisted Reverse Engineering Assistant

Evidence-first assistant for static reverse engineering. It analyzes uploaded binaries without executing them and presents deterministic, evidence-backed findings with optional AI explanations.

## Status

The first vertical slice is in place: binary upload validation and storage, a placeholder Celery pipeline, status/SSE progress, and deletion. The pipeline does not yet analyze binary contents and ends honestly as `PARTIAL`. See `docs/SPEC.md` and `AGENTS.md` for the product contract and permanent project rules.

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

## Development

The worker and frontend are placeholders. Implement one small end-to-end slice at a time, add tests with each feature, and keep fixture mode usable before enabling the real Ghidra runner.
