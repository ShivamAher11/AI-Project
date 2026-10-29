# AI-Assisted Reverse Engineering Assistant

Evidence-first assistant for static reverse engineering. It analyzes uploaded binaries without executing them and presents deterministic, evidence-backed findings with optional AI explanations.

## Status

Repository scaffold only. No application features are implemented yet. See `docs/SPEC.md` for the locked Implementation Master v1.4 and `AGENTS.md` for permanent project rules.

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

Stop the stack with `docker compose down` (named volumes are retained).

## Development

The worker and frontend are placeholders. Implement one small end-to-end slice at a time, add tests with each feature, and keep fixture mode usable before enabling the real Ghidra runner.
