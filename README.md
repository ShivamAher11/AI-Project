# AI-Assisted Reverse Engineering Assistant

Evidence-first assistant for static reverse engineering. It analyzes uploaded binaries without executing them and presents deterministic, evidence-backed findings with optional AI explanations.

## Status

The current vertical slice validates uploads, statically extracts PE x64 metadata with pinned LIEF, stores normalized JSON and metadata in PostgreSQL, and exposes upload/status/SSE/static-data/delete APIs. Ghidra, detection, and AI stages are still placeholders, so results end as `PARTIAL`. See `docs/SPEC.md` and `AGENTS.md` for the product contract and permanent project rules.

## Requirements

- Python 3.12
- Node.js (version to be pinned during frontend setup)
- Docker Compose for the full stack
- ngrok (to expose the local PolyStrata model for AI processing)

## Configuration

Copy `.env.example` to `.env`. Never commit `.env`.

The AI model is PolyStrata running locally on `http://127.0.0.1:8080` (OpenAI-compatible `/v1`). Expose it via ngrok with a traffic policy:

```powershell
ngrok http 8080 --traffic-policy-file polystrata-traffic.yaml
```

The traffic policy requires `Authorization: Bearer shreyashhostingai` on every request, matching `LLM_API_KEY` in `.env`. Copy the `Forwarding` HTTPS URL ngrok prints and set in `.env`:

```
LLM_BASE_URL=https://<ngrok-hostname>/v1
LLM_ALLOWED_HOSTS=<ngrok-hostname>
```

The template sets `CONSENT_CLOUD_LLM=true`. The API still disables AI unless consent, a key, a model, and an allowlisted endpoint are all present.

The API-side endpoint is OpenAI-compatible. After the stack starts, verify configuration with `GET http://localhost:8000/api/v1/ai/status` and test a real model completion with `POST http://localhost:8000/api/v1/ai/test`. Completed analyses also show an **Explain findings** control on the Overview page. This is an on-demand explanation only; deterministic scoring/findings remain unchanged, and raw uploaded binaries are never sent to the model. The worker does not call ngrok or the model directly.

## Run

From the repository root, start the stack:

```powershell
docker compose up --build
```

The API is available at `http://localhost:8000`; verify it with:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

Check AI is enabled:

```powershell
curl.exe http://localhost:8000/api/v1/ai/status
```

Test a live completion against your PolyStrata model:

```powershell
curl.exe -X POST http://localhost:8000/api/v1/ai/test
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

## Development

The frontend and Ghidra/detection/AI stages remain placeholders. Add tests with each feature and preserve the static-only, evidence-first boundary.
