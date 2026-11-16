# AI Provider Setup — PolyStrata via ngrok Tunnel

This document describes how to configure the API-side AI provider to talk to a
locally-running PolyStrata model through an ngrok HTTPS tunnel. All checks are
**opt-in** and run without network access by default. CI must stay offline.

## Architecture

```
Browser → API (FastAPI:8000) → api-egress → ngrok HTTPS → PolyStrata (127.0.0.1:8080/v1)
```

- **PolyStrata** runs locally on `127.0.0.1:8080` and serves an OpenAI-compatible
  API at `/v1/chat/completions`. Nothing leaves your PC unless you expose it via
  the ngrok tunnel.
- **ngrok** provides a public HTTPS endpoint to the local PolyStrata port, protected
  by Basic Auth at the tunnel edge. The API sends ngrok `Basic` auth **and**
  PolyStrata `Bearer` auth in separate headers on every request.
- **The worker never calls the model.** All provider calls happen in the API process.
- **No cloud fallback.** If `CONSENT_CLOUD_LLM` is not true, or no key/model/endpoint
  is configured, AI is disabled and deterministic static findings remain available.

## Required environment settings

Fill in your local `.env` (never commit it). Values shown are placeholders — replace
`<...>` with your own values.

| Variable | Meaning | Example |
|---|---|---|
| `LLM_API_KEY` | PolyStrata bearer key (sent as `Authorization: Bearer`) | your-poly-strata-key |
| `LLM_MODEL` | Model name accepted by PolyStrata | `qwen2.5-codebase` |
| `LLM_BASE_URL` | HTTPS ngrok URL + `/v1` | `https://abc123.ngrok-free.dev/v1` |
| `CONSENT_CLOUD_LLM` | Must be `true` to allow API → AI endpoint | `true` |
| `LLM_ALLOWED_HOSTS` | Exact ngrok hostname only (no wildcards, no suffix matches) | `abc123.ngrok-free.dev` |
| `LLM_TUNNEL_USERNAME` | ngrok Basic Auth username | `tunnel-user` |
| `LIM_TUNNEL_PASSWORD` | ngrok Basic Auth password | `tunnel-pass` |

The provider rejects:
- Non-HTTPS URLs for non-localhost hosts
- Hostnames not in `LLM_ALLOWED_HOSTS`
- URLs containing credentials, query strings, or fragments

## Setup steps (opt-in)

1. **Install PolyStrata** locally (see `PolyStrata/AI_SETUP.md`). It starts on
   `http://127.0.0.1:8080`. Verify with:
   ```
   curl http://127.0.0.1:8080/health
   ```

2. **Start ngrok** to the local PolyStrata port, protected by Basic Auth:
   ```
   ngrok http 8080 --auth "tunnel-user:tunnel-pass"
   ```
   Use a stable hostname. Record the `Forwarding` HTTPS URL (e.g.
   `https://abc123.ngrok-free.dev`).

3. **Configure `.env`** (never commit):
   ```
   LLM_BASE_URL=https://abc123.ngrok-free.dev/v1
   LLM_ALLOWED_HOSTS=abc123.ngrok-free.dev
   LLM_TUNNEL_USERNAME=tunnel-user
   LLM_TUNNEL_PASSWORD=tunnel-pass
   LLM_API_KEY=<PolyStrata API key>
   LLM_MODEL=<model name accepted by PolyStrata>
   CONSENT_CLOUD_LLM=true
   ```

4. **Verify configuration without sending a completion:**
   ```
   curl http://localhost:8000/api/v1/ai/status
   ```
   Returns `enabled` plus model/host. No secrets are exposed.

5. **Optional live smoke check** (requires credentials and network):
   ```
   curl http://localhost:8000/api/v1/ai/test -X POST
   ```
   This makes one small bounded completion and returns `ok`. It is **not** part of
   CI and must not be run without explicit credentials.

## Safety rules

- Never store `LLM_API_KEY`, `LLM_TUNNEL_USERNAME`, or `LLM_TUNNEL_PASSWORD` in
  source, fixtures, Docker images, or logs.
- Never add cloud fallback. If AI is disabled, deterministic findings remain
  available.
- Do not start a public tunnel or use credentials without explicit user setup.
- Host validation is exact-match only: `LLM_ALLOWED_HOSTS` accepts the exact
  ngrok hostname, no suffix or wildcard matching.

## Offline tests

Run without network, ngrok, or a live model:

```
python -m pytest tests/unit/test_ai_provider.py tests/unit/test_ai_schemas.py tests/unit/test_ai_cache.py -q
```

These use `MockProvider` and `httpx.MockTransport`; no credentials are needed.
