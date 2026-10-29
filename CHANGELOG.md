# Changelog

Intentional deviations from `docs/SPEC.md` are recorded here. Newest entries first.

## 2026-10-29 — Part 1: runnable infrastructure and schema

- Implemented Compose services, API health endpoint, initial PostgreSQL schema/migration, normalized schema, and full/partial fixtures.
- The normalized schema includes top-level `status` and `decomp_status` fields, which are not listed in §15's canonical JSON example. This is needed to validate the explicitly required `PARTIAL` / `TIMEOUT` fixture state and matches the state contract in §11.
- Worker is a healthy Python-only idle placeholder and the frontend is a minimal Vite/nginx placeholder, as requested for this part. Celery task processing, analysis endpoints, upload handling, and the product UI remain unimplemented.
- Postgres is pinned to image `postgres:16.15-alpine` for reproducible local setup. Frontend/API images and Python dependency versions are pinned in their Dockerfiles/requirements for this slice.

## 2026-10-29 — Part 2: upload-to-terminal job flow

- Added streaming file persistence with UUID-only paths, size/magic validation, duplicate-SHA provenance, Celery state updates, status/SSE routes, DELETE cancellation/cascade, startup TTL cleanup, and focused security/state/integration tests.
- Worker stages intentionally remain placeholders for this part. Successful uploads finish as `PARTIAL` with `PIPELINE_STUBBED`; no file contents are executed or parsed.
- Per `AGENTS.md`, the raw-body ASGI limit middleware and SSE `Last-Event-ID` replay remain deferred with `TODO(spec §12)` and `TODO(spec §19)` markers. Uploads use the Content-Length precheck and streamed file-byte counter.

## 2026-10-29 — Repository scaffold

- Added the initial repository structure and permanent solo-developer rules in `AGENTS.md`.
- No features are implemented. The deferrals documented in `AGENTS.md` are explicit project execution constraints supplied for this build; deferred spec areas will have `TODO(spec §N)` markers at their implementation seams.
- Corrected the spec's example band typo in project guidance: risk 48/100 is Medium under the locked thresholds.
