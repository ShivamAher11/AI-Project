# Changelog

Intentional deviations from `docs/SPEC.md` are recorded here. Newest entries first.

## 2026-10-29 — Part 1: runnable infrastructure and schema

- Implemented Compose services, API health endpoint, initial PostgreSQL schema/migration, normalized schema, and full/partial fixtures.
- The normalized schema includes top-level `status` and `decomp_status` fields, which are not listed in §15's canonical JSON example. This is needed to validate the explicitly required `PARTIAL` / `TIMEOUT` fixture state and matches the state contract in §11.
- Worker is a healthy Python-only idle placeholder and the frontend is a minimal Vite/nginx placeholder, as requested for this part. Celery task processing, analysis endpoints, upload handling, and the product UI remain unimplemented.
- Postgres is pinned to image `postgres:16.15-alpine` for reproducible local setup. Frontend/API images and Python dependency versions are pinned in their Dockerfiles/requirements for this slice.

## 2026-10-29 — Repository scaffold

- Added the initial repository structure and permanent solo-developer rules in `AGENTS.md`.
- No features are implemented. The deferrals documented in `AGENTS.md` are explicit project execution constraints supplied for this build; deferred spec areas will have `TODO(spec §N)` markers at their implementation seams.
- Corrected the spec's example band typo in project guidance: risk 48/100 is Medium under the locked thresholds.
