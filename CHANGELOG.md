# Changelog

Intentional deviations from `docs/SPEC.md` are recorded here. Newest entries first.

## 2026-11-16 — Ghidra headless integration

- Implemented real headless Ghidra execution and a Java exporter for function addresses/names/signatures, decompiled pseudocode, assembly, and direct internal call edges; normalized JSON now carries real toolchain versions and accurate decompilation status.
- Pinned Ghidra 12.1.3 with its verified release SHA-256 and Adoptium Temurin JDK 21.0.13+9 in the worker image. See `docs/VERSIONS.md`.
- Verified the real Docker/Ghidra path with the synthetic PE x64 sample: API returned `source=real`, `decomp_status=OK`, populated functions and direct call edges. Compose and the runner now default to real mode; fixtures remain available with `GHIDRA_MODE=fixture`.
- Focused mocked-runner and normalization tests pass. AI remains disabled, so the overall analysis status is honestly `PARTIAL`.
- Made migration `0004_rule_scoring` tolerate scoring columns already created by the metadata-based initial migration, allowing fresh Compose databases to upgrade.

## 2026-10-29 — Part 4: fixture-backed call graph and decompilation pipeline

- Added normalized `source` and per-function `centrality` fields to schema v1.0 to expose the explicitly required provenance and PageRank score; §15's example omitted these fields while §§17 and 33 require their behavior.
- Stored full decompilation artifacts under `/funcs/` as requested by this implementation task; SPEC §17's full-load path text still says `/functions/`. UUID/FID validation and canonical path containment are enforced.
- At this part, real Ghidra was deferred; fixture output, PageRank, normalized artifact persistence, API/UI source labeling were implemented. Real execution was added in the 2026-11-16 entry above; detection and AI stages remain placeholders.

## 2026-10-29 — Part 3: PE x64 static metadata

- Pinned and verified LIEF 1.0.0 against the official release, PyPI package files, and PE Python API; implemented PE x64-only parsing, hashes, sections/entropy, categorized imports/exports, bounded ASCII/UTF-16LE strings, schema-validated normalized JSON, database ingestion, and a static metadata API endpoint.
- Added `strings_truncated` to normalized schema and analysis metadata because the required 100,000-row string cap needs a persisted truncation indicator (SPEC §§13, 15, 16).
- Added an `export_symbols` table because SPEC §13 requires exports as LIEF-owned static truth, although §16 omitted an exports table.
- `evaluation/src/` contains only the three requested synthetic sources. They are compiled through a Dockerized MinGW-w64 builder and are never executed by the application.
- ELF, x86-32, ARM, Ghidra, and detector behavior remain deferred; non-PE-x64 input is rejected as FAILED with a safe status message.

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
