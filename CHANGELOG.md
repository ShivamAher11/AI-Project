## 2026-11-18 — Automatic report enrichment and grounded evidence

- Fixed report context reconstruction to include deterministic finding descriptions, interpretations, alternatives, and the import/string/function evidence refs tied to each finding. The prior context dropped those fields, so the model saw a finding ID and score without the supporting explanation.
- Bumped report prompt/cache version to 1.5 so reports created from incomplete finding context cannot be reused; the prompt now checks each rule hypothesis against its linked evidence and reports unsupported behavior accurately.
- Normalized a scalar `limitations` response to the schema-required one-item array without another model call; other invalid output still fails grounding validation.
- Recover omitted report `evidence_ids` only from exact current-analysis IDs cited in model text; missing citations still cannot support likely verdicts.
- Preserved bounded API validation/provider error messages in worker analysis status instead of replacing them with a generic AI failure message.
- Changed report synthesis prompt to include cited import, string, and function observations, require claim-specific evidence references, and specify exact JSON types.
- Fixed API pipeline reconstruction to read persisted signal IDs from the model's `id` field; the previous `signal_id` attribute lookup raised before any LLM stage ran.
- Fixed report validation to allow the required assessment `verdict`; automatic report synthesis now sends one provider request and leaves `ai_report` empty when validation fails.
- Changed the worker pipeline to one automatic report-synthesis request. Individual function summaries now run only from a requested function-level action; report prompt/cache version is 1.5.
- Intentional deviation from `docs/SPEC.md` §§1, 26–27: automatic function summaries and correlation calls are omitted to avoid up to 50 sequential requests; the automatic report uses one synthesis request, while function summaries require the user's Ask AI action.
- Kept the pipeline route synchronous so the single provider request runs in FastAPI's thread pool without blocking health checks or status requests.
- Removed the manual Overview explanation and Report enrichment controls. Both pages now consume the persisted pipeline assessment, and the report refreshes when the analysis reaches a terminal state.
- Kept deterministic findings and risk authoritative; AI failure remains a degraded/partial analysis.

## 2026-11-17 — Phase 5: automatic AI pipeline acceptance and security hardening

- Removed committed secret `LLM_API_KEY` from `.env`; `.env.example` now defaults `CONSENT_CLOUD_LLM=false`.
- Fixed `ai/provider.py`: local providers (`localhost`/`127.0.0.1`/`::1`/`.local`) run without cloud consent; remote providers require `CONSENT_CLOUD_LLM=true`. Removed `api.openai.com` from default `LLM_ALLOWED_HOSTS`.
- Fixed `docker/compose.yaml`: removed `api.openai.com` from default `LLM_ALLOWED_HOSTS`.
- Enforced `LLM_RPM` and `LLM_TPM_LIMIT` rate limits in `ai/summarizer.py` and `ai/assessor.py` (per-minute request and token guards).
- Verified upload bytes and file paths never appear in provider requests, logs, or AI run metadata (only bounded snippets + input hash SHA-256).
- Provider failure, disabled provider, and rate-limit exhaustion preserve deterministic output and mark analysis `PARTIAL`/`DEGRADED` honestly.

## 2026-11-17 — Phase 4: persist and expose AI assessment through API and UI

- Added `frontend/src/lib/api.ts` `AiAssessmentView` type and changed `OverviewView.aiReport` to `AiAssessmentView | null`.
- Updated `frontend/src/routes/Overview.tsx` to render the AI assessment panel: verdict badge, summary, rationale, uncertainty, limitations, evidence reference chips, and model/provenance metadata.
- Updated `frontend/src/routes/Report.tsx` to include the AI assessment (verdict, summary, rationale, uncertainty, limitations, evidence references, disclaimer) in the Markdown report output.
- Updated `shared/openapi.yaml` to document the `ai_report` assessment structure on `/analyses/{id}/overview` (verdict enum, evidence_ids, rationale, uncertainty, limitations, model, input_sha256, stages, tokens_used, tool_calls).
- Added `tests/unit/test_ai_pipeline.py` Phase 4 tests: all three verdict labels, evidence grounding to current analysis, cross-analysis evidence rejection, missing AI → partial state, partial analysis keeps deterministic findings, deterministic risk not modified by assessment, required assessment contract fields.
- No new top-level routes or settings pages added; assessment exposed through existing overview, function detail, and report routes.
- Deterministic findings, score, severity, confidence, and ATT&CK results unchanged and visible.

## 2026-10-29 — ngrok Ollama agent patch

- Filled the existing `ai/provider.py` seam with a bounded OpenAI-compatible HTTP client configured for `qwen2.5-codebase` and the supplied ngrok endpoint.
- Added API-mediated `/api/v1/ai/status`, `/api/v1/ai/test`, and on-demand analysis explanation endpoints. Explanations use selected persisted static evidence only; raw binaries never leave the API/worker boundary, and model output cannot modify deterministic scoring or findings.
- Added the Overview-page explanation control and passed AI environment values into the API container. The worker remains without outbound AI egress and the automatic AI pipeline stage remains stubbed, consistent with the existing project deferral.
- The local `.env` is required for the user-provided API key; no secret is bundled in this patch.

## 2026-11-16 — Member 2: AI Stage 1 function summaries

- Added strict `ai/schemas/function_summary_v1_0.json` and `ai/schemas/validate.py` enforcing no `score`, `risk_score`, `severity`, `confidence`, `confidence_score` fields and grounding every `function_id`/`evidence_id` to the current analysis (SPEC §§24, 28).
- Added `ai/prompts_v1.0/func.json` prompt v1.0 with `<<<BEGIN_UNTRUSTED_STATIC_EVIDENCE_JSON>>>` delimiters (SPEC §29).
- Added `ai/cache.py` stable SHA-256 cache key over model + prompt version + schema version + input hash (SPEC §26).
- Added `ai/provider.py` `MockProvider` + `LLMProvider.generate_structured` (bounded, non-streaming, temp 0).
- Added `ai/summarizer.py` Stage 1: deterministic ranking per SPEC §26 (3*rule_hits + 2*suspicious_api + centrality + entry_reachable + log(size), tie-break by address ascending), FUNC_MAX_CHARS=12000 bounded context, validation + grounding + ≤2 repair attempts, cache.
- Alembic `0006_ai_function_summary`: `functions.ai_summary_json` JSONB + `ai_runs.function_id` FK with reversible downgrade (Persistence Contract).
- `worker/tasks.py` AI_ANALYSIS stage now calls the API-mediated `/internal/analyses/{id}/function-summaries` endpoint; worker never calls the LLM directly.
- `backend/app/api/v1/ai.py` new internal Stage 1 endpoint; `backend/app/api/v1/analyses.py` function detail returns `ai_summary`.
- Models: `Function.ai_summary_json`, `AIRun.function_id` with FK + index.
- No test needs a live model; all AI tests use MockProvider. FastAPI/Postgres-backed tests run under Docker Compose per README.

## 2026-11-17 — Phase 3: full AI pipeline with evidence-based assessment

- Added `ai/schemas/report_assessment_v1_0.json` and `ai/schemas/correlation_v1_0.json` strict schemas for Stage 2 (correlation) and Stage 3 (report assessment) outputs.
- Added `ai/prompts_v1.0/correlate.json` and `ai/prompts_v1.0/report.json` v1.0 prompts with `<<<BEGIN_UNTRUSTED_STATIC_EVIDENCE_JSON>>>` delimiters (SPEC §§27, 29).
- Added `ai/assessor.py` `ReportAssessor`: Stage 2 behavior correlation + Stage 3 report synthesis producing one evidence-based assessment (`LIKELY_MALICIOUS` / `LIKELY_BENIGN` / `INCONCLUSIVE`). Likely verdicts require ≥1 valid evidence ID; INCONCLUSIVE otherwise.
- Extended `backend/app/api/v1/ai.py` `POST /internal/analyses/{id}/pipeline` to run all 3 stages (func summaries → correlate → report) with budget tracking (52 calls, 60k output tokens) and cache invalidation across prompt/schema versions.
- `worker/tasks.py` AI_ANALYSIS stage now calls the full pipeline endpoint; AI failure preserves deterministic results and marks analysis PARTIAL/DEGRADED honestly.
- Added `ai/schemas/validate.py` validators for correlation and assessment outputs, rejecting unknown fields, invented IDs, and AI-authored score/severity/confidence fields.
- Bumped prompt/output schema versions to 1.0 for correlate and report stages; cache keys include model + prompt version + schema version + input hash.
- Added `tests/unit/test_ai_pipeline.py` covering all verdict labels, evidence grounding, prompt injection, invalid output/repair limits, cache invalidation, provider failure, tool budget, and deterministic risk invariance.

## 2026-11-17 — Phase 2: bounded static-analysis tool allowlist

- Added `ai/tools.py`: a small typed allowlist of static-analysis tools
  (analysis.metadata, analysis.strings, analysis.functions,
  analysis.function_detail, analysis.findings, analysis.imports) that run only
  in the API process against persisted PostgreSQL evidence. Raw file bytes,
  upload paths, shell, network, and arbitrary SQL are never exposed.
- Added API endpoint `POST /ai/internal/analyses/{id}/tool` (pipeline-token
  authorized) that mediates every tool call. Unknown tools/arguments are
  rejected; unknown IDs return 404; budget exhaustion returns 429.
- Each tool call counts against SPEC §49 ceilings (52 calls, 60k output
  tokens) via `ToolBudget`; output is bounded per call.
- Extended `shared/openapi.yaml` with the tool endpoint and its error
  responses.
- Added `tests/unit/test_ai_tools.py` covering allowlist contents, argument
  validation, unknown tool/argument rejection, budget exhaustion, unknown
  analysis/function IDs, pipeline-token authorization, and a valid metadata
  call.

## 2026-11-17 — Approved AI-centered analysis direction

- Replaced the earlier AI-optional, explanation-only direction with an automatic multi-stage AI pipeline that can request bounded, allow-listed static analysis tools.
- Added arbitrary regular-file ingestion with format-specific parsers where available and a limited generic static fallback otherwise. The system never executes uploaded content or sends raw file bytes to the model.
- Added evidence-based AI assessment labels `LIKELY_MALICIOUS`, `LIKELY_BENIGN`, and `INCONCLUSIVE`; the assessment must cite current-analysis evidence and preserve uncertainty.
- Kept deterministic findings, score, severity, confidence, and ATT&CK ceilings outside AI control. Provider or tool failure preserves deterministic results and produces an honest partial/degraded state.
- Supersedes SPEC §§1–13, 26–30, 34, 38–50 and conflicting Member 2 guide rules. Prompt/output contract versions must be bumped when implemented.

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
