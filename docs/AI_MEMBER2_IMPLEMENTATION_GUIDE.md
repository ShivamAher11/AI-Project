# Member 2 AI Implementation Guide

## Approved Product Direction (2026-11-17)

Follow `docs/SPEC.md` §“Approved Amendment 1.5 — AI-Centered Static Analysis”. This amendment supersedes conflicting text below and in older project docs.

Member 2 delivers an automatic, evidence-grounded AI pipeline. The LLM may request bounded work from typed, allow-listed static tools. The isolated worker runs tools such as Ghidra; the API mediates model access. Never provide shell, arbitrary code execution, filesystem access, or network tools. Never execute uploaded content.

Accept arbitrary regular files within configured size limits. Use a format parser when available. Otherwise provide bounded generic observations from safe metadata, type detection, hashes, entropy, and printable strings. State limitations. Never send raw bytes or paths to the model.

The final AI assessment must be `LIKELY_MALICIOUS`, `LIKELY_BENIGN`, or `INCONCLUSIVE`, cite valid evidence IDs from the current analysis, and state uncertainty. Use `INCONCLUSIVE` when evidence is missing, weak, or conflicting. Keep AI assessment separate from deterministic findings, scores, severity, confidence, and ATT&CK ceilings.

Run function analysis, evidence correlation, and report synthesis automatically when a provider is configured. Keep remote-provider disclosure and deployment-level consent. AI or tool failure must preserve static results and report `PARTIAL`/`DEGRADED` honestly. Bump affected prompt/schema versions and invalidate stale cache entries.

Use `docs/AI_CODING_AGENT_PROMPTS.md` for the phase-by-phase implementation sessions. The implementation agent must update code and tests after reading this guide. The work does not stop at documentation.

## Purpose

This guide gives an AI coding agent the work order for Member 2's AI pipeline.
Follow this guide with `AGENTS.md` and `docs/SPEC.md`.
`docs/SPEC.md` controls product behavior and data contracts.
This guide narrows work to AI interpretation and its integration points.

Member 2 builds an automatic AI analysis pipeline from deterministic analysis results and bounded static-tool outputs.
The rules engine decides findings, scores, severity, confidence, and ATT&CK ceilings.
The model correlates supplied evidence and produces a separate evidence-based file assessment.

## Read Before Editing

1. Read `AGENTS.md`.
2. Read `docs/SPEC.md`, especially §§9, 18, 24–30, 31, 37–39, 41–44, 48–50.
3. Read `docs/VERSIONS.md` before changing a dependency or claiming a verification.
4. Read `CHANGELOG.md` before adding a deliberate deviation.
5. Run `git status --short` and inspect `git diff` before editing.
6. Preserve other members' changes. Do not reset, revert, or overwrite unrelated files.
7. Read existing fixtures, routes, models, prompts, and tests before adding replacements.

The working tree can contain unfinished work from other members.
Treat that work as shared. Change only files needed for this AI slice.

## Member 2 Ownership

Own these areas:

- `ai/provider.py`: bounded provider calls and endpoint configuration.
- `ai/cache.py`: stable cache key and cached validated results.
- `ai/schemas/`: strict schemas and response validation.
- `ai/prompts_v1.0/`: versioned function, correlation, and report prompts.
- AI parts of `worker/tasks.py`: stage state and API-mediated handoff.
- Focused AI persistence, API response, UI, migration, and unit tests.

Coordinate worker data contracts with Member 1.
Coordinate persisted API shape and routes with the backend owner.
Coordinate function and report UI with the frontend owner.
Do not rewrite extraction, detection, scoring, graph, or general UI systems.

## Fixed Rules

- Analyze files as static data. Never execute an uploaded file or derived content.
- Never send a raw binary, binary path, or complete artifact to the model.
- Send only bounded, selected text and metadata needed for the current explanation.
- Treat strings, names, assembly, and decompilation as untrusted data.
- Put evidence inside explicit data delimiters. Never let evidence act as instructions.
- Validate every model response in application code, even when the endpoint accepts JSON Schema.
- Check every returned evidence ID and function ID against the current analysis.
- Reject unknown fields. Reject AI-authored `score`, `risk_score`, `severity`, `confidence`, and `confidence_score` fields.
- Do not let AI edit rules, findings, score, severity, confidence, or score breakdown.
- Allow only the approved evidence-based assessment labels. Require valid evidence IDs and uncertainty. Use `INCONCLUSIVE` when evidence is insufficient or conflicting.
- A zero-finding analysis is not proof of benign behavior.
- Keep worker network access isolated. The worker calls the internal API, not PolyStrata.
- Keep external provider calls in the API process.
- Keep secrets out of Git, logs, responses, Docker images, prompts, and fixtures.
- Label fixture-derived results as `source: fixture` in API and UI.
- Report `COMPLETED`, `PARTIAL`, or `FAILED` honestly.
- Run AI automatically when a provider is configured. Static analysis and rule findings remain usable when AI or a tool fails.
- Permit only typed, allow-listed static-analysis tool requests. Never provide shell, arbitrary code execution, filesystem, or network tools.

## Existing Integration Points

Inspect these before extending them. Reuse existing routes and components.

| Area | Current contract | AI work |
|---|---|---|
| AI status | `GET /api/v1/ai/status` | Report safe configuration status; never return secrets. |
| Connection check | `POST /api/v1/ai/test` | Make one bounded, non-analysis request. |
| On-demand explanation | `POST /api/v1/ai/analyses/{analysis_id}/explanation` | Explain selected persisted evidence. |
| Pipeline handoff | `POST /api/v1/ai/internal/analyses/{analysis_id}/pipeline` | Accept only an authenticated worker request. |
| Function detail | `GET /api/v1/analyses/{id}/functions/{fid}` | Return a stored validated function summary when present. |
| Overview | `GET /api/v1/analyses/{id}/overview` | Return AI state and stored report without changing risk fields. |
| Report | Existing Markdown report route | Include the validated AI assessment as a labeled, evidence-linked result. |

Use these existing UI routes:

- `/analyses/:id/overview`: AI explanation panel and AI availability state.
- `/analyses/:id/functions/:fid`: function summary with evidence references.
- `/analyses/:id/report`: automatic AI assessment and synthesis beside deterministic report content.

Do not add an AI settings page or a new top-level route.
Keep model and tunnel configuration in environment settings.
Keep `Explain findings` only as an optional follow-up action. The normal pipeline must generate its assessment automatically.

The Overview panel must show the AI assessment, evidence links, uncertainty, and `AI-generated assessment — verify`.
It must show whether a result is pipeline-generated or on-demand.
It must show model name, generation time, and input hash when available.
It must show an error or disabled message without hiding deterministic findings.
It must state that raw binaries are not sent to the model.
It must disclose that selected snippets pass through the configured ngrok endpoint.

The Function Detail panel must separate observed data from AI interpretation.
It must show purpose, behavior, indicators, uncertainty, and benign alternative.
It must link evidence IDs to the existing evidence display.
It must show an empty or unavailable state when no valid summary exists.
Warn that decompilation can contain secrets before the user enables remote calls.

The Report view must preserve all deterministic sections and limitations.
It must identify AI-generated text and its availability state.
It must not add unsupported claims. It must label the evidence-based assessment and keep it separate from deterministic risk.

## Persistence Contract

The current models already include:

- `analyses.ai_status` for `OK`, `DEGRADED`, `DISABLED`, `NOT_RUN`, or `FAILED`.
- `analyses.ai_report` as JSONB for the pipeline report.
- `functions.ai_summary` as text for a legacy summary value.
- `ai_runs` for stage, model, prompt version, input hash, schema version, timing,
  token usage, status, and error code.

Keep existing columns compatible.
Add an Alembic migration for `functions.ai_summary_json` as nullable JSONB.
Keep `functions.ai_summary` readable during migration and transition.
Add nullable `ai_runs.function_id` with a foreign key to `functions.id` and an index.
Use `function_id` for a function summary run. Leave it null for analysis-level runs.
Use existing cascade behavior when an analysis or function is deleted.
Add a reversible downgrade for every new database object.

Persist only validated output.
Store model, prompt version, schema version, input hash, status, timestamps,
token usage, and safe error code in `ai_runs`.
Do not persist full prompts or raw extracted text in run metadata.
Keep enough validated output to render the UI without making another model call.

## Phase 0 — Freeze Contracts and Prepare Fixtures

### Goal

Make progress without waiting for another member's unfinished output.

### Actions

1. Read the current normalized schema and `shared/openapi.yaml`.
2. Use `fixtures/analysis-full.json` and `fixtures/analysis-partial.json` for integration tests.
3. Use fixture functions, evidence, imports, strings, findings, and graph edges as inputs.
4. Write a small AI input adapter around the normalized analysis contract.
5. Keep fixture source visible in API results and UI state.
6. Ask the owning member for a handoff before changing a shared field or route.

### Exit checks

- AI tests run without Ghidra, a live API, ngrok, or PolyStrata.
- Full and partial fixtures pass through the AI input adapter.
- No code assumes that a fixture is production output.
- Shared API and worker boundaries are written down in code or this guide.

## Phase 1 — Schemas, Prompts, Provider, and Cache

### Schemas

Use strict JSON Schema and equivalent Python validation.
Set `additionalProperties` to `false` at each object level.
Require schema version, IDs, and uncertainty fields.
Set sensible maximum lengths and array limits.
Do not accept numeric risk fields.

Function summary schema v1.0:

```json
{
  "type": "object",
  "required": ["schema_version", "function_id", "purpose", "behavior", "evidence_ids", "uncertainty"],
  "properties": {
    "schema_version": {"const": "1.0"},
    "function_id": {"type": "string"},
    "purpose": {"type": "string", "maxLength": 1000},
    "behavior": {"type": "array", "items": {"type": "string"}},
    "evidence_ids": {"type": "array", "items": {"type": "string"}},
    "suspicious_indicators": {"type": "array", "items": {"type": "string"}},
    "uncertainty": {"type": "string"},
    "alternative_explanation": {"type": "string"},
    "suggested_technique_id": {"type": "string"},
    "rationale": {"type": "string"}
  },
  "additionalProperties": false
}
```

Keep optional properties optional. Keep list lengths and text lengths bounded.
For Stage 2 and Stage 3, define separate schemas in the same strict style.
Stage 2 must cite evidence and affected function IDs.
Stage 3 must reference supplied findings and summaries only.

### Prompts

Keep prompts in `ai/prompts_v1.0/` and load them by stage.
Include a version in each prompt file and in every stored AI run.
Use the system prompt for fixed safety and output rules.
Put evidence in a JSON-escaped data block with explicit start and end delimiters.
Tell the model that evidence is data, not instructions.
Tell the model to return only the requested JSON object.
Do not place secrets, internal tokens, or filesystem paths in prompts.

Function prompt input:

- Function ID, address, name, signature, size, and decompiler status.
- Bounded decompilation or assembly excerpt.
- Relevant imports, strings, rule hits, and evidence IDs.
- Analysis ID and input hash for provenance.

Function prompt output:

- A short purpose statement.
- A concise behavior list.
- Suspicious indicators that cite supplied evidence only.
- Required uncertainty and a plausible benign explanation.
- Optional ATT&CK suggestion only when the rule pipeline supplied a candidate.

Do not ask Stage 1 to produce scores, severity, confidence, final verdict, or new findings. The final report stage produces the separate evidence-based assessment under Amendment 1.5.

### Provider

Use an injectable `MockProvider` as the default in unit tests.
Use `LLMProvider` for configured live requests.
Keep request and response types behind the provider interface.
Use non-streaming chat completions, temperature zero, and bounded output tokens.
Use strict timeouts and bounded retries for transient network errors only.
Do not retry a valid response because a person dislikes its wording.
Do not log request headers, credentials, full prompts, or model output by default.
Return safe status codes and messages for disabled, timeout, refused, or malformed calls.

PolyStrata accepts OpenAI-compatible `/v1/chat/completions` requests.
Its current documentation describes JSON Schema response formats as checked output.
It does not promise constrained generation for every model.
Send `response_format` when supported, then always validate in application code.
Test malformed and schema-invalid output even when the endpoint accepts a schema.

### Cache

Use SHA-256 over canonical normalized input, model, prompt version, and schema version.
Use stable JSON serialization with sorted keys and fixed separators.
Return cached output only after schema and evidence validation.
Never reuse output across models, prompt versions, schemas, or analysis inputs.

### Exit checks

- Unit tests reject missing fields, unknown fields, forbidden numeric fields, and bad types.
- Unit tests reject unknown evidence IDs and function IDs.
- Provider tests use mock HTTP transport and do not call the network.
- Cache tests prove stable keys and prove invalidation after version or input changes.
- No test needs the live model.

## Phase 2 — Stage 1 Function Summaries

### Input selection

Rank functions deterministically before sending any request.
Use the ranking signals and normalization in `docs/SPEC.md` §26.
Break ties by function address in ascending order.
Use `FUNC_AI_K=50` by default and reduce to 20 when the spec budget rule applies.
Log the selected count and whether the limit was reduced.

For each selected function, build bounded context from persisted analysis rows.
Keep the function's evidence IDs and source values together.
Drop assembly first when context exceeds the limit.
Then reduce the decompilation excerpt from its tail.
Never remove IDs needed to validate grounding.
Never pass a local artifact path or raw binary content.

Respect the §26 budgets:

- Function input ceiling: 12,000 characters.
- Function output ceiling: 1,500 tokens.
- Stage 2 input ceiling: 80,000 characters.
- Stage 3 input ceiling: 40,000 characters.
- Total output ceiling: 60,000 tokens per analysis.
- Default token rate limit: 30,000 tokens per minute.
- Default request rate limit: 60 requests per minute.
- Keep request retries and schema repair calls inside the total call budget.

### Output validation

1. Parse one JSON object. Reject markdown fences and trailing content.
2. Validate the exact function ID.
3. Validate all evidence IDs against the supplied evidence set for this analysis.
4. Reject any evidence or function ID from another analysis.
5. Reject forbidden fields and unknown fields.
6. Repair invalid JSON or grounding at most twice when budget allows.
7. Drop output that remains invalid. Mark AI state degraded and keep rule results.
8. Never repair by inventing, substituting, or guessing an evidence ID.

If the model returns no evidence and the input contains no usable evidence,
store no summary for that function and record an insufficient-evidence outcome.
Do not fabricate a citation to make the schema pass.

### Execution boundary

Keep model access in the API process.
The worker may call only the internal AI API with `PIPELINE_AI_INTERNAL_TOKEN`.
Compare the token with a constant-time comparison.
Reject missing or short internal tokens before processing.
Do not expose the internal route in frontend code.

The worker must preserve stage and progress behavior.
An AI timeout or invalid response must not erase persisted detection output.
Set `ai_status` to `DEGRADED` or `DISABLED` as appropriate.
Set the overall analysis to `PARTIAL` when AI failure affects completion.
Keep error messages safe and useful.

### Exit checks

- A full fixture produces at least one validated summary with valid evidence IDs.
- A partial fixture stays partial and keeps its static findings.
- AI disabled, provider timeout, invalid JSON, and grounding failure keep static output.
- Repeating the same input uses cache and creates no duplicate provider call.
- Deterministic score and findings match the pre-AI values exactly.

## Phase 3 — Persistence, API, and UI

### Persistence

Add the migration described in the Persistence Contract.
Store a summary only after validation.
Store per-function and analysis-level provenance in `ai_runs`.
Store Stage 3 output in `analyses.ai_report` only after validation.
Make cache and database writes transaction-safe.
Do not mark `ai_status=OK` until all required Stage 1 work completes.
Use `DEGRADED` when only some summaries complete.

### API

Keep existing route paths unless an existing contract cannot support Stage 1.
Extend OpenAPI and response types when a response changes.
Return structured summaries from the existing function detail route.
Return AI state and report from the existing overview route.
Return the same deterministic findings regardless of model output.
Use 404 for unknown analysis or function IDs.
Use 409 when an analysis is not ready for an on-demand request.
Use 503 when AI is disabled or not configured.
Use 502 for provider failure or invalid provider response.
Use the project's standard error envelope.
Never return provider credentials, tunnel credentials, or raw prompt content.

### UI

On Overview, keep the existing explanation action and AI panel.
Disable the action until analysis is `COMPLETED` or `PARTIAL`.
Show loading text while the API waits.
Show a safe error message when the provider fails.
Show deterministic results and the AI-unavailable state when the provider is disabled or unreachable. Mark the analysis partial.
Show AI report text only after API validation.

On Function Detail, add the structured Stage 1 summary.
Show purpose, behaviors, indicators, uncertainty, alternative, and evidence links.
Show an explicit empty state when the function was not selected or had no usable evidence.
Keep decompilation status and fixture provenance visible.

On Report, include Stage 3 output only when Stage 3 is enabled and validated.
Otherwise show the deterministic report and an accurate AI availability note.

### Exit checks

- Existing UI routes still render with AI disabled.
- API returns no raw secrets and validates IDs before returning summary data.
- Delete and TTL cleanup cascade AI runs and structured summaries.
- A migration upgrade and downgrade preserve all pre-existing summary text.
- OpenAPI describes all changed fields and error responses.

## Phase 4 — PolyStrata and ngrok Setup

### Local model service

1. Start PolyStrata on the local machine.
2. Keep its API bound to `127.0.0.1:8080` unless PolyStrata requires another port.
3. Configure a unique PolyStrata API key in its local model configuration.
4. Confirm its local OpenAI-compatible endpoint before starting ngrok.
5. Confirm the selected model name from the PolyStrata installation.
6. Do not assume the example model name in `.env.example` is installed.

PolyStrata currently documents `http://127.0.0.1:8080/v1` as its OpenAI-compatible base URL.
It states that clients can use the configured API key and model name.
Check its current documentation before changing exact paths or configuration fields:
[PolyStrata README](https://github.com/simplexai-labs/PolyStrata).

### ngrok tunnel

1. Create an ngrok HTTP endpoint to the local PolyStrata port.
2. Add ngrok Traffic Policy Basic Auth to the endpoint.
3. Keep Basic Auth credentials outside the repository.
4. Use a stable ngrok hostname when available.
5. Restrict `LLM_ALLOWED_HOSTS` to that exact hostname.
6. Test that an unauthenticated request is rejected.
7. Test that an authenticated request reaches only the PolyStrata API.

ngrok documents Basic Auth in Traffic Policy for public HTTP endpoints:
[ngrok endpoint authentication](https://ngrok.com/docs/gateway/traffic-policy/examples/add-authentication).
HTTPS alone does not restrict callers. Require authentication.

Start the tunnel with the protected local policy file:

```text
ngrok http 8080 --traffic-policy-file <protected-policy-file>
```

Do not commit the policy file when it contains credentials.
Use ngrok's protected secret storage when the selected ngrok setup supports it.

### Application settings

Keep these values in ignored `.env` or a secret manager:

```text
LLM_BASE_URL=https://<ngrok-hostname>/v1
LLM_ALLOWED_HOSTS=<ngrok-hostname>
LLM_MODEL=<model name accepted by PolyStrata>
LLM_API_KEY=<PolyStrata API key>
LLM_TUNNEL_USERNAME=<ngrok Basic Auth username>
LLM_TUNNEL_PASSWORD=<ngrok Basic Auth password>
CONSENT_CLOUD_LLM=true
```

Use separate HTTP Basic Auth credentials for ngrok and Bearer credentials for PolyStrata.
Do not reuse one secret for both layers.
Require `CONSENT_CLOUD_LLM=true` before sending extracted data to a remote provider. A configured local provider must run without cloud consent. Never silently fall back from local to remote.
Explain that model inference is local but request traffic crosses the ngrok service.
Do not silently fall back to a cloud model.
Do not add the ngrok token to the application request headers.
Do not put secrets in `.env.example`.

Update provider configuration to send both auth schemes to the same API request.
Use the exact allowlisted hostname and HTTPS for the public tunnel.
Keep any localhost-only HTTP mode limited to loopback addresses.
Do not weaken host validation to accept arbitrary URLs or suffix matches.

### Live smoke check

Make live checks opt-in. Never make CI depend on a local GPU or public tunnel.
Check status without exposing secrets.
Check one bounded completion with a harmless prompt.
Check one fixture-backed AI explanation with explicit user consent.
Confirm logs do not contain prompts, extracted code, or credentials.
Turn off the tunnel after the check when it is not needed.

## Phase 5 — AI Evidence Correlation and Report Synthesis

Stage 2 and Stage 3 are required parts of the approved AI-centered pipeline. Use the existing strict schemas and bounded context requirements as a baseline. Extend them for tool requests and the final evidence-based assessment. Keep prompt and output versions explicit. See SPEC Amendment 1.5 for the controlling behavior.

Implement these stages as required parts of the automatic AI pipeline. Add one stage at a time. Record any further scope deviation in `CHANGELOG.md`.

### Stage 2: behavior correlation

Input: validated Stage 1 summaries, deterministic rule hits, relevant evidence,
and call graph edges up to depth two.
Do not send full decompilation again.
Return structured behavior correlations, affected function IDs, evidence IDs,
uncertainty, and rationale.
Only qualify or reject rule-generated ATT&CK candidates.
Do not add techniques outside the locked candidate set.
Do not raise an ATT&CK confidence ceiling or deterministic score.
Reject output with missing or invalid evidence.

### Stage 3: report synthesis

Input: metadata, deterministic findings, validated summaries, qualified ATT&CK,
AI availability, and analysis limitations.
Return a concise executive summary, key behaviors, limitations, and AI availability.
Do not create findings, risk values, techniques, or certainty absent from input.
Keep the deterministic Markdown report usable when this stage is unavailable.

## Test Requirements

Write focused unit tests with each phase.
Use existing fixture data and fake provider responses.
Do not require network access in normal tests.

Required cases:

- Valid function output with evidence from the current analysis.
- Missing required field, wrong type, extra field, and forbidden risk field.
- Invalid evidence ID, invalid function ID, and cross-analysis ID.
- Prompt-injection text inside a string, function name, and decompilation excerpt.
- Empty evidence, missing decompilation, failed decompilation, and partial analysis.
- Context over limit, deterministic K=50 selection, and deterministic K=20 reduction.
- Cache hit, changed input, changed model, changed prompt version, and changed schema version.
- Provider 401, 403, 408, 429, 5xx, timeout, connection failure, malformed JSON, and empty output.
- Tunnel Basic Auth and PolyStrata Bearer Auth sent separately.
- AI disabled, missing consent, missing keys, hostname rejection, and non-HTTPS public URL.
- Worker internal token missing, too short, wrong, and correct.
- Database upgrade, downgrade, cascade delete, and preservation of legacy `ai_summary`.
- UI loading, disabled, unavailable, partial, valid summary, and no-evidence states.
- Deterministic score, findings, severity, and confidence remain byte-for-byte unchanged.

Use the repository's current test command from `README.md` or `AGENTS.md`.
Do not add a new test framework for this work.
Run focused AI tests first, then the project test suite when practical.
Report commands and results accurately. Do not claim tests passed without running them.

## Completion Criteria

Member 2's deliverable is the automatic multi-stage, evidence-grounded AI pipeline.
It must analyze selected functions, correlate evidence, request bounded static tools when useful, and produce the approved assessment labels.
It must work with fixtures and mocked providers/tools without a live model.
The local provider setup must be documented. Live smoke checks remain opt-in and must not run in CI.
AI failures must leave deterministic analysis available and correctly marked.
No raw binary may reach the model.
No AI output may alter deterministic risk or findings.
All added database and API fields must be versioned and documented.
Stage 1, Stage 2, and Stage 3 are required for the configured-provider AI assessment. Provider failure preserves deterministic output and marks the analysis partial/degraded.

At the end of each implementation part, report:

1. What works.
2. Exact commands to run it.
3. What remains stubbed.
4. Estimated overall project completion percentage.

## Agent Handoff Checklist

- [ ] Read project rules and relevant spec sections.
- [ ] Inspected working tree and preserved other members' edits.
- [ ] Confirmed fixture and normalized input contracts.
- [ ] Implemented strict schema validation and evidence checks.
- [ ] Implemented mock-first Stage 1 with deterministic ranking and bounded context.
- [ ] Persisted output and provenance with a reversible migration.
- [ ] Updated API, OpenAPI, and existing UI routes only where required.
- [ ] Kept AI failure separate from deterministic findings and risk.
- [ ] Added unit tests for success, failure, grounding, budget, and security cases.
- [ ] Configured PolyStrata and ngrok with separate credentials and exact host allowlist.
- [ ] Recorded intentional scope deviations in `CHANGELOG.md`.
- [ ] Reported working behavior, run commands, stubs, and project completion estimate.
