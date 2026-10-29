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

Run instructions will be added with the first runnable vertical slice.

## Development

Implement one small end-to-end slice at a time, add tests with each feature, and keep fixture mode usable before enabling the real Ghidra runner.