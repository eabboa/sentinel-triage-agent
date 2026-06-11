# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LangGraph pipeline for human-in-the-loop (HITL) Microsoft Sentinel incident triage. Fetches Sentinel incidents, enriches IOCs with CTI (VirusTotal/AbuseIPDB), classifies with Gemini LLMs, generates KQL hunting queries, and writes results back to Sentinel — pausing for human review before any closure or containment action.

## Commands

Python 3.13+, managed with `uv`. Always prefix Python commands with `uv run`.

```bash
uv sync --dev --locked          # Install dependencies (or: bash safe_install.sh for the supply-chain-gated install)
uv run pytest                   # Full test suite
uv run pytest tests/test_enrich_node.py                    # Single test file
uv run pytest tests/test_enrich_node.py::test_name         # Single test
uv run pytest --cov=. --cov-report=xml                     # Coverage (CI enforces >=80%, branch coverage)
uv run black . && uv run isort .                           # Format
uv run mypy .                   # Type check
uv run python main.py           # Run full pipeline (requires Azure auth + .env)
```

Pre-commit hooks run black, isort, `mypy .`, and the full pytest suite — all via `uv run`.

## Architecture

### Graph pipeline (graph.py)

`StateGraph` over `TriageState` (state.py, a TypedDict). Node order with conditional routing:

```
fetch → summarize → extract ─┬→ enrich → analyst → mitre_enrich ─┬→ escalation ─┐
                             └→ analyst (no IOCs)                ├→ kql ────────┼→ writeback
                                                                 └──────────────┘     │
                                                          ══ INTERRUPT (human) ══     │
                             containment (if approved) → close_review → learning → END
```

- `_next_after_extract`: skips `enrich` when no IPs/hashes/URLs were extracted.
- `_next_after_analyst` (runs after `mitre_enrich`): TruePositive >90% confidence → `escalation`; FalsePositive >95% → straight to `writeback`; otherwise `kql`.
- The graph compiles with `interrupt_after=["writeback"]` — **no autonomous incident closure or containment, ever**. `main.py` collects console approvals (closure, containment, reclassification) at the interrupt, applies them via `graph.update_state()`, then resumes with `graph.ainvoke(None, config)`.
- Checkpointer is `MemorySaver` (dev only). Thread IDs are deterministic (`uuid5` of incident ID) to allow HITL resume.

### State conventions (state.py)

- Nodes return partial dicts of state updates; they never mutate state in place.
- `errors` and `degraded_sources` use `Annotated[list, operator.add]` reducers — **append-only**. Non-fatal failures (CTI lookup failures, MITRE validation warnings, unresolvable MDE machine IDs) go into `errors` rather than halting the graph.

### Key design invariants

- **CTI neutral baseline** (enrich_node): failed CTI lookups are *stripped* from `cti_results` and logged to `errors` — the LLM must never see ambiguous error payloads. Each successful result carries a pre-computed `verdict` field (`malicious`/`suspicious`/`clean`) resolved by thresholds (`VT_MALICIOUS_THRESHOLD`, `ABUSEIPDB_MALICIOUS_THRESHOLD` env vars), so threshold inference never happens in the LLM. If a whole source is down, its name goes in `degraded_sources` and is disclosed in the analyst prompt.
- **Prompt injection isolation** (analyst_node): instructions go in `SystemMessage`, untrusted incident telemetry in `HumanMessage`. Keep this separation when modifying prompts.
- **Boundary validation**: all external data (Sentinel, VT, AbuseIPDB, LLM structured output) is validated against Pydantic models in `models/validation.py` (`extra="ignore"`). Validation failures raise typed exceptions from `models/exceptions.py` that capture the raw failing payload.
- **MITRE validation** (nodes/mitre_utils.py, mitre_enrich_node): LLM-suggested techniques are programmatically validated; hallucinated IDs are flagged into `errors`, never written back unverified.
- **RAG learning loop**: `learning_node` stores human-vs-LLM classification mismatches in ChromaDB (embedded with all-MiniLM-L6-v2); `analyst_node` retrieves them as few-shot examples. `seed_learning.py` bootstraps the DB from CSV.

### Rate limiting & retries

- Gemini: sliding-window limiter in `throttle.py` (14 RPM); shared `@llm_retry` tenacity decorator in `llm_utils.py`. All `ChatGoogleGenerativeAI` instances set `max_retries=0` — tenacity owns all backoff; don't reintroduce double-retry.
- VirusTotal: `aiolimiter.AsyncLimiter(4, 60)` enforces the 4 req/min free tier.
- Sentinel REST (`sentinel_api.py`): shared `_http_request` wrapper, 10s timeout, tenacity retries on 429/503/504; incident updates use ETag `If-Match` (raises `ConcurrencyConflictError` on 412). Closing an incident requires a full PUT (fetch, modify, PUT) — not PATCH. The alerts endpoint requires POST, not GET.
- Auth (`sentinel_auth.py`): `DefaultAzureCredential` only (no static secrets), module-level token cache guarded by `threading.Lock()`.

## Testing notes

- `tests/conftest.py` injects mock env vars **at module scope** because `sentinel_api.py` validates `SUBSCRIPTION_ID`/`RESOURCE_GROUP`/`WORKSPACE_NAME` at import time. Any new module-level env validation must keep working under this pattern.
- conftest also monkey-patches `aiohttp.ClientResponse.__init__` for aiohttp 3.11+ compatibility with `aioresponses`.
- pytest runs with `asyncio_mode = "auto"` — async tests need no decorator.
- Coverage omits `main.py`, `seed_learning.py`, `test_model.py`, and `nodes/learning_node.py`; `fail_under = 80` with branch coverage.

## Operational scripts

- `create_mock_incident.py` — deploys 10 adversarial Sentinel analytics rules for end-to-end testing (delete from Sentinel → Analytics afterwards).
- `seed_learning.py --csv file.csv [--dry-run]` — seeds ChromaDB for the RAG loop.
- `test_model.py` — Gemini connectivity smoke test.
