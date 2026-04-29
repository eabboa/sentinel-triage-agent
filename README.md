# sentinel-triage-agent

LangGraph pipeline for human-in-the-loop (HITL) Microsoft Sentinel incident triage.

**Lab write-up:** [Sentinel-Native Autonomous Triage Agent](https://github.com/eabboa/eabboa/blob/main/Home-Labs/Sentinel_Native_Autonomous_Triage_Agent.md)

---

## Architecture

```
                    ┌───────┐
                    │ START │
                    └───┬───┘
                        │
                   ┌────▼────┐
                   │  fetch  │  GET incident + POST alerts
                   └────┬────┘
                        │
                 ┌──────▼──────┐
                 │  summarize  │  Deterministic pre-processing
                 └──────┬──────┘
                        │
                  ┌─────▼─────┐
                  │  extract  │  Regex + LLM entity extraction
                  └─────┬─────┘
                        │
              ┌─────────┴─────────┐
       has IOCs?                no IOCs
              │                   │
        ┌─────▼─────┐             │
        │   enrich   │            │
        └─────┬─────┘             │
              └─────────┬─────────┘
                        │
                  ┌─────▼─────┐
                  │  analyst   │  LLM verdict + RAG few-shot
                  └─────┬─────┘
                        │
          ┌─────────────┼─────────────┐
     TP > 90%      ambiguous      FP > 95%
          │             │             │
   ┌──────▼──────┐ ┌───▼───┐          │
   │ escalation  │ │  kql  │          │
   └──────┬──────┘ └───┬───┘          │
          └─────────────┼─────────────┘
                        │
                 ┌──────▼──────┐
                 │  writeback  │  POST comment to Sentinel
                 └──────┬──────┘
                        │
              ══════ INTERRUPT ══════  (human review)
                        │
           ┌────────────┴────────────┐
    containment                 no containment
    approved?                        │
           │                         │
   ┌───────▼───────┐                 │
   │  containment   │  MDE isolate   │
   └───────┬───────┘                 │
           └────────────┬────────────┘
                        │
                ┌───────▼───────┐
                │ close_review  │  Sentinel close (if approved)
                └───────┬───────┘
                        │
                 ┌──────▼──────┐
                 │  learning   │  RAG correction loop
                 └──────┬──────┘
                        │
                    ┌───▼───┐
                    │  END  │
                    └───────┘
```

---

## Requirements

- Python 3.13+
- `uv` package manager
- Azure tenant with Microsoft Sentinel enabled
- Google AI Studio API key (Gemini)
- VirusTotal API key (free tier)
- AbuseIPDB API key (free tier)

---

## Setup

```bash
git clone https://github.com/eabboa/sentinel-triage-agent
cd sentinel-triage-agent
uv sync
```

Create `.env` at the project root (see `.env.example`):

```dotenv
SUBSCRIPTION_ID=
RESOURCE_GROUP=rg-sentinel-lab
WORKSPACE_NAME=law-sentinel-lab
GOOGLE_API_KEY=
VT_API_KEY=
ABUSEIPDB_API_KEY=
```

### Azure prerequisites

1. Create a Resource Group and Log Analytics Workspace in the same region.
2. Enable Microsoft Sentinel on the workspace.

#### For local development:
- Install Azure CLI (`winget install Microsoft.AzureCLI` on Windows). **Restart the terminal** upon installing to ensure the environmental variables.
- Run `az login` to authenticate.
- Verify your active context immediately after the browser hands back the token:

`az account show --query "{subscriptionId:id, tenantId:tenantId, user:user.name}" -o table`
- If the outputted subscription ID does not perfectly match the SUBSCRIPTION_ID defined in your .env file, you must explicitly bind the CLI to the correct boundary:

`az account set --subscription <YOUR_SUBSCRIPTION_ID>`

#### For production:
- Assign a Managed Identity (User-Assigned or System-Assigned) to your application/service with `Microsoft Sentinel Contributor` role at the Resource Group scope (IAM → Add role assignment). Wait ~10 minutes for propagation.

---

## Run

```bash
# Verify authentication
uv run python -c "from sentinel_auth import get_auth_headers; print(get_auth_headers())"

# Test incident fetch
uv run python -c "from sentinel_api import list_incidents; print(list_incidents())"

# Run full pipeline
uv run python main.py
```

---

## Project Structure

```
sentinel-triage-agent/
├── nodes/
│   ├── __init__.py
│   ├── fetch_node.py         # GET incident + POST alerts from Sentinel REST API
│   ├── summarize_node.py     # Deterministic pre-processing (no LLM)
│   ├── extract_node.py       # Regex (IPs/hashes/URLs) + LLM (usernames/hostnames)
│   ├── enrich_node.py        # Async AbuseIPDB + VirusTotal lookups
│   ├── analyst_node.py       # LLM verdict: TruePositive / FalsePositive / BenignPositive
│   ├── kql_node.py           # Schema-gated KQL hunting query generation
│   ├── containment_node.py   # HITL-gated MDE device isolation
│   ├── writeback_node.py     # POST comment + close_review_node (HITL closure gate)
│   └── learning_node.py      # RAG correction loop using ChromaDB
├── sentinel_auth.py          # DefaultAzureCredential (Managed Identity / Azure CLI)
├── sentinel_api.py           # Sentinel + MDE + Graph REST API wrapper
├── state.py                  # LangGraph TypedDict state schema (TriageState)
├── graph.py                  # StateGraph assembly with conditional routing
├── throttle.py               # Sliding-window async rate limiter for Gemini
├── main.py                   # Entry point (async batch processing with HITL prompts)
├── test_model.py             # Smoke test for Gemini connectivity
├── .env.example              # Template environment variables
├── pyproject.toml            # uv/pip project metadata and dependencies
└── .env                      # (gitignored) secrets
```

---

## Pipeline Nodes

### fetch_node
Retrieves the full incident object and associated alerts from the Sentinel REST API. Alert fetch failure is non-fatal, the pipeline proceeds with incident-level metadata.

### summarize_node
Deterministic (no LLM). Truncates descriptions and alert payloads to a condensed, token-efficient format before sending to the analyst LLM.

### extract_node
**Hybrid extraction.** Regex captures IPs, SHA-256/MD5 hashes, and URLs. A secondary LLM call (`gemini-1.5-flash`) extracts contextual entities, usernames, hostnames, and domains that regex cannot reliably parse.

### enrich_node
Concurrent CTI lookups via `aiohttp`:
- **AbuseIPDB** — IP reputation scores (abuse confidence, ISP, geolocation).
- **VirusTotal** — URL and file hash analysis stats. VT calls are serialized with a 15-second sleep to respect the free-tier rate limit.

All external calls use `tenacity` retries with exponential backoff on transient HTTP errors (429, 503, 504).

### analyst_node
The reasoning core. Sends the condensed summary, CTI results, and MITRE ATT&CK tactics to `gemini-2.5-flash` via `with_structured_output(AnalystVerdict)`. The Pydantic schema enforces deterministic JSON: `classification`, `is_true_positive`, `triage_summary`, `mitre_analysis`, `confidence` (0–100), and `recommended_action`.

**RAG few-shot injection:** Before each invocation, the node queries ChromaDB for historical analyst corrections similar to the current incident. Matched mismatches are injected into the prompt as few-shot examples, steering the model away from previously observed mistakes.

### kql_node
Generates 3 schema-validated KQL hunting queries using `gemini-2.5-flash-lite`. The prompt includes an explicit table schema map (SecurityAlert, SigninLogs, AuditLogs, SecurityEvent, OfficeActivity) with approved column names. Tables are filtered by detected MITRE ATT&CK tactics before prompt construction. Skipped entirely for FalsePositive classifications.

### writeback_node
Posts a formatted triage report to the Sentinel incident as a comment. Includes verdict, MITRE analysis, extracted entities, CTI enrichment, and KQL queries. **Does not close the incident**, closure is deferred to `close_review_node`.

### close_review_node
Executes the Sentinel close action **only after human approval**. The graph pauses after `writeback` (`interrupt_after=["writeback"]`) so an analyst can review the verdict, optionally approve containment, and then approve or deny closure.

### containment_node
HITL-gated. If `containment_approved` is set during the human review, isolates compromised devices via the Microsoft Defender for Endpoint machine isolation API. All API failures are captured as non-fatal errors.

### learning_node
Compares the LLM's classification against the human-provided classification. If they diverge, the mismatch (condensed summary + triage summary + human correction) is embedded via `all-MiniLM-L6-v2` and stored in ChromaDB. These records are later retrieved as few-shot examples by `analyst_node` to iteratively improve classification accuracy.

---

## Rate Limiting & Retry Strategy (This is only for testing environment, production will have API Keys)

### Gemini (LLM)
- **Sliding-window rate limiter** (`throttle.py`): Caps requests to 14 RPM, slightly under the Gemini free-tier limit of 15 RPM.
- **Batch sizing**: `main.py` fetches at most 5 incidents per run (5 incidents × ~3 LLM calls = 15 calls).
- **Concurrency**: `asyncio.Semaphore(3)` limits parallel incident processing.
- **Per-node retry**: Each LLM node wraps its invocation with `tenacity` (exponential backoff 5–60s + random jitter, 5 attempts) on `429 RESOURCE_EXHAUSTED` and `503 UNAVAILABLE`.
- **Internal retries disabled**: `max_retries=0` on all `ChatGoogleGenerativeAI` instances to prevent double-retry loops (tenacity manages all backoff).

### Azure Sentinel REST
- Shared HTTP wrapper (`sentinel_api._http_request`) with `timeout=10` and `tenacity` retries (3 attempts, exponential 1–10s) on transient failures (429, 503, 504).

### CTI (VirusTotal / AbuseIPDB)
- `aiohttp` with `ClientTimeout(total=10)` and `tenacity` retries (3 attempts) on `ClientError`, `TimeoutError`, and transient HTTP codes.
- VirusTotal calls are serialized with a 15-second inter-request sleep.

---

## Common Errors

| Error | Cause | Fix |
|---|---|---|
| `403 Forbidden` | RBAC not propagated yet | Wait 10 minutes |
| `incident_title` returns `"ERROR"` | `tactics` is a string list, not a dict list | Use `.get("tactics", [])` directly, not `label["labelName"]` |
| `405 Method Not Allowed` on alerts | Sentinel alerts endpoint requires POST, not GET | Use `requests.post()` |
| `TypeError: Invalid variable type: got True` | `aiohttp` rejects Python booleans in query params | Use `"true"` string instead of `True` |
| `ModuleNotFoundError` | Running system Python instead of venv | Prefix with `uv run` or activate `.venv\Scripts\activate` |
| `400 Bad Request` on incident close | Sentinel requires full PUT, not PATCH | Fetch the full incident object first, modify, then PUT |
| `429 RESOURCE_EXHAUSTED` | Gemini free-tier quota exceeded | Reduce `max_results` or increase `throttle.py` period |
| `412 Precondition Failed` | ETag mismatch — concurrent modification | Retry; the pipeline raises `ConcurrencyConflictError` |

---

## Enterprise Architecture Resilience & FMEA

This prototype includes hardened design decisions that reflect real-world SOC engineering requirements.

### 1. Human-in-the-loop (HITL) interrupt for incident closure
- A dedicated `close_review` node was added to the LangGraph pipeline.
- The graph now pauses before executing the Sentinel close action, using `interrupt_after=["writeback"]`.
- This prevents autonomous closure of any incident. All incidents are strictly routed for human review.
- A human analyst must approve closure by explicitly setting `close_approved` in the graph state before the incident is updated.
- The comment posted to Sentinel includes a visible review flag: **Pending Analyst Review**.

### 2. Exponential backoff and retry for transient API failures
- All Azure Sentinel REST calls now use a shared HTTP wrapper with explicit `timeout=10` seconds.
- `requests` calls are retried via `tenacity` on transient failures, including `429` rate-limit responses and `503/504` errors.
- This protects the prototype from bursty cloud throttling and intermittent service disruptions.
- CTI enrichment calls to third-party services (VirusTotal and AbuseIPDB) are also wrapped with `aiohttp` timeouts and `tenacity` retries.
- Failures after exhausted retries are logged explicitly and returned as structured error objects instead of crashing the graph.

### 3. Optimistic concurrency control
- Incident updates use Azure ETag validation (`If-Match` headers) to prevent silent overwrites when multiple SOC analysts or automation rules modify the same incident concurrently.
- A `ConcurrencyConflictError` is raised on `412 Precondition Failed` responses, enabling callers to implement retry-and-refresh logic.

### 4. Secretless authentication
- No static secrets or MSAL client credentials. All authentication flows through `azure-identity`'s `DefaultAzureCredential`, supporting Managed Identity (production) and Azure CLI (development) transparently.
- Tokens are cached module-level with 5-minute expiry buffer to avoid unnecessary round-trip latency.

### Why this matters for production SOCs
- SOC automation must fail safely: false positives should not trigger irreversible actions without human review.
- Cloud APIs often throttle high-volume tools, so retry/backoff patterns are essential to remain resilient and avoid cascading failures.
- Explicit timeout and retry handling ensures the system remains responsive rather than hanging indefinitely on external dependencies.
- These changes align the prototype with enterprise-grade incident handling expectations rather than a purely exploratory proof-of-concept.

---

## Changelog

### [v0.5.0] - 2026-04-29 (Rate Limiting & Stability)

**Note:** This is only for testing environment, production will have API Keys. The code is written in such a way that it can be easily adapted for production environment by replacing the API Keys with actual API Keys.

**Async rate limiter:** Added `throttle.py` with a sliding-window `APIRateLimiter` capping Gemini calls to 14 RPM. All LLM nodes (`analyst_node`, `extract_node`, `kql_node`) acquire the limiter before each invocation. 

**Per-node tenacity retries:** Each LLM node now wraps its invocation with `tenacity` (exponential backoff 5–60s + random jitter, 5 attempts) targeting `429 RESOURCE_EXHAUSTED` and `503 UNAVAILABLE` errors. Internal `max_retries=0` on `ChatGoogleGenerativeAI` prevents double-retry loops. 

### [v0.4.0] - 2026-04-29 (Security & Workflow Standardization)

**Mandatory Human-in-the-Loop Routing:** Removed the autonomous "FalsePositive" closure shortcut. All incidents, regardless of confidence score or classification, are now strictly routed through the `close_review` node to enforce a mandatory human review process.

**LangGraph State Persistence & Interruption:** Integrated LangGraph's human-in-the-loop interruption pattern in the main execution loop. Generated unique `thread_id` values per incident and configured `graph.ainvoke()` for state persistence, enabling the pipeline to reliably pause at the `close_review` interrupt point and await user approval before resuming execution.

**Security & Stability Hardening:** Resolved critical bugs including event loop crashes in asynchronous nodes and console deadlocks. Corrected authentication logic and prevented potential prompt-injection DoS attacks by enforcing secure HITL controls throughout the triage pipeline.

### [v0.3.0] - 2026-04-28

**Active Containment Execution (containment_node):** Introduced automated and HITL-gated remediation actions directly into the pipeline, enabling dynamic isolation of compromised entities (e.g., host isolation, IP blocking) via Azure APIs.

**RAG-Based Correction Loop (learning_node):** Implemented a Retrieval-Augmented Generation feedback mechanism. The agent now stores and retrieves historical analyst corrections to iteratively refine KQL query generation and incident classification accuracy.

**Conditional Graph Routing:** Upgraded the LangGraph pipeline with dynamic routing logic. The state machine now evaluates incident context mid-flight to conditionally bypass irrelevant nodes, dramatically reducing token consumption and execution latency.


### [v0.2.0] - 2026-04-28 (Enterprise Resilience Update)

This release shifts the pipeline from a functional prototype to a fault-tolerant architecture by addressing concurrency, identity, and deterministic execution risks.

#### Architecture & Concurrency
- **Optimistic Concurrency Control:** Implemented Azure ETag validation (`If-Match` headers) for incident `PUT` requests. This prevents race conditions and silent data overwrites when multiple SOC analysts or automation rules interact with the same incident simultaneously.
- **Asynchronous Orchestration:** Replaced synchronous polling loops with `asyncio.gather` and `asyncio.Semaphore` in the main pipeline. This allows concurrent incident processing while mathematically guaranteeing we do not exceed external API rate limits.

#### Identity & Determinism
- **Secretless Authentication:** Deprecated static MSAL client secrets in favor of `azure-identity` (`DefaultAzureCredential`). This eliminates hardcoded credentials and enforces identity-based access control via Azure Managed Identities.
- **Strict Schema Enforcement:** Replaced brittle JSON string parsing with LangChain's `with_structured_output` and Pydantic (`AnalystVerdict`), guaranteeing deterministic state transitions from the LLM. 
- **Fail-Safe CTI Scoring:** Refactored the confidence algorithm to treat timed-out or unreachable external threat intelligence as a neutral baseline. This prevents transient third-party API failures from artificially downgrading incident severity.
