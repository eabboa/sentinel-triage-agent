# sentinel-triage-agent

LangGraph pipeline for autonomous Microsoft Sentinel incident triage.

**Lab write-up:** [Sentinel-Native Autonomous Triage Agent](https://github.com/eabboa/eabboa/blob/main/Home-Labs/Sentinel_Native_Autonomous_Triage_Agent.md)

---

## Requirements

- Python 3.11+
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

Create `.env` at the project root:

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
- Install Azure CLI (`winget install Microsoft.AzureCLI` on Windows).
- Run `az login` to authenticate.

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
│   ├── fetch_node.py        # GET incident + POST alerts from Sentinel REST API
│   ├── summarize_node.py    # Deterministic pre-processing (no LLM)
│   ├── extract_node.py      # Regex (IPs/hashes/URLs) + LLM (usernames/hostnames)
│   ├── enrich_node.py       # Async AbuseIPDB + VirusTotal lookups
│   ├── analyst_node.py      # LLM verdict: TruePositive / FalsePositive / BenignPositive
│   ├── kql_node.py          # Schema-gated KQL hunting query generation
│   └── writeback_node.py    # POST comment + optional incident close
├── sentinel_auth.py         # Azure Identity DefaultAzureCredential (Managed Identity / Azure CLI)
├── sentinel_api.py          # Sentinel REST API wrapper
├── state.py                 # LangGraph TypedDict state schema
├── graph.py                 # StateGraph assembly
├── main.py                  # Entry point
└── .env
```

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

## Enterprise Architecture Resilience & FMEA

This prototype includes hardened design decisions that reflect real-world SOC engineering requirements.

### 1. Human-in-the-loop (HITL) interrupt for incident closure
- A dedicated `close_review` node was added to the LangGraph pipeline.
- The graph now pauses before executing the Sentinel close action, using `interrupt_before=["close_review"]`.
- This prevents autonomous closure of incidents classified as `BenignPositive`.
- A human analyst must approve closure by explicitly setting `close_approved` in the graph state before the incident is updated.
- The comment posted to Sentinel includes a visible review flag: **Pending Analyst Review**.

### 2. Exponential backoff and retry for transient API failures
- All Azure Sentinel REST calls now use a shared HTTP wrapper with explicit `timeout=10` seconds.
- `requests` calls are retried via `tenacity` on transient failures, including `429` rate-limit responses and `503/504` errors.
- This protects the prototype from bursty cloud throttling and intermittent service disruptions.
- CTI enrichment calls to third-party services (VirusTotal and AbuseIPDB) are also wrapped with `aiohttp` timeouts and `tenacity` retries.
- Failures after exhausted retries are logged explicitly and returned as structured error objects instead of crashing the graph.

### Why this matters for production SOCs
- SOC automation must fail safely: false positives should not trigger irreversible actions without human review.
- Cloud APIs often throttle high-volume tools, so retry/backoff patterns are essential to remain resilient and avoid cascading failures.
- Explicit timeout and retry handling ensures the system remains responsive rather than hanging indefinitely on external dependencies.
- These changes align the prototype with enterprise-grade incident handling expectations rather than a purely exploratory proof-of-concept.


## [0.2.0] - 2026-04-28 (Enterprise Resilience Update)

This release shifts the pipeline from a functional prototype to a fault-tolerant architecture by addressing concurrency, identity, and deterministic execution risks.

### Architecture & Concurrency
- **Optimistic Concurrency Control:** Implemented Azure ETag validation (`If-Match` headers) for incident `PUT` requests. This prevents race conditions and silent data overwrites when multiple SOC analysts or automation rules interact with the same incident simultaneously.
- **Asynchronous Orchestration:** Replaced synchronous polling loops with `asyncio.gather` and `asyncio.Semaphore` in the main pipeline. This allows parallel incident processing while mathematically guaranteeing we do not exceed external API rate limits.

### Identity & Determinism
- **Secretless Authentication:** Deprecated static MSAL client secrets in favor of `azure-identity` (`DefaultAzureCredential`). This eliminates hardcoded credentials and enforces identity-based access control via Azure Managed Identities.
- **Strict Schema Enforcement:** Replaced brittle JSON string parsing with LangChain's `with_structured_output` and Pydantic (`AnalystVerdict`), guaranteeing deterministic state transitions from the LLM. 
- **Fail-Safe CTI Scoring:** Refactored the confidence algorithm to treat timed-out or unreachable external threat intelligence as a neutral baseline. This prevents transient third-party API failures from artificially downgrading incident severity.

## [v0.3.0] - 2026-04-28

**Active Containment Execution (containment_node):** Introduced automated and HITL-gated remediation actions directly into the pipeline, enabling dynamic isolation of compromised entities (e.g., host isolation, IP blocking) via Azure APIs.

**RAG-Based Correction Loop (learning_node):** Implemented a Retrieval-Augmented Generation feedback mechanism. The agent now stores and retrieves historical analyst corrections to iteratively refine KQL query generation and incident classification accuracy.

**Conditional Graph Routing:** Upgraded the LangGraph pipeline with dynamic routing logic. The state machine now evaluates incident context mid-flight to conditionally bypass irrelevant nodes, dramatically reducing token consumption and execution latency.
