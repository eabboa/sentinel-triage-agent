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
TENANT_ID=
CLIENT_ID=
CLIENT_SECRET=
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
3. Register an app in Microsoft Entra ID → copy `CLIENT_ID` and `TENANT_ID`.
4. Generate a client secret → copy the value as `CLIENT_SECRET`.
5. Assign `Microsoft Sentinel Contributor` to the app at the Resource Group scope (IAM → Add role assignment). Wait ~10 minutes for propagation.

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
├── sentinel_auth.py         # OAuth2 Client Credentials via MSAL
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