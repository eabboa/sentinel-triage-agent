"""
Prometheus metrics definitions for the Sentinel Triage Agent.

All metrics are defined here so every module imports from one place.
Metrics are held in-memory by prometheus_client. To expose them,
start_http_server(port) serves /metrics for Prometheus to scrape.
"""

from prometheus_client import Counter, Histogram

# How long the full triage pipeline takes per incident (seconds).
TRIAGE_DURATION = Histogram(
    "triage_duration_seconds",
    "End-to-end triage duration per incident",
)

# How long each external CTI API call takes (milliseconds).
ENRICHMENT_LATENCY = Histogram(
    "enrichment_api_latency_ms",
    "Latency of individual CTI API calls",
    ["api_name"],  # "virustotal_url", "virustotal_hash", "abuseipdb"
)

# Total LLM response tokens consumed (cumulative counter).
LLM_RESPONSE_TOKENS = Counter(
    "llm_response_tokens_total",
    "Total LLM response tokens consumed",
)

# Counters for false-positive rate calculation:
#   false_positive_rate = TRIAGE_FP_TOTAL / TRIAGE_TOTAL
TRIAGE_TOTAL = Counter(
    "triage_total",
    "Total incidents triaged with a human decision",
)
TRIAGE_FP_TOTAL = Counter(
    "triage_false_positives_total",
    "Incidents where human reclassified as FalsePositive",
)
