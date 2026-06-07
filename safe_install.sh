#!/usr/bin/env bash
set -euo pipefail
# safe_install.sh — Pre-install security gate for local and agentic workflows.
# Use this instead of raw "uv sync" or "pip install" in any auto-execution context.
#
# Pipeline: slopcheck (phantom packages) → uv sync --locked (hash verify) → pip-audit (CVEs)

echo "=== [1/3] Slopcheck: scanning for hallucinated/phantom packages ==="
uvx slopcheck scan . | tee .slopcheck.log || true
if grep -q "Package does not exist on PyPI" .slopcheck.log; then
    echo "❌ Slopcheck found hallucinated packages. Aborting."
    rm -f .slopcheck.log
    exit 1
fi
rm -f .slopcheck.log

echo "=== [2/3] Installing dependencies (locked) ==="
uv sync --dev --locked

echo "=== [3/3] pip-audit: scanning for known vulnerabilities ==="
uvx pip-audit --requirement <(uv export --format requirements-txt --no-emit-project)

echo "✅ All security gates passed"
