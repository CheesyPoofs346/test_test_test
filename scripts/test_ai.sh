#!/usr/bin/env bash
# Simple helper to test AI API connectivity (NVIDIA Integrate, Gemini, OpenRouter)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/openrouter.sh"

if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for this test"
    exit 1
fi

echo "Running AI connectivity test..."
if test_openrouter; then
    echo "AI connectivity OK"
    exit 0
else
    echo "AI connectivity failed"
    exit 2
fi
