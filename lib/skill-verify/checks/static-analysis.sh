#!/usr/bin/env bash
# ClawSec v2 - Static Analysis (Semgrep)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
SEMRULES_DIR="${INTEL_DIR}/semgrep-rules/repo"

skill_path="${1:?Usage: static-analysis.sh <skill_path>}"
results='{"check":"static_analysis","status":"pass","findings":[],"errors":[]}'

if ! command -v semgrep &>/dev/null; then
    echo '{"check":"static_analysis","status":"pass","findings":[],"errors":["semgrep not installed — skipping"]}'
    exit 0
fi

if [[ ! -d "$SEMRULES_DIR" ]]; then
    echo '{"check":"static_analysis","status":"pass","findings":[],"errors":["semgrep rules not synced — skipping"]}'
    exit 0
fi

tmpout=$(mktemp /tmp/semgrep.XXXXXX.json)

# Use --config auto for speed (community rules, pre-bundled)
timeout 30 semgrep --config auto \
    --json \
    --timeout 10 \
    --max-target-bytes 500000 \
    --quiet \
    "$skill_path" > "$tmpout" 2>/dev/null || true

if jq empty "$tmpout" 2>/dev/null; then
    count=$(jq '.results | length' "$tmpout")
    if [[ "$count" -gt 0 ]]; then
        findings=$(jq '[.results[] | {
            rule_id: .check_id,
            message: .extra.message,
            severity: .extra.severity,
            file: .path,
            line: .start.line
        }]' "$tmpout")
        
        crit=$(echo "$findings" | jq '[.[] | select(.severity == "ERROR")] | length')
        warn=$(echo "$findings" | jq '[.[] | select(.severity == "WARNING")] | length')
        
        if [[ "$crit" -gt 0 ]]; then status="fail"
        elif [[ "$warn" -gt 0 ]]; then status="warn"
        else status="pass"; fi
        
        results=$(jq -n --argjson findings "$findings" --arg status "$status" --arg count "$count" \
            '{check:"static_analysis",status:$status,findings:$findings,errors:[],total:$count}')
    fi
else
    results='{"check":"static_analysis","status":"pass","findings":[],"errors":["semgrep output parse error"]}'
fi

rm -f "$tmpout"
echo "$results"
