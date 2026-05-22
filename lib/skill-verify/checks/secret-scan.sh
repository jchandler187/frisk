#!/usr/bin/env bash
# ClawSec v2 - Secret Scan (Gitleaks)
set -euo pipefail

source "$(dirname "$0")/../../common/colors.sh"

skill_path="${1:?Usage: secret-scan.sh <skill_path>}"
results='{"check":"secret_scan","status":"pass","findings":[],"errors":[]}'

if ! command -v gitleaks &>/dev/null; then
    echo '{"check":"secret_scan","status":"pass","findings":[],"errors":["gitleaks not installed — skipping"],"note":"skipped: gitleaks unavailable"}'
    exit 0
fi

# Run gitleaks on the skill directory
tmpout=$(mktemp /tmp/gitleaks.XXXXXX.json)

# gitleaks detect with no-git flag for untracked dirs
gitleaks detect --source "$skill_path" --no-git --report-format json --report-path "$tmpout" 2>/dev/null || true

if [[ -s "$tmpout" ]] && jq empty "$tmpout" 2>/dev/null; then
    count=$(jq 'length' "$tmpout")
    if [[ "$count" -gt 0 ]]; then
        findings=$(jq '[.[] | {
            rule: .RuleID,
            description: .Description,
            file: .File,
            line: .StartLine,
            match: .Match,
            severity: "high"
        }]' "$tmpout")
        results=$(jq -n --argjson findings "$findings" --arg count "$count" \
            '{check:"secret_scan",status:"fail",findings:$findings,errors:[],total:$count}')
    fi
fi

rm -f "$tmpout"
echo "$results"