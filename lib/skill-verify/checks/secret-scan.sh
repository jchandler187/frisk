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

# P1: Supplement gitleaks with credential-pattern heuristic.
# Gitleaks skips well-known example keys (AKIAIOSFODNN7EXAMPLE, etc.),
# but those in a skill package are still suspicious — they indicate hardcoded
# credential patterns that could be swapped for real keys.
CREDS_REGEX='(
    AKIA[0-9A-Z]{16}|                         # AWS Access Key ID pattern
    [A-Za-z0-9+/]{40}=[\s\r\n]||            # AWS Secret Access Key (base64, 40 chars + =)
    (?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|  # GitHub PAT pattern
    (?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}|   # Stripe key pattern
    xox[bpas]-[A-Za-z0-9-]{10,}               # Slack token pattern
)'

cred_findings='[]'
while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    cred_findings=$(jq -n --arg m "$match" \
        '[{type:"credential_pattern",description:("Hardcoded credential pattern detected: " + $m),severity:"high",source:"credential_heuristic"}]')
done < <(grep -rPa ${CREDS_REGEX:?} "$skill_path" 2>/dev/null | head -20 | sed -E 's/.*:\s*//' || true)

if [[ "$cred_findings" != '[]' ]]; then
    existing=$(echo "$results" | jq '.findings // []')
    merged=$(jq -n --argjson a "$existing" --argjson b "$cred_findings" '$a + $b')
    results=$(echo "$results" | jq --argjson findings "$merged" '.findings = $findings | .status = "fail"')
fi

echo "$results"