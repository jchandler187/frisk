# ⚡ Low Watt Labs — ClawSec
# ClawSec v2 - Secret Scan (Gitleaks)
set -euo pipefail

source "$(dirname "$0")/../../common/colors.sh"

skill_path="${1:?Usage: secret-scan.sh <skill_path>}"
results='{"check":"secret_scan","status":"pass","findings":[],"errors":[]}'

if ! command -v gitleaks &>/dev/null; then
    echo '{"check":"secret_scan","status":"warn","findings":[],"errors":["gitleaks not installed — results may be incomplete"]}'
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
# Each pattern runs separately to avoid bash multiline regex issues.

cred_findings='[]'
for pattern in 'AKIA[0-9A-Z]{16}' '(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{25,}' '(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}' 'xox[bpas]-[A-Za-z0-9-]{10,}'; do
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        new_finding=$(jq -n --arg m "$match" --arg p "$pattern" \
            '{"type":"credential_pattern","description":("Hardcoded credential pattern detected: " + $m),"severity":"high","source":"credential_heuristic","pattern":$p}')
        cred_findings=$(echo "$cred_findings" | jq --argjson n "$new_finding" '. + [$n]')
    done < <(grep -rPa "$pattern" "$skill_path" 2>/dev/null | sed -E 's/.*:\s*//' || true)
done

if [[ "$cred_findings" != '[]' ]]; then
    existing=$(echo "$results" | jq '.findings // []')
    merged=$(jq -n --argjson a "$existing" --argjson b "$cred_findings" '$a + $b')
    results=$(echo "$results" | jq --argjson findings "$merged" '.findings = $findings | .status = "fail"')
fi

echo "$results"