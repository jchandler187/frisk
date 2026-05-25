# ⚡ Low Watt Labs — Frisk
# Frisk v2 - Static Analysis (Semgrep)
#
# SECURITY MANIFEST:
# Environment variables accessed: FRISK_HOME, FRISK_INTEL_DIR (via config.sh)
# External endpoints called: none
# Local files read: skill_path (target directory), semgrep rules from intel cache
# Local files written: /tmp/semgrep.XXXXXX.json (temporary, deleted after scan)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"

INTEL_DIR="${FRISK_INTEL_DIR}"
SEMRULES_DIR="${INTEL_DIR}/semgrep-rules/repo"

skill_path="${1:?Usage: static-analysis.sh <skill_path>}"
results='{"check":"static_analysis","status":"pass","findings":[],"errors":[]}'

if ! command -v semgrep &>/dev/null; then
    echo '{"check":"static_analysis","status":"warn","findings":[],"errors":["semgrep not installed — results may be incomplete"]}'
    exit 0
fi

if [[ ! -d "$SEMRULES_DIR" ]]; then
    echo '{"check":"static_analysis","status":"warn","findings":[],"errors":["semgrep rules not synced — results may be incomplete"]}'
    exit 0
fi

tmpout=$(mktemp "${TMPDIR:-/tmp}/semgrep.XXXXXX.json")

# Use local semgrep rules from intel cache (no phone-home)
semgrep_rc=0
timeout 30 semgrep --config "$SEMRULES_DIR" --metrics=off \
    --json \
    --timeout 10 \
    --max-target-bytes 500000 \
    --quiet \
    "$skill_path" > "$tmpout" 2>/dev/null || semgrep_rc=$?

# Handle semgrep crash or timeout
if [[ "$semgrep_rc" -eq 124 ]]; then
    results='{"check":"static_analysis","status":"warn","findings":[],"errors":["semgrep timed out — results may be incomplete"]}'
    rm -f "$tmpout"
    echo "$results"
    exit 0
elif [[ "$semgrep_rc" -ne 0 ]] && [[ ! -s "$tmpout" ]]; then
    results='{"check":"static_analysis","status":"warn","findings":[],"errors":["semgrep crashed (exit '$semgrep_rc') — results may be incomplete"]}'
    rm -f "$tmpout"
    echo "$results"
    exit 0
fi

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
        
        # Escalate injection/traversal/secret findings to critical
        results=$(echo "$results" | jq --argjson findings "$findings" '.findings = $findings')
        results=$(echo "$results" | jq '
            .findings = [.findings[] |
                if .rule_id | test("command.injection|shell.injection|os.system|path.traversal|hardcoded.secret|secret.in.code|insecure-exec") then
                    .severity = "ERROR"
                elif .rule_id | test("sql.injection|xss|csrf|cors") then
                    .severity = "WARNING"
                else . end
            ]
        ')
        
        # Map Semgrep severity to Frisk scale: ERROR→high, WARNING→medium, INFO→low
        results=$(echo "$results" | jq '
            .findings = [.findings[] |
                if .severity == "ERROR" then .severity = "high"
                elif .severity == "WARNING" then .severity = "medium"
                elif .severity == "INFO" then .severity = "low"
                else . end
            ]
        ]')

        # Recount by Frisk severity
        crit=$(echo "$results" | jq '[.findings[] | select(.severity == "high" or .severity == "critical")] | length')
        warn=$(echo "$results" | jq '[.findings[] | select(.severity == "medium")] | length')
        info=$(echo "$results" | jq '[.findings[] | select(.severity == "low")] | length')
        
        if [[ "$crit" -gt 0 ]]; then status="fail"
        elif [[ "$warn" -gt 0 ]]; then status="warn"
        else status="pass"; fi
        
        results=$(echo "$results" | jq --arg status "$status" --arg count "$count" \
            '{check:"static_analysis",status:$status,findings:.findings,errors:[],total:$count}')
    fi
else
    results='{"check":"static_analysis","status":"warn","findings":[],"errors":["semgrep output parse error — results may be incomplete"]}'
fi

rm -f "$tmpout"
echo "$results"