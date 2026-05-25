# ⚡ Low Watt Labs — Frisk
# Frisk v2 - YARA Scan
#
# SECURITY MANIFEST:
# Environment variables accessed: FRISK_HOME, FRISK_INTEL_DIR (via config.sh)
# External endpoints called: none
# Local files read: skill_path (target directory), YARA rules from intel cache
# Local files written: /tmp/yara-compiled.XXXXXX, /tmp/yara-combined.XXXXXX.yar, /tmp/yara-scan.XXXXXX (all temporary, deleted after scan)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"

INTEL_DIR="${FRISK_INTEL_DIR}"
YARA_RULES_DIR="${INTEL_DIR}/yara-rules/repo/yara"

skill_path="${1:?Usage: yara-scan.sh <skill_path>}"
results='{"check":"yara_scan","status":"pass","findings":[],"errors":[]}'

if ! command -v yara &>/dev/null; then
    echo '{"check":"yara_scan","status":"warn","findings":[],"errors":["yara not installed — skipping"]}'
    exit 0
fi

if [[ ! -d "$YARA_RULES_DIR" ]]; then
    echo '{"check":"yara_scan","status":"warn","findings":[],"errors":["YARA rules not synced — skipping"]}'
    exit 0
fi

# Test-compile and collect valid rule files
good_rules=()
while IFS= read -r -d '' f; do
    if yarac "$f" /dev/null 2>/dev/null; then
        good_rules+=("$f")
    fi
done < <(find "$YARA_RULES_DIR" -name '*.yar' -o -name '*.yara' 2>/dev/null | sort -z)

# If we have good rules, build a compiled ruleset and scan
if [[ ${#good_rules[@]} -gt 0 ]]; then
    compiled_rules=$(mktemp "${TMPDIR:-/tmp}/yara-compiled.XXXXXX")
    # Build combined rule file for yarac
    combined_rules=$(mktemp "${TMPDIR:-/tmp}/yara-combined.XXXXXX.yar")
    for rulefile in "${good_rules[@]}"; do
        echo "include \"${rulefile}\"" >> "$combined_rules"
    done
    if yarac "$combined_rules" "$compiled_rules" 2>/dev/null; then
        # Scan with compiled rules for performance
        tmpout=$(mktemp "${TMPDIR:-/tmp}/yara-scan.XXXXXX")
        yara -r -C "$compiled_rules" "$skill_path" >> "$tmpout" 2>/dev/null || true
    else
        # Fallback: scan with source rules individually
        tmpout=$(mktemp "${TMPDIR:-/tmp}/yara-scan.XXXXXX")
        for rulefile in "${good_rules[@]}"; do
            yara -r "$rulefile" "$skill_path" >> "$tmpout" 2>/dev/null || true
        done
    fi
    rm -f "$combined_rules"
    
    if [[ -s "$tmpout" ]]; then
        findings='[]'
        while IFS=$'\t' read -r rule file; do
            rel="${file#$skill_path/}"
            findings=$(echo "$findings" | jq --arg rule "$rule" --arg file "$rel" \
                '. + [{rule: $rule, file: $file, severity: "high"}]')
        done < "$tmpout"
        
        count=$(echo "$findings" | jq 'length')
        if [[ "$count" -gt 0 ]]; then
            results=$(jq -n --argjson findings "$findings" --arg count "$count" \
                '{check:"yara_scan",status:"fail",findings:$findings,errors:[],total:$count}')
        fi
    fi
    rm -f "$tmpout"
fi

if [[ -n "${compiled_rules:-}" ]]; then
    rm -f "$compiled_rules"
fi
echo "$results"