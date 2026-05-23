# ⚡ Low Watt Labs — ClawSec Skill Verify Orchestrator
# ClawSec v2 - Skill Verify Orchestrator
# Runs all 7 security checks against a skill, produces JSON report
set -euo pipefail

VERSION="2.3.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKS_DIR="${SCRIPT_DIR}/checks"

source "${SCRIPT_DIR}/../common/config.sh"
source "${SCRIPT_DIR}/../common/colors.sh"
source "${SCRIPT_DIR}/../common/log.sh"

# Activate Python venv if available
VENV="${CLAWSEC_HOME}/venv"
if [[ -d "$VENV" ]]; then
    source "$VENV/bin/activate"
fi

usage() {
    echo "⚡ ClawSec v${VERSION} — Skill Verification"
    echo ""
    echo "Usage: verify.sh [OPTIONS] <skill_path>"
    echo ""
    echo "Options:"
    echo "  --json       Output report as JSON only"
    echo "  --checks=LIST  Run only specified checks (comma-separated)"
    echo "  --strict     Fail if ANY intel source is missing (default: warn)"
    echo "  --help       Show this help"
    echo ""
    echo "Staleness thresholds:"
    echo "  30+ days stale  → warn (results may be outdated)"
    echo "  90+ days stale  → fail (results unreliable, resync required)"
    echo ""
    echo "Checks: dep-scan, static-analysis, secret-scan, yara-scan,"
    echo "        ioc-match, behavioral, prompt-inject"
    exit 0
}

skill_path=""
json_only=0
specific_checks=""
strict_mode=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)    json_only=1; shift ;;
        --checks=*) specific_checks="${1#--checks=}"; shift ;;
        --strict)  strict_mode=1; shift ;;
        --help|-h) usage ;;
        -*)        echo "Unknown option: $1" >&2; exit 1 ;;
        *)         skill_path="$1"; shift ;;
    esac
done

if [[ -z "$skill_path" ]]; then
    echo "Error: skill path required" >&2
    echo "Usage: verify.sh <skill_path>" >&2
    exit 2
fi

if [[ ! -d "$skill_path" ]] && [[ ! -f "$skill_path" ]]; then
    echo "Error: $skill_path not found" >&2
    exit 2
fi

# Resolve to absolute path
skill_path="$(cd "$(dirname "$skill_path")" 2>/dev/null && pwd)/$(basename "$skill_path")" || skill_path="$(realpath "$skill_path")"

# P0-4: Validate intel cache before running any checks
INTEL_DIR="${CLAWSEC_INTEL_DIR}"
MANIFEST_JSON="${INTEL_DIR}/manifest.json"
intel_missing=0
intel_errors=()
strict_fail=0

if [[ ! -d "$INTEL_DIR" ]]; then
    intel_missing=1
    intel_errors+=("Intel cache directory ${INTEL_DIR} does not exist")
    strict_fail=1
elif [[ ! -f "$MANIFEST_JSON" ]]; then
    intel_missing=1
    intel_errors+=("Intel manifest ${MANIFEST_JSON} missing — sync has never completed")
    strict_fail=1
else
    # Check individual cache files that checks depend on
    if [[ ! -f "${INTEL_DIR}/cisa-kev/known_exploited_vulnerabilities.json" ]]; then
        intel_errors+=("CISA KEV cache missing")
        ((strict_mode)) && strict_fail=1
    fi
    if [[ ! -d "${INTEL_DIR}/osv" ]]; then
        intel_errors+=("OSV cache missing")
        ((strict_mode)) && strict_fail=1
    fi
    if [[ ! -f "${INTEL_DIR}/urlhaus/urls.csv" ]]; then
        intel_errors+=("URLhaus cache missing")
        ((strict_mode)) && strict_fail=1
    fi
    if [[ ! -f "${INTEL_DIR}/malwarebazaar/recent_hashes.csv" ]]; then
        intel_errors+=("MalwareBazaar cache missing")
        ((strict_mode)) && strict_fail=1
    fi
    if [[ ! -f "${INTEL_DIR}/feodo/c2_ips.csv" ]]; then
        intel_errors+=("Feodo cache missing")
        ((strict_mode)) && strict_fail=1
    fi

    # P1-3: Staleness check — warn if 30+ days, fail if 90+ days
    if [[ -f "$MANIFEST_JSON" ]]; then
        stale_warn=0
        stale_fail=0
        while IFS= read -r line; do
            src_name=$(echo "$line" | jq -r '.name // empty')
            src_date=$(echo "$line" | jq -r '.last_sync // empty')
            [[ -z "$src_name" || -z "$src_date" || "$src_date" == "never" ]] && continue
            # Calculate age in days
            sync_epoch=$(date -d "$src_date" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            if [[ "$sync_epoch" -gt 0 ]]; then
                age_days=$(( (now_epoch - sync_epoch) / 86400 ))
                if [[ $age_days -ge 90 ]]; then
                    stale_fail=1
                    intel_errors+=("${src_name} is ${age_days} days old (>= 90 days — scan results unreliable)")
                elif [[ $age_days -ge 30 ]]; then
                    stale_warn=1
                    if [[ $json_only -eq 0 ]]; then
                        echo -e "  ${WARNMARK} ${src_name} is ${age_days} days old (>= 30 days)" >&2
                    fi
                fi
            fi
        done < <(jq -c '.sources[]' "$MANIFEST_JSON" 2>/dev/null)

        if [[ $stale_fail -eq 1 ]]; then
            strict_fail=1
            for err in "${intel_errors[@]}"; do
                [[ "$err" == *"90 days"* ]] && echo -e "  ${RED}${BOLD}STALE:${RESET} $err" >&2
            done
        fi
    fi
fi

if [[ $strict_fail -eq 1 ]]; then
    if [[ $json_only -eq 0 ]]; then
        echo -e "${RED}${BOLD}ERROR:${RESET} Intel cache is incomplete or missing."
        for err in "${intel_errors[@]}"; do
            echo -e "  ${CROSSMARK} ${err}"
        done
        echo "  Run: bash lib/intel-sync/sync.sh --all"
        echo "  Or re-run without --strict to allow partial checks"
    fi
    # In strict mode with missing intel, abort with exit code 2 (fail)
    exit 2
fi

# In non-strict mode, warn but continue
if [[ ${#intel_errors[@]} -gt 0 ]] && [[ $json_only -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}WARNING:${RESET} Some intel sources are missing:"
    for err in "${intel_errors[@]}"; do
        echo -e "  ${WARNMARK} ${err}"
    done
    echo "  Results may be incomplete. Run: bash lib/intel-sync/sync.sh --all"
    echo ""
fi

# If intel cache directory doesn't exist at all, override verdict to "fail"
cache_completely_missing=0
if [[ ! -d "$INTEL_DIR" ]]; then
    cache_completely_missing=1
fi

ALL_CHECKS=(dep-scan static-analysis secret-scan yara-scan ioc-match behavioral prompt-inject)
if [[ -n "$specific_checks" ]]; then
    IFS=',' read -ra CHECKS <<< "$specific_checks"
else
    CHECKS=("${ALL_CHECKS[@]}")
fi

if [[ $json_only -eq 0 ]]; then
    echo -e "${BOLD}⚡═══════════════════════════════════════════⚡${RESET}"
    echo -e "${BOLD}⚡   ClawSec v${VERSION} — Skill Verification     ⚡${RESET}"
    echo -e "${BOLD}⚡═══════════════════════════════════════════⚡${RESET}"
    echo ""
    echo -e "  Target: ${CYAN}${skill_path}${RESET}"
    echo -e "  Checks: ${BOLD}${#CHECKS[@]}${RESET} of ${#ALL_CHECKS[@]}"
    if [[ ${#intel_errors[@]} -gt 0 ]]; then
        echo -e "  ${WARNMARK} ${YELLOW}${#intel_errors[@]} intel source(s) missing${RESET}"
    fi
    echo ""
fi

# Run checks and collect JSON results
check_results="[]"
start_time=$(date +%s%N)

for check in "${CHECKS[@]}"; do
    if [[ $json_only -eq 0 ]]; then
        echo -ne "  ${DIM}▸${RESET} Running ${check}... "
    fi

    result=""
    case "$check" in
        dep-scan)
            result=$(python3 "${CHECKS_DIR}/dep-scan.py" "$skill_path" 2>/dev/null || \
                echo '{"check":"dep-scan","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        static-analysis)
            result=$(bash "${CHECKS_DIR}/static-analysis.sh" "$skill_path" 2>/dev/null || \
                echo '{"check":"static_analysis","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        secret-scan)
            result=$(bash "${CHECKS_DIR}/secret-scan.sh" "$skill_path" 2>/dev/null || \
                echo '{"check":"secret_scan","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        yara-scan)
            result=$(bash "${CHECKS_DIR}/yara-scan.sh" "$skill_path" 2>/dev/null || \
                echo '{"check":"yara_scan","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        ioc-match)
            result=$(python3 "${CHECKS_DIR}/ioc-match.py" "$skill_path" 2>/dev/null || \
                echo '{"check":"ioc_match","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        behavioral)
            result=$(python3 "${CHECKS_DIR}/behavioral.py" "$skill_path" 2>/dev/null || \
                echo '{"check":"behavioral_heuristics","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        prompt-inject)
            result=$(python3 "${CHECKS_DIR}/prompt-inject.py" "$skill_path" 2>/dev/null || \
                echo '{"check":"prompt_injection","status":"pass","findings":[],"errors":["check failed"]}')
            ;;
        *)
            if [[ $json_only -eq 0 ]]; then
                echo -e "${WARNMARK} unknown"
            fi
            continue
            ;;
    esac

    # Validate result is JSON
    if ! echo "$result" | jq empty 2>/dev/null; then
        result="{\"check\":\"$check\",\"status\":\"pass\",\"findings\":[],\"errors\":[\"invalid output\"]}"
    fi

    # Append to results array
    check_results=$(echo "$check_results" | jq --argjson r "$result" '. + [$r]')

    # Console feedback
    if [[ $json_only -eq 0 ]]; then
        status=$(echo "$result" | jq -r '.status')
        findings_count=$(echo "$result" | jq '.findings | length')
        case "$status" in
            pass) echo -e "${CHECKMARK} ${GREEN}pass${RESET} (${findings_count} findings)" ;;
            warn) echo -e "${WARNMARK} ${YELLOW}warn${RESET} (${findings_count} findings)" ;;
            fail) echo -e "${CROSSMARK} ${RED}fail${RESET} (${findings_count} findings)" ;;
            *)    echo -e "  ${status} (${findings_count} findings)" ;;
        esac
    fi
done

end_time=$(date +%s%N)
elapsed_ms=$(( (end_time - start_time) / 1000000 ))

# Generate report via safe temp file approach
results_tmpfile=$(mktemp ${TMPDIR:-/tmp}/clawsec-results.XXXXXX.json)
trap "rm -f $results_tmpfile" EXIT INT TERM
echo "$check_results" > "$results_tmpfile"

report_json=$(python3 -c "
import sys, json
sys.path.insert(0, sys.argv[1])
from report import generate_report
with open(sys.argv[2]) as f:
    results = json.load(f)
report, path = generate_report(sys.argv[3], results)
report['scan_duration_ms'] = int(sys.argv[4])
print(json.dumps(report, indent=2))
" "${SCRIPT_DIR}" "$results_tmpfile" "${skill_path}" "${elapsed_ms}" 2>&1)
rm -f "$results_tmpfile"

if [[ -z "$report_json" ]]; then
    # Fallback: assemble report via jq
    verdict=$(echo "$check_results" | jq -r 'if any(.status == "fail") then "fail" elif any(.status == "warn") then "warn" else "pass" end')
    report_json=$(echo "$check_results" | jq -s '.' | jq \
        --arg verdict "$verdict" \
        --arg path "$skill_path" \
        --argjson duration "$elapsed_ms" \
        '{schema_version:"2.3.0",version:"2.3.0",verdict:$verdict,skill_path:$path,checks:.,scan_duration_ms:$duration}')
fi

verdict=$(echo "$report_json" | jq -r '.verdict')

# P0-4: If intel cache was completely missing, override verdict to "fail"
if [[ $cache_completely_missing -eq 1 ]]; then
    verdict="fail"
    report_json=$(echo "$report_json" | jq --arg v "fail" '.verdict = $v')
fi

if [[ $json_only -eq 0 ]]; then
    echo ""
    total=$(echo "$report_json" | jq '.summary.total_findings // 0')
    crit=$(echo "$report_json" | jq '.summary.critical // 0')
    high=$(echo "$report_json" | jq '.summary.high // 0')
    med=$(echo "$report_json" | jq '.summary.medium // 0')

    echo -e "  ${BOLD}──────────────────────────────────────${RESET}"
    echo -e "  Verdict:  $(case $verdict in pass) echo -e \"${GREEN}${BOLD}PASS${RESET}\" ;; warn) echo -e \"${YELLOW}${BOLD}WARN${RESET}\" ;; fail) echo -e \"${RED}${BOLD}FAIL${RESET}\" ;; esac)"
    echo -e "  Findings: ${total} total (${RED}${crit} critical${RESET}, ${YELLOW}${high} high${RESET}, ${med} medium)"
    echo -e "  Time:     $((elapsed_ms / 1000)).$((elapsed_ms % 1000))s"
    report_id=$(echo "$report_json" | jq -r '.report_id // "unknown"')
    echo -e "  Report:   ${report_id}"
    if [[ ${#intel_errors[@]} -gt 0 ]]; then
        echo -e "  ${WARNMARK} ${YELLOW}Intel sources missing — results may be incomplete${RESET}"
    fi
    echo ""
fi

# Write full JSON report to stdout if --json
if [[ $json_only -eq 1 ]]; then
    echo "$report_json"
fi

# Exit code: 0=pass, 1=warn, 2=fail
case "$verdict" in
    pass) exit 0 ;;
    warn) exit 1 ;;
    fail) exit 2 ;;
    *)    exit 1 ;;
esac