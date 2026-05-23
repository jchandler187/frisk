# ⚡ Low Watt Labs — ClawSec Intel Sync
# ClawSec v2 - Intel Sync Orchestrator
# Runs all intel source sync jobs, gracefully handling failures
set -euo pipefail

VERSION="2.5.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCES_DIR="${SCRIPT_DIR}/sources"

source "${SCRIPT_DIR}/../common/config.sh"
source "${SCRIPT_DIR}/../common/colors.sh"
source "${SCRIPT_DIR}/../common/log.sh"

usage() {
    echo "ClawSec v${VERSION} — Intel Sync"
    echo ""
    echo "Usage: sync.sh [OPTIONS] [SOURCE...]"
    echo ""
    echo "Options:"
    echo "  --all       Sync all sources (default)"
    echo "  --list      List available sources"
    echo "  --status    Show current cache status"
    echo "  --json      Output status as JSON"
    echo "  --help      Show this help"
    echo ""
    echo "Sources: cisa-kev, osv, epss, malwarebazaar, urlhaus,"
    echo "         threatfox, feodo, yara-rules, semgrep-rules"
    exit 0
}

ALL_SOURCES=(cisa-kev osv epss malwarebazaar urlhaus threatfox feodo yara-rules semgrep-rules)

# Ensure intel directories exist
INTEL_DIR="${CLAWSEC_INTEL_DIR}"
for src in "${ALL_SOURCES[@]}"; do
    mkdir -p "${INTEL_DIR}/${src}"
done
mkdir -p "${INTEL_DIR}/osv/npm" "${INTEL_DIR}/osv/PyPI"
mkdir -p "${CLAWSEC_REPORTS_DIR}" 
requested_sources=()
json_output=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)   shift ;;
        --list)  
            echo "Available intel sources:"
            for s in "${ALL_SOURCES[@]}"; do echo "  - $s"; done
            exit 0 ;;
        --status|--status-only)
            python3 "${SCRIPT_DIR}/manifest.py" status
            exit 0 ;;
        --json)
            json_output=1
            shift ;;
        --help|-h)
            usage ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1 ;;
        *)
            requested_sources+=("$1")
            shift ;;
    esac
done

# Default: all sources
[[ ${#requested_sources[@]} -eq 0 ]] && requested_sources=("${ALL_SOURCES[@]}")

echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║  ClawSec v${VERSION} — Intel Sync        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Syncing ${BOLD}${#requested_sources[@]}${RESET} source(s): ${CYAN}${requested_sources[*]}${RESET}"
echo ""

start_time=$(date +%s)
fail_count=0

for src in "${requested_sources[@]}"; do
    script="${SOURCES_DIR}/${src}.sh"
    if [[ -x "$script" ]]; then
        if ! "$script"; then
            fail_count=$((fail_count + 1))
        fi
    else
        echo -e "${WARNMARK} Unknown source: $src (no script at $script)"
        fail_count=$((fail_count + 1))
    fi
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo ""
if [[ $fail_count -eq 0 ]]; then
    echo -e "${CHECKMARK} Sync complete in ${elapsed}s — all sources fresh"
else
    echo -e "${WARNMARK} Sync complete in ${elapsed}s — ${fail_count} source(s) had issues (stale data preserved)"
fi

if [[ $json_output -eq 1 ]]; then
    python3 "${SCRIPT_DIR}/manifest.py" status
fi