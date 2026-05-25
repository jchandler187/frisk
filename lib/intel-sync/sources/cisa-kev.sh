# ⚡ Low Watt Labs
# CISA KEV sync
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${FRISK_INTEL_DIR}"
TARGET="${INTEL_DIR}/cisa-kev/known_exploited_vulnerabilities.json"
URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing CISA KEV..."

if safe_download "$URL" "$TARGET" "jq empty"; then
    count=$(jq '.vulnerabilities | length' "$TARGET" 2>/dev/null || echo 0)
    python3 "$MANIFEST_PY" update cisa-kev "$count" success
    echo -e "${CHECKMARK} CISA KEV: ${count} vulnerabilities"
else
    python3 "$MANIFEST_PY" update cisa-kev 0 failed "download failed"
    echo -e "${CROSSMARK} CISA KEV: download failed (using stale cache)"
fi