# ⚡ Low Watt Labs
# ThreatFox sync (abuse.ch)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
TARGET="${INTEL_DIR}/threatfox/iocs.csv"
URL="https://threatfox.abuse.ch/export/csv/recent/"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing ThreatFox..."

tmp=$(mktemp "${TARGET}.XXXXXX.new")
if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 "$URL" -o "$tmp"; then
    # Validate CSV content (not HTML error page or garbage)
    if ! validate_csv "$tmp" '^#'; then
        rm -f "$tmp"
        python3 "$MANIFEST_PY" update threatfox 0 failed "CSV validation failed (not valid CSV)"
        echo -e "${CROSSMARK} ThreatFox: CSV validation failed"
    else
        # Count actual data lines (skip comment lines starting with #)
        count=$(grep -cv '^#' "$tmp" 2>/dev/null || echo 0)
        mv -f "$tmp" "$TARGET"
        python3 "$MANIFEST_PY" update threatfox "$count" success
        echo -e "${CHECKMARK} ThreatFox: ${count} IOCs"
    fi
else
    rm -f "$tmp"
    python3 "$MANIFEST_PY" update threatfox 0 failed "download failed"
    echo -e "${CROSSMARK} ThreatFox: download failed"
fi