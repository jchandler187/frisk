# ⚡ Low Watt Labs
# Feodo Tracker sync (abuse.ch)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
TARGET="${INTEL_DIR}/feodo/c2_ips.csv"
URL="https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing Feodo Tracker..."

tmp=$(mktemp "${TARGET}.XXXXXX.new")
if curl -fsSL --max-time 60 --retry 3 --retry-delay 5 "$URL" -o "$tmp"; then
    count=$(grep -cv '^#' "$tmp" 2>/dev/null || echo 0)
    mv -f "$tmp" "$TARGET"
    python3 "$MANIFEST_PY" update feodo "$count" success
    echo -e "${CHECKMARK} Feodo Tracker: ${count} C2 IPs"
else
    rm -f "$tmp"
    python3 "$MANIFEST_PY" update feodo 0 failed "download failed"
    echo -e "${CROSSMARK} Feodo Tracker: download failed"
fi