# ⚡ Low Watt Labs
set -euo pipefail
source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
TARGET="${INTEL_DIR}/urlhaus/urls.csv"
URL="https://urlhaus.abuse.ch/downloads/csv/"
MANIFEST_PY="$(dirname "$0")/../manifest.py"
# The URLhaus ZIP contains a file named "csv.txt" — we extract it
# to a stable path so ioc-match.py always knows where to find it.
URLHAUS_INNER_FILE="csv.txt"

log_info "Syncing URLhaus..."
mkdir -p "${INTEL_DIR}/urlhaus"
zip_tmp=$(mktemp "/tmp/urlhaus.XXXXXX.zip")
if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 "$URL" -o "$zip_tmp"; then
    csv_tmp=$(mktemp "${TARGET}.XXXXXX.new")
    if unzip -p "$zip_tmp" "$URLHAUS_INNER_FILE" > "$csv_tmp" 2>/dev/null; then
        count=$(($(wc -l < "$csv_tmp") - 1))  # minus header
        mv -f "$csv_tmp" "$TARGET"
        python3 "$MANIFEST_PY" update urlhaus "$count" success
        echo -e "${CHECKMARK} URLhaus: ${count} malicious URLs"
    else
        rm -f "$csv_tmp"
        python3 "$MANIFEST_PY" update urlhaus 0 failed "unzip failed"
        echo -e "${CROSSMARK} URLhaus: decompression failed"
    fi
else
    python3 "$MANIFEST_PY" update urlhaus 0 failed "download failed"
    echo -e "${CROSSMARK} URLhaus: download failed"
fi
rm -f "$zip_tmp"
