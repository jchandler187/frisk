#!/usr/bin/env bash
# EPSS sync
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
TARGET="${INTEL_DIR}/epss/epss_scores-current.csv"
URL="https://epss.cyentia.com/epss_scores-current.csv.gz"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing EPSS..."

gz_tmp=$(mktemp "/tmp/epss.XXXXXX.csv.gz")
if curl -fsSL --max-time 120 --retry 3 --retry-delay 5 "$URL" -o "$gz_tmp"; then
    csv_tmp=$(mktemp "${TARGET}.XXXXXX.new")
    if gunzip -c "$gz_tmp" > "$csv_tmp"; then
        count=$(($(wc -l < "$csv_tmp") - 1))  # minus header
        mv -f "$csv_tmp" "$TARGET"
        python3 "$MANIFEST_PY" update epss "$count" success
        echo -e "${CHECKMARK} EPSS: ${count} CVE scores"
    else
        rm -f "$csv_tmp"
        python3 "$MANIFEST_PY" update epss 0 failed "gunzip failed"
        echo -e "${CROSSMARK} EPSS: decompression failed"
    fi
else
    python3 "$MANIFEST_PY" update epss 0 failed "download failed"
    echo -e "${CROSSMARK} EPSS: download failed"
fi
rm -f "$gz_tmp"