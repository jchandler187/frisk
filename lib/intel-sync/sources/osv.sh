#!/usr/bin/env bash
# OSV sync - npm and PyPI ecosystems
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
OSV_DIR="${INTEL_DIR}/osv"
MANIFEST_PY="$(dirname "$0")/../manifest.py"
URL_BASE="https://osv-vulnerabilities.storage.googleapis.com"

ECOSYSTEMS=("npm" "PyPI")
total=0
any_fail=0

for eco in "${ECOSYSTEMS[@]}"; do
    log_info "Syncing OSV $eco..."
    eco_dir="${OSV_DIR}/${eco}"
    mkdir -p "$eco_dir"

    zip_url="${URL_BASE}/${eco}/all.zip"
    zip_tmp=$(mktemp "/tmp/osv-${eco}.XXXXXX.zip")

    if curl -fsSL --max-time 300 --retry 3 --retry-delay 5 "$zip_url" -o "$zip_tmp"; then
        extract_tmp=$(mktemp -d "/tmp/osv-${eco}-extract.XXXXXX")
        if unzip -q -o "$zip_tmp" -d "$extract_tmp" 2>/dev/null; then
            find "$eco_dir" -maxdepth 1 -name '*.json' -delete 2>/dev/null || true
            find "$extract_tmp" -maxdepth 1 -name '*.json' -exec mv -t "$eco_dir" {} +
            count=$(find "$eco_dir" -maxdepth 1 -name '*.json' | wc -l)
            total=$((total + count))
            log_info "OSV $eco: $count advisories"
        else
            any_fail=1
            log_warn "OSV $eco: extraction failed"
        fi
        rm -rf "$extract_tmp"
    else
        any_fail=1
        log_warn "OSV $eco: download failed"
    fi
    rm -f "$zip_tmp"
done

status="success"
[[ $any_fail -eq 1 ]] && status="partial"
python3 "$MANIFEST_PY" update osv "$total" "$status"
if [[ $any_fail -eq 0 ]]; then
    echo -e "${CHECKMARK} OSV: ${total} advisories (npm + PyPI)"
else
    echo -e "${WARNMARK} OSV: partial sync — ${total} advisories"
fi
