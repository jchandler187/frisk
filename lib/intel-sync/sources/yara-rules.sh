# ⚡ Low Watt Labs
# YARA rules sync (Neo23x0/signature-base)
set -euo pipefail

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${CLAWSEC_INTEL_DIR}"
REPO_DIR="${INTEL_DIR}/yara-rules/repo"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing YARA rules (Neo23x0/signature-base)..."

if [[ -d "$REPO_DIR/.git" ]]; then
    if git -C "$REPO_DIR" pull --quiet 2>/dev/null; then
        status="success"
    else
        status="failed"
    fi
else
    rm -rf "$REPO_DIR"
    if git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$REPO_DIR" 2>/dev/null; then
        status="success"
    else
        status="failed"
    fi
fi

if [[ "$status" == "success" ]]; then
    count=$(find "$REPO_DIR/yara" -name '*.yar' -o -name '*.yara' 2>/dev/null | wc -l)
    python3 "$MANIFEST_PY" update yara-rules "$count" success
    echo -e "${CHECKMARK} YARA rules: ${count} rule files"
else
    python3 "$MANIFEST_PY" update yara-rules 0 failed "git pull/clone failed"
    echo -e "${CROSSMARK} YARA rules: git sync failed"
fi