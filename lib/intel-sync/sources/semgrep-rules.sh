# ⚡ Low Watt Labs
set -euo pipefail
source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${FRISK_INTEL_DIR}"
REPO_DIR="${INTEL_DIR}/semgrep-rules/repo"
MANIFEST_PY="$(dirname "$0")/../manifest.py"

log_info "Syncing Semgrep rules (semgrep/semgrep-rules)..."

if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" pull --quiet 2>/dev/null && status="success" || status="failed"
else
    rm -rf "$REPO_DIR"
    git clone --depth 1 https://github.com/semgrep/semgrep-rules.git "$REPO_DIR" 2>/dev/null && status="success" || status="failed"
fi

if [[ "$status" == "success" ]]; then
    count=$(find "$REPO_DIR" -type f \( -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | wc -l)
    python3 "$MANIFEST_PY" update semgrep-rules "$count" success
    echo -e "${CHECKMARK} Semgrep rules: ${count} rule files"
else
    python3 "$MANIFEST_PY" update semgrep-rules 0 failed "git pull/clone failed"
    echo -e "${CROSSMARK} Semgrep rules: git sync failed"
fi
