#!/usr/bin/env bash
# ClawSec API verification wrapper
# Activates venv and runs verify.sh --json
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common/config.sh"

VENV="${CLAWSEC_HOME}/.venv"
if [[ -d "$VENV" ]]; then
    source "$VENV/bin/activate"
fi
export PATH="$HOME/.local/bin:$PATH"
exec bash "${CLAWSEC_HOME}/lib/skill-verify/verify.sh" --json "$1"