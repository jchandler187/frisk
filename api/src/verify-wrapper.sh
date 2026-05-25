#!/usr/bin/env bash
# ⚡ Frisk API verification wrapper
# Activates venv and runs verify.sh --json
set -euo pipefail

# Resolve package root: this script is at <pkg>/api/src/verify-wrapper.sh
PKG_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"

source "${PKG_ROOT}/lib/common/config.sh"

VENV="${FRISK_HOME}/venv"
if [[ -d "$VENV" ]]; then
    source "$VENV/bin/activate"
fi
export PATH="$HOME/.local/bin:$PATH"
exec bash "${PKG_ROOT}/lib/skill-verify/verify.sh" --json "$1"
