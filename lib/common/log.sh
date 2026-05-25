#!/usr/bin/env bash
# ⚡ Frisk Common - Logging
# Usage: source this file, then use log_info/warn/err/ok

# Source config to get FRISK_INTEL_DIR if not already set
if [[ -z "${FRISK_HOME:-}" ]]; then
    SCRIPT_DIR_LOG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "${SCRIPT_DIR_LOG}/config.sh"
fi

export FRISK_LOG_FILE="${FRISK_HOME}/frisk.log"

_log() {
    local level="$1"; shift
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local msg="[$ts] [$level] $*"
    echo "$msg" >> "$FRISK_LOG_FILE" 2>/dev/null || true
}

log_info()  { _log "INFO" "$@"; }
log_warn()  { _log "WARN" "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() { [[ "${FRISK_DEBUG:-0}" == "1" ]] && _log "DEBUG" "$@"; }