#!/usr/bin/env bash
# ClawSec Common - Logging
# Usage: source this file, then use log_info/warn/err/ok

export CLAWSEC_LOG_FILE="${CLAWSEC_INTEL_DIR:-/srv/clawsec/intel}/../clawsec.log"

_log() {
    local level="$1"; shift
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local msg="[$ts] [$level] $*"
    echo "$msg" >> "$CLAWSEC_LOG_FILE" 2>/dev/null || true
}

log_info()  { _log "INFO" "$@"; }
log_warn()  { _log "WARN" "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() { [[ "${CLAWSEC_DEBUG:-0}" == "1" ]] && _log "DEBUG" "$@"; }