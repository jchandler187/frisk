#!/usr/bin/env bash
# ClawSec Common - Configuration
# Centralizes INTEL_DIR and CLAWSEC_HOME with env var overrides
# Usage: source "${SCRIPT_DIR}/../common/config.sh" (from any script)

export CLAWSEC_HOME="${CLAWSEC_HOME:-$HOME/clawsec-v2}"
export CLAWSEC_INTEL_DIR="${CLAWSEC_INTEL_DIR:-/srv/clawsec/intel}"