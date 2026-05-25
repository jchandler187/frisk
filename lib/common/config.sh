#!/usr/bin/env bash
# Frisk Common - Configuration
# Centralizes INTEL_DIR and FRISK_HOME with env var overrides
# Usage: source this file from any script

export FRISK_HOME="${FRISK_HOME:-$HOME/.frisk}"
export FRISK_INTEL_DIR="${FRISK_INTEL_DIR:-$FRISK_HOME/intel}"
export FRISK_REPORTS_DIR="${FRISK_REPORTS_DIR:-$FRISK_HOME/reports}"
