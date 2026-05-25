"""Frisk Common - Configuration

Centralizes INTEL_DIR and FRISK_HOME with env var overrides.
Usage:
    from lib.common.config import INTEL_DIR, FRISK_HOME
"""

import os

FRISK_HOME = os.environ.get("FRISK_HOME", os.path.expanduser("~/.frisk"))
INTEL_DIR = os.environ.get("FRISK_INTEL_DIR", os.path.join(FRISK_HOME, "intel"))
REPORTS_DIR = os.environ.get("FRISK_REPORTS_DIR", os.path.join(FRISK_HOME, "reports"))
