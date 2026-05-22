"""ClawSec Common - Configuration

Centralizes INTEL_DIR and CLAWSEC_HOME with env var overrides.
Usage:
    from lib.common.config import INTEL_DIR, CLAWSEC_HOME
"""

import os

CLAWSEC_HOME = os.environ.get("CLAWSEC_HOME", os.path.expanduser("~/clawsec-v2"))
INTEL_DIR = os.environ.get("CLAWSEC_INTEL_DIR", "/srv/clawsec/intel")