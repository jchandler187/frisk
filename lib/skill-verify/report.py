# ⚡ Low Watt Labs — Frisk Skill Verification Report
"""Frisk v2 - Report Generator

Aggregates check results into a final JSON report with verdict.
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))
from config import FRISK_HOME, INTEL_DIR

REPORTS_DIR = os.path.join(FRISK_HOME, "reports")

def generate_report(skill_path, check_results):
    """Generate a final report from all check results."""
    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Aggregate findings
    all_findings = []
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0

    for result in check_results:
        if "error" in result and not result.get("findings"):
            continue
        for f in result.get("findings", []):
            # P0-7: Escalate specific finding categories to critical severity
            ftype = f.get("type", "")
            category = f.get("category", "")
            pattern = f.get("pattern", "")
            escalate_categories = {"command_injection", "shell_injection", "path_traversal", "hardcoded_secret", "secret_in_code"}
            if ftype in escalate_categories or category in escalate_categories:
                f["severity"] = "critical"
            # Also escalate os.system and shell injection patterns from Semgrep
            if any(kw in pattern for kw in ["os.system", "shell=True", "execSync", "child_process.exec"]):
                f["severity"] = "critical"
            
            severity = f.get("severity", "low")
            if severity == "critical":
                total_critical += 1
            elif severity == "high":
                total_high += 1
            elif severity == "medium":
                total_medium += 1
            else:
                total_low += 1
            all_findings.append(f)

    # Determine overall verdict
    check_statuses = [r.get("status", "pass") for r in check_results]
    if "fail" in check_statuses or total_critical > 0:
        verdict = "fail"
    elif "warn" in check_statuses or total_high > 0:
        verdict = "warn"
    else:
        verdict = "pass"

    report = {
        "report_id": report_id,
        "schema_version": "2.0.0",
        "timestamp": now,
        "skill_path": skill_path,
        "verdict": verdict,
        "summary": {
            "total_findings": len(all_findings),
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
        "checks": check_results,
        "intel_cache": get_cache_timestamps(),
    }

    # Save report
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    return report, report_path

def get_cache_timestamps():
    """Get timestamps from manifest for report provenance."""
    manifest_path = os.path.join(INTEL_DIR, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            return {s["name"]: s.get("last_sync", "unknown") for s in manifest.get("sources", [])}
        except (json.JSONDecodeError, KeyError):
            pass
    return {}

def load_report(report_id):
    """Load a saved report by ID."""
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: report.py <report_id>")
        sys.exit(1)
    report = load_report(sys.argv[1])
    if report:
        print(json.dumps(report, indent=2))
    else:
        print(f"Report {sys.argv[1]} not found")
        sys.exit(1)