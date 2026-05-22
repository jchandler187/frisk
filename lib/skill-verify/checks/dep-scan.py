#!/usr/bin/env python3
"""ClawSec v2 - Dependency Scan

Scans skill dependencies against local OSV + CISA KEV + EPSS caches.
"""

import json
import os
import re
import sys
from pathlib import Path
from packaging.version import Version, InvalidVersion

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'common'))
from config import INTEL_DIR

def load_cisa_kev():
    """Load CISA KEV catalog, return set of CVE IDs."""
    path = os.path.join(INTEL_DIR, "cisa-kev", "known_exploited_vulnerabilities.json")
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return {v.get("cveID", "") for v in data.get("vulnerabilities", [])}

def load_epss():
    """Load EPSS scores, return dict of CVE -> (probability, percentile)."""
    path = os.path.join(INTEL_DIR, "epss", "epss_scores-current.csv")
    epss = {}
    if not os.path.exists(path):
        return epss
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or line.startswith("cve"):
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                try:
                    epss[parts[0]] = (float(parts[1]), float(parts[2]))
                except (ValueError, IndexError):
                    continue
    return epss

def load_osv_ecosystem(ecosystem):
    """Load all OSV advisories for an ecosystem."""
    advisories = []
    eco_dir = os.path.join(INTEL_DIR, "osv", ecosystem)
    if not os.path.isdir(eco_dir):
        return advisories
    for fname in os.listdir(eco_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(eco_dir, fname)
        try:
            with open(fpath) as f:
                adv = json.load(f)
            # Get affected package names
            for affected in adv.get("affected", []):
                pkg = affected.get("package", {})
                name = pkg.get("name", "")
                eco = pkg.get("ecosystem", "")
                ranges = affected.get("ranges", [])
                versions = affected.get("versions", [])
                if name:
                    advisories.append({
                        "id": adv.get("id", ""),
                        "summary": adv.get("summary", ""),
                        "cve_ids": [a for a in adv.get("aliases", []) if a.startswith("CVE-")],
                        "package": name,
                        "ecosystem": eco,
                        "ranges": ranges,
                        "versions": versions,
                        "severity": adv.get("database_specific", {}).get("severity", ""),
                    })
        except (json.JSONDecodeError, KeyError):
            continue
    return advisories

def parse_skill_deps(skill_path):
    """Parse dependencies from skill manifest/package files."""
    deps = []
    skill_path = Path(skill_path)

    # Check for package.json
    pkg_json = skill_path / "package.json"
    if pkg_json.exists():
        try:
            with open(pkg_json) as f:
                pkg = json.load(f)
            for name, ver in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
                deps.append({"name": name, "version": ver, "ecosystem": "npm"})
        except json.JSONDecodeError:
            pass

    # Check for requirements.txt
    req_file = skill_path / "requirements.txt"
    if req_file.exists():
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Parse package==version or package>=version
                m = re.match(r'^([a-zA-Z0-9_-]+)\s*[=<>!~]+\s*([0-9][0-9.]*)', line)
                if m:
                    deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})

    # Check SKILL.md for declared dependencies
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        with open(skill_md) as f:
            content = f.read()
        # Look for dependency sections
        dep_section = re.search(r'##\s*Dependencies?\s*\n(.*?)(?=\n##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if dep_section:
            for line in dep_section.group(1).split("\n"):
                m = re.match(r'-\s+([a-zA-Z0-9_/-]+)\s*[@=<>~]+\s*([0-9][0-9.]*)', line)
                if m:
                    deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "unknown"})

    return deps

def version_in_range(ver_str, ranges_list):
    """Check if a version falls within any vulnerable range from OSV ranges[]."""
    try:
        ver = Version(ver_str)
    except InvalidVersion:
        return False
    for r in ranges_list:
        rtype = r.get("type", "")
        if rtype != "SEMVER" and rtype != "ECOSYSTEM":
            continue
        introduced = None
        fixed = None
        for event in r.get("events", []):
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                fixed = event["fixed"]
            elif "last_affected" in event:
                fixed = event["last_affected"]  # treat as upper bound
        if introduced is None:
            continue
        try:
            introduced_ver = Version(introduced) if introduced != "0" else Version("0")
        except InvalidVersion:
            introduced_ver = Version("0")
        # Version is vulnerable if >= introduced and (< fixed or no fixed)
        if ver >= introduced_ver:
            if fixed is None:
                return True
            try:
                if ver < Version(fixed):
                    return True
            except InvalidVersion:
                return True  # can't parse fixed, assume vulnerable
    return False


def check_dependencies(skill_path):
    """Main check: match deps against OSV, flag KEV, rank by EPSS."""
    results = {
        "check": "dependency_scan",
        "status": "pass",
        "findings": [],
        "errors": []
    }

    deps = parse_skill_deps(skill_path)
    if not deps:
        results["status"] = "pass"
        results["note"] = "No declared dependencies found"
        return results

    kev = load_cisa_kev()
    epss = load_epss()

    # Build OSV lookup by ecosystem
    osv_advisories = {}
    for eco in ["npm", "PyPI"]:
        osv_advisories[eco] = load_osv_ecosystem(eco)

    for dep in deps:
        name = dep["name"]
        ecosystem = dep["ecosystem"]

        # Check OSV for this ecosystem
        if ecosystem in osv_advisories:
            for adv in osv_advisories[eco]:
                if adv["package"].lower() != name.lower():
                    continue
                ver = dep.get("version", "").lstrip("^~>=<!")
                if not ver:
                    continue
                # Check version against both explicit versions list and ranges
                is_vulnerable = False
                if adv.get("versions") and ver in adv["versions"]:
                    is_vulnerable = True
                elif adv.get("ranges") and version_in_range(ver, adv["ranges"]):
                    is_vulnerable = True
                if is_vulnerable:
                    finding = {
                        "package": name,
                        "version": ver,
                        "advisory": adv["id"],
                        "summary": adv.get("summary", ""),
                    }
                    # Check KEV
                    for cve in adv.get("cve_ids", []):
                        if cve in kev:
                            finding["in_kev"] = True
                            finding["cve"] = cve
                            break
                    # Check EPSS
                    for cve in adv.get("cve_ids", []):
                        if cve in epss:
                            prob, pct = epss[cve]
                            finding["epss_probability"] = prob
                            finding["epss_percentile"] = pct
                            break

                    if finding.get("in_kev"):
                        finding["severity"] = "critical"
                    elif finding.get("epss_probability", 0) > 0.02:
                        finding["severity"] = "high"
                    elif finding.get("epss_probability", 0) > 0.001:
                        finding["severity"] = "medium"
                    else:
                        finding["severity"] = "low"

                    results["findings"].append(finding)

    # Determine status
    if any(f.get("in_kev") for f in results["findings"]):
        results["status"] = "fail"
    elif any(f.get("severity") == "high" for f in results["findings"]):
        results["status"] = "warn"
    elif results["findings"]:
        results["status"] = "warn"

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: dep-scan.py <skill_path>")
        sys.exit(1)
    result = check_dependencies(sys.argv[1])
    print(json.dumps(result, indent=2))