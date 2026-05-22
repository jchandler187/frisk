#!/usr/bin/env python3
# ⚡ Low Watt Labs
"""ClawSec v2 - Dependency Scan

Scans skill dependencies against local OSV + CISA KEV + EPSS caches.
"""

import json
import os
import re
import sys
import unicodedata
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
    """Load OSV advisories for an ecosystem using the consolidated index.

    Falls back to full directory scan if index.json is missing.
    """
    eco_dir = os.path.join(INTEL_DIR, "osv", ecosystem)
    if not os.path.isdir(eco_dir):
        return []

    # Try loading via index for fast lookup
    index_path = os.path.join(eco_dir, "index.json")
    if os.path.exists(index_path):
        try:
            with open(index_path) as f:
                index = json.load(f)
            return _load_osv_via_index(eco_dir, index)
        except (json.JSONDecodeError, OSError):
            pass

    # Fallback: iterate all files (slow, ~10s for 219K advisories)
    advisories = []
    for fname in os.listdir(eco_dir):
        if not fname.endswith(".json") or fname == "index.json":
            continue
        fpath = os.path.join(eco_dir, fname)
        try:
            with open(fpath) as f:
                adv = json.load(f)
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


def _load_osv_via_index(eco_dir, index):
    """Load OSV advisories using the pre-built package index.

    The index maps lowercase package names to lists of advisory filenames.
    We only load advisory files referenced by the index entries we need.
    """
    advisories = []
    advisory_cache = {}  # cache parsed advisories by filename

    for pkg_name_lower, fnames in index.items():
        for fname in fnames:
            if fname in advisory_cache:
                adv = advisory_cache[fname]
            else:
                fpath = os.path.join(eco_dir, fname)
                try:
                    with open(fpath) as f:
                        adv = json.load(f)
                    advisory_cache[fname] = adv
                except (json.JSONDecodeError, KeyError, OSError):
                    continue

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


def check_staleness(missing_criticals=None):
    """Check intel cache staleness from manifest.

    Returns a list of staleness findings:
    - 30+ days: warn severity
    - 90+ days: critical severity (scan can't be trusted)
    """
    import datetime
    findings = []
    manifest_path = os.path.join(INTEL_DIR, "manifest.json")

    if not os.path.exists(manifest_path):
        return findings

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    now = datetime.datetime.now(datetime.timezone.utc)

    for src in manifest.get("sources", []):
        last_sync = src.get("last_sync", "")
        if not last_sync or last_sync == "never":
            findings.append({
                "category": "intel_stale",
                "source": src["name"],
                "severity": "critical",
                "description": f"Intel source {src['name']} has never been synced. Run: clawsec sync {src['name']}"
            })
            continue

        try:
            # Parse ISO timestamp
            ts = last_sync.replace("Z", "+00:00")
            sync_dt = datetime.datetime.fromisoformat(ts)
            if sync_dt.tzinfo is None:
                sync_dt = sync_dt.replace(tzinfo=datetime.timezone.utc)
            age_days = (now - sync_dt).days
        except (ValueError, AttributeError):
            continue

        if age_days >= 90:
            findings.append({
                "category": "intel_stale",
                "source": src["name"],
                "severity": "critical",
                "description": f"Intel source {src['name']} is {age_days} days old (>= 90 days). Scan results cannot be trusted. Run: clawsec sync {src['name']}"
            })
        elif age_days >= 30:
            findings.append({
                "category": "intel_stale",
                "source": src["name"],
                "severity": "high",
                "description": f"Intel source {src['name']} is {age_days} days old (>= 30 days). Results may be outdated. Run: clawsec sync {src['name']}"
            })

    return findings


def check_intel_cache():
    """Verify intel cache directory and required sources exist."""
    missing = []
    if not os.path.isdir(INTEL_DIR):
        return ["intel_cache_dir", "cisa_kev", "osv", "epss"]
    if not os.path.exists(os.path.join(INTEL_DIR, "cisa-kev", "known_exploited_vulnerabilities.json")):
        missing.append("cisa_kev")
    if not os.path.isdir(os.path.join(INTEL_DIR, "osv")):
        missing.append("osv")
    if not os.path.exists(os.path.join(INTEL_DIR, "epss", "epss_scores-current.csv")):
        missing.append("epss")
    return missing

def check_dependencies(skill_path):
    """Main check: match deps against OSV, flag KEV, rank by EPSS."""
    results = {
        "check": "dependency_scan",
        "status": "pass",
        "findings": [],
        "errors": []
    }

    # Validate intel cache before proceeding
    missing = check_intel_cache()
    for source in missing:
        results["findings"].append({
            "category": "intel_missing",
            "severity": "critical",
            "description": f"Required intel source {source} is missing or corrupt. Results may be incomplete."
        })
    if not os.path.isdir(INTEL_DIR):
        results["status"] = "fail"
        results["errors"].append("intel cache directory missing")
        return results

    # P1-3: Check staleness of intel sources
    staleness = check_staleness()
    for s in staleness:
        results["findings"].append(s)
    # If any source is 90+ days stale, override verdict to fail
    if any(s["severity"] == "critical" for s in staleness):
        results["status"] = "fail"
        results["errors"].append("Intel sources critically stale (>= 90 days). Scan results unreliable.")

    deps = parse_skill_deps(skill_path)
    if not deps:
        results["status"] = "pass"
        results["note"] = "No declared dependencies found"
        return results

    kev = load_cisa_kev()
    epss = load_epss()

    # Only load OSV ecosystems for which we found dependencies
    # This prevents cross-matching (e.g., npm "requests" matching PyPI advisory)
    ecosystems_found = set(d["ecosystem"] for d in deps if d["ecosystem"] in ("npm", "PyPI"))
    osv_advisories = {}

    # For indexed lookups, use the index to load only relevant advisories
    for eco in ecosystems_found:
        eco_dir = os.path.join(INTEL_DIR, "osv", eco)
        index_path = os.path.join(eco_dir, "index.json")

        if os.path.exists(index_path):
            # Fast path: load only advisories for our dependency names
            try:
                with open(index_path) as f:
                    index = json.load(f)

                # Collect all unique filenames for our deps
                needed_fnames = set()
                for dep in deps:
                    key = dep["name"].lower()
                    if key in index:
                        needed_fnames.update(index[key])

                # Load only the needed advisory files
                eco_advisories = []
                for fname in needed_fnames:
                    fpath = os.path.join(eco_dir, fname)
                    try:
                        with open(fpath) as f:
                            adv = json.load(f)
                        for affected in adv.get("affected", []):
                            pkg = affected.get("package", {})
                            name = pkg.get("name", "")
                            pkg_eco = pkg.get("ecosystem", "")
                            ranges = affected.get("ranges", [])
                            versions = affected.get("versions", [])
                            if name:
                                eco_advisories.append({
                                    "id": adv.get("id", ""),
                                    "summary": adv.get("summary", ""),
                                    "cve_ids": [a for a in adv.get("aliases", []) if a.startswith("CVE-")],
                                    "package": name,
                                    "ecosystem": pkg_eco,
                                    "ranges": ranges,
                                    "versions": versions,
                                    "severity": adv.get("database_specific", {}).get("severity", ""),
                                })
                    except (json.JSONDecodeError, KeyError, OSError):
                        continue

                osv_advisories[eco] = eco_advisories
            except (json.JSONDecodeError, OSError):
                osv_advisories[eco] = load_osv_ecosystem(eco)
        else:
            # No index, fall back to full scan
            osv_advisories[eco] = load_osv_ecosystem(eco)

    for dep in deps:
        name = dep["name"]
        ecosystem = dep["ecosystem"]

        # Only check OSV advisories from the same ecosystem
        if ecosystem in osv_advisories:
            for adv in osv_advisories[ecosystem]:
                if unicodedata.normalize('NFKC', adv["package"].lower()) != unicodedata.normalize('NFKC', name.lower()):
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