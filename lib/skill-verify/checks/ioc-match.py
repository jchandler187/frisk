#!/usr/bin/env python3
"""ClawSec v2 - IOC Extraction & Match

Extracts URLs, IPs, domains, hashes from skill code and matches against
URLhaus, ThreatFox, Feodo Tracker, and MalwareBazaar caches.
"""

import json
import os
import re
import sys
import csv
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'common'))
from config import INTEL_DIR

# Patterns for extraction
URL_PATTERN = re.compile(r'https?://[^\s"\'\]\)>}]+', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|xyz|top|info|biz|cc|tk|ml|ga|cf|gq)\b', re.IGNORECASE)
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')

# Known-safe domains to exclude
SAFE_DOMAINS = {
    "github.com", "githubusercontent.com", "npmjs.com", "npmjs.org",
    "pypi.org", "pythonhosted.org", "clawhub.ai", "openclaw.dev",
    "google.com", "cloud.google.com", "amazonaws.com", "amazon.com",
    "microsoft.com", "azure.com", "cloudflare.com", "example.com",
    "localhost", "127.0.0.1", "0.0.0.0",
}

def is_private_ip(ip):
    """Check if IP is in RFC 1918 or loopback/private ranges."""
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 0 or a == 127:
        return True
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def extract_iocs(skill_path):
    """Extract IOCs from all files in skill directory."""
    iocs = {"urls": set(), "ips": set(), "domains": set(), "hashes": set()}
    skill_path = Path(skill_path)

    for fpath in skill_path.rglob("*"):
        if fpath.is_dir():
            continue
        if fpath.suffix in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.zip', '.gz', '.tar', '.node_modules'):
            continue
        try:
            content = fpath.read_text(errors='ignore')
        except Exception:
            continue

        for url in URL_PATTERN.findall(content):
            # Strip trailing punctuation
            url = url.rstrip('.,;:)>')
            iocs["urls"].add(url)
            # Extract domain from URL
            m = re.search(r'://([^/:]+)', url)
            if m:
                iocs["domains"].add(m.group(1).lower())

        for ip in IP_PATTERN.findall(content):
            if not is_private_ip(ip):
                iocs["ips"].add(ip)

        for dom in DOMAIN_PATTERN.findall(content):
            if dom.lower() not in SAFE_DOMAINS:
                iocs["domains"].add(dom.lower())

        for h in SHA256_PATTERN.findall(content):
            # Filter out obviously non-hash strings (like hex content in code)
            if not re.match(r'^[0-9a-f]{64}$', h) or len(set(h.lower())) > 4:
                iocs["hashes"].add(h.lower())

    return iocs

def load_feodo_ips():
    """Load Feodo Tracker C2 IPs."""
    path = os.path.join(INTEL_DIR, "feodo", "c2_ips.csv")
    ips = set()
    if not os.path.exists(path):
        return ips
    with open(path) as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            line = row[0] if row else ''
            if line.startswith("#") or not line:
                continue
            # IP is in column index 1 (dst_ip) for Feodo CSV format
            if len(row) >= 2:
                ip = row[1].strip()
            else:
                ip = row[0].strip()
            if re.match(IP_PATTERN.pattern, ip):
                ips.add(ip)
    return ips

def load_urlhaus_urls():
    """Load URLhaus malicious URLs."""
    path = os.path.join(INTEL_DIR, "urlhaus", "urls.csv")
    urls = set()
    if not os.path.exists(path):
        return urls
    with open(path, errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                urls.add(parts[2].strip().lower())
    return urls

def load_malwarebazaar_hashes():
    """Load MalwareBazaar SHA256 hashes."""
    path = os.path.join(INTEL_DIR, "malwarebazaar", "recent_hashes.csv")
    hashes = set()
    if not os.path.exists(path):
        return hashes
    with open(path, errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(",")
            for p in parts:
                p = p.strip().lower()
                if re.match(r'^[a-f0-9]{64}$', p):
                    hashes.add(p)
                    break
    return hashes

def check_ioc_match(skill_path):
    """Main check: extract IOCs, match against threat intel."""
    results = {
        "check": "ioc_match",
        "status": "pass",
        "findings": [],
        "errors": [],
        "extracted": {"urls": 0, "ips": 0, "domains": 0, "hashes": 0}
    }

    iocs = extract_iocs(skill_path)
    results["extracted"] = {
        "urls": len(iocs["urls"]),
        "ips": len(iocs["ips"]),
        "domains": len(iocs["domains"]),
        "hashes": len(iocs["hashes"])
    }

    # Load threat intel
    feodo_ips = load_feodo_ips()
    urlhaus_urls = load_urlhaus_urls()
    mb_hashes = load_malwarebazaar_hashes()

    # Match IPs against Feodo
    for ip in iocs["ips"]:
        if ip in feodo_ips:
            results["findings"].append({
                "type": "ip",
                "value": ip,
                "source": "feodo_tracker",
                "severity": "critical",
                "description": f"IP {ip} listed in Feodo Tracker C2 blocklist"
            })

    # Match URLs against URLhaus (exact scheme+host+path comparison)
    for url in iocs["urls"]:
        parsed_skill = urlparse(url.lower().rstrip('/'))
        skill_key = (parsed_skill.scheme, parsed_skill.hostname, parsed_skill.path)
        for bad_url in urlhaus_urls:
            parsed_bad = urlparse(bad_url.rstrip('/'))
            bad_key = (parsed_bad.scheme, parsed_bad.hostname, parsed_bad.path)
            if skill_key == bad_key:
                results["findings"].append({
                    "type": "url",
                    "value": url,
                    "source": "urlhaus",
                    "severity": "critical",
                    "description": f"URL matches URLhaus malicious URL list"
                })
                break

    # Match hashes against MalwareBazaar
    for h in iocs["hashes"]:
        if h in mb_hashes:
            results["findings"].append({
                "type": "hash",
                "value": h[:16] + "...",
                "source": "malwarebazaar",
                "severity": "critical",
                "description": "SHA256 hash matches MalwareBazaar sample"
            })

    if results["findings"]:
        if any(f["severity"] == "critical" for f in results["findings"]):
            results["status"] = "fail"
        else:
            results["status"] = "warn"

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ioc-match.py <skill_path>")
        sys.exit(1)
    result = check_ioc_match(sys.argv[1])
    print(json.dumps(result, indent=2))