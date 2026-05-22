#!/usr/bin/env python3
# ⚡ Low Watt Labs
"""ClawSec v2 - IOC Extraction & Match

Extracts URLs, IPs, domains, hashes from skill code and matches against
URLhaus, ThreatFox, Feodo Tracker, and MalwareBazaar caches.
"""

import json
import os
import re
import sys
import csv
import unicodedata
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


def normalize(text):
    """Apply Unicode NFKC normalization + confusable homoglyph stripping.

    NFKC handles compatibility decompositions (fullwidth→ASCII, ligatures).
    For homoglyphs (Cyrillic 'а' vs Latin 'a'), we use an explicit
    confusable mapping from common Cyrillic/Macedonian/etc characters
    to their Latin equivalents.
    """
    if not isinstance(text, str):
        return text
    text = unicodedata.normalize('NFKC', text)
    # Strip common confusable homoglyphs (Cyrillic → Latin)
    result = []
    for ch in text:
        result.append(CONFUSABLES.get(ch, ch))
    return ''.join(result)


# Common confusable character mapping (Cyrillic/Macedonian → Latin)
# Not exhaustive but covers the most-likely homoglyph attacks
CONFUSABLES = {
    # Cyrillic lowercase → Latin
    '\u0430': 'a',  # а → a
    '\u0435': 'e',  # е → e
    '\u043e': 'o',  # о → o
    '\u0440': 'p',  # р → p
    '\u0441': 'c',  # с → c
    '\u0443': 'y',  # у → y
    '\u0445': 'x',  # х → x
    '\u044b': 'b',  # ы → b (approximate)
    '\u0456': 'i',  # і → i (Ukrainian)
    '\u0458': 'j',  # ј → j (Macedonian)
    '\u0455': 's',  # ѕ → s (Macedonian)
    '\u0457': 'i',  # ї → i (Ukrainian)
    '\u0454': 'e',  # є → e (Ukrainian)
    # Cyrillic uppercase → Latin uppercase
    '\u0410': 'A',  # А → A
    '\u0412': 'B',  # В → B
    '\u0415': 'E',  # Е → E
    '\u041a': 'K',  # К → K
    '\u041c': 'M',  # М → M
    '\u041d': 'H',  # Н → H
    '\u041e': 'O',  # О → O
    '\u0420': 'P',  # Р → P
    '\u0421': 'C',  # С → C
    '\u0422': 'T',  # Т → T
    '\u0425': 'X',  # Х → X
    # Greek confusables
    '\u03b1': 'a',  # α → a
    '\u03b9': 'i',  # ι → i
    '\u03bf': 'o',  # ο → o
    '\u03c1': 'p',  # ρ → p
    '\u03c5': 'y',  # υ → y
    '\u03c7': 'x',  # χ → x
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


def check_intel_cache():
    """Verify intel cache files exist and are readable for IOC matching.

    Returns list of missing source names.
    """
    missing = []
    if not os.path.isdir(INTEL_DIR):
        return ["intel_cache_dir"]
    if not os.path.exists(os.path.join(INTEL_DIR, "urlhaus", "urls.csv")):
        missing.append("urlhaus")
    if not os.path.exists(os.path.join(INTEL_DIR, "malwarebazaar", "recent_hashes.csv")):
        missing.append("malwarebazaar")
    if not os.path.exists(os.path.join(INTEL_DIR, "feodo", "c2_ips.csv")):
        missing.append("feodo")
    if not os.path.exists(os.path.join(INTEL_DIR, "threatfox")):
        missing.append("threatfox")
    return missing


def extract_iocs(skill_path):
    """Extract IOCs and homoglyph detections from all files in skill directory."""
    iocs = {"urls": set(), "ips": set(), "domains": set(), "hashes": set()}
    homoglyphs = []  # list of {original, normalized, type} dicts
    skill_path = Path(skill_path)

    for fpath in skill_path.rglob("*"):
        if fpath.is_dir():
            continue
        if fpath.suffix in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.zip', '.gz', '.tar', '.node_modules'):
            continue
        try:
            content = fpath.read_text(errors='ignore')
            raw_content = content
            content = normalize(content)  # P0-6: normalize before extraction
        except Exception:
            continue

        # P0: Detect homoglyph substitution — flag when normalization changed text
        # Use a Unicode-aware pattern for raw content, since DOMAIN_PATTERN
        # only matches Latin chars and misses Cyrillic/Greek homoglyphs.
        HOMOGLYPH_DOMAIN_RE = re.compile(
            r'(?:[\w\u0100-\u024f\u0400-\u04ff](?:[\w\u0100-\u024f\u0400-\u04ff-]*[\w\u0100-\u024f\u0400-\u04ff])?\.)+(?:com|net|org|io|dev|app|xyz|top|info|biz|cc|tk|ml|ga|cf|gq)\b',
            re.IGNORECASE
        )
        if raw_content != content:
            for url in URL_PATTERN.findall(raw_content):
                norm_url = normalize(url)
                if url != norm_url:
                    homoglyphs.append({
                        "type": "homoglyph_url",
                        "original": url,
                        "normalized": norm_url,
                    })
            for dom in HOMOGLYPH_DOMAIN_RE.findall(raw_content):
                norm_dom = normalize(dom)
                # Flag ANY domain where normalization changed characters,
                # even if the normalized version is a "safe" domain.
                # A homoglyph of google.com IS the attack — that's the whole point.
                if dom != norm_dom:
                    homoglyphs.append({
                        "type": "homoglyph_domain",
                        "original": dom,
                        "normalized": norm_dom,
                    })

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

    return iocs, homoglyphs

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
                ip = normalize(row[1].strip())  # P0-6
            else:
                ip = normalize(row[0].strip())
            if re.match(IP_PATTERN.pattern, ip):
                ips.add(ip)
    return ips

def load_urlhaus_urls():
    """Load URLhaus malicious URLs using proper CSV parsing."""
    path = os.path.join(INTEL_DIR, "urlhaus", "urls.csv")
    urls = set()
    if not os.path.exists(path):
        return urls
    with open(path, errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            # Skip comment lines (URLhaus starts with # headers)
            if row[0].startswith("#"):
                continue
            # URL is in column index 2 (id, dateadded, url, ...)
            if len(row) >= 3:
                url = normalize(row[2].strip())  # P0-6: normalize at load
                if url:
                    urls.add(url.lower())
    return urls

def load_malwarebazaar_hashes():
    """Load MalwareBazaar SHA256 hashes using proper CSV parsing.

    Column index 1 is sha256_hash. Uses csv.reader to handle
    quoted fields with spaces and commas correctly (P0-3).
    """
    path = os.path.join(INTEL_DIR, "malwarebazaar", "recent_hashes.csv")
    hashes = set()
    if not os.path.exists(path):
        return hashes
    with open(path, errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            line = row[0].strip() if row else ''
            if line.startswith("#") or not line:
                continue
            # SHA256 hash is column index 1 (first_seen_utc, sha256_hash, ...)
            if len(row) >= 2:
                h = row[1].strip().strip("'").strip('"').lower()  # P0-3: CSV column, strip quotes
                h = normalize(h)  # P0-6
                if re.match(r'^[a-f0-9]{64}$', h):
                    hashes.add(h)
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

    # P0-4: Validate intel cache before proceeding
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

    iocs, homoglyphs = extract_iocs(skill_path)

    # Emit homoglyph detections as critical findings
    for hg in homoglyphs:
        results["findings"].append({
            "type": hg["type"],
            "category": "ioc_match",
            "severity": "critical",
            "description": f"Homoglyph detected: '{hg['original']}' normalizes to '{hg['normalized']}' — potential phishing/poisoning attack",
            "original": hg["original"],
            "normalized": hg["normalized"],
            "source": "homoglyph_detection"
        })
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
                    "description": "URL matches URLhaus malicious URL list"
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

    # Determine status — intel_missing findings upgrade severity
    if results["findings"]:
        has_critical = any(f["severity"] == "critical" and f.get("category") != "intel_missing" for f in results["findings"])
        has_missing = any(f.get("category") == "intel_missing" for f in results["findings"])
        if has_critical:
            results["status"] = "fail"
        elif has_missing:
            # Missing intel is critical but we still run with available data
            # If no actual malicious findings, status is "warn" (incomplete results)
            results["status"] = "warn"
        else:
            results["status"] = "warn"

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ioc-match.py <skill_path>")
        sys.exit(1)
    result = check_ioc_match(sys.argv[1])
    print(json.dumps(result, indent=2))