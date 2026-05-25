#!/usr/bin/env python3
# ⚡ Low Watt Labs
# SECURITY MANIFEST:
# Environment variables accessed: FRISK_HOME, FRISK_INTEL_DIR (via config imports)
# External endpoints called: none (all intel is local)
# Local files read: skill_path (target directory), intel cache
# Local files written: none
"""Frisk v2 - Behavioral Heuristics

Flags dangerous behavior patterns in skill code:
- Shell execution without sanitization
- Writes to system paths
- Fetch + execute remote code
- Large base64-encoded payloads
- Capability overreach (requests more than declared)
"""

import json
import os
import re
import base64
import sys
import unicodedata
from pathlib import Path

DANGEROUS_SHELL_PATTERNS = [
    (r'os\.system\s*\(', "os.system() call — unsanitized shell execution"),
    (r'subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
     "subprocess with shell=True — injection risk"),
    (r'exec\s*\(', "exec() call — dynamic code execution"),
    (r'eval\s*\(', "eval() call — dynamic code evaluation"),
    (r'child_process\.exec\b', "Node.js child_process.exec — shell injection risk"),
    (r'\.execSync\s*\(', "Node.js execSync — shell injection risk"),
    (r'\.execFile\s*\([^)]*shell\s*:\s*true', "Node.js execFile with shell:true"),
]

SYSTEM_WRITE_PATTERNS = [
    (r'open\s*\([^)]*[\'"]/(etc|usr|var|tmp|boot|srv)/', "Write to system path"),
    (r'with\s+open\s*\([^)]*[\'"]/(etc|usr|var|tmp|boot|srv)/', "Write to system path"),
    (r'fs\.(writeFileSync|appendFileSync|writeFile|appendFile)\s*\([^)]*[\'"]/(etc|usr|var|tmp|boot|srv)/',
     "Node.js write to system path"),
    (r'mkdir\s*\([^)]*[\'"]/(etc|usr|var|srv)/', "mkdir on system path"),
    (r'os\.makedirs\s*\([^)]*[\'"]/(etc|usr|var|srv)/', "os.makedirs on system path"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r'\.\.\/+(etc|var|usr|home|root|srv|tmp|boot)\b',
     "Path traversal attempt: resolves outside workspace"),
    (r'\.\.\\+(etc|var|usr|home|root|srv|tmp|boot)\b',
     "Path traversal attempt (backslash): resolves outside workspace"),
    (r'\.\./\.\./',
     "Nested path traversal: relative path escapes workspace"),
    (r'\.\.\\\\',
     "Nested path traversal (backslash): relative path escapes workspace"),
]

PATH_ABSOLUTE_FORBIDDEN = [
    (r'["\']/(etc|var|usr(?!/local))/',
     "Absolute system path access outside workspace"),
    (r'["\']/root/',
     "Absolute path to /root — should not access root home"),
    (r'["\']/home/',
     "Absolute path to home directory - suspicious in skill code"),
]

FETCH_EXEC_PATTERNS = [
    (r'(requests\.get|urllib\.request\.urlopen|fetch|axios|http\.get)\s*.*\n.*exec\s*\(',
     "fetch-then-exec pattern — remote code execution risk"),
    (r'(requests\.get|urllib\.request\.urlopen|fetch|axios)\s*.*\n.*eval\s*\(',
     "fetch-then-eval pattern — remote code execution risk"),
    (r'curl\s.*\|\s*(ba)?sh', "curl pipe to shell — classic RCE pattern"),
    (r'wget\s.*\|\s*(ba)?sh', "wget pipe to shell — classic RCE pattern"),
]

CAPABILITY_PATTERNS = {
    "network": [r'requests\.', r'socket\.', r'http\.', r'fetch\s*\(', r'axios\.'],
    "filesystem": [r'open\s*\(', r'os\.path\.', r'os\.makedirs', r'fs\.', r'readFileSync', r'writeFileSync'],
    "shell": [r'os\.system', r'subprocess\.', r'child_process', r'exec\s*\(', r'execSync'],
    "environment": [r'os\.environ', r'process\.env'],
}

def find_base64_payloads(content, threshold=2048):
    """Find suspiciously large base64 strings."""
    findings = []
    # Match base64-looking strings
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{%d,}={0,2}' % threshold)
    for match in b64_pattern.finditer(content):
        b64_str = match.group()
        try:
            decoded = base64.b64decode(b64_str)
            # Check if it's binary-ish (non-printable content)
            non_printable = sum(1 for b in decoded if b < 32 and b not in (9, 10, 13))
            if non_printable > len(decoded) * 0.1:
                # ELF binaries embedded as base64 are critical — they're trojan horses
                is_elf = decoded[:4] == b'\x7fELF'
                severity = "critical" if is_elf else "high"
                desc = f"Embedded ELF binary ({len(decoded)} bytes)" if is_elf else f"Large base64 payload ({len(decoded)} bytes decoded, appears binary)"
                findings.append({
                    "type": "embedded_elf_binary" if is_elf else "large_base64_payload",
                    "size_bytes": len(decoded),
                    "encoded_size": len(b64_str),
                    "severity": severity,
                    "description": desc
                })
        except Exception:
            pass
    return findings

def check_capabilities_declared(skill_path):
    """Check if skill's declared capabilities match actual behavior."""
    skill_md = Path(skill_path) / "SKILL.md"
    declared = set()
    if skill_md.exists():
        content = skill_md.read_text(errors='ignore')
        # Look for capability declarations
        cap_section = re.search(r'##\s*(?:Capabilities|Permissions|Requires)\s*\n(.*?)(?=\n##|\Z)',
                                content, re.DOTALL | re.IGNORECASE)
        if cap_section:
            for cap in CAPABILITY_PATTERNS:
                if re.search(r'\b' + cap + r'\b', cap_section.group(1), re.IGNORECASE):
                    declared.add(cap)

    return declared

def check_behavioral(skill_path):
    """Main behavioral heuristics check."""
    results = {
        "check": "behavioral_heuristics",
        "status": "pass",
        "findings": [],
        "errors": []
    }

    skill_path = Path(skill_path)
    all_code = ""
    code_files = []

    for fpath in skill_path.rglob("*"):
        if fpath.is_dir() or fpath.suffix in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.zip'):
            continue
        try:
            content = fpath.read_text(errors='ignore')
            content = unicodedata.normalize('NFKC', content)  # P0-6: normalize homoglyphs
            all_code += content + "\n"
            code_files.append((fpath, content))
        except Exception:
            continue

    if not all_code:
        results["note"] = "No readable code files found"
        return results

    # 1. Shell execution without sanitization
    for pattern, desc in DANGEROUS_SHELL_PATTERNS:
        for match in re.finditer(pattern, all_code):
            results["findings"].append({
                "type": "dangerous_shell",
                "pattern": pattern,
                "description": desc,
                "severity": "high"
            })
            break  # one finding per pattern

    # 2. System path writes
    for pattern, desc in SYSTEM_WRITE_PATTERNS:
        for match in re.finditer(pattern, all_code):
            results["findings"].append({
                "type": "system_write",
                "pattern": pattern,
                "description": desc,
                "severity": "high"
            })
            break

    # 3. Fetch + exec
    for pattern, desc in FETCH_EXEC_PATTERNS:
        if re.search(pattern, all_code, re.DOTALL):
            results["findings"].append({
                "type": "fetch_exec",
                "pattern": pattern,
                "description": desc,
                "severity": "critical"
            })

    # 4. Path traversal detection (P0-5)
    normalized_code = all_code.replace('\\'  + '\\', '/')  # normalize backslash paths
    for pattern, desc in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, all_code):
            results["findings"].append({
                "type": "path_traversal",
                "pattern": pattern,
                "description": desc,
                "severity": "critical"
            })
    for pattern, desc in PATH_ABSOLUTE_FORBIDDEN:
        if re.search(pattern, all_code):
            results["findings"].append({
                "type": "path_traversal",
                "pattern": pattern,
                "description": desc,
                "severity": "critical"
            })

    # 5. Large base64 payloads
    b64_findings = find_base64_payloads(all_code)
    results["findings"].extend(b64_findings)

    # 6. Capability overreach
    declared = check_capabilities_declared(skill_path)
    if declared:
        for cap, patterns in CAPABILITY_PATTERNS.items():
            if cap not in declared:
                for pattern in patterns:
                    if re.search(pattern, all_code):
                        results["findings"].append({
                            "type": "capability_overreach",
                            "capability": cap,
                            "description": f"Uses {cap} capabilities but doesn't declare them",
                            "severity": "medium"
                        })
                        break

    # P0-7: Severity escalation — certain categories MUST be critical
    ESCALATE_TO_CRITICAL = {"command_injection", "shell_injection", "path_traversal", "hardcoded_secret", "secret_in_code"}
    SHELL_INJ_KEYWORDS = ["os.system", "shell=True", "execSync", "child_process.exec", "os.system()", "subprocess.*shell"]
    for f in results["findings"]:
        ftype = f.get("type", "")
        category = f.get("category", "")
        pattern = f.get("pattern", "")
        desc = f.get("description", "")
        if ftype in ESCALATE_TO_CRITICAL or category in ESCALATE_TO_CRITICAL:
            f["severity"] = "critical"
        # Also escalate dangerous_shell/shell injection findings to critical
        if ftype == "dangerous_shell":
            f["severity"] = "critical"
        # Escalate any pattern containing shell injection keywords
        for kw in SHELL_INJ_KEYWORDS:
            if kw in pattern or kw in desc:
                f["severity"] = "critical"
                break

    # Determine status
    if any(f["severity"] == "critical" for f in results["findings"]):
        results["status"] = "fail"
    elif any(f["severity"] == "high" for f in results["findings"]):
        results["status"] = "warn"
    elif results["findings"]:
        results["status"] = "warn"

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: behavioral.py <skill_path>")
        sys.exit(1)
    try:
        result = check_behavioral(sys.argv[1])
    except Exception as e:
        result = {
            "check": "behavioral_heuristics",
            "status": "warn",
            "findings": [],
            "errors": [f"Behavioral analysis failed: {str(e)}"]
        }
    print(json.dumps(result, indent=2))