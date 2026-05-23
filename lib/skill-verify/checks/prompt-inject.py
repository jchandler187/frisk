#!/usr/bin/env python3
# ⚡ Low Watt Labs
# SECURITY MANIFEST:
# Environment variables accessed: CLAWSEC_HOME, CLAWSEC_INTEL_DIR (via config imports)
# External endpoints called: none (all intel is local)
# Local files read: skill_path (target directory), intel cache
# Local files written: none
"""ClawSec v2 - Prompt Injection Pattern Detection

Scans SKILL.md and config files for instruction override, role manipulation,
and safety bypass attempts that could compromise an agent using the skill.
"""

import json
import os
import re
import sys
from pathlib import Path

# Patterns indicating prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction overrides
    (r'(?i)ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?)',
     "Attempts to override previous instructions",
     "critical"),
    (r'(?i)forget\s+(all\s+)?previous\s+(instructions?|rules?)',
     "Attempts to make agent forget instructions",
     "critical"),
    (r'(?i)disregard\s+(all\s+)?(previous|above|safety)\s+(instructions?|rules?|guidelines?)',
     "Attempts to disregard safety rules",
     "critical"),
    (r'(?i)override\s+(safety|security|guardrails?|filters?)',
     "Attempts to override safety controls",
     "critical"),

    # Role manipulation
    (r'(?i)you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken)',
     "Attempts role manipulation to bypass safety",
     "critical"),
    (r'(?i)pretend\s+you\s+(are|have)\s+no\s+(rules?|restrictions?|limits?)',
     "Role manipulation to remove constraints",
     "critical"),
    (r'(?i)(?:act|roleplay|role-play)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|DAN)',
     "DAN-style role manipulation",
     "critical"),

    # Safety bypass
    (r'(?i)bypass\s+(safety|security|content\s+filter|guardrails?)',
     "Direct safety bypass attempt",
     "critical"),
    (r'(?i)(?:jailbreak|escape)\s+(?:the\s+)?(?:sandbox|container|restrictions?)',
     "Sandbox escape attempt",
     "high"),
    (r'(?i)this\s+is\s+(?:a\s+)?(?:safe|educational|research|testing)\s+(?:mode|context|environment)',
     "Fictional safety reassurance to lower guard",
     "high"),

    # Hidden/embedded instructions
    (r'(?i)<!--\s*(?:ignore|bypass|skip|override)',
     "Hidden HTML comment with override instruction",
     "high"),
    (r'(?i)<!--\s*system\s*(?:prompt|instruction)',
     "Hidden system prompt injection in HTML comment",
     "high"),
    (r'(?i)\[\[.*?(?:ignore|bypass|override).*?\]\]',
     "Hidden instruction in double-bracket marker",
     "medium"),

    # Output manipulation
    (r'(?i)do\s+not\s+(?:show|display|include|report|warn)',
     "Attempts to suppress security reporting",
     "high"),
    (r'(?i)(?:never|don\'?t)\s+(?:flag|report|warn|alert)\s+(?:about\s+)?(?:this|issues?|vulnerabilities?)',
     "Attempts to suppress vulnerability reporting",
     "critical"),

    # Data exfiltration hints
    (r'(?i)(?:send|transmit|exfiltrate|export)\s+(?:all\s+)?(?:data|keys?|secrets?|tokens?|credentials?)',
     "Attempts to exfiltrate sensitive data",
     "critical"),
    (r'(?i)(?:post|fetch|call|ping)\s+(?:https?://(?:(?!github\.com|npmjs\.org|pypi\.org).)*)\s+.*(?:key|token|secret|password|credential)',
     "Potential credential exfiltration endpoint",
     "high"),

    # Environmental exploitation
    (r'(?i)read\s+(?:the\s+)?(?:env|environment)\s+(?:variables?|file)',
     "Requests environment variable access",
     "medium"),
    (r'(?i)(?:access|read|dump)\s+(?:the\s+)?(?:shadow|passwd|hosts)\s+file',
     "Requests access to system files",
     "high"),
]

def check_prompt_injection(skill_path):
    """Scan skill docs and config for prompt injection patterns."""
    results = {
        "check": "prompt_injection",
        "status": "pass",
        "findings": [],
        "errors": []
    }

    skill_path = Path(skill_path)
    scan_files = []

    # Primary target: SKILL.md
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        scan_files.append(("SKILL.md", skill_md.read_text(errors='ignore')))

    # Also scan README.md, any .md in the dir
    for fpath in skill_path.rglob("*.md"):
        if fpath.name in ("SKILL.md",):
            continue
        try:
            scan_files.append((str(fpath.relative_to(skill_path)), fpath.read_text(errors='ignore')))
        except Exception:
            pass

    # Also check any config files
    for fpath in skill_path.rglob("*.json"):
        try:
            scan_files.append((str(fpath.relative_to(skill_path)), fpath.read_text(errors='ignore')))
        except Exception:
            pass

    for filename, content in scan_files:
        for pattern, description, severity in INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, content, re.DOTALL))
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].replace('\n', ' ').strip()

                finding = {
                    "type": "prompt_injection",
                    "pattern": pattern,
                    "description": description,
                    "severity": severity,
                    "file": filename,
                    "context": f"...{context}..."
                }
                # Deduplicate: don't add same pattern+file combos
                if not any(f["pattern"] == pattern and f["file"] == filename for f in results["findings"]):
                    results["findings"].append(finding)

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
        print("Usage: prompt-inject.py <skill_path>")
        sys.exit(1)
    try:
        result = check_prompt_injection(sys.argv[1])
    except Exception as e:
        result = {
            "check": "prompt_injection",
            "status": "warn",
            "findings": [],
            "errors": [f"Prompt injection analysis failed: {str(e)}"]
        }
    print(json.dumps(result, indent=2))