# ClawSec v2 — Independent Verification Audit

**Date:** 2026-05-22  
**Auditor:** Fresh subagent (no prior exposure to codebase)  
**Tool version:** 2.0.0  

---

## Step 1: Intel Cache Status

All 9 intel sources synced and populated:

| Source | Records | Status |
|--------|---------|--------|
| CISA KEV | 1,601 | ✅ success |
| EPSS | 334,568 | ✅ success |
| MalwareBazaar | 3,464 | ✅ success |
| URLhaus | 77,943 | ✅ success |
| ThreatFox | 3,165 | ✅ success |
| Feodo Tracker | 6 | ✅ success |
| YARA Rules | 746 | ✅ success |
| Semgrep Rules | 2,183 | ✅ success |
| OSV | 239,251 | ✅ success |

All synced today (2026-05-22). No stale sources. ✅

---

## Step 2: Fixture Results

### 2a: Clean skill (expected PASS, zero findings)

- **Exit code:** 0
- **Verdict:** PASS
- **Findings:** 0 total
- **Result:** ✅ PASS — matches expected

### 2b: Shell injection — `os.system(user_input)` (expected FAIL, critical)

- **Exit code:** 2
- **Verdict:** FAIL
- **Findings:** 1 critical (behavioral_heuristics: `os.system()` call)
- **Result:** ✅ PASS — matches expected

### 2c: Hardcoded AWS secret (expected FAIL, critical)

- **Exit code:** 0
- **Verdict:** PASS
- **Findings:** 0 total
- **Result:** ❌ FAIL — secret was NOT detected

**Root cause:** The test fixture used AWS example keys (`AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`). Gitleaks intentionally allows these well-known example credentials. When re-tested with a realistic-looking non-example key (`AKIAISO3FODNN7REALLY`), gitleaks correctly detected it.

**Assessment:** This is a **test fixture quality issue**, not a ClawSec bug. Gitleaks' allowlist for known example keys is correct behavior. However, this reveals a **real gap**: ClawSec has no secondary check for credentials that look like secrets but happen to be example values. If a malicious skill embeds AWS example keys as placeholders that work in a specific environment, they'd be missed. The behavioral heuristics also don't flag `AWS_ACCESS_KEY_ID=` patterns in `.env` files. **Severity: P1 — recommend adding a dedicated credential-pattern heuristic (regex for `AWS_ACCESS_KEY_ID=AKIA...`, `AWS_SECRET_ACCESS_KEY=...`, etc.) as a complement to gitleaks, or at minimum a warning for AWS example keys.**

### 2d: Path traversal — `../../../etc/passwd` (expected FAIL, critical)

- **Exit code:** 2
- **Verdict:** FAIL
- **Findings:** 2 critical (path_traversal patterns matched)
- **Result:** ✅ PASS — matches expected

### 2e: Unicode homoglyph — Cyrillic `а` in `pаypal.com` (expected detection)

- **Exit code:** 0
- **Verdict:** PASS
- **Findings:** 0 total
- **Result:** ❌ FAIL — homoglyph was NOT detected

**Root cause:** The ioc-match check normalizes text before extraction using a confusable-to-Latin mapping. `pаypal.com` (with Cyrillic а U+0430) is normalized to `paypal.com` before URL extraction. Then `paypal.com` is correctly identified as a safe domain and skipped. The homoglyph is **silently normalized away without generating a finding**.

**Assessment:** This is a **P0 bug**. The entire point of homoglyph detection is to flag that the original text used deceptive Unicode characters. The code normalizes correctly (mapping is accurate) but never compares original vs. normalized to emit a finding. An attacker could register `pаypal.com` (Cyrillic homoglyph) and it would sail through ClawSec undetected because the normalized form matches a safe domain. The fix: after normalization, compare original and normalized text; if they differ, emit a `unicode_homoglyph` finding at `high` or `critical` severity.

### 2f: Dependency with known vulnerability — express 4.17.3 (expected WARN or FAIL)

- **Exit code:** 1
- **Verdict:** WARN
- **Findings:** 3 total (0 critical, 0 high, 2 medium, 1 low)
- **Result:** ✅ PASS — express 4.17.3 vulnerabilities detected as medium severity

---

## Step 3: Report Verification

Checked 7 reports in `~/clawsec-v2/reports/`:

| Field | Present? | Notes |
|-------|----------|-------|
| `schema_version` | ✅ Yes | Value: `"2.0.0"` |
| `version` | ❌ Not in report alongside schema_version | Reports have `schema_version` but not `version` — the README implies both might exist; minor inconsistency |
| Intel cache timestamps | ✅ Yes | All 9 sources present with ISO timestamps |
| Missing intel | ✅ Handled | Graceful degradation — checks report errors if sources missing |

**Note on `version` vs `schema_version`:** Reports have `schema_version: "2.0.0"` but no `version` field. The `report.py` code sets `schema_version`, not `version`. The earlier report format used `version`. Not a bug since schema_version serves the versioning purpose, but the field name changed between code and README reference.

---

## Step 4: Bypass Attempt

Created a creative bypass skill with:
1. **String concatenation** splitting `https://evil.example.com` across multiple parts
2. **Base64-encoded payload**: `aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk7` (decodes to `import os; os.system('rm -rf /');`)
3. **eval()** of the decoded payload
4. **Hidden prompt injection** in an HTML comment inside `<details>`

**Result: FAIL (exit 2, 4 critical findings)**

| Finding | Source |
|---------|--------|
| `eval()` call — dynamic code evaluation | behavioral_heuristics |
| `curl pipe to shell — classic RCE pattern` | behavioral_heuristics (from prompt injection text) |
| Attempts to disregard safety rules | prompt_injection |
| Attempts role manipulation to bypass safety | prompt_injection |

**What was caught:** eval(), the curl-to-shell text in the HTML comment, and two prompt injection patterns.  
**What was NOT caught:** The base64 payload itself (decoded to `import os; os.system('rm -rf /')`) — it was only 61 bytes encoded, well under the 2KB threshold. The string concatenation obfuscation of the URL wasn't detected (documented limitation). The `require()` pattern wasn't separately flagged.

---

## Findings Summary

### P0 — Critical Bugs

1. **Unicode homoglyph detection is broken**: The `normalize()` function in `ioc-match.py` correctly maps confusable characters to Latin equivalents but never emits a finding when the original text differs from normalized. Homoglyph phishing URLs currently pass undetected because the normalized form matches a safe/domain or misses the threat feed entirely.

### P1 — High Priority

2. **No credential-pattern heuristic complement to gitleaks**: Well-known example secrets (AWS example keys, test GitHub tokens, etc.) pass gitleaks' allowlist and get zero detection. Recommend adding a regex-based credential-pattern check in behavioral heuristics that at minimum warns on patterns like `AWS_ACCESS_KEY_ID=AKIA...`, `AWS_SECRET_ACCESS_KEY=`, `GITHUB_TOKEN=ghp_`, etc. — even if they turn out to be examples, the user should be aware.

### P2 — Medium / Low

3. **Base64 payload threshold too high for short payloads**: The 2KB threshold for suspicious base64 detection means a 61-byte encoded `rm -rf /` payload goes undetected. It was caught by the `eval()` heuristic, but the base64 content itself isn't flagged. Consider lowering the threshold or adding a secondary check that decodes smaller base64 strings and scans the decoded content for dangerous patterns.

4. **Report field inconsistency**: Reports use `schema_version` but README references `version`. Minor but could confuse API consumers.

5. **`version` field missing from reports**: Earlier reports had a `version` field; current reports have `schema_version` instead. The change isn't documented.

---

## Overall Verdict

**FIX_THEN_SHIP**

The tool works well for its primary use cases — shell injection, path traversal, dependency vulnerabilities, prompt injection, and behavioral patterns are all detected correctly. The bypass attempt was caught. The intel cache is healthy and well-populated.

However, the **P0 homoglyph bug** is a real security gap. An attacker can register lookalike domains using Cyrillic/Greek characters and they'll be normalized away to safe domains without any finding. This needs to be fixed before shipping.

The P1 credential-pattern heuristic is a hardening measure that should be added in the next iteration but doesn't block a v2.0 release if the P0 is fixed first.

**Required before ship:**
- Fix homoglyph detection in `ioc-match.py` to emit findings when original ≠ normalized text
- Add at least a warning-level finding for common credential patterns (`AWS_ACCESS_KEY_ID=`, `SECRET_KEY=`, etc.) as a complement to gitleaks

**Recommended but not blocking:**
- Lower or tier the base64 payload size threshold
- Align report field names (`version` vs `schema_version`)