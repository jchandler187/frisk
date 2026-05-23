# ClawSec v2 Independent Security Audit

**Auditor:** 2Clawz (subagent, Claude Code audit session)
**Date:** 2026-05-23
**Target:** ClawSec v2.0.0 — Skill Verification Orchestrator
**Host:** Node-2 (192.168.1.86), ~/projects/clawsec/
**Schema Version:** 2.0.0

---

## Fixture Test Results

| Fixture | Expected Verdict | Actual Verdict | Findings | Severity Breakdown | Time | Pass? |
|---|---|---|---|---|---|---|
| fixture-clean | PASS | PASS | 0 | — | 7.34s | ✅ |
| fixture-hardcoded-secret | FAIL | FAIL | 2 | 0C/2H/0M | 6.48s | ✅ |
| fixture-base64-payload | FAIL | WARN | 1 | 0C/1H/0M | 6.56s | ⚠️ |
| fixture-malware-hash | FAIL | FAIL | 1 | 1C/0H/0M | 6.58s | ✅ |
| fixture-path-traversal | FAIL | FAIL | 2 | 2C/0H/0M | 6.77s | ✅ |
| fixture-shell-injection | FAIL | FAIL | 1 | 1C/0H/0M | 6.59s | ✅ |
| fixture-kev-dep | WARN | WARN | 7 | 0C/2H/1M/4L | 7.39s | ✅ |
| fixture-urlhaus-url | FAIL | PASS | 0 | — | 6.63s | ❌ |
| red-team-1 | FAIL | PASS | 0 | — | 6.67s | ❌ |
| red-team-2 | FAIL | PASS | 0 | — | 6.63s | ❌ |
| red-team-3 | FAIL/WARN | WARN | 3 | 0C/2H/1M | 6.60s | ⚠️ |
| red-team-4 | WARN | WARN | 1 | 0C/0H/0M/1L | 7.30s | ✅ |
| red-team-5 | FAIL | FAIL | 3 | 1C/1H/1M | 6.65s | ✅ |
| red-team-reaudit-1 | FAIL | FAIL | 2 | 2C/0H/0M | 6.81s | ✅ |
| red-team-reaudit-2 | FAIL | PASS | 0 | — | 6.67s | ❌ |
| red-team-reaudit-3 | FAIL | FAIL | 1 | 1C/0H/0M | 6.58s | ✅ |
| red-team-reaudit-4 | WARN | WARN | 1 | 0C/0H/0M/1L | 7.32s | ✅ |
| red-team-reaudit-5 | FAIL | PASS | 0 | — | 6.69s | ❌ |

## Evasion Test Results

Created `/tmp/audit-test/SKILL.md` with three deliberate evasion techniques plus a bonus malicious dependency:

| Evasion Technique | Detection | Caught? |
|---|---|---|
| GitHub PAT (`ghp_A1b2...`) | secret_scan: PASS (0 findings) | ❌ **MISSED** |
| `eval()` call in function | behavioral_heuristics: `dangerous_shell` (critical) | ✅ Caught |
| Cyrillic homoglyph URLs (`pаypal.com`, `gооgle.com`) | ioc_match: homoglyph detection (4 findings, critical) | ✅ Caught |
| Typosquat dependency (`lodassh`) | dep_scan: PASS (0 findings) | ❌ **MISSED** |

**Overall evasion verdict:** FAIL (2 of 4 evasion techniques caught). The tool caught the two most sophisticated vector types (homoglyphs, eval) but missed the two most common attack patterns (credential leaks, typosquat packages).

---

## Bugs Found

### BUG-001: URLhaus IOC lookup not matching known-malicious IPs [P0 — CRITICAL]

**Fixtures affected:** `fixture-urlhaus-url`, `red-team-1`, `red-team-2`

The `ioc_match` check correctly extracts URLs, IPs, and domains from skill content but fails to match them against the URLhaus intel feed. Both `fixture-urlhaus-url` and `red-team-1` contain the known-malicious URL `http://110.36.15.1:37864/i` (listed in URLhaus). The check reports extracting 1 URL, 1 IP, 1 domain — yet returns 0 findings (PASS).

This means **any URLhaus-listed C2 URL in a skill passes verification**. This is the most serious gap in the scanner.

### BUG-002: GitHub Personal Access Token pattern not detected by secret_scan [P0 — CRITICAL]

**Evasion test affected:** `ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7`

The `secret_scan` check caught AWS access key patterns (AKIA...) in `fixture-hardcoded-secret` but completely missed the `ghp_` GitHub PAT pattern in the evasion test. The tool uses Semgrep rules for secret detection — the `generic-api-key` rule caught the AWS secret key, and `aws-access-token` caught the AKIA prefix, but no rule covers GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes).

This is a common credential type in CI/CD skill packages and should be added to the secret scanning ruleset.

### BUG-003: Base64-encoded ELF binary scored as WARN instead of FAIL [P1 — HIGH]

**Fixture affected:** `fixture-base64-payload`

The `fixture-base64-payload` skill contains a full ELF binary (the `f0VMRgIB...` magic bytes decode to a Linux x86-64 ELF). The behavioral check correctly identifies it as a "large base64 payload (appears binary)" but rates it `high` severity rather than `critical`. A compiled executable embedded as base64 in a skill package is a trojan horse — it should be a critical/Fail verdict, not a warning.

### BUG-004: Typosquat dependency not flagged [P1 — HIGH]

**Evasion test / red-team-reaudit-4:** The `lodassh` package (a known typosquat of `lodash`, flagged by OSV advisory MAL-2025-25511) was only caught at `low` severity in `red-team-reaudit-4` (WARN verdict). In the evasion test, it wasn't detected at all because the skill had no `package.json` or explicit dependency declaration — the dep scan only processes structured dependency manifests, not informal references in SKILL.md prose.

This means an attacker can reference malicious packages in documentation text and bypass dependency scanning entirely.

### BUG-005: red-team-2 (string-concatenated malicious URL) passes all checks [P1 — HIGH]

**Fixture affected:** `red-team-2`

The skill constructs `http://110.36.15.1:37864/i` via string concatenation (`"http://110.36.15" + ".1:37864/i"`). The `ioc_match` check only extracts literal URLs from text — it doesn't perform taint analysis or string concatenation deobfuscation. This same URL was listed in URLhaus but wouldn't be caught even if URLhaus matching worked (BUG-001), because the URL is never present as a complete literal string.

### BUG-006: red-team-reaudit-5 (environment-conditional exfiltration) not detected [P1 — HIGH]

**Fixture affected:** `red-team-reaudit-5`

This skill contains a Python backdoor pattern: `if os.environ.get('DEPLOY_MODE'):` that conditionally exfiltrates `AWS_SECRET_ACCESS_KEY` to `http://malicious-c2.example.com/exfil`. The scanner gave it a clean PASS. The behavioral heuristics engine doesn't model conditional execution paths or data flow from environment variables to outbound network calls.

### BUG-007: red-team-reaudit-2 (concatenated URL evasion) passes all checks [P1 — HIGH]

**Fixture affected:** `red-team-reaudit-2`

Same as BUG-005 but with JavaScript syntax: `var url = "http://110.36.15" + ".1:37864/i"`. No check detected this obfuscation. The `ioc_match` module extracted 1 URL but scored 0 findings, and the behavioral heuristics didn't flag string concatenation near URL construction.

### BUG-008: static_analysis check silently fails on fixture-hardcoded-secret [P2 — MEDIUM]

**Fixture affected:** `fixture-hardcoded-secret`

The JSON report for this fixture shows `"errors": ["check failed"]` in the static_analysis section. The overall verdict is still FAIL (because secret_scan caught it), but a silently failing static analysis check is concerning — there's no surface-level indication that a full check didn't run.

---

## Severity Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| BUG-001 | P0 / Critical | URLhaus IP/domain matching non-functional | Open |
| BUG-002 | P0 / Critical | GitHub PAT patterns not scanned | Open |
| BUG-003 | P1 / High | Base64 ELF binary scored WARN, not FAIL | Open |
| BUG-004 | P1 / High | Typosquat deps in prose (no manifest) not scanned | Open |
| BUG-005 | P1 / High | String-concatenated URLs bypass IOC extraction | Open |
| BUG-006 | P1 / High | Conditional exfiltration paths not modeled | Open |
| BUG-007 | P1 / High | JS string concat URL evasion passes all checks | Open |
| BUG-008 | P2 / Medium | static_analysis silent check failure | Open |

---

## Overall Verdict: **FIX_THEN_SHIP**

The architecture is solid — 7 checks, intel feeds, homoglyph detection, behavioral heuristics. The checks that work work well (secret scanning for AWS keys, path traversal detection, eval() detection, homoglyph detection, malware hash matching, KEV dependency scanning). But there are two P0 flaws that make the tool unreliable as a gate:

1. **URLhaus matching is broken.** The #1 reason to have IOC matching is to catch known-bad URLs and IPs, and it's not doing that. Three test fixtures and one evasion technique sailed through because of this.

2. **GitHub PATs sail through secret_scan.** If you're scanning skill packages for CI/CD pipelines, this is the credential type you're most likely to find.

Until BUG-001 and BUG-002 are fixed, a skill author can include a known C2 URL and a GitHub PAT in plain text and receive a PASS verdict. That's not a ship-ready security gate.

Ship after BUG-001 and BUG-002 are resolved. BUG-003 through BUG-007 are important but can be tracked as follow-up; they represent harder evasion classes that require deeper analysis (taint tracking, string deobfuscation, semantic code analysis). BUG-008 should also be fixed before shipping since silent check failures undermine trust in the overall verdict.