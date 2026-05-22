# Audit Pass 3: P0 Fix Report

**Date:** 2026-05-22
**Auditor:** 2Clawz (subagent)
**Scope:** Fix all 7 P0 findings from adversarial audit

---

## Summary

All 7 P0 findings fixed, tested, and validated.

| P0 | Finding | Status |
|----|---------|--------|
| P0-1 | dep-scan cross-matches npm deps against PyPI advisories | ✅ Fixed |
| P0-2 | URLhaus sync produces garbage data | ✅ Fixed |
| P0-3 | MalwareBazaar hash matching broken by CSV quoting | ✅ Fixed |
| P0-4 | Missing intel cache produces silent pass | ✅ Fixed |
| P0-5 | Path traversal not detected | ✅ Fixed |
| P0-6 | Unicode homoglyph bypass | ✅ Fixed |
| P0-7 | Shell injection rated "warn" instead of "fail" | ✅ Fixed |

---

## Detailed Fixes

### P0-1: dep-scan ecosystem filtering

**File:** `lib/skill-verify/checks/dep-scan.py`

**Problem:** `parse_skill_deps()` tagged deps with ecosystem labels (npm/PyPI), but `check_dependencies()` always loaded both `npm` and `PyPI` OSV advisories and matched all deps against all ecosystems. An npm package named "requests" would falsely match the PyPI "requests" CVE.

**Fix:** Changed `check_dependencies()` to only load OSV ecosystems that match the ecosystems found in the skill's deps. Only deps tagged `npm` are checked against npm OSV advisories; only deps tagged `PyPI` are checked against PyPI advisories. No cross-matching.

Also added intel cache validation to `check_dependencies()` — if OSV/CISA-KEV/EPSS data is missing, it emits `intel_missing` findings with `critical` severity.

### P0-2: URLhaus sync stabilizes filename

**File:** `lib/intel-sync/sources/urlhaus.sh`

**Problem:** The actual URLhaus ZIP contains a file called `csv.txt` (not matching `*.csv` glob). The `unzip -p '*.csv'` glob was fragile and could fail silently, producing empty or garbage data.

**Fix:** Tested the actual download to confirm the inner filename is `csv.txt`. Changed the script to extract `$URLHAUS_INNER_FILE` (set to `csv.txt`) explicitly instead of using a glob. Added `mkdir -p` for the urlhaus directory. The extracted file is written to the stable path `${INTEL_DIR}/urlhaus/urls.csv` so `ioc-match.py` always knows where to find it.

Synced URLhaus after fix: 77,944 records loaded successfully.

### P0-3: MalwareBazaar CSV proper parsing

**File:** `lib/skill-verify/checks/ioc-match.py`

**Problem:** `load_malwarebazaar_hashes()` used `line.split(',')` to parse CSV rows, but MalwareBazaar CSV has quoted fields containing commas and spaces. Regex-based hash extraction would miss or mangle hashes when fields contained commas.

**Fix:** Replaced all manual `line.split(',')` parsing with Python's `csv.reader()`. For MalwareBazaar, the SHA256 hash is extracted from column index 1 by position, not by regex. For URLhaus, the URL is extracted from column index 2. All fields are `.strip()`'d and quotes are handled automatically by the csv module.

### P0-4: Missing/corrupt intel cache → fail, not silent pass

**Files:** `lib/skill-verify/verify.sh`, `lib/skill-verify/checks/ioc-match.py`, `lib/skill-verify/checks/dep-scan.py`

**Problem:** If `/srv/clawsec/intel/` didn't exist, or individual cache files were missing, all checks would silently produce zero findings and `verify.sh` would return "pass". A security tool saying "everything's fine" when it can't check anything is the worst failure mode.

**Fix:**

1. **verify.sh**: Added pre-check that `INTEL_DIR` exists and `manifest.json` is present. Added `--strict` flag that fails (exit 2) if ANY intel source is missing. In default mode, warns but continues with available data. If `INTEL_DIR` doesn't exist at all, verdict is overridden to "fail" regardless.

2. **Each check script**: Now validates its required cache files exist before running. If a cache file is missing, it adds an `intel_missing` finding with `critical` severity. If the entire `INTEL_DIR` is missing, the check returns `status: "fail"` early.

3. **dep-scan.py**: Added `check_intel_cache()` function that validates CISA KEV, OSV, and EPSS cache files. Missing sources produce `intel_missing` findings.

4. **ioc-match.py**: Added `check_intel_cache()` function that validates URLhaus, MalwareBazaar, Feodo, and ThreatFox cache files.

### P0-5: Path traversal detection

**File:** `lib/skill-verify/checks/behavioral.py`

**Problem:** A skill manifest containing `../../../etc/passwd` or `/etc/shadow` passed all checks with zero findings.

**Fix:** Added two new pattern lists to behavioral.py:

- `PATH_TRAVERSAL_PATTERNS`: Detects `../etc/`, `..\etc\`, nested `../../`, etc. — flagged as `type: "path_traversal"`, `severity: "critical"`.
- `PATH_ABSOLUTE_FORBIDDEN`: Detects absolute paths to `/etc/`, `/var/`, `/usr/` (except `/usr/local/`), `/root/`, `/home/<other-user>/` — flagged as `type: "path_traversal"`, `severity: "critical"`.

Test fixture `/tmp/clawsec-test-fixtures/path-traversal/` confirms detection: 3 critical + 2 high findings, verdict FAIL.

### P0-6: Unicode homoglyph bypass

**File:** `lib/skill-verify/checks/ioc-match.py`, `lib/skill-verify/checks/behavioral.py`

**Problem:** URLs containing Cyrillic homoglyph characters (e.g., Cyrillic 'а' U+0430) would not match against URLhaus entries using Latin equivalents, allowing phishing domains to evade detection.

**Fix:** Added `normalize()` function to `ioc-match.py` that applies:
1. Unicode NFKC normalization (handles fullwidth, ligatures, compatibility decompositions)
2. Explicit confusable character mapping (Cyrillic → Latin, Greek → Latin)

The `CONFUSABLES` dictionary maps 24+ commonly-confused characters including Cyrillic а→a, е→e, о→o, р→p, с→c and Greek α→a, etc.

Normalization is applied:
- At **IOC data load time** in `load_urlhaus_urls()`, `load_malwarebazaar_hashes()`, `load_feodo_ips()`
- At **extraction time** in `extract_iocs()` and `check_behavioral()`

The same `normalize()` function is imported/applied in behavioral.py for URL and path extraction.

Verified: `normalize('pаypal.com')` (Cyrillic а) → `'paypal.com'` (Latin a).

### P0-7: Shell injection severity escalation

**Files:** `lib/skill-verify/checks/behavioral.py`, `lib/skill-verify/checks/static-analysis.sh`, `lib/skill-verify/report.py`

**Problem:** `os.system(user_input)` and `subprocess.call(cmd, shell=True)` were rated `high` severity, not `critical`. For a security verification tool, RCE vectors must be critical/fail severity.

**Fix:**

1. **behavioral.py**: Added post-processing escalation step that promotes `dangerous_shell` type findings from `high` to `critical`. Also checks pattern descriptions for `os.system`, `shell=True`, `execSync`, `child_process.exec`. Path traversal, hardcoded secrets, and command/shell injection categories are all escalated via the `ESCALATE_TO_CRITICAL` set.

2. **static-analysis.sh**: Added jq filter that promotes Semgrep findings with rule IDs containing `command.injection`, `shell.injection`, `os.system`, `path.traversal`, `hardcoded.secret`, `secret.in.code`, or `insecure-exec` from `WARNING` to `ERROR` severity before computing overall check status.

3. **report.py**: Added severity escalation in `generate_report()` that promotes findings by type, category, or pattern to `critical` regardless of what the original check reported. Categories: `command_injection`, `shell_injection`, `path_traversal`, `hardcoded_secret`, `secret_in_code`. Pattern keywords: `os.system`, `shell=True`, `execSync`, `child_process.exec`.

Test fixture `/tmp/clawsec-test-fixtures/shell-inject/` confirms detection: 2 critical findings, verdict FAIL.

---

## Test Results

| Fixture | Expected | Actual |
|---------|----------|--------|
| clean-skill | PASS | ✅ PASS (0 findings) |
| path-traversal | FAIL | ✅ FAIL (3 critical, 2 high) |
| shell-inject | FAIL | ✅ FAIL (2 critical) |
| homoglyph | (IOC-match extracts normalized URLs) | ✅ NFKC+confusable normalization working |

**Intel sync:** All 9 sources synced successfully. URLhaus now returns 77,944 records (was 0 before fix).

**CLI:** `python3 cli/clawsec.py status` runs without error.

**Bash syntax:** All modified `.sh` files pass `bash -n`.
**Python syntax:** All modified `.py` files pass `python3 -m py_compile`.