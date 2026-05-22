# ClawSec v2 — P0/P1 Fix Summary

**Date:** 2026-05-22  
**Auditor:** 2Clawz (subagent)  
**Scope:** All P0 and P1 bugs from `01-errors.md`

---

## P0 Fixes

### P0-1: YARA scan never actually scans anything ✅
**File:** `lib/skill-verify/checks/yara-scan.sh`  
**Fix:** Replaced `yara -C "$f" -o /dev/null` (wrong: -C means load compiled rules) with `yarac "$f" /dev/null` (test-compile). Now builds a combined rule file from all valid rules, compiles with `yarac`, and scans with `-C` flag (now correct: loading our own compiled rules). Falls back to individual source-rule scanning if combined compilation fails. Removed dead `meta_file`/`compile_log` variables.

### P0-2: URLhaus sync saves raw ZIP as CSV ✅
**File:** `lib/intel-sync/sources/urlhaus.sh`  
**Fix:** Download ZIP to temp file, decompress with `unzip -p "$zip_tmp" '*.csv'` before saving as CSV. Count adjusted to `wc -l - 1` (minus header), matching EPSS pattern. ZIP temp file cleaned up after.

### P0-3: URLhaus matching uses substring comparison ✅
**File:** `lib/skill-verify/checks/ioc-match.py:113-117`  
**Fix:** Replaced `url_lower in bad_url or bad_url in url_lower` with exact URL matching using `urllib.parse.urlparse`. Compares `(scheme, hostname, path)` tuples. No more false positives from substring containment.

### P0-4: dep-scan CVE extraction reads wrong field ✅
**File:** `lib/skill-verify/checks/dep-scan.py:64`  
**Fix:** Changed from `[r.get("id") for r in adv.get("references", []) if "CVE" in r.get("id", "")]` to `[a for a in adv.get("aliases", []) if a.startswith("CVE-")]`. OSV uses `aliases` for CVE cross-references, not `references[].id`.

### P0-5: dep-scan version matching misses 93% of vulnerable packages ✅
**File:** `lib/skill-verify/checks/dep-scan.py:88`  
**Fix:** Added `version_in_range()` function using `packaging.version.Version` to parse OSV `ranges[].events` (introduced/fixed/last_affected). Version matching now checks both explicit `versions` list and semver/ecosystem ranges. Added `packaging>=23.0` to `requirements.txt`.

---

## P1 Fixes

### P1-1: API path traversal ✅
**File:** `api/src/routes.js:73,82`  
**Fix:** Added `sanitizeId()` function — validates id is alphanumeric+hyphens only. Both `/report/:id` and `/badge/:id` endpoints now sanitize the id, then use `path.resolve()` + `startsWith(REPORTS_DIR + path.sep)` as a belt-and-suspenders check.

### P1-2: API shell injection via slug ✅
**File:** `api/src/routes.js:31`  
**Fix:** Replaced `execSync('clawhub install "' + slug + '" --dir "' + tmpDir + '"')` with `execFileSync('clawhub', ['install', slug, '--dir', tmpDir])`. Array args bypass shell interpolation entirely.

### P1-3: Private IP filter only blocks 172.16.x ✅
**File:** `lib/skill-verify/checks/ioc-match.py:87`  
**Fix:** Replaced `ip.startswith(('172.16.', ...))` with `is_private_ip()` function that properly checks RFC 1918 172.16.0.0/12 range: first octet 172 and second octet 16-31.

### P1-4: Feodo CSV column index wrong ✅
**File:** `lib/skill-verify/checks/ioc-match.py:75-84`  
**Fix:** Replaced manual `line.split(",")` with `csv.reader()` for proper quote handling. IP now read from column index 1 (`dst_ip`) instead of column 0 (`first_seen_utc`).

---

## Verification

All fixes verified:
- `python cli/clawsec.py status` — runs cleanly
- `python cli/clawsec.py scan /tmp/test-clean-skill/` — completes with PASS verdict, 0 findings, no crash
- `is_private_ip()` — tested all edge cases (172.17-172.31 private, 172.32+ public)
- `version_in_range()` — tested introduced/fixed ranges, no-fix ranges, ecosystem type
- CVE alias extraction — confirmed old code returns empty, new code extracts from aliases
- URLhaus exact matching — confirmed substring false positive eliminated, exact match works
- API sanitizeId — path traversal and injection characters rejected
- API execFileSync — no shell interpolation
- Feodo CSV — csv.reader correctly extracts IP from quoted column index 1
- Both shell scripts pass `bash -n` syntax check
- `routes.js` passes `node -c` syntax check
- `packaging` installed in venv