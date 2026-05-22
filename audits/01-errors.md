# ClawSec v2 — Error Audit (Pass 1)

**Date:** 2026-05-22  
**Auditor:** 2Clawz (subagent)  
**Scope:** All source code in ~/clawsec-v2/ (excluding .venv/, node_modules/)

## Summary

| Severity | Count |
|----------|-------|
| P0 (Critical — broken/insecure, must fix before shipping) | 5 |
| P1 (High — wrong results or data loss under normal use) | 4 |
| P2 (Medium — wrong under edge cases, missing validation) | 4 |
| P3 (Low — cosmetic, dead code, inefficiency) | 3 |
| **Total** | **16** |

---

## P0 — Critical

### P0-1: YARA scan never actually scans anything
**File:** `lib/skill-verify/checks/yara-scan.sh:33`  
**Description:** The rule validation loop uses `yara -C "$f" -o /dev/null` to test if a rule file is valid. `-C` means "load compiled rules" (not "compile rules"), and `-o` is not a valid yara flag. This command always fails (exit 123), so `good_rules` is always empty, and the yara-scan check produces zero findings for any input. The entire YARA check is a no-op.  
**Fix:** Replace with `yara "$f" /dev/null 2>/dev/null` (test compile by scanning empty input), or use `yarac "$f" /dev/null 2>/dev/null` (yarac compiles, checking syntax). Then use compiled rules for the actual scan for performance.

### P0-2: URLhaus sync saves raw ZIP as CSV — IOC matching reads garbage
**File:** `lib/intel-sync/sources/urlhaus.sh:14-17`  
**Description:** The URLhaus source downloads from `https://urlhaus.abuse.ch/downloads/csv/` which serves a ZIP-compressed CSV. The sync script saves it directly as `urls.csv` without decompressing. Python's `load_urlhaus_urls()` reads the zip file as text, producing garbage strings. These garbage strings then match everything via the substring comparison in `ioc-match.py:113-117`, causing massive false positives (github.com, clawhub.ai, etc. are flagged as malicious).  
**Fix:** Decompress the ZIP before saving, like `epss.sh` does with gunzip. Use `unzip -p` or `python3 -c "import zipfile; ..."` to extract the inner CSV.

### P0-3: URLhaus matching uses substring comparison — extreme false positive rate
**File:** `lib/skill-verify/checks/ioc-match.py:113-117`  
**Description:** Even if the URLhaus data were correct, the matching uses `url_lower in bad_url or bad_url in url_lower` — a substring match. Any skill URL that contains any URLhaus URL as a substring (or whose URL is a substring of a URLhaus entry) triggers a finding. For example, if URLhaus has `http://evil.com/pattern`, then `https://github.com/user/pattern-readme` would match because "pattern" is a substring. This produces huge false positive rates.  
**Fix:** Use exact URL matching or at minimum domain+path prefix matching. Parse both URLs and compare scheme+host+path, not substring containment.

### P0-4: dep-scan OSV CVE ID extraction reads wrong field — no CVE cross-referencing
**File:** `lib/skill-verify/checks/dep-scan.py:64`  
**Description:** CVE IDs are extracted from OSV advisories with `[r.get("id") for r in adv.get("references", []) if "CVE" in r.get("id", "")]`. But OSV reference objects use key `"url"`, not `"id"`. This always returns an empty list, so no findings ever get KEV or EPSS enrichment. The correct source for CVE IDs is `adv.get("aliases", [])` (which contains CVE identifiers directly) plus parsing the `"url"` field of references.  
**Fix:** Change to: `cve_ids = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]`

### P0-5: dep-scan version matching misses 93% of vulnerable packages
**File:** `lib/skill-verify/checks/dep-scan.py:88`  
**Description:** Version matching checks `ver in adv["versions"]` — exact membership in a versions list. Only ~7% of OSV advisories include a `versions` list; the rest define vulnerability ranges via `ranges` (semver events). Packages with known vulnerabilities but no explicit versions list are never flagged. This means dep-scan is ineffective for the vast majority of advisories.  
**Fix:** Implement semver range resolution. Parse `ranges[].events` (introduced/fixed) and test if the dep's version falls within the vulnerable range. Libraries like `packaging` (Python) or `semver` can handle this.

---

## P1 — High

### P1-1: API path traversal in report and badge endpoints
**File:** `api/src/routes.js:73,82`  
**Description:** `req.params.id` is interpolated directly into a file path with no validation. A request to `/api/v1/report/....//....//....//etc//passwd` resolves outside REPORTS_DIR. `path.join` doesn't prevent traversal with enough `../` segments. No check that the resolved path starts with REPORTS_DIR.  
**Fix:** Add `const resolved = path.resolve(REPORTS_DIR, id + '.json'); if (!resolved.startsWith(REPORTS_DIR + path.sep)) return res.status(403).json({error:'invalid id'});` Also sanitize id to alphanumeric+hyphens only.

### P1-2: API scan route — shell injection via slug
**File:** `api/src/routes.js:31`  
**Description:** `execSync('clawhub install "' + slug + '" --dir "' + tmpDir + '"')` interpolates user-provided `slug` into a shell command with only double-quote escaping. A slug like `foo"; rm -rf /; echo "` would execute arbitrary commands.  
**Fix:** Use `execFileSync('clawhub', ['install', slug, '--dir', tmpDir])` instead — passes args without shell interpolation. Or escape the slug rigorously.

### P1-3: Private IP filter only blocks 172.16.x — misses 172.17-172.31
**File:** `lib/skill-verify/checks/ioc-match.py:87`  
**Description:** The private IP exclusion list checks `ip.startswith(('127.', '10.', '172.16.', '192.168.', '0.'))`. RFC 1918 defines the 172.x private range as 172.16.0.0/12, covering 172.16.0.0 through 172.31.255.255. IPs like 172.20.0.1 are private but pass through, potentially causing false positives against internal infrastructure addresses.  
**Fix:** Replace `172.16.` with proper CIDR check: parse first two octets and check `172.16 <= int(octet2) <= 31` when first octet is 172.

### P1-4: Feodo Tracker IP CSV — column index assumes fixed format
**File:** `lib/skill-verify/checks/ioc-match.py:75-84`  
**Description:** `load_feodo_ips()` takes `parts[0]` as the IP, but the actual Feodo CSV has `"first_seen_utc","dst_ip",...` format with quoted fields and the IP is at column index 1 (after splitting on comma). Splitting `'"2022-06-04 21:24:53","162.243.103.246","8080",...'` on commas gives `parts[0] = '"2022-06-04 21:24:53"'`, not the IP. The current code matches zero IPs.  
**Fix:** Parse as proper CSV (with quote handling), or use `csv.reader`, or extract IP via regex from the line rather than positional split.

---

## P2 — Medium

### P2-1: manifest.py atomic write is not atomic on different filesystem
**File:** `lib/intel-sync/manifest.py:24-27`  
**Description:** `os.rename(tmp, MANIFEST_PATH)` uses `os.rename` which is atomic on the same filesystem but fails with `OSError` cross-filesystem. The tmp file default location is `/srv/clawsec/intel/` (same dir as manifest), so this works in practice, but if `/srv/clawsec/intel` is a different mount, the rename would fail silently. More importantly, there's no `os.sync()` or `fsync` before rename, so a crash between write and rename could lose data.  
**Fix:** Add `f.flush(); os.fsync(f.fileno())` before close. Use `os.replace()` instead of `os.rename()` (works cross-filesystem on Python 3.3+).

### P2-2: verify.sh report.py invocation fails silently — fallback jq path drops fields
**File:** `lib/skill-verify/verify.sh:72-85`  
**Description:** The inline Python invocation of `report.py` has `sys.path.insert(0, sys.argv[1])` where argv[1] is the SCRIPT_DIR. If Python can't import `report` (e.g. path issue), the fallback assembles a minimal report via jq that lacks `report_id`, `summary`, and `intel_cache` fields. The verdict computation in the fallback also differs from report.py's logic.  
**Fix:** Add error propagation from the inline Python call. If it fails, log the error and ensure the fallback produces a complete-enough report.

### P2-3: clawsec.py cmd_scan captures output only in json_mode
**File:** `cli/clawsec.py:57-58`  
**Description:** `subprocess.run(cmd, capture_output=json_mode, text=True)` — when `json_mode` is False, `capture_output` is False, so the verify.sh output goes directly to the terminal. This is intentional for interactive use, but means `result.returncode` is the only captured info. If stderr has errors, they go to the parent terminal (which may be fine). However, if stdout is a pipe (e.g. `clawsec scan path | head`), verify.sh's ANSI color codes and the exit code flow may break.  
**Fix:** Consider always capturing stderr, at minimum; or document that non-json mode is for interactive TTY only.

### P2-4: sync.sh --status passes through to manifest.py but --json only runs status at end
**File:** `lib/intel-sync/sync.sh:20-22 vs 53-55`  
**Description:** `--status` exits immediately showing manifest status. But `--json` doesn't show status — it only runs status at the very end after syncing. If someone runs `sync.sh --json --status`, the `--status` handler exits before any sync runs. The `--json` flag is meant for post-sync status output but there's no way to get both "sync then show JSON status" — `--json` must come last and `--status` short-circuits.  
**Fix:** Make `--json` flag meaningful: if `--json` is set, output JSON status after sync completes (current behavior). Remove the ambiguous `--status` short-circuit or rename it to `--status-only`.

---

## P3 — Low

### P3-1: yara-scan.sh dead code — echo to /dev/null
**File:** `lib/skill-verify/checks/yara-scan.sh:29`  
**Description:** `echo 'include "yara/apt_apt30_backspace.yar"' > /dev/null` does nothing — writes to /dev/null. The `meta_file` variable is created via mktemp but never written to (the echo goes to /dev/null instead). Both `meta_file` and `compiled_rules` are cleaned up without being used.  
**Fix:** Remove the dead code and the unused `meta_file`/`compiled_rules` variables.

### P3-2: OSV count in manifest inflated by header+comment lines for some sources
**File:** Multiple sync sources  
**Description:** Some source syncers count records with `grep -cv '^#'` which includes the CSV header line (not a comment). Feodo shows "6 records" but there are only 5 data entries. The `count` is header + data, not just data. This is misleading but not functionally harmful.  
**Fix:** Subtract 1 from grep -cv count for CSV sources with headers, or use `tail -n +2 | grep -cv '^#'`.

### P3-3: setup.sh uses sudo without checking if user has sudo
**File:** `setup.sh:36,67,69`  
**Description:** `setup.sh` runs `sudo apt-get`, `sudo mkdir`, `sudo chown` without checking if the user has sudo access. No fallback or clear error message if sudo fails.  
**Fix:** Check `sudo -n true` at the start and bail early with a clear message if no sudo access.

---

## Verdict: FAIL — Cannot ship

This code has 5 P0 bugs that make core security checks non-functional:

1. **YARA scan never works** (broken compile flag)
2. **URLhaus data is garbage** (ZIP not decompressed) producing only false positives
3. **URLhaus matching logic** would produce false positives even with correct data (substring match)
4. **dep-scan CVE cross-referencing is broken** (wrong field name, no aliases)
5. **dep-scan misses 93% of vulnerable packages** (no semver range matching)

Together these mean 3 of the 7 security checks (yara-scan, ioc-match, dep-scan) produce unreliable or zero results. A "pass" verdict from ClawSec v2 cannot be trusted.

Additionally, the API has shell injection and path traversal vulnerabilities (P1-1, P1-2) that must be fixed before any network exposure.

**Assessment:** The architecture and integration glue (verify.sh orchestrator, report.py, manifest.py, CLI, sync orchestrator) are solid. The bugs are concentrated in the individual check implementations and data pipeline correctness. Fix the P0s and P1s, re-audit, and this can ship.