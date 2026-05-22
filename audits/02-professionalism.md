# Audit Pass 2: Organization & Professionalism

**Date:** 2026-05-22
**Auditor:** 2Clawz (subagent)
**Repo:** ~/clawsec-v2/
**Scope:** Code organization, professionalism, ship-readiness — NOT bugs (those were pass 1)

---

## Summary

| Severity | Count |
|----------|-------|
| P2 (shipping blocker) | 7 |
| P3 (polish before public) | 13 |
| **Total** | **20** |

---

## Findings

### 1. Repository Structure

**P2-01: Missing .gitignore**
- File: repo root
- Description: No .gitignore exists. The `reports/` directory contains 28 test reports, `.venv/` and `node_modules/` would be committed, and `api-keys.json` (containing API keys!) would be committed to version control.
- Fix: Add `.gitignore` with `reports/*.json`, `.venv/`, `node_modules/`, `api/api-keys.json`, `*.log`, `__pycache__/`, `.env`

**P2-02: Missing LICENSE**
- File: repo root
- Description: package.json declares `"license": "MIT"` but no LICENSE file exists. This is legally meaningless and will cause license scanners to flag it. Also blocks anyone from actually using it under MIT terms.
- Fix: Add a LICENSE file (MIT or whichever is intended)

**P3-01: Missing CONTRIBUTING.md**
- File: repo root
- Description: No contribution guidelines. If this is going on ClawHub or any public registry, contributors need to know the process.
- Fix: Add CONTRIBUTING.md with setup instructions, PR process, coding conventions

**P3-02: Reports directory contains test artifacts in repo**
- File: reports/
- Description: 28 JSON test reports are in the source tree. These are runtime artifacts, not source code.
- Fix: Remove test reports from the tree (or move to `tests/fixtures/` if they're intentional test data), add `reports/*.json` to `.gitignore`

**P3-03: api-keys.json in source tree**
- File: api/api-keys.json
- Description: Contains demo keys (`demo-key-free`, `demo-key-pro`). Even demo keys in version control is a bad look for a security product. Also, the file is loaded on every request — there's no `.gitignore` to prevent real keys from being committed.
- Fix: Move to `api/api-keys.json.example` with the demo keys, add real file to `.gitignore`, update middleware.js to check both paths

### 2. Code Organization Within Files

**P2-03: Hardcoded paths everywhere**
- Files: Nearly every file in the codebase
- Description: `/srv/clawsec/intel` is hardcoded in 10+ files (all Python check scripts, all bash sync scripts, manifest.py, report.py, routes.js, log.sh, clawsec.py). `~/clawsec-v2` is hardcoded or partially resolved in 5+ files. No central config or env var for `INTEL_DIR` or `CLAWSEC_DIR`.
- Fix: Create a `config.sh` and `config.py` (or use env vars `CLAWSEC_INTEL_DIR`, `CLAWSEC_HOME`) with sensible defaults. Source/import everywhere instead of hardcoding. This is the single biggest portability blocker.

**P3-04: requirements.txt includes unused dependencies**
- File: requirements.txt
- Description: `flask>=3.0.0` and `gunicorn>=21.2.0` are listed but the API is Express/Node.js, not Flask. These are dead dependencies that waste install time and surface area.
- Fix: Remove flask and gunicorn from requirements.txt. If there's a future Python API planned, add a comment.

**P3-05: Duplicate color definitions in setup.sh**
- File: setup.sh lines 12-18
- Description: setup.sh redefines ANSI color variables (RED, GREEN, YELLOW, etc.) and log functions that already exist in `lib/common/colors.sh` and `lib/common/log.sh`. Should source the shared library.
- Fix: Source `lib/common/colors.sh` and `lib/common/log.sh` in setup.sh instead of redefining

**P3-06: Inconsistent variable naming between Bash and Python**
- Files: All bash scripts use UPPER_SNAKE_CASE, Python uses UPPER_SNAKE_CASE for module constants
- Description: Python check scripts inconsistently name the `INTEL_DIR` constant (sometimes module-level UPPER, sometimes passed). Within Python, naming is actually consistent — snake_case functions, UPPER module constants. The bash side is also consistent (UPPER exports). This is fine per-language but the cross-language boundary (INTEL_DIR hardcoding) is the real issue, already captured in P2-03.
- Fix: Addressed by P2-03 fix

### 3. CLI Professionalism

**P3-07: `--json` flag is defined on both root parser and subcommands**
- File: cli/clawsec.py
- Description: `--json` is added to the root `argparse` parser AND to `scan` and `sync` subparsers. The root-level `--json` is unreachable once a subcommand is specified, creating confusing help text.
- Fix: Remove `--json` from the root parser, keep it only on subcommands that support it (scan, sync, status, report)

**P3-08: `clawsec scan` doesn't show banner**
- File: cli/clawsec.py
- Description: `banner()` is only called when no subcommand is given. Running `clawsec scan` jumps straight to output with no branding. The shell scripts (sync.sh, verify.sh) show banners. Inconsistent.
- Fix: Either show a one-line header in scan/sync/status or remove banners entirely. Pick one approach.

**P3-09: README claims `pip install clawsec` and `npm i -g @lowwattlabs/clawsec`**
- File: README.md, pricing.html
- Description: Neither package is published to PyPI or npm. The CLI is a local script with no setup.py/pyproject.toml, and the npm package has no bin field or install script.
- Fix: Either publish the packages or remove the install commands from README/pricing page and replace with "clone and run setup.sh"

**P3-10: `clawsec status --json` doesn't work from CLI**
- File: cli/clawsec.py
- Description: The `status` subparser doesn't have a `--json` flag defined (unlike scan and sync), but `cmd_status` checks `args.json`. The flag definition is missing.
- Fix: Add `status_parser.add_argument("--json", action="store_true", help="JSON output")`

### 4. API Professionalism

**P2-04: `execSync` used without import — will crash at runtime**
- File: api/src/routes.js line 83
- Description: Line 8 imports `{ execFileSync }` from `child_process`, but line 83 calls `execSync` (not `execFileSync`). `execSync` is not destructured from the import and isn't a global in Node.js without importing it. This will throw a `ReferenceError: execSync is not defined` at runtime when the scan endpoint is hit via the API.
- Fix: Change the import to `const { execFileSync, execSync } = require('child_process');`

**P2-05: Pro tier features are advertised but not implemented**
- File: api/public/pricing.html, README.md
- Description: The Pro tier ($9/month) advertises "CI/CD webhook support", "HTML reports", and "Priority intel updates". None of these exist in the codebase. There are no webhooks, no HTML report generation (only JSON), and no priority mechanism for sync. Charging for features that don't exist is deceptive.
- Fix: Either implement the features or remove them from the pricing page. Replace "CI/CD webhook support" with "API key for programmatic access" (which does work), remove "HTML reports" until implemented, and remove "Priority intel updates" or replace with "Faster rate limits"

**P3-11: README claims "10 intel sources" but only 9 sync scripts exist**
- File: README.md, sync.sh
- Description: README says "Intel Sources (10)" but `ALL_SOURCES` in sync.sh lists 9: cisa-kev, osv, epss, malwarebazaar, urlhaus, threatfox, feodo, yara-rules, semgrep-rules. The README table also lists 9 rows. The headline count is wrong.
- Fix: Change README headline to "9 Intel Sources" or split OSV into "OSV (npm)" and "OSV (PyPI)" as two source rows to justify "10"

**P3-12: Rate limit retry_after not returned as HTTP header**
- File: api/src/middleware.js
- Description: Rate limit 429 responses include a JSON body with `retry_after` text but don't set the standard `Retry-After` HTTP header. Well-behaved clients prefer the header.
- Fix: Add `res.set('Retry-After', String(blockDuration))` before returning 429

**P3-13: No request body size validation beyond Express default**
- File: api/src/routes.js, middleware.js
- Description: Express has a 10mb JSON body limit set in server.js (line 23), but there's no validation that `content` objects aren't absurdly large or that `slug` is a reasonable string. A malicious client could POST a 10MB `content` blob.
- Fix: Add a `slug` format validation (regex for valid ClawHub slug), and consider a smaller content size limit (1MB is generous for a skill)

### 5. Documentation Quality

**P2-06: README install commands are fictitious**
- File: README.md lines "pip install clawsec" and "npm i -g @lowwattlabs/clawsec"
- Description: Neither package is published. The README claims `pip install clawsec` and `npm i -g @lowwattlabs/clawsec` work. They don't. A non-developer following the README will hit errors immediately.
- Fix: Same as P3-09 — publish packages or replace with actual install steps

**P3-14: No environment variable documentation**
- File: README.md
- Description: The API server reads `CLAWSEC_PORT`, `HOME`, and `PATH` env vars. The CLI reads hardcoded paths. The systemd units set `CLAWSEC_PORT`, `NODE_ENV`, and `PATH`. None of these are documented in the README.
- Fix: Add a "Configuration" or "Environment Variables" section to README listing all env vars, their defaults, and what they control

**P3-15: No API documentation beyond curl examples**
- File: README.md
- Description: The API has 5 endpoints (scan, report, badge, status, health) but documentation is just two curl examples. No OpenAPI/Swagger spec, no schema docs for request/response bodies, no description of error response format.
- Fix: Add at minimum an "API Reference" section with endpoint table, request/response schemas, and error format. An OpenAPI spec in `api/openapi.yaml` would be professional.

### 6. Config & Deployment

**P3-16: setup.sh uses sudo without warning**
- File: setup.sh lines 58, 63, 87
- Description: `install_system_deps()` runs `sudo apt-get install`, `setup_dirs()` runs `sudo mkdir -p` and `sudo chown`. Setup doesn't warn the user it needs sudo upfront or check if sudo is available before starting. The first 30 lines of setup will succeed without sudo, then fail silently.
- Fix: Add a pre-flight check: `[ "$(id -u)" -eq 0 ] || command -v sudo &>/dev/null || { echo "Setup requires sudo for system package installation"; exit 1; }`. Also add a `--skip-system-deps` flag.

**P3-17: systemd services use hardcoded user `openclaw`**
- File: clawsec-api.service, clawsec-sync.service
- Description: Both service files have `User=openclaw`. If someone installs ClawSec on their own machine, they'd need to edit these. The `WorkingDirectory` is also hardcoded to `/home/openclaw/clawsec-v2`.
- Fix: Use `%i` or template units, or at minimum add a comment explaining the user/path should be edited. Better: use `DynamicUser=true` and an `EnvironmentFile=` for paths.

### 7. Consistency

**P2-07: `execSync` vs `execFileSync` inconsistency in routes.js**
- File: api/src/routes.js
- Description: Line 44 uses `execFileSync` (safe, takes array args) for `clawhub install`. Line 83 uses `execSync` with string interpolation (`bash "${verifyWrapper}" "${targetDir}"`) which is a shell injection vector if `targetDir` contains metacharacters. The API endpoint accepts arbitrary `path` from the request body that flows directly into this shell command.
- Fix: Rewrite line 83 to use `execFileSync('bash', [verifyWrapper, targetDir], ...)` — the same safe pattern used at line 44. This is also a security issue (shell injection via crafted path).

**P3-18: Exit code 2 used for two different meanings**
- Files: cli/clawsec.py vs verify.sh
- Description: `clawsec.py cmd_scan` exits with code 2 when the skill path doesn't exist. `verify.sh` exits with code 2 when the verdict is "fail" (security findings). These conflict — you can't distinguish "path not found" from "found malicious code" by exit code alone.
- Fix: Use exit code 3 for "invalid arguments / not found" and keep 0/1/2 for pass/warn/fail verdicts. Update clawsec.py accordingly.

### 8. Ship-Readiness Checklist

| Question | Answer |
|----------|--------|
| Would you run this in production without shame? | Almost. The `execSync` bug (P2-04 + P2-07) would crash the API on first scan request, so no — that's a blocker. |
| Would a security professional trust the output? | Yes — the checks are solid and backed by real threat intel. The trust badge is a nice touch. |
| Can a non-developer install and use it from the README alone? | No — `pip install clawsec` doesn't exist (P2-06), and setup.sh needs sudo without saying so (P3-16). |
| Is the pricing page honest? | No — Pro tier lists 3 features that don't exist (P2-05). |

---

## Verdict

**Needs polish before adversarial audit.**

The engine is good — the checks work, the intel pipeline is solid, the badge system is clean. But this isn't ship-ready:

1. The API has a runtime crash bug (`execSync` not imported, P2-04) that means the `/api/v1/scan` endpoint will throw `ReferenceError` when hit. This alone blocks shipping.
2. The same line is a shell injection vector (P2-07) — a security product with an RCE in its own API is a terrible look.
3. The pricing page advertises features that don't exist (P2-05) — that's not a polish issue, that's honesty.
4. The README tells people to run `pip install clawsec` which doesn't exist (P2-06) — the first thing a new user tries will fail.

Fix P2-01 through P2-07 before going any further. The P3 items can be addressed in parallel or right after, but the P2s are blockers.