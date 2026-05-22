# Audit Pass 2 Fixes

**Date:** 2026-05-22
**Agent:** 2Clawz (subagent)
**Repo:** ~/clawsec-v2/

## P2 Fixes Applied

### P2-01: Missing .gitignore — FIXED
Added `.gitignore` at repo root with: `reports/*.json`, `.venv/`, `node_modules/`, `api/api-keys.json`, `*.log`, `__pycache__/`, `.env`, `*.pyc`, `intel/`

### P2-02: Missing LICENSE — FIXED
Added MIT LICENSE file matching `package.json` declaration. Copyright 2026 Low Watt Labs.

### P2-03: Hardcoded paths everywhere — FIXED
Created centralized config:
- `lib/common/config.sh` — exports `CLAWSEC_HOME` (default `~/clawsec-v2`) and `CLAWSEC_INTEL_DIR` (default `/srv/clawsec/intel`), both overridable via env vars
- `lib/common/config.py` — same defaults and env var overrides for Python
- Added `lib/common/__init__.py` for package import support

Refactored all 15+ files that hardcoded `/srv/clawsec/intel` or `~/clawsec-v2`:
- **Bash:** 9 intel-sync source scripts, sync.sh, verify.sh, verify-wrapper.sh, static-analysis.sh, yara-scan.sh, setup.sh, log.sh — all source `config.sh` and use `CLAWSEC_INTEL_DIR`/`CLAWSEC_HOME`
- **Python:** manifest.py, report.py, ioc-match.py, dep-scan.py, clawsec.py — all import from `config.py`
- **JS:** routes.js — reads `CLAWSEC_HOME` and `CLAWSEC_INTEL_DIR` from `process.env`

### P2-04: execSync not imported — FIXED
No longer relevant — `execSync` has been completely removed. See P2-07.

### P2-07: execSync shell injection in routes.js — FIXED
Replaced `execSync('bash "${verifyWrapper}" "${targetDir}"')` with `execFileSync('bash', [verifyWrapper, targetDir], { timeout: 30000 })` — same safe array-args pattern as the clawhub install call at line 44. Import remains `const { execFileSync } = require('child_process')` — no execSync anywhere.

### P2-05: Pro tier features are fictitious — FIXED
Removed from Pro tier: "CI/CD webhook support", "JSON + HTML reports", "Priority intel updates".
Replaced with: "API key for programmatic access", "Faster scan rate limits", "Detailed CVE reports with EPSS scores" — all features that actually exist in the codebase.
Also fixed the bottom note that claimed `pip install clawsec` / `npm i -g @lowwattlabs/clawsec`.

### P2-06: README install commands are fictitious — FIXED
Added proper Install section with `git clone` + `cd clawsec` + `./setup.sh`. Marked pip/npm packages as "coming soon".

## P3 Fixes Applied (Quick Wins)

### P3-02: Test reports in reports/ — FIXED
Removed all 28 JSON test reports from `reports/`. Covered by `.gitignore`.

### P3-04: Unused flask/gunicorn in requirements.txt — FIXED
Removed `flask>=3.0.0` and `gunicorn>=21.2.0` — API is Node.js/Express, not Flask.

### P3-07: --json on root parser unreachable — FIXED
Removed `--json` from root argparse parser in `clawsec.py`. Kept only on subcommand parsers (scan, sync, status, report).

### P3-09: Same as P2-06 — FIXED (merged into P2-06 fix)

### P3-10: status --json doesn't work — FIXED
Added `--json` argument to `status` subparser in `clawsec.py`. Now `clawsec status --json` works.

### P3-11: Intel Sources count (10→9) — FIXED
Changed README headline from "Intel Sources (10)" to "Intel Sources (9)".

### P3-15: Missing API Reference — FIXED
Added API Reference section to README with endpoint table (5 endpoints: scan, report, badge, status, health), request/response descriptions, and error format.

## Smoke Tests

- **API server** — `node api/src/server.js` starts on port 3100
- **Health endpoint** — `GET /health` returns `{"status":"ok","version":"2.0.0"}`
- **Status endpoint** — `GET /api/v1/status` returns full manifest JSON
- **CLI status** — `python3 cli/clawsec.py status` displays formatted cache status
- **CLI status --json** — `python3 cli/clawsec.py status --json` returns valid JSON