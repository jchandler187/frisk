# Changelog

## v1.0.0 (2026-05-24)
Initial unified release. Frisk consolidates the former ClawSec/SafeInstall project under one name.

### Features
- 7 autonomous security checks: dep-scan, static-analysis, secret-scan, yara-scan, ioc-match, behavioral, prompt-inject
- 9 threat intel sources: CISA KEV, OSV (npm + PyPI), EPSS, MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker, YARA Rules, Semgrep Rules
- Local-first: all scanning offline, zero telemetry
- ClawHub slug scanning with sandboxed download
- JSON output for CI/CD pipelines
- Express API server with rate limiting

### Bug fixes (from pre-release audits)
- URLhaus sync: validates extracted CSV before parsing
- Credential heuristic: per-pattern grep instead of multiline regex
- ELF binary detection: bumped severity from WARN to FAIL
- Static analysis: returns WARN when semgrep is missing (not silent PASS)
- OSV index_file: fixed Python scoping bug
- Intel sync: fixed mkdir expansion bug in sync.sh

## v1.0.1 (2026-05-24)
- Renamed package from @lowwattlabs/clawsec to @lowwattlabs/frisk
- Binary names: frisk, frisk-api (formerly clawsec, clawsec-api)
- Config dirs: ~/.frisk/ (formerly ~/.clawsec/)
- GitHub repo moved to jchandler187/frisk
- SKILL.md aligned with actual package and binary names

## v3.0.1 (2026-05-25)
- SKILL.md version aligned with npm package (3.0.1)
- GitHub repo fully renamed — all ClawSec references replaced with Frisk
- One product, one name: Frisk everywhere (GitHub, npm, ClawHub)

## v3.0.2 (2026-05-25)
- Audit fixes: all P0 issues resolved
- Removed stale .bak file and __pycache__ from repo/tarball
- Added *.bak, __pycache__/, frisk-temp/ to .npmignore
- All version strings unified to 3.0.2

## v3.0.3 (2026-05-25)
- Fixed __pycache__ inclusion in npm tarball (added **/__pycache__/ to .npmignore)
- Cleaned all __pycache__ directories from repo
