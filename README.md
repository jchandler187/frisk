# ⚡ Low Watt Labs — ClawSec v2

Professional security verification tool that scans ClawHub skills against 10 continuously-updated threat intelligence sources using 7 autonomous security checks.

## Architecture

```
clawsec-v2/
├── lib/
│   ├── intel-sync/          # Intel cache synchronization
│   │   ├── sync.sh           # Main sync orchestrator
│   │   ├── sources/          # Per-source sync scripts (9 sources)
│   │   └── manifest.py       # Cache manifest management
│   ├── skill-verify/         # Skill verification engine
│   │   ├── verify.sh         # Main verify orchestrator
│   │   ├── checks/           # 7 security check scripts
│   │   │   ├── dep-scan.py           # Dependency scanning (OSV + CISA KEV + EPSS)
│   │   │   ├── static-analysis.sh   # Semgrep static analysis
│   │   │   ├── secret-scan.sh       # Gitleaks secret detection
│   │   │   ├── yara-scan.sh          # YARA rule matching
│   │   │   ├── ioc-match.py          # IOC extraction + threat intel matching
│   │   │   ├── behavioral.py        # Behavioral heuristics
│   │   │   └── prompt-inject.py      # Prompt injection detection
│   │   └── report.py         # Report generation & storage
│   └── common/               # Shared utilities
├── api/                      # Cloud API (Node.js + Express)
│   ├── src/
│   │   ├── server.js         # Express server (port 3100)
│   │   ├── routes.js         # API routes
│   │   ├── middleware.js     # Rate limiting + auth
│   │   ├── badge.js          # SVG trust badge generator
│   │   └── verify-wrapper.sh # Verify execution wrapper
│   └── public/               # Landing + pricing pages
├── cli/                      # Python CLI
│   └── clawsec.py
├── setup.sh                  # Dependency installer
├── requirements.txt
├── package.json
└── reports/                  # Saved verification reports
```

## Intel Sources (9)

| Source | Type | Records | Update Frequency |
|--------|------|---------|-----------------|
| CISA KEV | Known Exploited Vulnerabilities | ~1,600 | Daily |
| OSV (npm + PyPI) | Open Source Vulnerabilities | ~219,000 | Daily |
| EPSS | Exploit Prediction Scoring | ~334,000 | Daily |
| MalwareBazaar | Malware hashes + samples | ~3,500 | Daily |
| URLhaus | Malicious URLs | ~15,400 | Daily |
| ThreatFox | IOCs (IPs, domains, hashes) | ~3,200 | Daily |
| Feodo Tracker | C2 IP addresses | ~6 | Daily |
| YARA Rules (Neo23x0) | Malware/signature detection | ~746 rules | Daily |
| Semgrep Rules | Static analysis rules | ~2,183 rules | Daily |

All data cached under `$CLAWSEC_INTEL_DIR` (default: `/srv/clawsec/intel/`) with atomic writes and graceful degradation on failure.

## Security Checks (7)

1. **Dependency Scan** — Matches declared dependencies against OSV, flags CISA KEV as critical, ranks by EPSS probability
2. **Static Analysis** — Semgrep with community rules for code vulnerabilities
3. **Secret Scan** — Gitleaks for leaked API keys, tokens, credentials
4. **YARA Scan** — Neo23x0 signature-base rules for malware/packer/suspicious patterns
5. **IOC Match** — Extracts URLs/IPs/domains/hashes, matches against URLhaus/ThreatFox/Feodo/MalwareBazaar
6. **Behavioral Heuristics** — Flags shell injection, system writes, fetch-exec, large base64 payloads, capability overreach
7. **Prompt Injection** — Detects instruction overrides, role manipulation, safety bypasses in SKILL.md

## What ClawSec DOES Check

These are the categories covered by the 7 security checks:

- **Known vulnerabilities in declared dependencies** (OSV + CISA KEV + EPSS)
- **Static code patterns** — shell injection, eval, exec, path traversal, system writes (Semgrep + behavioral heuristics)
- **Leaked secrets and credentials** — API keys, tokens, passwords (Gitleaks)
- **Known malware signatures** — YARA rules matching packers, ransomware, suspicious binaries
- **Threat intel IOC matches** — URLs, IPs, domains, and hashes from URLhaus, ThreatFox, Feodo, MalwareBazaar
- **Prompt injection attempts** — instruction overrides, role manipulation, jailbreak patterns in SKILL.md
- **Large encoded payloads** — suspicious base64 blobs above 2KB that decode to binary content

## What ClawSec Does NOT Check

ClawSec is a static analysis tool. It examines skill code and configuration files without executing them. The following categories are **out of scope** and represent known limitations:

- **String concatenation obfuscation** — URLs split across concatenation (`"http://evil" + ".com/payload"`) are not detected. Static regex extraction only matches complete URLs. A future deobfuscation pass may address this.
- **Lazy-loaded payloads** — Skills that fetch and execute remote code at runtime from a clean URL (e.g., `fetch(url).then(r => eval(r.text()))`) are partially caught (the `eval` is flagged) but the malicious URL itself is not flagged if it isn't in threat intel databases.
- **Conditional/time-bomb behavior** — Code that only misbehaves under specific environment variables, dates, or runtime conditions is not reliably detected. This requires dynamic analysis (sandbox execution), which is outside the current scope.
- **Dependency confusion/typo squatting** — Packages not in OSV (e.g., `expresss`, `lodassh`) return "no known vulnerabilities" even if suspicious. Typo detection is not implemented.
- **Runtime behavior** — Anything that only manifests when the skill is actually executed: network calls at runtime, data exfiltration through normal API usage, side effects from legitimate-looking code.
- **Transitive dependencies** — Only direct dependencies declared in `package.json`, `requirements.txt`, or SKILL.md are scanned. Vulnerabilities in sub-dependencies of dependencies are not tracked.
- **Novel or zero-day threats** — Threats not yet present in any intel feed (OSV, CISA KEV, URLhaus, etc.) cannot be detected.

## Threat Model

**In scope:** ClawSec analyzes skill source code and configuration files against known threat indicators (vulnerability databases, IOC feeds, YARA rules, static analysis patterns). The assumed attacker can:

- Embed malicious code in skill files
- Declare dependencies with known CVEs
- Include URLs, IPs, domains, or hashes from threat intel databases
- Use obfuscation techniques (base64, unicode homoglyphs)
- Attempt prompt injection in SKILL.md
- Hide secrets, tokens, or credentials in code

**Out of scope:**

- Dynamic/runtime analysis — the skill is not executed
- Novel threats not yet in IOC feeds or vulnerability databases
- Supply chain attacks on intel sources (no hash verification on downloads)
- Network-level attacks during skill installation
- Social engineering or phishing via skill descriptions

## Intel Cache Staleness

ClawSec checks the age of each intel source during scans:

- **30+ days stale** → Warning (results may be outdated)
- **90+ days stale** → Critical failure (scan results unreliable, resync required)

Run `clawsec sync` to refresh stale intel sources.

## Operational Runbook

### Intel sync failures

If `clawsec sync` reports failures:
1. Check network connectivity to the failed source URL
2. Re-run `clawsec sync <source>` for the specific failed source
3. If repeated failures, check the manifest: `clawsec status --json`
4. Stale data from previous successful syncs is preserved — scans will still work with reduced coverage

### Cache corruption

If intel data is corrupted:
1. Remove the corrupted source directory: `rm -rf /srv/clawsec/intel/<source>`
2. Re-sync: `clawsec sync <source>`
3. For OSV, also remove the index file: `rm -f /srv/clawsec/intel/osv/*/index.json`
4. The next sync will rebuild the index automatically

### False positive disputes

If a finding is a false positive:
1. Check the specific check and finding category
2. For IOC matches — the URL/IP/hash is in a threat intel database; verify by searching the source directly
3. For behavioral heuristics — review the pattern match; some legitimate code may trigger heuristics (e.g., `os.system()` in testing)
4. Reports include the matched pattern and context for manual review
5. No suppression mechanism exists yet — findings require human judgment

### Adding a new intel source

1. Create a sync script in `lib/intel-sync/sources/<name>.sh`
2. The script should download data to `/srv/clawsec/intel/<name>/`
3. Call `manifest.py update <name> <count> <status>` at the end
4. Add the source to `ALL_SOURCES` in `lib/intel-sync/sync.sh`
5. Create a check script or add matching logic to an existing check (e.g., `ioc-match.py`)
6. Add the source to the intel cache validation in `verify.sh`

## CLI Usage

```bash
# Verify a skill
clawsec scan ./my-skill
clawsec scan ./my-skill --json        # JSON output

# Refresh intel cache
clawsec sync                          # All sources
clawsec sync cisa-kev epss            # Specific sources

# Check cache status
clawsec status

# View saved report
clawsec report abc12345
```

**Exit codes:** 0 = pass, 1 = warn, 2 = fail

## API Usage

```bash
# Start server (port 3100)
node api/src/server.js

# Scan by path
curl -X POST http://localhost:3100/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/skill"}'

# Scan by content
curl -X POST http://localhost:3100/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": {"SKILL.md": "# My Skill\n..."} }'

# Get report
curl http://localhost:3100/api/v1/report/{id}

# Get trust badge
curl http://localhost:3100/api/v1/badge/{id}.svg

# Cache status
curl http://localhost:3100/api/v1/status

# Health check
curl http://localhost:3100/health
```

**Rate limits:** 5 scans/day (free), 1,000/day (Pro with API key)

## API Reference

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/scan` | Submit skill for verification | API key (Pro) |
| GET | `/api/v1/report/{id}` | Retrieve a saved report | No |
| GET | `/api/v1/badge/{id}.svg` | Trust badge SVG | No |
| GET | `/api/v1/status` | Intel cache status | No |
| GET | `/health` | Health check | No |

### POST /api/v1/scan

Request body (one of):
- `{"slug": "skill-name"}` — install from ClawHub and scan
- `{"path": "/path/to/skill"}` — scan local directory
- `{"content": {"SKILL.md": "..."}}` — scan provided files

Response: JSON report with `report_id`, `verdict`, `checks`, `summary`.

### GET /api/v1/report/{id}

Returns the full JSON report for a given report ID.

### GET /api/v1/badge/{id}.svg

Returns an SVG trust badge: green (pass), yellow (warn), red (fail).

### GET /api/v1/status

Returns the intel manifest JSON with source names, record counts, and last sync times.

### Error responses

All errors return `{"error": "description"}` with appropriate HTTP status codes (400, 403, 404, 429).
Rate-limited responses include a `retry_after` message.

## Install

```bash
git clone https://github.com/lowwattlabs/clawsec.git
cd clawsec
./setup.sh
```

> `pip install clawsec` and `npm i -g @lowwattlabs/clawsec` coming soon.

## Setup

```bash
bash setup.sh    # Installs all dependencies (yara, semgrep, gitleaks, etc.)
clawsec sync     # Populate intel cache (first run takes a few minutes for OSV)
```

## Deployment

### Systemd Services

```bash
# API service
sudo cp clawsec-api.service /etc/systemd/system/
sudo systemctl enable clawsec-api
sudo systemctl start clawsec-api

# Daily intel sync
sudo cp clawsec-sync.service clawsec-sync.timer /etc/systemd/system/
sudo systemctl enable clawsec-sync.timer
sudo systemctl start clawsec-sync.timer
```

## Test Results

- ✅ Safe skill: PASS (exit 0, 0 findings)
- ✅ Malicious skill: FAIL (exit 2, 14 findings — 5 critical, 6 high)
- ✅ All 7 checks running and producing results
- ✅ All 9 intel sources synced (561k+ total records)
- ✅ API health, scan, report, badge, status endpoints working
- ✅ Landing page and pricing page served
- ✅ CLI scan, sync, status, report commands working
- ✅ Scan completes in ~5 seconds

## Built By

Low Watt Labs — local-first security tooling.