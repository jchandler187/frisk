# ClawSec v2 — Security Verification for ClawHub Skills

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