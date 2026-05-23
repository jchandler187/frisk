# ⚡ ClawSec

Security verification tool that scans ClawHub skills against 9 continuously-updated threat intelligence sources using 7 autonomous security checks.

If you find it useful, [buy me a coffee](https://buymeacoffee.com/lowwattlabs) ⚡

## Quick Start

```bash
# Install globally via npm
npm install -g @lowwattlabs/clawsec

# Scan a local skill directory
clawsec scan ./my-skill

# Scan with JSON output
clawsec scan ./my-skill --json

# Sync threat intel
clawsec sync

# Check intel cache status
clawsec status
```

First run automatically sets up a Python venv at `~/.clawsec/venv/` and installs dependencies. The first `clawsec sync` (or auto-sync) downloads approximately 50–100 MB of threat intel data.

## Docker

```bash
# Build
docker build -t lowwattlabs/clawsec .

# Run
docker run -p 3100:3100 lowwattlabs/clawsec

# Scan via API inside container
docker run lowwattlabs/clawsec clawsec scan /path/to/skill
```

## CLI Usage

```bash
# Verify a skill
clawsec scan ./my-skill
clawsec scan ./my-skill --json        # JSON output
clawsec scan ./my-skill --checks=dep-scan,secret-scan  # Run specific checks

# Scan by ClawHub slug
clawsec scan my-awesome-skill

# Refresh intel cache
clawsec sync                          # All sources
clawsec sync cisa-kev epss            # Specific sources

# Check cache status
clawsec status
clawsec status --json                 # JSON output

# View saved report
clawsec report abc12345
clawsec report abc12345 --json        # JSON output
```

**Exit codes:** 0 = pass, 1 = warn, 2 = fail

## API Usage

### Start the API server

```bash
# Via npm global install
clawsec-api

# Or directly
node api/src/server.js

# With custom config
CLAWSEC_HOME=~/.clawsec CLAWSEC_PORT=3100 clawsec-api
```

### API endpoints

```bash
# Scan by path
curl -X POST http://localhost:3100/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/skill"}'

# Scan by ClawHub slug
curl -X POST http://localhost:3100/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"slug": "my-skill"}'

# Scan by content
curl -X POST http://localhost:3100/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": {"SKILL.md": "# My Skill\n..."}}'

# Get report
curl http://localhost:3100/api/v1/report/{id}

# Get trust badge
curl http://localhost:3100/api/v1/badge/{id}.svg

# Cache status
curl http://localhost:3100/api/v1/status

# Health check
curl http://localhost:3100/health
```

## Security Checks (7)

1. **Dependency Scan** — Matches declared dependencies against OSV, flags CISA KEV as critical, ranks by EPSS probability
2. **Static Analysis** — Semgrep with community rules for code vulnerabilities
3. **Secret Scan** — Gitleaks for leaked API keys, tokens, credentials
4. **YARA Scan** — Neo23x0 signature-base rules for malware/packer/suspicious patterns
5. **IOC Match** — Extracts URLs/IPs/domains/hashes, matches against URLhaus/ThreatFox/Feodo/MalwareBazaar
6. **Behavioral Heuristics** — Flags shell injection, system writes, fetch-exec, large base64 payloads, capability overreach
7. **Prompt Injection** — Detects instruction overrides, role manipulation, safety bypasses in SKILL.md

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

All data cached under `~/.clawsec/intel/` with atomic writes and graceful degradation on failure.

## Configuration

ClawSec uses environment variables with sensible defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAWSEC_HOME` | `~/.clawsec` | Root directory for venv, intel, reports |
| `CLAWSEC_INTEL_DIR` | `~/.clawsec/intel` | Intel cache directory |
| `CLAWSEC_REPORTS_DIR` | `~/.clawsec/reports` | Reports directory |
| `CLAWSEC_PORT` | `3100` | API server port |

## Local Development

```bash
git clone https://github.com/jchandler187/clawsec.git
cd clawsec
./setup.sh          # Installs system deps + Python venv
clawsec sync        # Populate intel cache (first run takes a few minutes for OSV)
clawsec scan ./path # Verify a skill
```

## Architecture

```
clawsec/
├── bin/
│   ├── clawsec.js       (CLI entry point)
│   ├── clawsec-api.js   (API entry point)
│   └── setup-venv.js    (postinstall venv setup)
├── api/
│   └── src/
│       ├── server.js     (Express server, port 3100)
│       ├── routes.js     (API routes)
│       ├── middleware.js  (Rate limiting + auth)
│       ├── badge.js      (SVG trust badge generator)
│       └── verify-wrapper.sh
├── cli/
│   └── clawsec.py       (Python CLI)
├── lib/
│   ├── intel-sync/       (Intel cache synchronization)
│   │   ├── sync.sh        (Main sync orchestrator)
│   │   ├── sources/       (Per-source sync scripts)
│   │   └── manifest.py    (Cache manifest management)
│   ├── skill-verify/      (Skill verification engine)
│   │   ├── verify.sh      (Main verify orchestrator)
│   │   ├── checks/         (7 security check scripts)
│   │   └── report.py       (Report generation & storage)
│   └── common/            (Shared utilities + config)
├── Dockerfile
├── package.json
├── requirements.txt
├── setup.sh
└── README.md
```

## What ClawSec DOES Check

- **Known vulnerabilities in declared dependencies** (OSV + CISA KEV + EPSS)
- **Static code patterns** — shell injection, eval, exec, path traversal, system writes (Semgrep + behavioral heuristics)
- **Leaked secrets and credentials** — API keys, tokens, passwords (Gitleaks)
- **Known malware signatures** — YARA rules matching packers, ransomware, suspicious binaries
- **Threat intel IOC matches** — URLs, IPs, domains, and hashes from URLhaus, ThreatFox, Feodo, MalwareBazaar
- **Prompt injection attempts** — instruction overrides, role manipulation, jailbreak patterns in SKILL.md
- **Large encoded payloads** — suspicious base64 blobs above 2KB that decode to binary content

## What ClawSec Does NOT Check

- String concatenation obfuscation
- Lazy-loaded payloads (partially caught via eval/evalSub)
- Conditional/time-bomb behavior
- Dependency confusion/typo squatting
- Runtime behavior (requires dynamic analysis)
- Transitive vulnerabilities
- Novel/zero-day threats not in any feed

## Intel Cache Staleness

- **30+ days stale** → Warning (results may be outdated)
- **90+ days stale** → Critical failure (results unreliable, resync required)

Run `clawsec sync` to refresh stale intel sources.

## License

MIT-0 — Low Watt Labs ⚡

