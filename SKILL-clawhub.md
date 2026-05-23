---
name: clawsec
description: "Scan ClawHub skills for security vulnerabilities before installing — 9 threat intel sources, 7 autonomous checks, instant slug scan."
version: 2.3.3
metadata:
  openclaw:
    emoji: "⚡"
    homepage: https://github.com/jchandler187/clawsec
    requires:
      env:
        - CLAWSEC_HOME
      bins:
        - python3
        - clawhub
      anyBins:
        - gitleaks
        - semgrep
        - yara
    primaryEnv: CLAWSEC_HOME
    envVars:
      - name: CLAWSEC_HOME
        required: false
        description: "Base directory for intel cache and reports (default: ~/.clawsec)"
      - name: CLAWSEC_INTEL_DIR
        required: false
        description: "Override intel cache directory (default: CLAWSEC_HOME/intel)"
      - name: CLAWSEC_REPORTS_DIR
        required: false
        description: "Override reports directory (default: CLAWSEC_HOME/reports)"
    install:
      - kind: node
        package: "@lowwattlabs/clawsec"
        bins:
          - clawsec
---

# ⚡ ClawSec

Security verification for ClawHub skills. Scan any skill — by local path or ClawHub slug — against 9 continuously-updated threat intelligence sources using 7 autonomous security checks.

## What it does

ClawSec scans a skill directory for security issues before you install it. It checks dependencies against known vulnerability databases, scans for hardcoded secrets, detects indicators of compromise, and looks for prompt injection vectors — all without sending your data anywhere.

**One command to scan any ClawHub skill:**

```
clawsec scan weather-forecast
```

That downloads the skill from ClawHub, scans it, shows results, and cleans up. No manual steps.

**Or scan a local skill directory:**

```
clawsec scan ./my-skill
```

## When to use this skill

Use ClawSec when you are about to install a skill from ClawHub and want to verify it is safe. Also use it when developing your own skills — run a scan before publishing to catch issues early.

## Parameters

- **target** (required) — A local directory path or a ClawHub skill slug (e.g. `weather-forecast`). If a slug is provided, the skill is downloaded temporarily, scanned, and removed.
- **checks** (optional) — Comma-separated list of checks to run: `dep-scan`, `static-analysis`, `secret-scan`, `yara-scan`, `ioc-match`, `behavioral`, `prompt-inject`. Default: all 7.
- **json** (optional) — Output results as JSON for programmatic use.

## Return value

ClawSec outputs a structured report with:

- **verdict** — `pass`, `warn`, or `fail`
- **findings** — Array of issues found, each with severity (`critical`, `high`, `medium`), description, and file location
- **report_id** — Short ID for later retrieval via `clawsec report <id>`

Exit codes: 0 = pass, 1 = warn, 2 = fail

## Checks

| Check | What it does |
|-------|-------------|
| dep-scan | Cross-references dependencies against CISA KEV and OSV databases |
| static-analysis | Runs Semgrep rules for security anti-patterns |
| secret-scan | Scans for hardcoded API keys, tokens, and credentials using Gitleaks |
| yara-scan | Matches files against YARA rules for malware patterns |
| ioc-match | Matches IPs, domains, URLs, and file hashes against ThreatFox, URLhaus, MalwareBazaar, and Feodo trackers |
| behavioral | Detects suspicious patterns: eval usage, shell injection, data exfiltration vectors, DNS tunneling |
| prompt-inject | Detects prompt injection and instruction-hiding patterns in SKILL.md |

## Threat intel sources (9, continuously synced)

CISA KEV · OSV (npm + PyPI) · EPSS · MalwareBazaar · URLhaus · ThreatFox · Feodo Tracker · YARA Rules · Semgrep Rules

Run `clawsec sync` to refresh the intel cache.

## Security & Privacy

- **No data leaves your machine.** All scanning happens locally. No telemetry, no phone-home, no analytics.
- **Downloaded skills are sandboxed.** When scanning by slug, the skill is downloaded to a 0700-permission temp directory, all files have execute permissions stripped before scanning, and npm postinstall scripts are suppressed. The skill is deleted after scanning.
- **Credentials stay local.** ClawSec reads environment variables for configuration but never transmits them.

### External endpoints

ClawSec downloads threat intel feeds from these public sources during `clawsec sync`:

| Source | URL | Data sent |
|--------|-----|-----------|
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/ | None (GET only) |
| OSV | https://api.osv.dev/v1/query | Package name + version for dependency lookup |
| EPSS | https://epss.cyentia.com/api/v1/ | None (GET only) |
| MalwareBazaar | https://mb-api.abuse.ch/api/v1/ | None (POST for hash lookup) |
| URLhaus | https://urlhaus-api.abuse.ch/v1/urls/ | None (GET only) |
| ThreatFox | https://threatfox-api.abuse.ch/api/v1/ | None (POST for IOC lookup) |
| Feodo Tracker | https://feodotracker.abuse.ch/downloads/ | None (GET only) |
| YARA Rules | https://github.com/Yara-Rules/rules.git | None (git clone) |
| Semgrep Rules | https://github.com/returntocorp/semgrep-rules.git | None (git clone) |

During `clawsec scan`, no network requests are made. All intel is local.

### Local files read

- `~/.clawsec/intel/` — Threat intel cache
- Skill directory passed as scan target

### Local files written

- `~/.clawsec/intel/` — Synced threat intel data
- `~/.clawsec/reports/` — Scan reports (JSON)
- `~/.clawsec/venv/` — Python virtual environment for scan checks

### Trust statement

By using ClawSec, you trust the threat intel sources listed above to provide accurate vulnerability and IOC data. No skill code or scan targets are transmitted to any external service. Install it only if you trust the Low Watt Labs project and the listed intel sources.

## Install

```bash
npm install -g @lowwattlabs/clawsec
```

First run automatically creates a Python venv and syncs threat intel. After that, `clawsec scan` works with zero configuration.

## Docker

```bash
docker build -t lowwattlabs/clawsec .
docker run -p 3100:3100 lowwattlabs/clawsec
```

## Pricing

Free. No paid tier, no API keys, no limits. If you find it useful, [buy me a coffee](https://buymeacoffee.com/lowwattlabs).

## License

MIT-0 — same as all ClawHub skills.