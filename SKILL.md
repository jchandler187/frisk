---
name: frisk
description: "Catch leaked credentials and supply-chain threats in ClawHub skills before you install — 9 intel sources, 7 checks, credential leak detection, instant slug scan."
version: 3.1.0
metadata:
  openclaw:
    emoji: "⚡"
    homepage: https://github.com/jchandler187/frisk
    requires:
      env:
        - FRISK_HOME
      bins:
        - python3
        - clawhub
      anyBins:
        - gitleaks
        - semgrep
        - yara
    primaryEnv: FRISK_HOME
    envVars:
      - name: FRISK_HOME
        required: false
        description: "Base directory for intel cache and reports (default: ~/.frisk)"
      - name: FRISK_INTEL_DIR
        required: false
        description: "Override intel cache directory (default: FRISK_HOME/intel)"
      - name: FRISK_REPORTS_DIR
        required: false
        description: "Override reports directory (default: FRISK_HOME/reports)"
    install:
      - kind: node
        package: "@lowwattlabs/frisk"
        bins:
          - frisk
---

# ⚡ Frisk

**Your `npm install` just handed someone your AWS keys.** Frisk catches it.

Credential theft is the #1 attack vector in the AI agent supply chain. OpenAI Codex tokens, Red Hat npm packages, TanStack — all stolen through compromised dependencies. The perimeter doesn't matter when the credentials are already inside.

Frisk scans ClawHub skills against 9 threat intel sources with 7 autonomous security checks. It catches leaked API keys, credential patterns, malware signatures, shell injection, and prompt injection — before you install.

## What it does

Frisk scans a skill directory for security issues before you install it. It checks for leaked credentials, matches dependencies against known vulnerability databases, detects indicators of compromise, and looks for prompt injection vectors — all without sending your data anywhere.

**One command to scan any ClawHub skill:**

```
frisk scan weather-forecast
```

That downloads the skill from ClawHub, scans it, shows results, and cleans up. No manual steps.

**Or scan a local skill directory:**

```
frisk scan ./my-skill
```

## When to use this skill

Use Frisk when you are about to install a skill from ClawHub and want to verify it is safe. Also use it when developing your own skills — run a scan before publishing to catch issues early.

## Parameters

- **target** (required) — A local directory path or a ClawHub skill slug (e.g. `weather-forecast`). If a slug is provided, the skill is downloaded temporarily, scanned, and removed.
- **checks** (optional) — Comma-separated list of checks to run: `dep-scan`, `static-analysis`, `secret-scan`, `yara-scan`, `ioc-match`, `behavioral`, `prompt-inject`. Default: all 7.
- **json** (optional) — Output results as JSON for programmatic use.

## Return value

Frisk outputs a structured report with:

- **verdict** — `pass`, `warn`, or `fail`
- **findings** — Array of issues found, each with severity (`critical`, `high`, `medium`), description, and file location
- **report_id** — Short ID for later retrieval via `frisk report <id>`

Exit codes: 0 = pass, 1 = warn, 2 = fail

## Checks

| Check | What it does |
|-------|-------------|
| dep-scan | Cross-references dependencies against CISA KEV and OSV databases |
| static-analysis | Runs Semgrep rules for security anti-patterns |
| secret-scan | Scans for leaked API keys, tokens, and credential patterns using Gitleaks + heuristic matching (AWS keys, GitHub tokens, Stripe keys, Slack tokens). Real or example — if a credential pattern ships in your skill, that's a problem. |
| yara-scan | Matches files against YARA rules for malware patterns |
| ioc-match | Matches IPs, domains, URLs, and file hashes against ThreatFox, URLhaus, MalwareBazaar, and Feodo trackers |
| behavioral | Detects suspicious patterns: eval usage, shell injection, data exfiltration vectors, DNS tunneling |
| prompt-inject | Detects prompt injection and instruction-hiding patterns in SKILL.md |

## The credential theft problem

Every major supply chain attack in 2026 was a credential problem, not a perimeter problem:

- **OpenAI Codex** — npm packages stole authentication tokens from developer environments
- **Red Hat** — Miasma attack compromised npm packages through credential harvesting
- **TanStack** — 35,000+ incidents from compromised dependencies
- **Lithuanian Registry** — 600K records stolen via info-stealer on an authorized user's machine

Frisk's credential leak scan catches this at the source. If a skill ships with hardcoded AWS keys, GitHub tokens, Stripe secrets, or Slack tokens — even example keys — that's a credential waiting to be swapped for a real one. Frisk flags it before you install.

## Threat intel sources (9, continuously synced)

CISA KEV · OSV (npm + PyPI) · EPSS · MalwareBazaar · URLhaus · ThreatFox · Feodo Tracker · YARA Rules · Semgrep Rules

Run `frisk sync` to refresh the intel cache.

## Security & Privacy

- **No data leaves your machine.** All scanning happens locally. No telemetry, no phone-home, no analytics.
- **Downloaded skills are sandboxed.** When scanning by slug, the skill is downloaded to a 0700-permission temp directory, all files have execute permissions stripped before scanning, and npm postinstall scripts are suppressed. The skill is deleted after scanning.
- **Credentials stay local.** Frisk reads environment variables for configuration but never transmits them.

### External endpoints

Frisk downloads threat intel feeds from these public sources during `frisk sync`:

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

During `frisk scan`, no network requests are made. All intel is local.

### Local files read

- `~/.frisk/intel/` — Threat intel cache
- Skill directory passed as scan target

### Local files written

- `~/.frisk/intel/` — Synced threat intel data
- `~/.frisk/reports/` — Scan reports (JSON)
- `~/.frisk/venv/` — Python virtual environment for scan checks
- `~/.frisk/frisk.log` — Scan log output

### Trust statement

By using Frisk, you trust the threat intel sources listed above to provide accurate vulnerability and IOC data. No skill code or scan targets are transmitted to any external service. Install it only if you trust the Low Watt Labs project and the listed intel sources.

## Install

```bash
npm install -g @lowwattlabs/frisk
```

First run automatically creates a Python venv and syncs threat intel. After that, `frisk scan` works with zero configuration.

## Docker

```bash
docker build -t lowwattlabs/frisk .
docker run -p 3100:3100 lowwattlabs/frisk
```

## Pricing

Free. No paid tier, no API keys, no limits. If you find it useful, [buy me a coffee](https://buymeacoffee.com/lowwattlabs).

## License

MIT-0 — same as all ClawHub skills.
