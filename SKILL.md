---
name: frisk
description: "Pre-install security audit and vulnerability scanner for ClawHub skills — scan by slug or local path, 9 threat intel sources, 7 checks including malware scanning, dependency vulnerabilities, and credential leak detection."
version: 3.1.2
metadata:
  openclaw:
    emoji: "⚡"
    homepage: https://github.com/lowwattlabs/frisk
    requires:
      bins:
        - python3
        - clawhub
      anyBins:
        - gitleaks
        - semgrep
        - yara
    install:
      - kind: node
        package: "@lowwattlabs/frisk"
        bins:
          - frisk
    envVars:
      - name: FRISK_HOME
        required: false
        description: "Base directory for intel cache and reports (default: ~/.frisk)"
      - name: FRISK_INTEL_DIR
        required: false
        description: "Override intel cache directory (default: FRISK_HOME/intel)"
      - name: FRISK_REPORTS_DIR
        required: false
        description: "Override reports output directory (default: FRISK_HOME/reports)"
---

# ⚡ Frisk

**Your `npm install` just handed someone your AWS keys.** Frisk catches it.

Credential theft is the #1 attack vector in the AI agent supply chain. OpenAI Codex tokens, Red Hat npm packages, TanStack — all stolen through compromised dependencies. The perimeter doesn't matter when the credentials are already inside.

Frisk scans ClawHub skills against 9 threat intel sources with 7 autonomous security checks. It catches leaked API keys, credential patterns, malware signatures, shell injection, and prompt injection — before you install.

If you find it useful, [buy me a coffee](https://buymeacoffee.com/lowwattlabs) ⚡

## Why Frisk exists

Semantic guardrails are vibes. Frisk is proof.

Most agent security today tries to detect bad intent through embeddings and heuristics — hoping the distance between "help me" and "exploit this" is wide enough. It never is. When an agent gains the ability to execute a tool or modify a file, the conversation is over. The only thing that matters is whether the operation carries a real threat.

Frisk doesn't guess intent. It matches signatures. 2,371 malicious skills were found on ClawHub in 2026. Someone has to check before you install. That's what this does.

## Registry scanning vs local scanning

OpenClaw and NVIDIA are building [ClawScan](https://openclaw.ai/blog/openclaw-nvidia-skill-security) — a registry-level scanning pipeline that validates skills before they enter the ClawHub marketplace. That's defense at the gate.

Frisk is defense at your door. Same checks, your machine, no registry dependency. Use both:

- **ClawScan** catches threats before they enter the registry
- **Frisk** catches what slips through, what's already installed, and what comes from outside the registry (local skills, git clones, private packages)

Trust the registry. Verify locally.

## When to use

- Before installing a skill from ClawHub — verify it is safe
- Before publishing your own skills — catch issues early
- When reviewing skills for your team or organization
- As part of CI/CD or pipeline validation
- When you want to verify a skill is safe before trusting it with your environment
- Any time an agent encounters an untrusted skill and needs a security check

## Quick start

```bash
frisk scan weather-forecast        # Scan by ClawHub slug
frisk scan ./my-skill              # Scan a local skill directory
frisk scan ./my-skill --checks dep-scan,secret-scan
frisk scan ./my-skill --json       # JSON output for pipelines
```

First run sets up a Python venv and syncs threat intel automatically. After that, scanning works with zero configuration.

## How it works

Frisk downloads the skill to a sandboxed 0700 temp directory, strips execute bits from all files, suppresses npm install scripts, runs all enabled checks against the local intel cache, produces a structured JSON report with findings, and cleans up the downloaded skill.

Exit codes: 0 = pass, 1 = warn, 2 = fail

## Checks

| Check | What it does |
|-------|-------------|
| dep-scan | Cross-references dependencies against CISA KEV and OSV databases |
| static-analysis | Runs Semgrep rules for security anti-patterns (offline, no phone-home) |
| secret-scan | Scans for hardcoded API keys, tokens, and credentials using Gitleaks + heuristic matching for AWS access keys (AKIA...), GitHub tokens (ghp_/gho_/ghs_...), Stripe keys (sk_live/pk_live...), and Slack tokens (xoxb-/xoxp-...) |
| yara-scan | Matches files against YARA rules for malware patterns |
| ioc-match | Matches IPs, domains, URLs, and file hashes against ThreatFox, URLhaus, MalwareBazaar, and Feodo Tracker |
| behavioral | Detects eval usage, shell injection, data exfiltration vectors, DNS tunneling |
| prompt-inject | Detects prompt injection and instruction-hiding patterns in SKILL.md |

## Threat intel sources (9)

CISA KEV, OSV (npm + PyPI), EPSS, MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker, YARA Rules, Semgrep Rules

Run `frisk sync` to refresh the intel cache. First scan auto-syncs if no cache exists.

## The credential theft problem

Every major supply chain attack in 2026 was a credential problem, not a perimeter problem:

- **OpenAI Codex** — npm packages stole authentication tokens from developer environments
- **Red Hat** — Miasma attack compromised npm packages through credential harvesting
- **TanStack** — 42 packages with 84 versions compromised (official postmortem)
- **Lithuanian Registry** — 600K records stolen via info-stealer on an authorized user's machine

The common thread: valid credentials in the wrong hands. Frisk's credential leak scan catches this at the source.

## Parameters

When an agent invokes this skill through OpenClaw:

- **target** (required) — Local directory path or ClawHub skill slug. If a slug is given, the skill is downloaded to a sandboxed temp directory, scanned, and removed.
- **checks** (optional) — Comma-separated list: `dep-scan`, `static-analysis`, `secret-scan`, `yara-scan`, `ioc-match`, `behavioral`, `prompt-inject`. Default: all 7.
- **json** (optional) — Output results as JSON for programmatic use.

## Security and Privacy

- No telemetry, no phone-home, no analytics. All scanning is local.
- During scan, zero network requests. All intel is read from the local cache.
- During sync, only public threat intel feeds are contacted. No skill code or scan targets are ever transmitted externally.
- Slug scans are sandboxed: 0700 temp dir, execute bits stripped, npm scripts suppressed, cleaned up after scanning.

### Local files

- Read: `~/.frisk/intel/` (threat intel cache), skill directory passed as target
- Written: `~/.frisk/intel/`, `~/.frisk/reports/`, `~/.frisk/venv/`, `~/.frisk/frisk.log`
- First sync downloads approximately 50-100 MB of threat intel data

## Install

```bash
npm install -g @lowwattlabs/frisk
```

Or let OpenClaw install it via the skill install spec above.

## Also by Low Watt Labs

- **🪙 HOARD** — Durable agent memory that survives session resets. [GitHub](https://github.com/lowwattlabs/hoard) · [npm](https://npmjs.com/package/@lowwattlabs/hoard) · [ClawHub](https://clawhub.ai/lowwattlabs/hoard)
- **⚡ LFIT** — Local HD image generation on your hardware. Free, private, zero API keys. [GitHub](https://github.com/lowwattlabs/lfit) · [npm](https://npmjs.com/package/@lowwattlabs/lfit) · [ClawHub](https://clawhub.ai/lowwattlabs/lfit)

## License

MIT-0
