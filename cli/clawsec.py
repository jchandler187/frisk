#!/usr/bin/env python3
# ⚡ Low Watt Labs — ClawSec
"""⚡ ClawSec v2 — Skill Security Verification

Usage:
    clawsec scan <slug|path>   Verify a skill
    clawsec sync [source...]   Refresh intel cache
    clawsec status             Show cache status
    clawsec report <id>        View a saved report
    clawsec --help             Show help
    clawsec --version          Show version
"""

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "2.5.0"
CLAWSEC_DIR = os.environ.get("CLAWSEC_HOME", os.path.expanduser("~/.clawsec"))
INTEL_DIR = os.environ.get("CLAWSEC_INTEL_DIR", os.path.join(CLAWSEC_DIR, "intel"))
REPORTS_DIR = os.environ.get("CLAWSEC_REPORTS_DIR", os.path.join(CLAWSEC_DIR, "reports"))

# Resolve package root — cli/clawsec.py -> parent = package root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(SCRIPT_DIR)

# ANSI colors
R = "\033[0;31m"
G = "\033[0;32m"
Y = "\033[0;33m"
B = "\033[0;34m"
C = "\033[0;36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner():
    print(f"""{BOLD}
  ╔═════════════════════════════════════════╗
  ║   ClawSec v{VERSION}                      ║
  ║   ⚡ Security Verification for ClawHub  ║
  ╚═════════════════════════════════════════╝{RESET}
""")


def is_slug(target):
    """Check if target looks like a ClawHub slug (no path separators, no dots, not a local path)."""
    if os.path.exists(target):
        return False
    if "/" in target or target.startswith("."):
        return False
    # Slugs are alphanumeric with hyphens, no extensions
    if target.startswith("-") or target.endswith("-"):
        return False
    return True


def harden_skill_dir(skill_dir):
    """
    Remove execute permissions from all files in the skill directory.
    This prevents any scripts from being executed accidentally before or during scanning.
    We only need to READ these files, never execute them.
    """
    for root, dirs, files in os.walk(skill_dir):
        for f in files:
            fpath = os.path.join(root, f)
            try:
                current_mode = os.stat(fpath).st_mode
                # Remove all execute bits (user, group, other)
                os.chmod(fpath, current_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            except OSError:
                pass


def download_slug(slug):
    """
    Download a skill from ClawHub by slug.
    
    Security measures:
    - Downloads to a restricted temp directory (0700 permissions)
    - Strips execute permissions from all downloaded files before returning
    - Uses --no-input flag to prevent any interactive prompts
    - Does NOT run any postinstall scripts from the downloaded skill
    
    Returns (skill_path, cleanup_dir) or None on failure.
    """
    # Create temp dir with restricted permissions (owner only)
    tmpdir = tempfile.mkdtemp(prefix="clawsec-scan-")
    os.chmod(tmpdir, stat.S_IRWXU)  # 0700 — owner read/write/exec only

    try:
        result = subprocess.run(
            ["clawhub", "install", slug, "--dir", tmpdir, "--no-input"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "npm_config_ignore_scripts": "true"}  # Never run skill's postinstall
        )
        if result.returncode != 0:
            print(f"{R}Error:{RESET} Failed to install '{slug}' from ClawHub", file=sys.stderr)
            if result.stderr:
                print(f"  {DIM}{result.stderr.strip()}{RESET}", file=sys.stderr)
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        # Find the installed skill directory
        entries = list(Path(tmpdir).iterdir())
        if not entries:
            print(f"{R}Error:{RESET} ClawHub install produced no output for '{slug}'", file=sys.stderr)
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None

        # Determine skill path
        if len(entries) == 1 and entries[0].is_dir():
            skill_path = str(entries[0])
        else:
            skill_path = tmpdir

        # SECURITY: Strip execute permissions from ALL downloaded files.
        # We only need to read them for scanning — never execute them.
        harden_skill_dir(skill_path)

        return skill_path, tmpdir

    except FileNotFoundError:
        print(f"{R}Error:{RESET} 'clawhub' CLI not found. Install it with: npm install -g clawhub", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None
    except subprocess.TimeoutExpired:
        print(f"{R}Error:{RESET} ClawHub install timed out for '{slug}'", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None


def cmd_scan(args):
    """Run verification against a skill path or ClawHub slug."""
    target = args.target
    json_mode = args.json
    cleanup_dir = None

    # If it looks like a slug, try to download from ClawHub
    if is_slug(target):
        if not json_mode:
            print(f"  {C}⚡ Downloading '{target}' from ClawHub...{RESET}", flush=True)
        result = download_slug(target)
        if result is None:
            sys.exit(2)
        target, cleanup_dir = result
        if not json_mode:
            print(f"  {G}✓{RESET} Downloaded to {target}", flush=True)

    if not os.path.exists(target):
        print(f"{R}Error:{RESET} '{args.target}' not found (not a local path and not a valid ClawHub slug)", file=sys.stderr)
        sys.exit(2)

    # Run verify.sh — resolve relative to package root
    verify_sh = os.path.join(PKG_ROOT, "lib", "skill-verify", "verify.sh")
    # Fallback: check CLAWSEC_HOME (for dev/local setups)
    if not os.path.exists(verify_sh):
        verify_sh = os.path.join(CLAWSEC_DIR, "lib", "skill-verify", "verify.sh")

    cmd = ["bash", verify_sh]
    if json_mode:
        cmd.append("--json")
    if args.checks:
        cmd.append(f"--checks={args.checks}")
    cmd.append(target)

    result = subprocess.run(cmd, capture_output=json_mode, text=True)
    if json_mode:
        print(result.stdout)

    # Clean up downloaded skill
    if cleanup_dir:
        shutil.rmtree(cleanup_dir, ignore_errors=True)

    sys.exit(result.returncode)


def cmd_sync(args):
    """Run intel sync."""
    # Ensure intel directories exist
    intel_dirs = ['cisa-kev', 'osv', 'osv/npm', 'osv/PyPI', 'epss', 'malwarebazaar', 'urlhaus', 'threatfox', 'feodo', 'yara-rules', 'semgrep-rules']
    for d in intel_dirs:
        os.makedirs(os.path.join(INTEL_DIR, d), exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    sync_sh = os.path.join(PKG_ROOT, "lib", "intel-sync", "sync.sh")
    if not os.path.exists(sync_sh):
        sync_sh = os.path.join(CLAWSEC_DIR, "lib", "intel-sync", "sync.sh")

    cmd = ["bash", sync_sh]
    if args.json:
        cmd.append("--json")
    cmd.extend(args.sources)
    result = subprocess.run(cmd, text=True)
    sys.exit(result.returncode)


def cmd_status(args):
    """Show cache status."""
    manifest_py = os.path.join(PKG_ROOT, "lib", "intel-sync", "manifest.py")
    if not os.path.exists(manifest_py):
        manifest_py = os.path.join(CLAWSEC_DIR, "lib", "intel-sync", "manifest.py")
    manifest_path = os.path.join(INTEL_DIR, "manifest.json")

    if args.json:
        result = subprocess.run(["python3", manifest_py, "status"], capture_output=True, text=True)
        print(result.stdout)
        return

    if not os.path.exists(manifest_path):
        print(f"  {Y}No intel cache found{RESET}. Run {BOLD}clawsec sync{RESET} first.")
        return

    with open(manifest_path) as f:
        manifest = json.load(f)

    print(f"  {BOLD}Intel Cache Status{RESET}")
    print(f"  {'─' * 50}")

    for src in manifest.get("sources", []):
        status_icon = G + "✓" + RESET if src["status"] == "success" else Y + "⚠" + RESET if src["status"] == "partial" else R + "✗" + RESET
        last_sync = src.get("last_sync", "never")
        if last_sync != "never":
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                last_sync = dt.strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                pass
        count = src.get("record_count", 0)
        name = src["name"]
        print(f"  {status_icon}  {name:<18} {count:>8} records  {DIM}{last_sync}{RESET}")

    print(f"  {'─' * 50}")
    updated = manifest.get("updated_at", "never")
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        updated = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        pass
    print(f"  Last full sync: {updated}")


def cmd_report(args):
    """View a saved report."""
    report_id = args.report_id
    report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")

    if not os.path.exists(report_path):
        print(f"{R}Error:{RESET} Report {report_id} not found", file=sys.stderr)
        sys.exit(1)

    with open(report_path) as f:
        report = json.load(f)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    # Pretty-print
    verdict = report.get("verdict", "unknown")
    verdict_color = G if verdict == "pass" else Y if verdict == "warn" else R
    summary = report.get("summary", {})

    print(f"\n  {BOLD}Report: {report_id}{RESET}")
    print(f"  {'─' * 50}")
    print(f"  Skill:     {report.get('skill_path', 'unknown')}")
    print(f"  Verdict:   {verdict_color}{BOLD}{verdict.upper()}{RESET}")
    print(f"  Findings:  {summary.get('total_findings', 0)} total "
          f"({R}{summary.get('critical', 0)} critical{RESET}, "
          f"{Y}{summary.get('high', 0)} high{RESET}, "
          f"{summary.get('medium', 0)} medium)")
    print(f"  Time:      {report.get('timestamp', 'unknown')}")
    print(f"  {'─' * 50}")

    for check in report.get("checks", []):
        status = check.get("status", "unknown")
        icon = G + "✓" + RESET if status == "pass" else Y + "⚠" + RESET if status == "warn" else R + "✗" + RESET
        name = check.get("check", "unknown")
        findings = check.get("findings", [])
        errors = check.get("errors", [])
        count = len(findings) if findings else 0

        print(f"\n  {icon} {name} ({status})")
        if count > 0:
            for f in findings[:5]:
                desc = f.get("description", f.get("message", "No description"))
                sev = f.get("severity", "unknown")
                sev_color = R if sev in ("critical", "high") else Y if sev == "medium" else ""
                print(f"    {sev_color}● {desc}{RESET}")
            if count > 5:
                print(f"    {DIM}... and {count - 5} more{RESET}")
        if errors:
            for e in errors[:3]:
                print(f"    {DIM}err: {e}{RESET}")

    print()


def main():
    parser = argparse.ArgumentParser(
        prog="clawsec",
        description="⚡ ClawSec v2 — Security Verification for ClawHub Skills",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  clawsec scan ./my-skill          Verify a local skill directory
  clawsec scan weather-forecast     Download and scan from ClawHub
  clawsec scan ./my-skill --json   Machine-readable output
  clawsec sync                     Refresh all intel sources
  clawsec sync cisa-kev epss       Sync specific sources
  clawsec status                   Show cache status
  clawsec report abc123            View saved report"""
    )
    parser.add_argument("--version", action="version", version=f"clawsec v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Verify a skill (local path or ClawHub slug)")
    scan_parser.add_argument("target", help="Skill path or ClawHub slug (e.g. 'weather-forecast')")
    scan_parser.add_argument("--checks", help="Comma-separated list of checks to run")
    scan_parser.add_argument("--json", action="store_true", help="JSON output")

    # sync
    sync_parser = subparsers.add_parser("sync", help="Refresh intel cache")
    sync_parser.add_argument("sources", nargs="*", help="Specific sources to sync")
    sync_parser.add_argument("--json", action="store_true", help="JSON output")

    # status
    status_parser = subparsers.add_parser("status", help="Show cache status")
    status_parser.add_argument("--json", action="store_true", help="JSON output")

    # report
    report_parser = subparsers.add_parser("report", help="View saved report")
    report_parser.add_argument("report_id", help="Report ID")
    report_parser.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()

    if args.command is None:
        banner()
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "sync":
        cmd_sync(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()