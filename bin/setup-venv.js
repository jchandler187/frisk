#!/usr/bin/env node
/**
 * ⚡ Frisk postinstall — sets up Python venv and runs initial intel sync
 * Called by npm postinstall. Safe to run multiple times.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const FRISK_HOME = process.env.FRISK_HOME || path.join(os.homedir(), '.frisk');
const VENV_DIR = path.join(FRISK_HOME, 'venv');
const PYTHON = path.join(VENV_DIR, 'bin', 'python3');
const INTEL_DIR = path.join(FRISK_HOME, 'intel');

// Don't fail install if setup fails — user can run frisk setup later
try {
  // Step 1: Create Python venv if needed
  if (!fs.existsSync(PYTHON)) {
    fs.mkdirSync(FRISK_HOME, { recursive: true });
    console.log('⚡ Setting up Frisk Python environment (first run)...');
    execSync(`python3 -m venv "${VENV_DIR}"`, { stdio: 'inherit' });

    const PKG_ROOT = path.resolve(__dirname, '..');
    const REQUIREMENTS = path.join(PKG_ROOT, 'requirements.txt');

    if (fs.existsSync(REQUIREMENTS)) {
      execSync(`"${PYTHON}" -m pip install --quiet --upgrade pip`, { stdio: 'pipe' });
      execSync(`"${PYTHON}" -m pip install --quiet -r "${REQUIREMENTS}"`, { stdio: 'pipe' });
    }
    console.log('  ✅ Python environment ready.');
  }

  // Step 2: Create intel directories and sync
  const intelDirs = [
    'cisa-kev', 'osv', 'osv/npm', 'osv/PyPI', 'epss',
    'malwarebazaar', 'urlhaus', 'threatfox', 'feodo',
    'yara-rules', 'yara-rules/repo', 'semgrep-rules', 'semgrep-rules/repo'
  ];
  for (const d of intelDirs) {
    fs.mkdirSync(path.join(INTEL_DIR, d), { recursive: true });
  }
  fs.mkdirSync(path.join(FRISK_HOME, 'reports'), { recursive: true });

  // Only sync if intel cache is empty (first install)
  const manifest = path.join(INTEL_DIR, 'manifest.json');
  if (!fs.existsSync(manifest)) {
    console.log('⚡ Downloading threat intel (first run, may take a few minutes)...');
    const PKG_ROOT = path.resolve(__dirname, '..');
    const syncSh = path.join(PKG_ROOT, 'lib', 'intel-sync', 'sync.sh');
    if (fs.existsSync(syncSh)) {
      try {
        execSync(`bash "${syncSh}"`, {
          stdio: 'inherit',
          env: {
            ...process.env,
            FRISK_HOME: FRISK_HOME,
            FRISK_INTEL_DIR: INTEL_DIR,
            FRISK_REPORTS_DIR: path.join(FRISK_HOME, 'reports'),
            PATH: `${path.join(os.homedir(), '.local', 'bin')}:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`,
          }
        });
      } catch {
        // Sync failure is non-fatal — user can run frisk sync later
        console.log('  ⚠ Intel sync had issues. Run "frisk sync" to retry.');
      }
    }
  }

  console.log('⚡ Frisk ready. Run "frisk scan ./my-skill" to get started.');
} catch {
  // Postinstall is best-effort. The CLI will try again on first run.
  process.exit(0);
}