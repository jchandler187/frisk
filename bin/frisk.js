#!/usr/bin/env node
/**
 * ⚡ Frisk CLI Entry Point
 * Bootstraps Python venv if needed, then delegates to frisk.py
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const FRISK_HOME = process.env.FRISK_HOME || path.join(os.homedir(), '.frisk');
const VENV_DIR = path.join(FRISK_HOME, 'venv');
const PYTHON = path.join(VENV_DIR, 'bin', 'python3');

// Resolve package root — walk up from __dirname to find cli/frisk.py
function findPackageRoot() {
  let dir = __dirname;
  // Check if we're running from installed package
  if (fs.existsSync(path.join(dir, '..', 'cli', 'frisk.py'))) {
    return path.resolve(dir, '..');
  }
  // Fallback
  return path.resolve(dir, '..');
}

const PKG_ROOT = findPackageRoot();
const FRISK_PY = path.join(PKG_ROOT, 'cli', 'frisk.py');
const REQUIREMENTS = path.join(PKG_ROOT, 'requirements.txt');

function log(msg) {
  // Only show setup messages, not the ⚡ branding (Python handles that)
  process.stderr.write(msg + '\n');
}

function setupVenv() {
  if (fs.existsSync(PYTHON)) {
    return true;
  }

  log('⚡ Setting up Frisk Python environment (first run only)...');

  try {
    // Create FRISK_HOME
    fs.mkdirSync(FRISK_HOME, { recursive: true });

    // Create venv
    log('  Creating Python venv...');
    execSync(`python3 -m venv "${VENV_DIR}"`, { stdio: 'inherit' });

    // Install requirements
    if (fs.existsSync(REQUIREMENTS)) {
      log('  Installing Python dependencies...');
      execSync(`"${PYTHON}" -m pip install --quiet --upgrade pip`, { stdio: 'inherit' });
      execSync(`"${PYTHON}" -m pip install --quiet -r "${REQUIREMENTS}"`, { stdio: 'inherit' });
    }

    log('  ✅ Python environment ready.');
    return true;
  } catch (err) {
    log(`❌ Failed to set up Python environment: ${err.message}`);
    log('   Try running: frisk setup');
    return false;
  }
}

function run() {
  // Ensure venv exists
  if (!setupVenv()) {
    process.exit(1);
  }

  // Build args — pass through all CLI args
  const args = [FRISK_PY, ...process.argv.slice(2)];

  // Set env vars for Python subprocess
  const env = {
    ...process.env,
    FRISK_HOME: FRISK_HOME,
    FRISK_INTEL_DIR: process.env.FRISK_INTEL_DIR || path.join(FRISK_HOME, 'intel'),
    PATH: `${path.join(os.homedir(), '.local', 'bin')}:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin'}`,
  };

  const child = spawn(PYTHON, args, {
    env,
    stdio: 'inherit',
  });

  child.on('close', (code) => {
    process.exit(code ?? 1);
  });

  child.on('error', (err) => {
    log(`❌ Failed to run frisk: ${err.message}`);
    process.exit(1);
  });
}

run();