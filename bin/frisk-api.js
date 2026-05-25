#!/usr/bin/env node
/**
 * ⚡ Frisk API Server Entry Point
 * Starts the Express API server
 */

const path = require('path');

// Set defaults before requiring server
const FRISK_HOME = process.env.FRISK_HOME || path.join(require('os').homedir(), '.frisk');
const INTEL_DIR = process.env.FRISK_INTEL_DIR || path.join(FRISK_HOME, 'intel');
const REPORTS_DIR = path.join(FRISK_HOME, 'reports');

process.env.FRISK_HOME = FRISK_HOME;
process.env.FRISK_INTEL_DIR = INTEL_DIR;
process.env.FRISK_REPORTS_DIR = REPORTS_DIR;

// Require the server — it reads env vars at module level
require('../api/src/server');