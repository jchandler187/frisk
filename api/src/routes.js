/**
 * ⚡ ClawSec v2 - API Routes
 */

const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const { generateBadge } = require('./badge');

const router = express.Router();
const CLAWSEC_DIR = process.env.CLAWSEC_HOME || path.join(os.homedir(), '.clawsec');
const REPORTS_DIR = process.env.CLAWSEC_REPORTS_DIR || path.join(CLAWSEC_DIR, 'reports');
const INTEL_DIR = process.env.CLAWSEC_INTEL_DIR || path.join(CLAWSEC_DIR, 'intel');

// Validate id param: alphanumeric + hyphens only, max 128 chars
function sanitizeId(id) {
    if (!id || !/^[a-zA-Z0-9_-]+$/.test(id) || id.length > 128) return null;
    return id;
}

// Validate slug for clawhub install: same rules as id
function sanitizeSlug(slug) {
    if (!slug || !/^[a-zA-Z0-9_-]+$/.test(slug) || slug.length > 128) return null;
    return slug;
}

// Strip execute permissions from all files in a directory tree.
// Security: downloaded skills are READ ONLY during scanning — never executed.
function hardenSkillDir(dir) {
    try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                hardenSkillDir(fullPath);
            } else {
                try {
                    const mode = fs.statSync(fullPath).mode;
                    // Remove all execute bits (user, group, other)
                    fs.chmodSync(fullPath, mode & ~0o111);
                } catch {}
            }
        }
    } catch {}
}

// Create a restricted temp directory for skill downloads.
// Returns the path to the temp dir.
function createScanTempDir() {
    const tmpDir = path.join(os.tmpdir(), 'clawsec-scan-' + uuidv4());
    fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
    return tmpDir;
}

router.post('/scan', (req, res) => {
    const { slug, content, path: reqPath } = req.body;

    if (!slug && !content && !reqPath) {
        return res.status(400).json({
            error: 'Must provide slug, content, or path',
            required: ['slug | content | path']
        });
    }

    let targetDir;
    let cleanup = false;

    try {
        if (reqPath && fs.existsSync(reqPath)) {
            targetDir = reqPath;
        } else if (slug) {
            // Validate slug before passing to clawhub install
            const safeSlug = sanitizeSlug(slug);
            if (!safeSlug) {
                return res.status(400).json({ error: 'Invalid slug: must be alphanumeric with hyphens/underscores, max 128 chars' });
            }
            // Download from ClawHub into restricted temp directory
            const tmpDir = createScanTempDir();
            try {
                // SECURITY: suppress npm postinstall scripts from the downloaded skill
                execFileSync('clawhub', ['install', safeSlug, '--dir', tmpDir, '--no-input'], {
                    timeout: 60000,
                    encoding: 'utf8',
                    env: { ...process.env, npm_config_ignore_scripts: 'true' }
                });
                // Find the installed skill directory
                const dirs = fs.readdirSync(tmpDir);
                if (dirs.length > 0) {
                    targetDir = path.join(tmpDir, dirs[0]);
                }
                // SECURITY: strip execute permissions from all downloaded files
                if (targetDir) {
                    hardenSkillDir(targetDir);
                }
                cleanup = true;
            } catch (e) {
                // Clean up on failure
                try { fs.rmSync(tmpDir, { recursive: true }); } catch {}
                return res.status(404).json({ error: 'Skill not found: ' + slug });
            }
        } else if (content) {
            // Write content to temp dir
            const tmpDir = createScanTempDir();

            if (typeof content === 'string') {
                fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), content);
            } else if (typeof content === 'object') {
                // Object with file contents
                for (const [filename, fileContent] of Object.entries(content)) {
                    // Sanitize filename against path traversal
                    const safeName = path.basename(filename).replace(/\.\./g, '');
                    if (safeName !== filename || filename.includes('..')) {
                        return res.status(400).json({ error: 'Invalid filename: ' + filename });
                    }
                    // Ensure resolved path stays within tmpDir
                    const filePath = path.resolve(tmpDir, filename);
                    if (!filePath.startsWith(path.resolve(tmpDir) + path.sep)) {
                        return res.status(400).json({ error: 'Path traversal in filename: ' + filename });
                    }
                    const dirPath = path.dirname(filePath);
                    if (!fs.existsSync(dirPath)) {
                        fs.mkdirSync(dirPath, { recursive: true });
                    }
                    fs.writeFileSync(filePath, fileContent);
                }
            }
            targetDir = tmpDir;
            cleanup = true;
        }

        if (!targetDir) {
            return res.status(400).json({ error: 'Could not resolve skill target' });
        }

        // Run verification — resolve from package root, not CLAWSEC_DIR
        const verifyWrapper = path.join(__dirname, 'verify-wrapper.sh');
        let result;
        try {
            const output = execFileSync('bash', [verifyWrapper, targetDir], {
                timeout: 30000,
                encoding: 'utf8',
                env: { ...process.env, PATH: process.env.HOME + '/.local/bin:' + process.env.PATH }
            });
            result = JSON.parse(output.trim());
        } catch (e) {
            // Non-zero exit (warn=1, fail=2) still gives stdout via e.stdout
            const output = e.stdout || e.stderr || '';
            try {
                result = JSON.parse(output.trim());
            } catch(e2) {
                result = {
                    verdict: 'error',
                    error: 'Verification failed',
                    details: e.message,
                    stdout_preview: (e.stdout || '').substring(0, 200)
                };
            }
        }

        // Save report
        const reportId = result.report_id || uuidv4();
        const reportPath = path.join(REPORTS_DIR, reportId + '.json');
        fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));

        // Add scan URL to response
        result.report_url = '/api/v1/report/' + reportId;
        result.badge_url = '/api/v1/badge/' + reportId + '.svg';

        res.json({ report_id: reportId, ...result });

    } finally {
        if (cleanup && targetDir) {
            try { fs.rmSync(targetDir, { recursive: true }); } catch {}
            // Also try cleaning parent if it's a scan temp dir
            const parentDir = path.dirname(targetDir);
            if (parentDir.includes('clawsec-scan-')) {
                try { fs.rmSync(parentDir, { recursive: true }); } catch {}
            }
        }
    }
});

// GET /api/v1/report/:id - Retrieve a saved report
router.get('/report/:id', (req, res) => {
    const id = sanitizeId(req.params.id);
    if (!id) return res.status(403).json({ error: 'invalid id' });
    const reportPath = path.join(REPORTS_DIR, id + '.json');
    const resolved = path.resolve(reportPath);
    if (!resolved.startsWith(REPORTS_DIR + path.sep)) return res.status(403).json({ error: 'invalid id' });
    if (!fs.existsSync(resolved)) {
        return res.status(404).json({ error: 'Report not found' });
    }
    const report = JSON.parse(fs.readFileSync(resolved, 'utf8'));
    res.json(report);
});

// GET /api/v1/badge/:id.svg - Trust badge
router.get('/badge/:id.svg', (req, res) => {
    const rawId = req.params.id.replace('.svg', '');
    const id = sanitizeId(rawId);
    if (!id) return res.type('svg').status(403).send(generateBadge('unknown'));
    const reportPath = path.join(REPORTS_DIR, id + '.json');
    const resolved = path.resolve(reportPath);
    if (!resolved.startsWith(REPORTS_DIR + path.sep)) return res.type('svg').status(403).send(generateBadge('unknown'));
    if (!fs.existsSync(resolved)) {
        return res.type('svg').status(404).send(generateBadge('unknown'));
    }
    const report = JSON.parse(fs.readFileSync(resolved, 'utf8'));
    res.type('svg').send(generateBadge(report.verdict));
});

// GET /api/v1/status - Intel cache status
router.get('/status', (req, res) => {
    const manifestPath = path.join(INTEL_DIR, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
        return res.json({ sources: [], updated_at: null });
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    res.json(manifest);
});

module.exports = router;