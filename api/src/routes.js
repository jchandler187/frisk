/**
 * ClawSec v2 - API Routes
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const { generateBadge } = require('./badge');

const router = express.Router();
const CLAWSEC_DIR = path.join(process.env.CLAWSEC_HOME || (process.env.HOME || '/home/openclaw') + '/clawsec-v2');
const REPORTS_DIR = path.join(CLAWSEC_DIR, 'reports');
const INTEL_DIR = process.env.CLAWSEC_INTEL_DIR || '/srv/clawsec/intel';

// POST /api/v1/scan - Submit skill for verification
// Validate id param: alphanumeric + hyphens only
function sanitizeId(id) {
    if (!/^[a-zA-Z0-9-]+$/.test(id)) return null;
    return id;
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
            // Try to install from ClawHub
            const tmpDir = `/tmp/clawsec-scan-${uuidv4().slice(0, 8)}`;
            try {
                execFileSync('clawhub', ['install', slug, '--dir', tmpDir], {
                    timeout: 60000, encoding: 'utf8'
                });
                // Find the installed skill
                const dirs = fs.readdirSync(tmpDir);
                if (dirs.length > 0) {
                    targetDir = path.join(tmpDir, dirs[0]);
                    cleanup = true;
                }
            } catch (e) {
                return res.status(404).json({ error: `Skill not found: ${slug}` });
            }
        } else if (content) {
            // Write content to temp dir
            const tmpDir = `/tmp/clawsec-scan-${uuidv4().slice(0, 8)}`;
            fs.mkdirSync(tmpDir, { recursive: true });

            if (typeof content === 'string') {
                fs.writeFileSync(path.join(tmpDir, 'SKILL.md'), content);
            } else if (typeof content === 'object') {
                // Object with file contents
                for (const [filename, fileContent] of Object.entries(content)) {
                    const filePath = path.join(tmpDir, filename);
                    fs.mkdirSync(path.dirname(filePath), { recursive: true });
                    fs.writeFileSync(filePath, fileContent);
                }
            }
            targetDir = tmpDir;
            cleanup = true;
        }

        if (!targetDir) {
            return res.status(400).json({ error: 'Could not resolve skill target' });
        }

        // Run verification
        const verifyWrapper = path.join(CLAWSEC_DIR, 'api', 'src', 'verify-wrapper.sh');
        let result;
        try {
            const output = execFileSync('bash', [verifyWrapper, targetDir], {
                timeout: 30000,
                encoding: 'utf8',
                env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` }
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
        const reportId = result.report_id || uuidv4().slice(0, 8);
        const reportPath = path.join(REPORTS_DIR, `${reportId}.json`);
        fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));

        // Add scan URL to response
        result.report_url = `/api/v1/report/${reportId}`;
        result.badge_url = `/api/v1/badge/${reportId}.svg`;

        res.json({ report_id: reportId, ...result });

    } finally {
        if (cleanup && targetDir && targetDir.startsWith('/tmp/clawsec-scan-')) {
            try { fs.rmSync(targetDir, { recursive: true }); } catch {}
        }
    }
});

// GET /api/v1/report/:id - Retrieve a saved report
router.get('/report/:id', (req, res) => {
    const id = sanitizeId(req.params.id);
    if (!id) return res.status(403).json({ error: 'invalid id' });
    const reportPath = path.join(REPORTS_DIR, `${id}.json`);
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
    const reportPath = path.join(REPORTS_DIR, `${id}.json`);
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