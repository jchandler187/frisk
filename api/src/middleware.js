/**
 * ⚡ Frisk v2 - API Middleware
 * Rate limiting, auth, request logging, raw body capture for webhooks
 */

const { RateLimiterMemory } = require('rate-limiter-flexible');
const path = require('path');
const os = require('os');
const fs = require('fs');

const FRISK_DIR = process.env.FRISK_HOME || path.join(os.homedir(), '.frisk');

// Routes that skip auth + rate limiting (public endpoints)
const PUBLIC_PATHS = [
    '/api/v1/checkout',
    '/api/v1/webhook',
    '/api/v1/key',
    '/health',
];

// Rate limiter: 5 scans/day for free tier, much higher for API key holders
const freeLimiter = new RateLimiterMemory({
    points: 5,
    duration: 86400, // 24 hours
    blockDuration: 86400,
});

const proLimiter = new RateLimiterMemory({
    points: 1000,
    duration: 86400,
    blockDuration: 3600,
});

// Load API keys from config
function loadApiKeys() {
    const keysFile = path.join(FRISK_DIR, 'api', 'api-keys.json');
    if (fs.existsSync(keysFile)) {
        try {
            return JSON.parse(fs.readFileSync(keysFile, 'utf8'));
        } catch {
            return {};
        }
    }
    return {};
}

// Raw body capture middleware — stores unparsed body on req.rawBody
// Required for Stripe webhook signature verification
const rawBodyCapture = (req, res, buf, encoding) => {
    if (buf && buf.length > 0) {
        req.rawBody = buf.toString(encoding || 'utf8');
    }
};

// Rate limiter middleware
const rateLimiter = async (req, res, next) => {
    // Skip rate limiting for public paths
    if (PUBLIC_PATHS.some(p => req.path.startsWith(p))) {
        return next();
    }

    const apiKey = req.headers['x-api-key'] || (req.headers['authorization'] || '').replace('Bearer ', '');
    const keys = loadApiKeys();

    if (apiKey && keys[apiKey]) {
        // Pro user
        try {
            await proLimiter.consume(apiKey);
            req.userTier = 'pro';
            req.userId = keys[apiKey].email || apiKey;
        } catch {
            return res.status(429).json({
                error: 'Rate limit exceeded',
                tier: 'pro',
                retry_after: '1 hour'
            });
        }
    } else {
        // Free tier - rate limit by IP
        const clientIp = req.ip || req.connection.remoteAddress;
        try {
            await freeLimiter.consume(clientIp);
            req.userTier = 'free';
        } catch {
            return res.status(429).json({
                error: 'Rate limit exceeded',
                tier: 'free',
                limit: '5 scans/day',
                upgrade: 'Get an API key for higher limits'
            });
        }
    }
    next();
};

// API key auth (optional - works without, just gets free tier)
const apiKeyAuth = (req, res, next) => {
    // Skip auth for public paths
    if (PUBLIC_PATHS.some(p => req.path.startsWith(p))) {
        return next();
    }

    const apiKey = req.headers['x-api-key'] || (req.headers['authorization'] || '').replace('Bearer ', '');
    if (apiKey) {
        const keys = loadApiKeys();
        if (keys[apiKey]) {
            req.authenticated = true;
            req.userTier = keys[apiKey].tier || 'pro';
            req.userId = keys[apiKey].email || 'unknown';
        }
    }
    next();
};

// Request logger
const requestLogger = (req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const tier = req.userTier || 'free';
        console.log('[' + new Date().toISOString() + '] ' + req.method + ' ' + req.path + ' ' + res.statusCode + ' ' + duration + 'ms [' + tier + ']');
    });
    next();
};

module.exports = {
    rateLimiter,
    apiKeyAuth,
    requestLogger,
    rawBodyCapture,
    PUBLIC_PATHS,
};
