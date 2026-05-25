/**
 * ⚡ Frisk v2 - Cloud API Server
 * Express-based security verification service
 */

const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const routes = require('./routes');
const middleware = require('./middleware');

const FRISK_DIR = process.env.FRISK_HOME || path.join(os.homedir(), '.frisk');
const REPORTS_DIR = process.env.FRISK_REPORTS_DIR || path.join(FRISK_DIR, 'reports');
const PORT = process.env.FRISK_PORT || 3100;

const app = express();

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(middleware.rateLimiter);
app.use(middleware.apiKeyAuth);
app.use(middleware.requestLogger);

// CORS
app.use(require('cors')({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// API routes
app.use('/api/v1', routes);

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: '2.5.0', uptime: process.uptime() });
});

// Error handler
app.use((err, req, res, next) => {
    console.error("[ERROR] " + err.message);
    res.status(err.status || 500).json({
        error: err.message || 'Internal server error',
        status: err.status || 500
    });
});

// Start
const HOST = process.env.FRISK_HOST || '127.0.0.1';
// NOTE: For Docker, set FRISK_HOST=0.0.0.0 to bind all interfaces
app.listen(PORT, HOST, () => {
    console.log(`⚡ Frisk API v2.4.0 listening on ${HOST}:${PORT}`);
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
});
