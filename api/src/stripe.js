/**
 * ⚡ Frisk Wedge — Stripe Checkout Integration
 * Handles checkout sessions, webhooks, and API key provisioning
 */

const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const Stripe = require('stripe');

const FRISK_DIR = process.env.FRISK_HOME || path.join(os.homedir(), '.frisk');
const API_KEYS_FILE = path.join(FRISK_DIR, 'api', 'api-keys.json');

// Stripe price IDs — created in Stripe Dashboard
const PRICES = {
    monthly: process.env.STRIPE_PRICE_MONTHLY || 'price_1Tga4vCVgG0KBE70w3VncDJe',
    annual: process.env.STRIPE_PRICE_ANNUAL || 'price_1Tga4wCVgG0KBE704NkoNUzt',
};

const DOMAIN = process.env.FRISK_DOMAIN || 'http://localhost:3100';

// Load or initialize API keys store
function loadApiKeys() {
    if (fs.existsSync(API_KEYS_FILE)) {
        try {
            return JSON.parse(fs.readFileSync(API_KEYS_FILE, 'utf8'));
        } catch {
            return {};
        }
    }
    return {};
}

function saveApiKeys(keys) {
    const dir = path.dirname(API_KEYS_FILE);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(API_KEYS_FILE, JSON.stringify(keys, null, 2));
}

// Provision a new API key for a paying customer
function provisionKey(email, tier, customerId, subscriptionId) {
    const keys = loadApiKeys();
    const apiKey = 'frk_wedge_' + uuidv4().replace(/-/g, '');
    keys[apiKey] = {
        tier: tier,
        email: email,
        stripe_customer_id: customerId,
        stripe_subscription_id: subscriptionId,
        created: new Date().toISOString(),
        active: true,
    };
    saveApiKeys(keys);
    return apiKey;
}

const router = express.Router();

// POST /api/v1/checkout — Create a Stripe Checkout Session
router.post('/checkout', async (req, res) => {
    const { plan, email } = req.body;

    const priceId = PRICES[plan];
    if (!priceId) {
        return res.status(400).json({
            error: 'Invalid plan',
            valid_plans: ['monthly', 'annual'],
        });
    }

    let stripe;
    try {
        const secretKey = process.env.STRIPE_SECRET_KEY;
        if (!secretKey) {
            throw new Error('STRIPE_SECRET_KEY not configured');
        }
        stripe = new Stripe(secretKey);
    } catch (e) {
        console.error('[STRIPE] Init error:', e.message);
        return res.status(500).json({ error: 'Payment system not configured' });
    }

    try {
        const sessionParams = {
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: DOMAIN + '/api/v1/key?session_id={CHECKOUT_SESSION_ID}',
            cancel_url: DOMAIN + '/',
        };

        if (email) {
            sessionParams.customer_email = email;
        }

        const session = await stripe.checkout.sessions.create(sessionParams);

        console.log('[STRIPE] Checkout session created: ' + session.id);
        res.json({ url: session.url, session_id: session.id });
    } catch (e) {
        console.error('[STRIPE] Checkout error:', e.message);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// GET /api/v1/checkout — Create checkout via GET (for landing page buttons)
router.get('/checkout', async (req, res) => {
    const plan = req.query.plan || 'monthly';
    const priceId = PRICES[plan];

    if (!priceId) {
        return res.status(400).json({
            error: 'Invalid plan',
            valid_plans: ['monthly', 'annual'],
        });
    }

    let stripe;
    try {
        const secretKey = process.env.STRIPE_SECRET_KEY;
        if (!secretKey) {
            throw new Error('STRIPE_SECRET_KEY not configured');
        }
        stripe = new Stripe(secretKey);
    } catch (e) {
        console.error('[STRIPE] Init error:', e.message);
        return res.status(500).json({ error: 'Payment system not configured' });
    }

    try {
        const sessionParams = {
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: DOMAIN + '/api/v1/key?session_id={CHECKOUT_SESSION_ID}',
            cancel_url: DOMAIN + '/',
        };

        if (req.query.email) {
            sessionParams.customer_email = req.query.email;
        }

        const session = await stripe.checkout.sessions.create(sessionParams);

        // Redirect directly — this is a GET from a browser button
        res.redirect(303, session.url);
    } catch (e) {
        console.error('[STRIPE] Checkout error:', e.message);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

// POST /api/v1/webhook — Stripe webhook endpoint
// NOTE: This route needs raw body for signature verification.
// The server must NOT apply express.json() to this path.
router.post('/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let stripe;
    try {
        const secretKey = process.env.STRIPE_SECRET_KEY;
        if (!secretKey) throw new Error('STRIPE_SECRET_KEY not configured');
        stripe = new Stripe(secretKey);
    } catch (e) {
        console.error('[STRIPE] Init error:', e.message);
        return res.status(500).json({ error: 'Payment system not configured' });
    }

    let event;
    if (webhookSecret) {
        // Verify signature when secret is configured
        try {
            event = stripe.webhooks.constructEvent(req.rawBody, sig, webhookSecret);
        } catch (e) {
            console.error('[STRIPE] Webhook signature verification failed:', e.message);
            return res.status(400).json({ error: 'Invalid signature' });
        }
    } else {
        // No webhook secret — use raw body parsing (dev/test only)
        try {
            event = JSON.parse(req.rawBody);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid payload' });
        }
        console.warn('[STRIPE] Webhook received without signature verification (STRIPE_WEBHOOK_SECRET not set)');
    }

    console.log('[STRIPE] Webhook event: ' + event.type);

    switch (event.type) {
        case 'checkout.session.completed': {
            const session = event.data.object;
            const email = session.customer_email || session.customer_details?.email || 'unknown';
            const customerId = session.customer;
            const subscriptionId = session.subscription;

            // Determine tier from price ID
            const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
            const priceId = lineItems.data[0]?.price?.id;
            const tier = priceId === PRICES.annual ? 'wedge-annual' : 'wedge-monthly';

            const apiKey = provisionKey(email, tier, customerId, subscriptionId);
            console.log('[STRIPE] Provisioned API key for ' + email + ' (tier: ' + tier + ')');

            // Store key in session metadata so /key page can retrieve it
            try {
                await stripe.checkout.sessions.update(session.id, {
                    metadata: { frisk_api_key: apiKey },
                });
            } catch (e) {
                console.warn('[STRIPE] Could not update session metadata:', e.message);
            }
            break;
        }

        case 'customer.subscription.deleted': {
            // Deactivate key when subscription ends
            const subscription = event.data.object;
            const keys = loadApiKeys();
            for (const [key, data] of Object.entries(keys)) {
                if (data.stripe_subscription_id === subscription.id) {
                    data.active = false;
                    data.deactivated = new Date().toISOString();
                    console.log('[STRIPE] Deactivated key for ' + data.email);
                }
            }
            saveApiKeys(keys);
            break;
        }

        default:
            console.log('[STRIPE] Unhandled event type: ' + event.type);
    }

    res.json({ received: true });
});

// GET /api/v1/key — Show API key after checkout
router.get('/key', async (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) {
        return res.status(400).send('<h1>Missing session ID</h1><p>Use the link from your checkout confirmation.</p>');
    }

    let stripe;
    try {
        const secretKey = process.env.STRIPE_SECRET_KEY;
        if (!secretKey) throw new Error('STRIPE_SECRET_KEY not configured');
        stripe = new Stripe(secretKey);
    } catch (e) {
        console.error('[STRIPE] Init error:', e.message);
        return res.status(500).send('<h1>Server error</h1>');
    }

    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== 'paid') {
            return res.send('<h1>Payment not completed</h1><p>Please complete your checkout first.</p>');
        }

        const apiKey = session.metadata?.frisk_api_key;

        // If key wasn't stored in metadata (webhook hasn't fired yet), wait and retry
        let resolvedKey = apiKey;
        if (!resolvedKey) {
            // Poll a few times — webhook may still be processing
            for (let i = 0; i < 10; i++) {
                await new Promise(r => setTimeout(r, 1000));
                const refreshed = await stripe.checkout.sessions.retrieve(sessionId);
                resolvedKey = refreshed.metadata?.frisk_api_key;
                if (resolvedKey) break;
            }
        }

        if (!resolvedKey) {
            // Fallback: look up by customer email
            const email = session.customer_email || session.customer_details?.email;
            if (email) {
                const keys = loadApiKeys();
                for (const [key, data] of Object.entries(keys)) {
                    if (data.email === email && data.active) {
                        resolvedKey = key;
                        break;
                    }
                }
            }
        }

        if (!resolvedKey) {
            return res.send('<h1>Key provisioning in progress</h1><p>Your payment was received. Your API key is being provisioned — please refresh in a few seconds.</p>');
        }

        res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Frisk Wedge — Your API Key</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: #0d1117; color: #c9d1d9; line-height: 1.6;
            display: flex; align-items: center; justify-content: center; min-height: 100vh;
        }
        .container { max-width: 560px; padding: 48px 24px; }
        h1 { color: #3fb950; font-size: 1.8em; margin-bottom: 8px; }
        .subtitle { color: #8b949e; margin-bottom: 32px; }
        .key-box {
            background: #161b22; border: 1px solid #3fb950; border-radius: 8px;
            padding: 16px 20px; margin-bottom: 24px; word-break: break-all;
            font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.95em; color: #f0f6fc;
        }
        .copy-btn {
            background: #2ea043; color: #fff; border: none; padding: 10px 24px;
            border-radius: 6px; font-size: 1em; cursor: pointer; margin-right: 12px;
        }
        .copy-btn:hover { background: #3fb950; }
        .usage { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; margin-top: 24px; }
        .usage h3 { color: #f0f6fc; margin-bottom: 12px; }
        .usage code { background: #0d1117; padding: 2px 6px; border-radius: 4px; color: #3fb950; }
        .warning { color: #d4a72c; margin-top: 16px; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Wedge Activated!</h1>
        <p class="subtitle">Your Frisk Wedge subscription is live.</p>

        <div class="key-box" id="apikey">${resolvedKey}</div>

        <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('apikey').textContent); this.textContent='Copied!'; setTimeout(() => this.textContent='Copy Key', 2000);">Copy Key</button>

        <div class="usage">
            <h3>Using your key</h3>
            <p>Pass it in the <code>X-API-Key</code> header:</p>
            <pre style="background:#0d1117; padding:12px; border-radius:6px; margin-top:8px; overflow-x:auto; color:#c9d1d9; font-size:0.85em;">curl -H "X-API-Key: ${resolvedKey}" \\
  https://frisk.lowwatt.dev/api/v1/scan \\
  -d '{"slug": "example-skill"}'</pre>
            <p style="margin-top:12px; color:#8b949e;">Or with the CLI:</p>
            <pre style="background:#0d1117; padding:12px; border-radius:6px; margin-top:8px; overflow-x:auto; color:#c9d1d9; font-size:0.85em;">export FRISK_API_KEY=${resolvedKey}
frisk --api skill-slug</pre>
        </div>

        <p class="warning">⚠️ Save this key somewhere safe — it won't be shown again.</p>
    </div>
</body>
</html>`);
    } catch (e) {
        console.error('[STRIPE] Key retrieval error:', e.message);
        res.status(500).send('<h1>Error retrieving key</h1><p>Please contact support@lowwatt.dev</p>');
    }
});

module.exports = router;
