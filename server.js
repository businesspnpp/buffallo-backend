const express   = require('express');
const cors      = require('cors');
const crypto    = require('crypto');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Security headers
app.use(helmet());

// JSON body parsing (limit size to prevent payload attacks)
app.use(express.json({ limit: '10kb' }));

// Allow requests only from your ert confrimcel frontend
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PATCH']
}));

// Rate limiters
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});

const createLinkLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many links created, please try again in an hour.' }
});

app.use(generalLimiter);

// Admin key middleware for protected endpoints
function requireAdminKey(req, res, next) {
    const key = req.headers['x-admin-key'];
    if (!process.env.ADMIN_KEY || key !== process.env.ADMIN_KEY)
        return res.status(401).json({ error: 'Unauthorized' });
    next();
}

// Token format validator (32 hex chars only)
const HEX_32 = /^[0-9a-f]{32}$/;

// Supabase client — set SUPABASE_URL and SUPABASE_ANON_KEY in Render env vars
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// ── POST /api/create-link ──────────────────────────────────────────
// Body: { amount: 150, ref: "INV-001" }
// Returns: { token: "abc123", url: "https://yoursite.vercel.app/payment.html?token=abc123" }
app.post('/api/create-link', createLinkLimiter, async (req, res) => {
    const { amount, ref } = req.body;

    if (!amount || !ref)
        return res.status(400).json({ error: 'amount and ref are required' });

    if (typeof ref !== 'string' || ref.length > 100)
        return res.status(400).json({ error: 'Invalid reference' });

    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed <= 0 || parsed > 1000000)
        return res.status(400).json({ error: 'Invalid amount' });

    const token      = crypto.randomBytes(16).toString('hex');
    const expires_at = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(); // 48h

    const { data, error } = await supabase
        .from('payment_links')
        .insert([{ token, amount: parsed.toFixed(2), ref, expires_at }])
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost';
    const url = `${frontendUrl}/payment.html?token=${token}`;

    res.json({ token, url, expires_at: data.expires_at });
});

// ── GET /api/link/:token ───────────────────────────────────────────
// Returns the amount + ref for a given token (used by payment.html)
app.get('/api/link/:token', async (req, res) => {
    const { token } = req.params;

    if (!HEX_32.test(token))
        return res.status(400).json({ error: 'Invalid token' });

    const { data, error } = await supabase
        .from('payment_links')
        .select('*')
        .eq('token', token)
        .single();

    if (error || !data)
        return res.status(404).json({ error: 'Payment link not found' });

    if (data.used)
        return res.status(410).json({ error: 'This payment link has already been used' });

    if (new Date(data.expires_at) < new Date())
        return res.status(410).json({ error: 'This payment link has expired' });

    res.json({
        amount:     data.amount,
        ref:        data.ref,
        created_at: data.created_at,
        expires_at: data.expires_at
    });
});

// ── GET /api/links ─────────────────────────────────────────────────
// Admin: list all generated links (requires X-Admin-Key header)
app.get('/api/links', requireAdminKey, async (req, res) => {
    const { data, error } = await supabase
        .from('payment_links')
        .select('id, token, amount, ref, created_at, expires_at, used, used_at')
        .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// ── PATCH /api/link/:token/use ─────────────────────────────────────
// Mark a link as used after payment is confirmed
app.patch('/api/link/:token/use', async (req, res) => {
    const { token } = req.params;

    if (!HEX_32.test(token))
        return res.status(400).json({ error: 'Invalid token' });

    const { data, error } = await supabase
        .from('payment_links')
        .update({ used: true, used_at: new Date().toISOString() })
        .eq('token', token)
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, used_at: data.used_at });
});

// ── POST /api/payments ─────────────────────────────────────────────
// Record a completed card payment (name + amount + reference only — no card data)
app.post('/api/payments', async (req, res) => {
    const { card_holder, amount, reference } = req.body;

    if (!card_holder || !amount || !reference)
        return res.status(400).json({ error: 'card_holder, amount and reference are required' });

    if (typeof card_holder !== 'string' || card_holder.length > 100)
        return res.status(400).json({ error: 'Invalid card_holder' });

    if (typeof reference !== 'string' || reference.length > 100)
        return res.status(400).json({ error: 'Invalid reference' });

    const parsed = parseInt(amount, 10);
    if (isNaN(parsed) || parsed <= 0 || parsed > 1000000)
        return res.status(400).json({ error: 'Invalid amount' });

    const { data, error } = await supabase
        .from('dikarata')
        .insert([{ card_holder: card_holder.trim(), amount: parsed, reference: reference.trim() }])
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });

    res.status(201).json({ id: data.id, created_at: data.created_at });
});

// ── Health check ───────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'Buffalo API running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Buffalo Payment API running on port ${PORT}`));
