const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// Allow requests from your Vercel frontend (set FRONTEND_URL in Render env vars)
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PATCH']
}));

// Supabase client — set SUPABASE_URL and SUPABASE_ANON_KEY in Render env vars
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// ── POST /api/create-link ──────────────────────────────────────────
// Body: { amount: 150, ref: "INV-001" }
// Returns: { token: "abc123", url: "https://yoursite.vercel.app/payment.html?token=abc123" }
app.post('/api/create-link', async (req, res) => {
    const { amount, ref } = req.body;

    if (!amount || !ref)
        return res.status(400).json({ error: 'amount and ref are required' });

    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed <= 0)
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

    if (!token || token.length !== 32)
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
// Admin: list all generated links
app.get('/api/links', async (req, res) => {
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

    const { data, error } = await supabase
        .from('payment_links')
        .update({ used: true, used_at: new Date().toISOString() })
        .eq('token', token)
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, used_at: data.used_at });
});

// ── Health check ───────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'Buffalo API running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Buffalo Payment API running on port ${PORT}`));
