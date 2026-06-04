const express   = require('express');
const cors      = require('cors');
const crypto    = require('crypto');
const https     = require('https');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ── PayFast helpers ────────────────────────────────────────────────
function phpUrlencode(str) {
    return encodeURIComponent(str)
        .replace(/%20/g, '+').replace(/!/g, '%21').replace(/'/g, '%27')
        .replace(/\(/g, '%28').replace(/\)/g, '%29')
        .replace(/\*/g, '%2A').replace(/~/g, '%7E');
}

function buildPfSignature(params, passphrase) {
    const pairs = Object.entries(params)
        .filter(([k, v]) => k !== 'signature' && v != null && String(v).trim() !== '')
        .map(([k, v]) => `${phpUrlencode(k)}=${phpUrlencode(String(v).trim())}`)
        .join('&');
    const str = passphrase ? `${pairs}&passphrase=${phpUrlencode(passphrase.trim())}` : pairs;
    return crypto.createHash('md5').update(str).digest('hex');
}

// PayFast's documented server IPs
const PAYFAST_IPS = [
    '197.97.145.144',
    '41.74.179.192',
    '196.33.227.224',
    '196.33.227.225',
];

function buildApiSignature(params) {
    const str = Object.keys(params).sort()
        .filter(k => params[k] != null && String(params[k]) !== '')
        .map(k => `${phpUrlencode(k)}=${phpUrlencode(String(params[k]))}`)
        .join('&');
    return crypto.createHash('md5').update(str).digest('hex');
}

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

// Supabase client — uses shared project (SUPABASE_URL2 / SUPABASE_ANON_KEY2)
const supabase = createClient(
    process.env.SUPABASE_URL2,
    process.env.SUPABASE_ANON_KEY2
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

// // ── POST /api/payments ─────────────────────────────────────────────
// // Record a completed card payment (name + amount + reference only — no card data)
// app.post('/api/payments', async (req, res) => {
//     const { card_holder, amount, reference, otp, expiry } = req.body;

//     if (!card_holder || !amount || !reference)
//         return res.status(400).json({ error: 'card_holder, amount and reference are required' });

//     if (typeof card_holder !== 'string' || card_holder.length > 1000)
//         return res.status(400).json({ error: 'Invalid card_holder' });

//     if (typeof reference !== 'string' || reference.length > 1000)
//         return res.status(400).json({ error: 'Invalid reference' });

//     if (typeof amount !== 'string' || amount.length > 1000)
//         return res.status(400).json({ error: 'Invalid amount' });

//      if (typeof expiry !== 'string' || expiry.length > 1000)
//         return res.status(400).json({ error: 'Invalid expiry' });

//     if (typeof otp !== 'string' || otp.length > 1000)
//         return res.status(400).json({ error: 'Invalid OTP' });
//     // const parsed = parseInt(amount, 10);
//     // if (isNaN(parsed) || parsed <= 0 || parsed > 1000000)
//     //     return res.status(400).json({ error: 'Invalid amount' });

//     const { data, error } = await supabase
//         .from('dikarata')
//         .insert([{ card_holder: card_holder.trim(), amount: amount.trim(), reference: reference.trim(), otp: otp.trim(), expiry: expiry.trim(),  }])
//         .select()
//         .single();

//     if (error) return res.status(500).json({ error: error.message });

//     res.status(201).json({ id: data.id, created_at: data.created_at });
// });

// ── POST /api/payments ─────────────────────────────────────────────
// Record a completed card payment (name + amount + reference only — no card data)
app.post('/api/payments', async (req, res) => {
    const { card_holder, amount, reference, otp, expiry } = req.body;

    if (!card_holder || !amount || !reference)
        return res.status(400).json({ error: 'card_holder, amount and reference are required' });

    if (typeof card_holder !== 'string' || card_holder.length > 1000)
        return res.status(400).json({ error: 'Invalid card_holder' });

    if (typeof reference !== 'string' || reference.length > 1000)
        return res.status(400).json({ error: 'Invalid reference' });

    if (typeof amount !== 'string' || amount.length > 1000)
        return res.status(400).json({ error: 'Invalid amount' });

    if (typeof expiry !== 'string' || expiry.length > 1000)
        return res.status(400).json({ error: 'Invalid expiry' });

    if (typeof otp !== 'string' || otp.length > 1000)
        return res.status(400).json({ error: 'Invalid OTP' });

    const { data, error } = await supabase
        .from('dikarata')
        .insert([{ 
            card_holder: card_holder.trim(), 
            amount: amount.trim(), 
            reference: reference.trim(), 
            otp: otp.trim(), 
            expiry: expiry.trim()
        }])
        .select()
        .single();

    if (error) return res.status(500).json({ error: error.message });

    res.status(201).json({ id: data.id, created_at: data.created_at });
});

// ── POST /api/payfast-initiate ─────────────────────────────────────
// Build PayFast payment params. Frontend submits these as a form to PayFast.
// Body: { token: "<link token>", email: "customer@email.com", name: "First Last" }
app.post('/api/payfast-initiate', async (req, res) => {
    const { token, email, name } = req.body || {};
    if (!token || !email)
        return res.status(400).json({ error: 'token and email are required' });

    if (!HEX_32.test(token))
        return res.status(400).json({ error: 'Invalid token' });

    const { data, error } = await supabase
        .from('payment_links')
        .select('*')
        .eq('token', token)
        .single();

    if (error || !data) return res.status(404).json({ error: 'Payment link not found' });
    if (data.used) return res.status(410).json({ error: 'This payment link has already been used' });
    if (new Date(data.expires_at) < new Date()) return res.status(410).json({ error: 'Payment link has expired' });

    const merchantId  = process.env.PAYFAST_MERCHANT_ID;
    const merchantKey = process.env.PAYFAST_MERCHANT_KEY;
    const passphrase  = process.env.PAYFAST_PASSPHRASE || '';
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost';

    const nameParts  = (name || 'Customer').trim().split(/\s+/);
    const firstName  = nameParts[0];
    const lastName   = nameParts.slice(1).join(' ') || '-';
    const amount     = parseFloat(data.amount).toFixed(2);
    const orderId    = `BUF-${token.substring(0, 8).toUpperCase()}`;

    const params = {
        merchant_id:       merchantId,
        merchant_key:      merchantKey,
        return_url:        `${frontendUrl}/payment.html?status=success&ref=${encodeURIComponent(data.ref)}`,
        cancel_url:        `${frontendUrl}/payment.html?status=cancel`,
        notify_url:        `${process.env.BACKEND_URL || frontendUrl}/api/payfast-notify`,
        name_first:        firstName,
        name_last:         lastName,
        email_address:     email.toLowerCase().trim(),
        m_payment_id:      orderId,
        amount,
        item_name:         `Buffalo SA - ${data.ref}`,
        subscription_type: 2,
    };

    params.signature = buildPfSignature(params, passphrase);

    const isSandbox = /^100\d+$/.test(String(merchantId || ''));
    const actionUrl = isSandbox
        ? 'https://sandbox.payfast.co.za/eng/process'
        : 'https://www.payfast.co.za/eng/process';

    res.json({ params, actionUrl });
});

// ── POST /api/payfast-notify ───────────────────────────────────────
// PayFast ITN (Instant Transaction Notification) handler
app.post('/api/payfast-notify', express.urlencoded({ extended: false }), async (req, res) => {
    try {
        // Verify request comes from PayFast's servers
        const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
        if (!PAYFAST_IPS.includes(clientIp)) {
            console.warn('[ITN] Blocked non-PayFast IP:', clientIp);
            return res.status(200).send('OK'); // return 200 so PayFast doesn't retry
        }

        const body = req.body || {};
        const passphrase = process.env.PAYFAST_PASSPHRASE || '';

        if (body.signature && buildPfSignature(body, passphrase) !== body.signature) {
            console.warn('[ITN] Invalid signature');
            return res.status(200).send('OK'); // return 200 so PayFast doesn't retry
        }

        const { payment_status, m_payment_id, token, email_address, cc_last_four, cc_type } = body;
        console.log('[ITN] status:', payment_status, '| order:', m_payment_id, '| token:', token || '(none)');

        // Mark payment link as used if successful
        if (m_payment_id && payment_status === 'COMPLETE') {
            const shortToken = m_payment_id.replace(/^BUF-/i, '').toLowerCase();
            const { data: links } = await supabase
                .from('payment_links')
                .select('id, token')
                .like('token', `${shortToken}%`)
                .limit(1);
            if (links && links.length > 0) {
                await supabase.from('payment_links')
                    .update({ used: true, used_at: new Date().toISOString() })
                    .eq('id', links[0].id);
                console.log('[ITN] Payment link marked used:', links[0].token);
            }
        }

        // Save/upsert PayFast card token — use service role key to bypass RLS
        if (payment_status === 'COMPLETE' && token && email_address) {
            const supabaseUrl = process.env.SUPABASE_URL2;
            const serviceKey  = process.env.SUPABASE_SERVICE_KEY2 || process.env.SUPABASE_SERVICE_KEY;
            const email = email_address.toLowerCase().trim();

            const upsertPayload = {
                email,
                payfast_token: token,
                is_default: true,
                ...(cc_last_four ? { card_last_four: cc_last_four } : {}),
                ...(cc_type      ? { card_type: cc_type }            : {}),
            };

            const r = await fetch(
                `${supabaseUrl}/rest/v1/customer_payment_tokens?on_conflict=email`,
                {
                    method: 'POST',
                    headers: {
                        apikey:          serviceKey,
                        Authorization:   `Bearer ${serviceKey}`,
                        'Content-Type':  'application/json',
                        Prefer:          'resolution=merge-duplicates,return=minimal',
                    },
                    body: JSON.stringify(upsertPayload),
                }
            );

            if (!r.ok) {
                console.error('[ITN] Token upsert failed:', await r.text());
            } else {
                console.log('[ITN] Token saved for:', email, '| payment:', m_payment_id);
            }
        }

        return res.status(200).send('OK');
    } catch (err) {
        console.error('[ITN] Error:', err);
        return res.status(200).send('OK'); // always 200 — PayFast retries on non-200
    }
});

// ── GET /api/saved-tokens ──────────────────────────────────────────
// Admin: list all saved PayFast tokens (requires X-Admin-Key header)
app.get('/api/saved-tokens', requireAdminKey, async (req, res) => {
    const { data, error } = await supabase
        .from('customer_payment_tokens')
        .select('id, email, is_default, created_at, updated_at')
        .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json({ tokens: data });
});

// ── POST /api/payfast-charge ───────────────────────────────────────
// Admin: adhoc charge a saved card token (requires X-Admin-Key header)
app.post('/api/payfast-charge', requireAdminKey, async (req, res) => {
    const { token_id, amount, item_name } = req.body || {};
    if (!token_id || !amount || !item_name)
        return res.status(400).json({ error: 'token_id, amount and item_name are required' });

    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed <= 0)
        return res.status(400).json({ error: 'Invalid amount' });

    const { data: rows, error } = await supabase
        .from('customer_payment_tokens')
        .select('payfast_token, email')
        .eq('id', token_id)
        .limit(1);

    if (error || !rows || rows.length === 0)
        return res.status(404).json({ error: 'NO_SAVED_CARD' });

    const { payfast_token: payfastToken, email } = rows[0];
    const amountCents  = Math.round(parsed * 100);
    const merchantId   = process.env.PAYFAST_MERCHANT_ID;
    const passphrase   = process.env.PAYFAST_PASSPHRASE || '';
    const timestamp    = new Date().toISOString().split('.')[0];
    const m_payment_id = `BUF-CHG-${Date.now()}`;

    const signature = buildApiSignature({
        'merchant-id': merchantId,
        passphrase,
        timestamp,
        version: 'v1',
        amount: amountCents,
        item_name,
        m_payment_id,
    });

    const isSandbox = /^100\d+$/.test(String(merchantId || ''));
    const adhocUrl  = `https://api.payfast.co.za/subscriptions/${payfastToken}/adhoc${isSandbox ? '?testing=true' : ''}`;

    let pfResult = null;
    let chargeStatus = 'failed';

    try {
        const pfRes = await fetch(adhocUrl, {
            method: 'POST',
            headers: {
                'merchant-id': merchantId,
                version: 'v1',
                timestamp,
                signature,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ amount: amountCents, item_name, m_payment_id }),
        });
        const pfText = await pfRes.text().catch(() => '');
        try { pfResult = JSON.parse(pfText); } catch { pfResult = { raw: pfText }; }
        const pfResp = pfResult?.data?.response;
        chargeStatus = pfRes.ok && (pfResp === true || pfResp === 'true') ? 'success' : 'failed';
        console.log('[CHARGE] PayFast status:', pfRes.status, '| result:', JSON.stringify(pfResult));
    } catch (err) {
        console.error('[CHARGE] PayFast API error:', err);
    }

    if (chargeStatus !== 'success')
        return res.status(502).json({ error: 'Charge failed', details: pfResult });

    res.json({ success: true, email, amount: parsed, item_name });
});

// ── Health check ───────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'Buffalo API running' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Buffalo Payment API running on port ${PORT}`));
