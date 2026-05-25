-- Run this SQL in Supabase → SQL Editor → New Query

CREATE TABLE payment_links (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    token       TEXT        UNIQUE NOT NULL,
    amount      NUMERIC(10,2) NOT NULL,
    ref         TEXT        NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN     DEFAULT FALSE,
    used_at     TIMESTAMPTZ
);

-- Index for fast token lookup
CREATE INDEX idx_payment_links_token ON payment_links(token);
