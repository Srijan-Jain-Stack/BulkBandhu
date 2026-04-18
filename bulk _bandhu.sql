-- ============================================================
-- GROUP BUY POOLING PLATFORM — PostgreSQL Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────
-- USERS
-- ─────────────────────────────────────────
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    avatar_url      TEXT,
    stripe_customer_id  TEXT UNIQUE,          -- for escrow/payment
    is_verified     BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);

-- ─────────────────────────────────────────
-- POOLS
-- ─────────────────────────────────────────
CREATE TYPE pool_status AS ENUM (
    'open',       -- accepting commitments
    'success',    -- MOQ reached, payment captured
    'failed',     -- deadline passed without hitting MOQ
    'cancelled',  -- creator cancelled
    'fulfilled'   -- goods shipped / delivered
);

CREATE TABLE pools (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id      UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    title           TEXT NOT NULL,
    description     TEXT,
    image_url       TEXT,
    product_url     TEXT,

    -- MOQ configuration
    moq             INTEGER NOT NULL CHECK (moq > 0),       -- minimum order quantity
    unit_price      NUMERIC(12,2) NOT NULL CHECK (unit_price > 0),
    currency        CHAR(3) NOT NULL DEFAULT 'USD',

    -- State
    status          pool_status NOT NULL DEFAULT 'open',
    committed_qty   INTEGER NOT NULL DEFAULT 0,             -- denormalised counter (updated via trigger)

    -- Lifecycle
    deadline        TIMESTAMPTZ NOT NULL,
    success_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_pools_status     ON pools(status);
CREATE INDEX idx_pools_creator    ON pools(creator_id);
CREATE INDEX idx_pools_deadline   ON pools(deadline) WHERE status = 'open';

-- ─────────────────────────────────────────
-- COMMITMENTS
-- ─────────────────────────────────────────
CREATE TYPE commitment_status AS ENUM (
    'pending',      -- user committed, payment authorised (hold)
    'captured',     -- pool succeeded, payment captured
    'refunded',     -- pool failed / cancelled, authorisation released
    'cancelled'     -- user withdrew before pool succeeded
);

CREATE TABLE commitments (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pool_id             UUID NOT NULL REFERENCES pools(id) ON DELETE RESTRICT,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    quantity            INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
    unit_price_snapshot NUMERIC(12,2) NOT NULL,   -- price locked at commitment time

    -- Payment / escrow
    stripe_payment_intent_id    TEXT UNIQUE,
    stripe_charge_id            TEXT,
    status                      commitment_status NOT NULL DEFAULT 'pending',

    committed_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (pool_id, user_id)   -- one commitment per user per pool (adjustable)
);

CREATE INDEX idx_commitments_pool   ON commitments(pool_id);
CREATE INDEX idx_commitments_user   ON commitments(user_id);
CREATE INDEX idx_commitments_status ON commitments(status);

-- ─────────────────────────────────────────
-- REFRESH TOKENS  (JWT refresh token store)
-- ─────────────────────────────────────────
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- ─────────────────────────────────────────
-- TRIGGERS — keep pools.committed_qty in sync
-- ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_pool_committed_qty()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    UPDATE pools
    SET committed_qty = (
        SELECT COALESCE(SUM(quantity), 0)
        FROM commitments
        WHERE pool_id = COALESCE(NEW.pool_id, OLD.pool_id)
          AND status IN ('pending', 'captured')
    ),
    updated_at = NOW()
    WHERE id = COALESCE(NEW.pool_id, OLD.pool_id);

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_commitment_qty
AFTER INSERT OR UPDATE OR DELETE ON commitments
FOR EACH ROW EXECUTE FUNCTION update_pool_committed_qty();

-- ─────────────────────────────────────────
-- TRIGGER — auto-transition pool to 'success'
-- ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION check_pool_moq()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.committed_qty >= NEW.moq AND NEW.status = 'open' THEN
        NEW.status    := 'success';
        NEW.success_at := NOW();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_pool_moq_check
BEFORE UPDATE OF committed_qty ON pools
FOR EACH ROW EXECUTE FUNCTION check_pool_moq();

-- ─────────────────────────────────────────
-- UPDATED_AT helper
-- ─────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_users_updated_at    BEFORE UPDATE ON users    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_pools_updated_at    BEFORE UPDATE ON pools    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_commit_updated_at   BEFORE UPDATE ON commitments FOR EACH ROW EXECUTE FUNCTION set_updated_at();