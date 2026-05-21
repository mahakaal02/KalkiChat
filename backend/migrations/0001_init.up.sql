-- KalkiChat schema. Forward-only.
-- ============================================================================
-- Conventions:
--   * All IDs are 26-char ULIDs stored as TEXT for human-grep-ability.
--   * Timestamps are TIMESTAMPTZ in UTC.
--   * Plaintext message bodies are NEVER stored. Only ciphertext envelopes.
--   * Foreign keys are explicit; cascade rules favour data minimization.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Users ──────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    login           TEXT NOT NULL UNIQUE,             -- the "user ID" the user types
    password_hash   TEXT NOT NULL,                    -- Argon2id-PHC
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','suspended','deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);
CREATE INDEX users_login_lower_idx ON users (LOWER(login));

-- ── Admins ─────────────────────────────────────────────────────────────────
CREATE TABLE admins (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret_enc BYTEA NOT NULL,                   -- AES-GCM encrypted at rest
    role            TEXT NOT NULL DEFAULT 'admin'
                    CHECK (role IN ('admin','super_admin')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- ── Devices (a device is a per-install identity for either a user or admin) ─
CREATE TABLE devices (
    id                 TEXT PRIMARY KEY,
    owner_kind         TEXT NOT NULL CHECK (owner_kind IN ('user','admin')),
    owner_id           TEXT NOT NULL,
    name               TEXT NOT NULL,
    platform           TEXT NOT NULL CHECK (platform IN ('android','ios','web')),
    identity_ed25519   BYTEA NOT NULL,                 -- 32 bytes
    identity_x25519    BYTEA NOT NULL,                 -- 32 bytes
    fcm_token          TEXT,
    apns_token         TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at         TIMESTAMPTZ
);
CREATE INDEX devices_owner_idx     ON devices (owner_kind, owner_id);
CREATE INDEX devices_active_idx    ON devices (owner_kind, owner_id) WHERE revoked_at IS NULL;

-- ── Refresh token families (rotating, one-time-use) ─────────────────────────
CREATE TABLE refresh_tokens (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    family_id    TEXT NOT NULL,
    token_hash   BYTEA NOT NULL,                       -- SHA-256
    used_at      TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX refresh_tokens_device_idx ON refresh_tokens (device_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

-- ── Prekeys ────────────────────────────────────────────────────────────────
CREATE TABLE signed_prekeys (
    device_id      TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    prekey_id      INTEGER NOT NULL,
    pubkey         BYTEA NOT NULL,
    signature      BYTEA NOT NULL,                     -- Ed25519 over pubkey
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE one_time_prekeys (
    id           BIGSERIAL PRIMARY KEY,
    device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    prekey_id    INTEGER NOT NULL,
    pubkey       BYTEA NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, prekey_id)
);
CREATE INDEX one_time_prekeys_unconsumed_idx
    ON one_time_prekeys (device_id) WHERE consumed_at IS NULL;

-- ── Conversation (one row per user; admin team is the implicit counterpart) ─
CREATE TABLE conversations (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Messages (CIPHERTEXT ONLY) ─────────────────────────────────────────────
CREATE TABLE messages (
    id                     TEXT PRIMARY KEY,
    conversation_id        TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    envelope               BYTEA NOT NULL,             -- opaque ciphertext envelope
    signature              BYTEA NOT NULL,             -- Ed25519 sender signature
    media_id               TEXT,                       -- nullable; FK below
    client_id              TEXT NOT NULL,              -- caller-supplied UUID, for idempotency
    delivered_at           TIMESTAMPTZ,
    read_at                TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sender_device_id, client_id)
);
CREATE INDEX messages_conv_created_idx ON messages (conversation_id, created_at DESC);
CREATE INDEX messages_recipient_unread_idx
    ON messages (recipient_device_id) WHERE delivered_at IS NULL;
-- Index that powers the retention scan. Partial keeps it tiny.
CREATE INDEX messages_retention_idx ON messages (created_at);

-- ── Media ──────────────────────────────────────────────────────────────────
CREATE TABLE media_blobs (
    id                TEXT PRIMARY KEY,
    s3_key            TEXT NOT NULL UNIQUE,
    size_bytes        BIGINT NOT NULL,
    content_hash_sha256 BYTEA NOT NULL,
    uploader_device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX media_retention_idx ON media_blobs (created_at);

-- One wrapped AES key per recipient device. Deleting these rows is the
-- crypto-erasure mechanism.
CREATE TABLE media_keys (
    media_id              TEXT NOT NULL REFERENCES media_blobs(id) ON DELETE CASCADE,
    recipient_device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    wrapped_key           BYTEA NOT NULL,
    nonce                 BYTEA NOT NULL,
    kem_pubkey            BYTEA NOT NULL,
    PRIMARY KEY (media_id, recipient_device_id)
);

ALTER TABLE messages
    ADD CONSTRAINT messages_media_fk
    FOREIGN KEY (media_id) REFERENCES media_blobs(id) ON DELETE SET NULL;

-- ── Sessions (for active WS tracking; not auth) ────────────────────────────
CREATE TABLE active_sessions (
    device_id     TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    connected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ping_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Onboarding (WhatsApp deep-link config) ─────────────────────────────────
CREATE TABLE whatsapp_config (
    id                 INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    phone_e164         TEXT NOT NULL,
    message_template   TEXT NOT NULL,
    updated_by_admin   TEXT REFERENCES admins(id),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default row (idempotent).
INSERT INTO whatsapp_config (id, phone_e164, message_template)
VALUES (1, '+910000000000',
        'Hello, I would like access to KalkiChat. My preferred user ID is {user_id}.')
ON CONFLICT (id) DO NOTHING;

-- ── Audit log (no message content) ─────────────────────────────────────────
CREATE TABLE audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    actor_kind    TEXT NOT NULL CHECK (actor_kind IN ('admin','system','user')),
    actor_id      TEXT,
    action        TEXT NOT NULL,
    target_kind   TEXT,
    target_id     TEXT,
    ip            INET,
    user_agent    TEXT,
    metadata      JSONB,                              -- never includes message body
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX audit_logs_created_idx ON audit_logs (created_at DESC);
CREATE INDEX audit_logs_actor_idx   ON audit_logs (actor_kind, actor_id);

-- Tamper-evidence: append-only via trigger.
CREATE OR REPLACE FUNCTION audit_logs_no_update() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_no_update_trig
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_no_update();

-- ── Rate limit / abuse tracking ────────────────────────────────────────────
CREATE TABLE login_failures (
    login         TEXT NOT NULL,
    ip            INET NOT NULL,
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX login_failures_login_idx ON login_failures (login, attempted_at);
CREATE INDEX login_failures_ip_idx    ON login_failures (ip, attempted_at);

-- ── Helper: keep updated_at fresh on users ─────────────────────────────────
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_touch BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
