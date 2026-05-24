-- 0003_admin_plaintext_sync: the bridge between admin-mobile (the
-- cryptographic endpoint that decrypts incoming user messages) and
-- admin-web (the display surface humans use to read & reply).
--
-- Design context
-- ──────────────
-- E2E in this product is rooted on the admin's mobile device — that's where
-- the long-term identity key and Double-Ratchet state live. Admin-web has
-- no private key material, by design, so it cannot decrypt the ciphertext
-- in the `messages` table directly.
--
-- This migration adds a small *plaintext mirror* with two halves:
--
--   admin_plaintext        — decrypted message bodies, indexed by
--                            conversation_id. Populated by admin-mobile
--                            immediately after it decrypts. Read by both
--                            admin-mobile (display) and admin-web (display).
--                            30-day retention, swept by the retention worker.
--
--   admin_outbound_queue   — messages that admin-web has composed but that
--                            still need admin-mobile to wrap with the
--                            outgoing Double-Ratchet step before they
--                            become first-class `messages` rows. Drained by
--                            admin-mobile via a poll loop; rows transition
--                            pending → sent (and stick around briefly so
--                            admin-web can show "delivered" indicators).
--
-- Why store plaintext at all?
-- ───────────────────────────
-- Without this table, an admin who replies via admin-web has no way to
-- see what the user *said* (admin-web sees only opaque envelopes). The
-- product trade-off, accepted by the operator, is: plaintext at rest for
-- ≤30 days, scoped to admin↔user conversations only, encrypted-at-rest
-- via the cluster's storage layer (LUKS / EBS / etc), retention-purged.
-- User↔admin messages remain E2E on the wire.

-- ──────────────────────────────────────────────────────────────────────────
-- admin_plaintext
-- ──────────────────────────────────────────────────────────────────────────
-- One row per decrypted message. `message_id` is the FK to the ciphertext
-- row in `messages`, so a retention sweep of `messages` (rare; ciphertext
-- TTL is independent) cascades cleanly. Direction is denormalized for
-- fast display — "inbound" = from the user, "outbound" = from the admin.

CREATE TABLE admin_plaintext (
    -- 1-to-1 with messages.id. Cascade so retention sweeps stay consistent.
    message_id          TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    conversation_id     TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    direction           TEXT NOT NULL CHECK (direction IN ('inbound','outbound')),
    -- Plaintext body. TEXT (not BYTEA) — admin chat is human-readable only;
    -- media is referenced via messages.media_id and stays separately E2E.
    body                TEXT NOT NULL,
    -- The wall-clock time of the underlying ciphertext message — pulled
    -- through from messages.created_at so the admin UI can sort/display
    -- without re-joining.
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- When admin-mobile relayed the plaintext to the server. Separate from
    -- created_at because mobile can decrypt out-of-order after coming back
    -- online (e.g. user sent at 09:00, admin-mobile drained the WS at 11:00).
    decrypted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The hot query is "give me plaintext for everything in this conversation,
-- chronological order" — exactly what admin-web does on every refresh.
CREATE INDEX admin_plaintext_convo_created_idx
    ON admin_plaintext (conversation_id, created_at);

-- Retention sweep hits this every minute; keep the scan tight.
CREATE INDEX admin_plaintext_decrypted_at_idx
    ON admin_plaintext (decrypted_at);

-- ──────────────────────────────────────────────────────────────────────────
-- admin_outbound_queue
-- ──────────────────────────────────────────────────────────────────────────
-- Admin-web POSTs a plaintext reply here; admin-mobile polls, encrypts,
-- pushes to /v1/admin/users/{id}/messages, then PATCHes the row to
-- status='sent' (carrying the resulting messages.id back so admin-web can
-- show a delivered receipt).
--
-- Rows persist for ~24h after being marked sent — long enough for the web
-- UI to render the receipt; the retention worker reaps the tail.

CREATE TABLE admin_outbound_queue (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The admin who composed it. Lets the UI show "you" vs. "another admin"
    -- in a future multi-admin world; for now there's exactly one row.
    admin_id        TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    body            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','sent','failed')),
    -- Server message id, populated when status transitions to 'sent'.
    -- Used by admin-web to correlate this queue row with the eventual
    -- `admin_plaintext` row for delivered/read indicators.
    server_message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    -- Optional error message when status='failed' (e.g. "user has no
    -- registered devices"). Shown to the admin so they know to retry.
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ
);

-- admin-mobile drains by `WHERE status='pending' ORDER BY created_at`.
-- Partial index keeps the scan O(pending), not O(total ever queued).
CREATE INDEX admin_outbound_queue_pending_idx
    ON admin_outbound_queue (created_at) WHERE status = 'pending';

-- admin-web polls the user-scoped tail on every refresh — index by user
-- so the lookup stays a single index scan even after thousands of rows.
CREATE INDEX admin_outbound_queue_user_idx
    ON admin_outbound_queue (user_id, created_at DESC);
