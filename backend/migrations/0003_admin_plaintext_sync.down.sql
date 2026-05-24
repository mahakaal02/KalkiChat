-- The migrate CLI doesn't expose `down` in prod, but golang-migrate requires
-- a paired .down.sql per version. Drop in reverse-dependency order.
DROP INDEX IF EXISTS admin_outbound_queue_user_idx;
DROP INDEX IF EXISTS admin_outbound_queue_pending_idx;
DROP TABLE IF EXISTS admin_outbound_queue;

DROP INDEX IF EXISTS admin_plaintext_decrypted_at_idx;
DROP INDEX IF EXISTS admin_plaintext_convo_created_idx;
DROP TABLE IF EXISTS admin_plaintext;
