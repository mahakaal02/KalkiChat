-- The migrate CLI doesn't expose `down` in prod (see cmd/migrate/main.go), but
-- golang-migrate requires a paired .down.sql per version.
DROP INDEX IF EXISTS idx_users_must_change_password;
ALTER TABLE users DROP COLUMN IF EXISTS must_change_password;
