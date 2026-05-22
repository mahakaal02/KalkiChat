-- 0002_admin_user_mgmt: support admin-created accounts with forced password
-- change on first login, and a quick lookup for the "needs reset" cohort.

-- New column: FALSE by default so existing rows (seeded test users) aren't
-- forced into the change-password gate retroactively. Admin-created accounts
-- INSERT with TRUE; the user clears it via POST /v1/auth/change-password.
ALTER TABLE users
    ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial index so an admin dashboard query "show me accounts pending their
-- first password change" stays index-only as the user base grows. Most users
-- will be FALSE, so we don't index those.
CREATE INDEX idx_users_must_change_password
    ON users (must_change_password)
    WHERE must_change_password = TRUE;
