package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kcrypto "github.com/kalkichat/backend/internal/crypto"
)

// RefreshIssue creates a new refresh token, persists its hash, returns the
// opaque token to the caller.
func RefreshIssue(ctx context.Context, db *pgxpool.Pool, deviceID, familyID string, ttl time.Duration) (string, error) {
	id := uuid.NewString()
	if familyID == "" {
		familyID = uuid.NewString()
	}
	raw, err := kcrypto.RandomBase64(32)
	if err != nil {
		return "", err
	}
	hash := kcrypto.SHA256([]byte(raw))
	_, err = db.Exec(ctx, `
		INSERT INTO refresh_tokens (id, device_id, family_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, id, deviceID, familyID, hash, time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	return id + "." + raw, nil
}

// RefreshRotate consumes the provided refresh token and issues a new one in
// the same family. If the token has already been used, the entire family is
// revoked (Signal-style replay defence).
func RefreshRotate(ctx context.Context, db *pgxpool.Pool, presented string, ttl time.Duration) (newToken, deviceID, familyID string, err error) {
	id, raw, ok := splitRefresh(presented)
	if !ok {
		return "", "", "", ErrBadRefresh
	}
	hash := kcrypto.SHA256([]byte(raw))

	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var dbHash []byte
	var usedAt, revokedAt *time.Time
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT token_hash, used_at, revoked_at, expires_at, device_id, family_id
		FROM refresh_tokens
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(&dbHash, &usedAt, &revokedAt, &expiresAt, &deviceID, &familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", ErrBadRefresh
	}
	if err != nil {
		return "", "", "", err
	}
	if !ctEq(dbHash, hash) {
		return "", "", "", ErrBadRefresh
	}
	if revokedAt != nil || time.Now().After(expiresAt) {
		return "", "", "", ErrBadRefresh
	}
	if usedAt != nil {
		// Replay! Revoke entire family.
		_, _ = tx.Exec(ctx, `
			UPDATE refresh_tokens SET revoked_at = NOW()
			WHERE family_id = $1 AND revoked_at IS NULL
		`, familyID)
		if err := tx.Commit(ctx); err != nil {
			return "", "", "", err
		}
		return "", "", "", ErrReplayed
	}
	_, err = tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return "", "", "", err
	}

	newID := uuid.NewString()
	rawNew, err := kcrypto.RandomBase64(32)
	if err != nil {
		return "", "", "", err
	}
	hashNew := kcrypto.SHA256([]byte(rawNew))
	_, err = tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, device_id, family_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, newID, deviceID, familyID, hashNew, time.Now().Add(ttl))
	if err != nil {
		return "", "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", err
	}
	return newID + "." + rawNew, deviceID, familyID, nil
}

// RefreshRevoke invalidates a specific token.
func RefreshRevoke(ctx context.Context, db *pgxpool.Pool, presented string) error {
	id, _, ok := splitRefresh(presented)
	if !ok {
		return ErrBadRefresh
	}
	_, err := db.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1`, id)
	return err
}

// RefreshRevokeDevice nukes all refresh tokens for a device.
func RefreshRevokeDevice(ctx context.Context, db *pgxpool.Pool, deviceID string) error {
	_, err := db.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE device_id = $1 AND revoked_at IS NULL
	`, deviceID)
	return err
}

// ErrBadRefresh signals an unknown / expired / revoked token.
var ErrBadRefresh = errors.New("auth: invalid refresh token")

// ErrReplayed signals reuse of an already-consumed token.
var ErrReplayed = errors.New("auth: refresh token replayed")

func splitRefresh(s string) (id, raw string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// ctEq is a constant-time byte comparison.
func ctEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
