package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/kalkichat/backend/internal/auth"
)

// authChangePassword lets a logged-in user replace their password.
//
// Request body:
//
//	{
//	  "current_password": "<old>",
//	  "new_password":     "<new, ≥10 chars>"
//	}
//
// The handler:
//  1. Reads the caller's user id from the bearer-token claims.
//  2. Verifies the supplied current_password against the stored hash.
//  3. Rejects new_password == current_password (cheap reuse guard).
//  4. Re-hashes new_password with the configured Argon2id parameters.
//  5. Clears must_change_password and bumps updated_at in the same UPDATE.
//
// A successful response is just `{"ok": true}`; the caller's existing access
// + refresh tokens remain valid (rotating them is a separate concern).
func authChangePassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		if c == nil || c.Owner != "user" {
			writeErr(w, http.StatusUnauthorized, "NOT_USER", "")
			return
		}

		var in struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		if in.CurrentPassword == "" || in.NewPassword == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_FIELDS", "")
			return
		}
		if in.CurrentPassword == in.NewPassword {
			writeErr(w, http.StatusBadRequest, "PASSWORD_REUSED",
				"new password must differ from current password")
			return
		}

		ctx := r.Context()
		var pwHash string
		err := d.DB.QueryRow(ctx, `
			SELECT password_hash FROM users WHERE id = $1
		`, c.OwnerID).Scan(&pwHash)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusUnauthorized, "USER_UNKNOWN", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		ok, err := auth.Verify(in.CurrentPassword, pwHash)
		if err != nil || !ok {
			writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "")
			return
		}

		newHash, err := auth.Argon2idParams{
			Memory:      d.Cfg.Argon2.MemoryKiB,
			Iterations:  d.Cfg.Argon2.Time,
			Parallelism: d.Cfg.Argon2.Parallelism,
		}.Hash(in.NewPassword)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}

		_, err = d.DB.Exec(ctx, `
			UPDATE users
			   SET password_hash = $1,
			       must_change_password = FALSE,
			       updated_at = NOW()
			 WHERE id = $2
		`, newHash, c.OwnerID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}
