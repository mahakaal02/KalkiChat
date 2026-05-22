package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kalkichat/backend/internal/audit"
	"github.com/kalkichat/backend/internal/auth"
)

// adminCreateUser provisions a new user account from the admin console.
//
// Request body:
//
//	{
//	  "login":            "alice",
//	  "initial_password": "<12+ chars>"   // optional; server generates if absent
//	}
//
// Behaviour:
//   - login is lowercased and trimmed; must match ^[a-z0-9][a-z0-9._-]{2,31}$
//   - if initial_password is empty, the server generates a 16-char alphanumeric
//     password and returns it in the response (one-time disclosure to the admin)
//   - the user row is INSERTed with must_change_password=TRUE, forcing the
//     first-login change-password gate
//   - duplicate login → 409 USER_EXISTS (Postgres unique-violation 23505)
//
// Authorization: admin cookie (mounted under adminAuthMiddleware).
//
// Audit: action "user.create".
var loginPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

func adminCreateUser(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Login           string `json:"login"`
			InitialPassword string `json:"initial_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		login := strings.ToLower(strings.TrimSpace(in.Login))
		if !loginPattern.MatchString(login) {
			writeErr(w, http.StatusBadRequest, "BAD_LOGIN",
				"3-32 chars, lowercase letters/digits/._-, must start with a letter or digit")
			return
		}

		pw := in.InitialPassword
		generated := pw == ""
		if generated {
			var err error
			pw, err = generatePassword(16)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "RNG", err.Error())
				return
			}
		} else if len(pw) < 10 {
			writeErr(w, http.StatusBadRequest, "WEAK_PASSWORD",
				"initial_password must be at least 10 characters")
			return
		}

		hash, err := auth.Argon2idParams{
			Memory:      d.Cfg.Argon2.MemoryKiB,
			Iterations:  d.Cfg.Argon2.Time,
			Parallelism: d.Cfg.Argon2.Parallelism,
		}.Hash(pw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}

		userID := "usr_" + uuid.NewString()
		_, err = d.DB.Exec(r.Context(), `
			INSERT INTO users
				(id, login, password_hash, status, must_change_password)
			VALUES ($1, $2, $3, 'active', TRUE)
		`, userID, login, hash)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				writeErr(w, http.StatusConflict, "USER_EXISTS", "")
				return
			}
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		c := claimsFromCtx(r.Context())
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "user.create", TargetKind: "user", TargetID: userID,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
			Metadata: map[string]any{
				"login":              login,
				"password_generated": generated,
			},
		})

		out := map[string]any{
			"id":                   userID,
			"login":                login,
			"status":               "active",
			"must_change_password": true,
		}
		// Only return the cleartext when WE generated it. If the admin supplied
		// it, they already have it; echoing back would create needless copies.
		if generated {
			out["initial_password"] = pw
		}
		writeJSON(w, http.StatusCreated, out)
	}
}

// generatePassword returns a base62-ish password of the requested length using
// crypto/rand. The character set deliberately omits look-alikes (0/O, 1/l/I)
// so an admin reading the password over voice can dictate it without errors.
func generatePassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}
