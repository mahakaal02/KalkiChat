package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kalkichat/backend/internal/crypto"
)

type ctxKey string

const (
	ctxClaims ctxKey = "claims"
)

// authMiddleware enforces a valid bearer token. When [db] is non-nil it
// also fire-and-forget refreshes devices.last_seen_at for the calling
// device so downstream "online?" queries see a real timestamp instead of
// the never-updated register-time default. We accept the rare false
// positive (token-valid-but-revoked race) because the alternative is
// every consumer of last_seen_at being permanently wrong.
func authMiddleware(signer *crypto.JWTSigner, db *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if signer == nil {
				writeErr(w, http.StatusInternalServerError, "JWT_NOT_CONFIGURED", "")
				return
			}
			tok := bearer(r)
			if tok == "" {
				writeErr(w, http.StatusUnauthorized, "MISSING_TOKEN", "")
				return
			}
			c, err := signer.Verify(tok)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "INVALID_TOKEN", err.Error())
				return
			}
			// Bearer tokens have Sub == device_id. Async + no error
			// propagation: this MUST NOT add latency to the request path
			// or block on the DB.
			if db != nil && c.Sub != "" {
				go func(dev string) {
					_, _ = db.Exec(context.Background(),
						`UPDATE devices SET last_seen_at = NOW() WHERE id = $1`, dev)
				}(c.Sub)
			}
			ctx := context.WithValue(r.Context(), ctxClaims, c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// adminAuthMiddleware enforces admin auth. Accepts the JWT from either
// the admin_session cookie (admin web dashboard) or a Bearer header
// (admin companion-device mobile app, post /v1/admin/devices/register).
// Cookie takes precedence so the web flow stays unchanged.
//
// Like authMiddleware, this also refreshes devices.last_seen_at when the
// caller is using a Bearer token (admin mobile) — cookie sessions don't
// carry a device id (Sub == admin id), so they're left alone.
func adminAuthMiddleware(signer *crypto.JWTSigner, db *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if signer == nil {
				writeErr(w, http.StatusInternalServerError, "JWT_NOT_CONFIGURED", "")
				return
			}
			var token string
			isBearer := false
			if c, err := r.Cookie("admin_session"); err == nil {
				token = c.Value
			} else if b := bearer(r); b != "" {
				token = b
				isBearer = true
			}
			if token == "" {
				writeErr(w, http.StatusUnauthorized, "MISSING_SESSION", "")
				return
			}
			c, err := signer.Verify(token)
			if err != nil || c.Owner != "admin" {
				writeErr(w, http.StatusUnauthorized, "INVALID_SESSION", "")
				return
			}
			// Only Bearer tokens have Sub == device_id. Cookie sessions
			// have Sub == admin_id and there's no device to touch.
			if isBearer && db != nil && c.Sub != "" {
				go func(dev string) {
					_, _ = db.Exec(context.Background(),
						`UPDATE devices SET last_seen_at = NOW() WHERE id = $1`, dev)
				}(c.Sub)
			}
			ctx := context.WithValue(r.Context(), ctxClaims, c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// claimsFromCtx returns parsed claims (or nil if unauthenticated).
func claimsFromCtx(ctx context.Context) *crypto.JWTClaims {
	v, _ := ctx.Value(ctxClaims).(*crypto.JWTClaims)
	return v
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}

