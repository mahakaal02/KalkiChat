package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kalkichat/backend/internal/crypto"
)

type ctxKey string

const (
	ctxClaims ctxKey = "claims"
)

// authMiddleware enforces a valid bearer token.
func authMiddleware(signer *crypto.JWTSigner) func(http.Handler) http.Handler {
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
			ctx := context.WithValue(r.Context(), ctxClaims, c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// adminAuthMiddleware enforces admin auth via cookie-bound JWT.
func adminAuthMiddleware(signer *crypto.JWTSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if signer == nil {
				writeErr(w, http.StatusInternalServerError, "JWT_NOT_CONFIGURED", "")
				return
			}
			cookie, err := r.Cookie("admin_session")
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "MISSING_SESSION", "")
				return
			}
			c, err := signer.Verify(cookie.Value)
			if err != nil || c.Owner != "admin" {
				writeErr(w, http.StatusUnauthorized, "INVALID_SESSION", "")
				return
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

