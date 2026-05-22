package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kalkichat/backend/internal/auth"
	kcrypto "github.com/kalkichat/backend/internal/crypto"
)

type loginRequest struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
	Device   struct {
		Name             string `json:"name"`
		Platform         string `json:"platform"`
		IdentityEd25519  string `json:"identity_ed25519"`
		IdentityX25519   string `json:"identity_x25519"`
		FCMToken         string `json:"fcm_token,omitempty"`
		APNSToken        string `json:"apns_token,omitempty"`
	} `json:"device"`
}

type loginResponse struct {
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	DeviceID           string `json:"device_id"`
	ExpiresIn          int    `json:"expires_in"`
	MustChangePassword bool   `json:"must_change_password"`
}

func authLogin(d Deps, signer *kcrypto.JWTSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in loginRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		in.UserID = strings.TrimSpace(in.UserID)
		if in.UserID == "" || in.Password == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_FIELDS", "")
			return
		}
		if !validPlatform(in.Device.Platform) {
			writeErr(w, http.StatusBadRequest, "BAD_PLATFORM", "")
			return
		}

		ctx := r.Context()

		// Lookup user.
		var (
			userID     string
			pwHash     string
			status     string
			mustChange bool
		)
		err := d.DB.QueryRow(ctx, `
			SELECT id, password_hash, status, must_change_password
			  FROM users WHERE LOWER(login) = LOWER($1)
		`, in.UserID).Scan(&userID, &pwHash, &status, &mustChange)
		if errors.Is(err, pgx.ErrNoRows) {
			// Constant-time-ish: do a dummy Argon2id anyway to mask timing.
			_, _ = auth.Verify(in.Password, "$argon2id$v=19$m=65536,t=3,p=2$"+
				"AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		if status != "active" {
			writeErr(w, http.StatusForbidden, "ACCOUNT_NOT_ACTIVE", "")
			return
		}

		ok, err := auth.Verify(in.Password, pwHash)
		if err != nil || !ok {
			_, _ = d.DB.Exec(ctx, `INSERT INTO login_failures (login, ip) VALUES ($1, $2)`,
				in.UserID, clientIP(r))
			writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "")
			return
		}

		idEd, err := base64.StdEncoding.DecodeString(in.Device.IdentityEd25519)
		if err != nil || len(idEd) != 32 {
			writeErr(w, http.StatusBadRequest, "BAD_KEY", "identity_ed25519")
			return
		}
		idX, err := base64.StdEncoding.DecodeString(in.Device.IdentityX25519)
		if err != nil || len(idX) != 32 {
			writeErr(w, http.StatusBadRequest, "BAD_KEY", "identity_x25519")
			return
		}

		deviceID := "dev_" + uuid.NewString()
		_, err = d.DB.Exec(ctx, `
			INSERT INTO devices
				(id, owner_kind, owner_id, name, platform,
				 identity_ed25519, identity_x25519, fcm_token, apns_token)
			VALUES ($1,'user',$2,$3,$4,$5,$6,$7,$8)
		`, deviceID, userID, in.Device.Name, in.Device.Platform,
			idEd, idX, nullable(in.Device.FCMToken), nullable(in.Device.APNSToken))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		// Ensure conversation exists.
		convoID := "cnv_" + uuid.NewString()
		_, err = d.DB.Exec(ctx, `
			INSERT INTO conversations (id, user_id)
			VALUES ($1, $2)
			ON CONFLICT (user_id) DO NOTHING
		`, convoID, userID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		access, err := signer.Sign(kcrypto.JWTClaims{
			Sub: deviceID, OwnerID: userID, Owner: "user",
			Audience: "kalki.user",
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		refresh, err := auth.RefreshIssue(ctx, d.DB, deviceID, "", d.Cfg.JWTRefreshTTL)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "REFRESH", err.Error())
			return
		}

		_, _ = d.DB.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID)

		writeJSON(w, http.StatusOK, loginResponse{
			AccessToken:        access,
			RefreshToken:       refresh,
			DeviceID:           deviceID,
			ExpiresIn:          int(d.Cfg.JWTAccessTTL.Seconds()),
			MustChangePassword: mustChange,
		})
	}
}

func authRefresh(d Deps, signer *kcrypto.JWTSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		ctx := r.Context()
		newRef, deviceID, _, err := auth.RefreshRotate(ctx, d.DB, in.RefreshToken, d.Cfg.JWTRefreshTTL)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "INVALID_REFRESH", err.Error())
			return
		}
		var ownerID, ownerKind string
		err = d.DB.QueryRow(ctx, `
			SELECT owner_id, owner_kind FROM devices WHERE id = $1 AND revoked_at IS NULL
		`, deviceID).Scan(&ownerID, &ownerKind)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "DEVICE_GONE", "")
			return
		}
		access, err := signer.Sign(kcrypto.JWTClaims{
			Sub: deviceID, OwnerID: ownerID, Owner: ownerKind,
			Audience: "kalki." + ownerKind,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, loginResponse{
			AccessToken:  access,
			RefreshToken: newRef,
			DeviceID:     deviceID,
			ExpiresIn:    int(d.Cfg.JWTAccessTTL.Seconds()),
		})
	}
}

func authLogout(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "MISSING_TOKEN", "")
			return
		}
		_, _ = d.DB.Exec(r.Context(), `UPDATE devices SET revoked_at = NOW() WHERE id = $1`, c.Sub)
		_ = auth.RefreshRevokeDevice(r.Context(), d.DB, c.Sub)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func validPlatform(p string) bool {
	switch p {
	case "android", "ios", "web":
		return true
	}
	return false
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if i := strings.Index(ip, ","); i >= 0 {
			return strings.TrimSpace(ip[:i])
		}
		return ip
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
