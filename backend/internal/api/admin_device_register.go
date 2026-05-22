package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kalkichat/backend/internal/audit"
	"github.com/kalkichat/backend/internal/auth"
	kcrypto "github.com/kalkichat/backend/internal/crypto"
)

// adminDeviceRegister is the admin-companion-device equivalent of
// authLogin (which is for user mobile). One round-trip:
//
//	POST /v1/admin/devices/register
//	{
//	  "email":     "alice@kalki.local",
//	  "password":  "...",
//	  "totp_code": "123456",
//	  "device": {
//	    "name":             "Alice iPhone",
//	    "platform":         "ios",
//	    "identity_ed25519": "<base64 32B>",
//	    "identity_x25519":  "<base64 32B>",
//	    "fcm_token":        "<optional>",
//	    "apns_token":       "<optional>"
//	  }
//	}
//	→ 200 {
//	  "access_token":  "<JWT, audience=kalki.admin>",
//	  "refresh_token": "<opaque>",
//	  "device_id":     "dev_…",
//	  "admin_id":      "adm_…",
//	  "expires_in":    900
//	}
//
// Why not reuse /v1/admin/auth/login + /v1/admin/auth/totp?
//
// Those return an HttpOnly cookie scoped to the admin operator and have
// no device-binding. The companion-device flow needs:
//   * a Bearer JWT (cookies don't ride WebSocket frames cleanly),
//   * the JWT's `sub` claim bound to a specific device row so the WS hub
//     can route inbound messages to it,
//   * the device's identity keys uploaded atomically with the auth so
//     there's no half-registered state.
//
// Implementing it as a single endpoint keeps the admin mobile auth flow
// as simple as the user mobile auth flow and lets the existing
// /v1/prekeys + /v1/ws routes "just work" with the resulting token —
// they already accept any JWT with owner=admin or owner=user.
//
// Audit: action "admin_device.register" with metadata {device_id, platform}.
func adminDeviceRegister(d Deps, signer *kcrypto.JWTSigner, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			TOTPCode string `json:"totp_code"`
			Device   struct {
				Name            string `json:"name"`
				Platform        string `json:"platform"`
				IdentityEd25519 string `json:"identity_ed25519"`
				IdentityX25519  string `json:"identity_x25519"`
				FCMToken        string `json:"fcm_token,omitempty"`
				APNSToken       string `json:"apns_token,omitempty"`
			} `json:"device"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		in.Email = strings.ToLower(strings.TrimSpace(in.Email))
		if in.Email == "" || in.Password == "" || in.TOTPCode == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_FIELDS", "")
			return
		}
		if !validPlatform(in.Device.Platform) {
			writeErr(w, http.StatusBadRequest, "BAD_PLATFORM", "")
			return
		}

		ctx := r.Context()

		// 1. Verify the admin operator's email + password.
		var (
			adminID string
			pwHash  string
			totpEnc []byte
		)
		err := d.DB.QueryRow(ctx, `
			SELECT id, password_hash, totp_secret_enc FROM admins WHERE email = $1
		`, in.Email).Scan(&adminID, &pwHash, &totpEnc)
		if errors.Is(err, pgx.ErrNoRows) {
			// Constant-time-ish: still hash the supplied password to keep
			// timing roughly equal between bad-email and bad-password paths.
			_, _ = auth.Verify(in.Password, "$argon2id$v=19$m=65536,t=3,p=2$"+
				"AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		ok, err := auth.Verify(in.Password, pwHash)
		if err != nil || !ok {
			writeErr(w, http.StatusUnauthorized, "BAD_CREDENTIALS", "")
			return
		}

		// 2. Verify TOTP. Re-uses the seal/open + Verify helpers that the
		//    web admin login flow uses, so a brute-forced TOTP secret is
		//    only valid in the cleartext-in-memory window of this call.
		encKey, err := hex.DecodeString(d.Cfg.TOTPEncKeyHex)
		if err != nil || len(encKey) != 32 {
			writeErr(w, http.StatusInternalServerError, "TOTP_KEY", "")
			return
		}
		totpSecret, err := auth.TOTPOpenSealed(encKey, totpEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "TOTP_DECRYPT", "")
			return
		}
		if !auth.TOTPVerify(totpSecret, in.TOTPCode) {
			writeErr(w, http.StatusUnauthorized, "BAD_TOTP", "")
			return
		}

		// 3. Validate the device's identity keys.
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

		// 4. Insert the device row with owner_kind='admin'. The schema
		//    already accepts this — see migration 0001.
		deviceID := "dev_" + uuid.NewString()
		_, err = d.DB.Exec(ctx, `
			INSERT INTO devices
				(id, owner_kind, owner_id, name, platform,
				 identity_ed25519, identity_x25519, fcm_token, apns_token)
			VALUES ($1,'admin',$2,$3,$4,$5,$6,$7,$8)
		`, deviceID, adminID, in.Device.Name, in.Device.Platform,
			idEd, idX, nullable(in.Device.FCMToken), nullable(in.Device.APNSToken))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		// 5. Issue a device-scoped JWT. The `Owner: "admin"` claim is what
		//    authMiddleware checks; the `Audience: "kalki.admin"` separates
		//    these tokens from user-mobile tokens so a misrouted token
		//    can't be reused across the trust boundary.
		access, err := signer.Sign(kcrypto.JWTClaims{
			Sub: deviceID, OwnerID: adminID, Owner: "admin",
			Audience: "kalki.admin",
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

		_, _ = d.DB.Exec(ctx, `UPDATE admins SET last_login_at = NOW() WHERE id = $1`, adminID)
		_ = rec.Record(ctx, audit.Event{
			ActorKind: "admin", ActorID: adminID,
			Action: "admin_device.register", TargetKind: "device", TargetID: deviceID,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
			Metadata: map[string]any{
				"platform": in.Device.Platform,
				"name":     in.Device.Name,
			},
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  access,
			"refresh_token": refresh,
			"device_id":     deviceID,
			"admin_id":      adminID,
			"expires_in":    int(d.Cfg.JWTAccessTTL.Seconds()),
		})
	}
}
