package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/kalkichat/backend/internal/audit"
	"github.com/kalkichat/backend/internal/auth"
	kcrypto "github.com/kalkichat/backend/internal/crypto"
	"github.com/kalkichat/backend/internal/messages"
	"github.com/kalkichat/backend/internal/ws"
)

// adminLogin: step 1 — email + password. Sets a short-lived "pre-2fa" cookie.
func adminLogin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		ctx := r.Context()
		var (
			id, pwHash, role string
			totpEnc          []byte
		)
		err := d.DB.QueryRow(ctx, `
			SELECT id, password_hash, totp_secret_enc, role FROM admins WHERE email = LOWER($1)
		`, in.Email).Scan(&id, &pwHash, &totpEnc, &role)
		if errors.Is(err, pgx.ErrNoRows) {
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
		// Issue a "pre-2fa" token good for 5 minutes, restricted to /admin/auth/totp.
		signer, _ := kcrypto.NewJWTSigner(d.Cfg.JWTPrivateKeyPEM, d.Cfg.JWTPublicKeyPEM, 5*time.Minute)
		tok, err := signer.Sign(kcrypto.JWTClaims{
			Sub: id, OwnerID: id, Owner: "admin-pre2fa", Audience: "kalki.admin-pre2fa",
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_pre2fa",
			Value:    tok,
			Path:     "/v1/admin/auth/totp",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300,
		})
		writeJSON(w, http.StatusOK, map[string]any{"step": "totp_required"})
	}
}

// adminTOTP: step 2 — TOTP code. Sets the full session cookie.
func adminTOTP(d Deps, sessionSigner *kcrypto.JWTSigner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_pre2fa")
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "PRE2FA_REQUIRED", "")
			return
		}
		preSigner, _ := kcrypto.NewJWTSigner(d.Cfg.JWTPrivateKeyPEM, d.Cfg.JWTPublicKeyPEM, 5*time.Minute)
		c, err := preSigner.Verify(cookie.Value)
		if err != nil || c.Owner != "admin-pre2fa" {
			writeErr(w, http.StatusUnauthorized, "PRE2FA_BAD", "")
			return
		}
		var in struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		var totpEnc []byte
		err = d.DB.QueryRow(r.Context(), `SELECT totp_secret_enc FROM admins WHERE id=$1`, c.Sub).Scan(&totpEnc)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "ADMIN_MISSING", "")
			return
		}
		encKey, err := hex.DecodeString(d.Cfg.TOTPEncKeyHex)
		if err != nil || len(encKey) != 32 {
			writeErr(w, http.StatusInternalServerError, "TOTP_KEY", "")
			return
		}
		secret, err := auth.TOTPOpenSealed(encKey, totpEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "TOTP_DECRYPT", "")
			return
		}
		if !auth.TOTPVerify(secret, in.Code) {
			writeErr(w, http.StatusUnauthorized, "BAD_TOTP", "")
			return
		}
		tok, err := sessionSigner.Sign(kcrypto.JWTClaims{
			Sub: c.Sub, OwnerID: c.Sub, Owner: "admin", Audience: "kalki.admin",
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_pre2fa",
			Value:    "",
			Path:     "/v1/admin/auth/totp",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(d.Cfg.JWTAccessTTL.Seconds()),
		})
		_, _ = d.DB.Exec(r.Context(), `UPDATE admins SET last_login_at = NOW() WHERE id = $1`, c.Sub)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminListUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, login, status, created_at, last_login_at, must_change_password
			FROM users
			WHERE ($1 = '' OR LOWER(login) LIKE LOWER('%' || $1 || '%'))
			ORDER BY created_at DESC
			LIMIT 100
		`, q)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var id, login, status string
			var created, lastLogin *time.Time
			var mustChange bool
			if err := rows.Scan(&id, &login, &status, &created, &lastLogin, &mustChange); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id":                   id,
				"login":                login,
				"status":               status,
				"created_at":           created,
				"last_login":           lastLogin,
				"must_change_password": mustChange,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	}
}

func adminGetUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var login, status string
		var mustChange bool
		err := d.DB.QueryRow(r.Context(), `
			SELECT login, status, must_change_password FROM users WHERE id=$1
		`, id).Scan(&login, &status, &mustChange)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "USER_UNKNOWN", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		drows, err := d.DB.Query(r.Context(), `
			SELECT id, name, platform, created_at, last_seen_at, revoked_at
			FROM devices WHERE owner_kind='user' AND owner_id=$1
			ORDER BY created_at DESC
		`, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer drows.Close()
		devs := make([]map[string]any, 0)
		for drows.Next() {
			var did, dname, platform string
			var created, last time.Time
			var revoked *time.Time
			_ = drows.Scan(&did, &dname, &platform, &created, &last, &revoked)
			devs = append(devs, map[string]any{
				"id": did, "name": dname, "platform": platform,
				"created_at": created, "last_seen_at": last, "revoked_at": revoked,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":                   id,
			"login":                login,
			"status":               status,
			"must_change_password": mustChange,
			"devices":              devs,
		})
	}
}

func adminSuspendUser(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		_, err := d.DB.Exec(r.Context(), `UPDATE users SET status='suspended' WHERE id=$1`, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		_, _ = d.DB.Exec(r.Context(), `UPDATE devices SET revoked_at = NOW()
			WHERE owner_kind='user' AND owner_id=$1 AND revoked_at IS NULL`, id)
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "user.suspend", TargetKind: "user", TargetID: id,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminUnsuspendUser(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		_, err := d.DB.Exec(r.Context(), `UPDATE users SET status='active' WHERE id=$1`, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "user.unsuspend", TargetKind: "user", TargetID: id,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminRevokeSessions(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		_, _ = d.DB.Exec(r.Context(), `UPDATE devices SET revoked_at = NOW()
			WHERE owner_kind='user' AND owner_id=$1 AND revoked_at IS NULL`, id)
		_, _ = d.DB.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = NOW()
			WHERE device_id IN (SELECT id FROM devices WHERE owner_kind='user' AND owner_id=$1)`, id)
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "user.revoke_sessions", TargetKind: "user", TargetID: id,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminGetConversation(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		var convoID string
		err := d.DB.QueryRow(r.Context(), `SELECT id FROM conversations WHERE user_id=$1`, userID).Scan(&convoID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "NO_CONVERSATION", "")
			return
		}
		// Pick *an* admin device for the recipient/sender filter so the
		// admin web UI sees the user↔admin thread. Cookie sessions have
		// Sub == admin id, bearer sessions have Sub == device id; use
		// OwnerID (always admin id) to look up admin-owned devices.
		adminID := c.OwnerID
		if adminID == "" {
			adminID = c.Sub
		}
		var adminDevice string
		err = d.DB.QueryRow(r.Context(), `
			SELECT id FROM devices WHERE owner_kind='admin' AND owner_id=$1 AND revoked_at IS NULL
			ORDER BY last_seen_at DESC LIMIT 1
		`, adminID).Scan(&adminDevice)
		if err != nil {
			writeErr(w, http.StatusFailedDependency, "NO_ADMIN_DEVICE", "")
			return
		}
		// LEFT JOIN admin_plaintext so the response carries the decrypted
		// body whenever admin-mobile has relayed it. Rows without a
		// plaintext partner come back with `plaintext: null`, which the
		// web UI renders as a "decrypting…" placeholder.
		rows, err := d.DB.Query(r.Context(), `
			SELECT m.id, m.sender_device_id, m.envelope, m.signature, m.media_id, m.created_at,
			       ap.body, ap.direction
			FROM messages m
			LEFT JOIN admin_plaintext ap ON ap.message_id = m.id
			WHERE m.conversation_id=$1
			  AND (m.sender_device_id=$2 OR m.recipient_device_id=$2)
			ORDER BY m.created_at ASC
			LIMIT 500
		`, convoID, adminDevice)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		msgs := make([]map[string]any, 0)
		for rows.Next() {
			var id, sender string
			var env, sig []byte
			var mediaID, plaintext, direction *string
			var created time.Time
			if err := rows.Scan(&id, &sender, &env, &sig, &mediaID, &created,
				&plaintext, &direction); err != nil {
				continue
			}
			row := map[string]any{
				"id":               id,
				"sender_device_id": sender,
				"envelope":         base64.StdEncoding.EncodeToString(env),
				"signature":        base64.StdEncoding.EncodeToString(sig),
				"media_id":         mediaID,
				"created_at":       created,
				// nil-safe: web UI checks `=== null` and falls back to the
				// "decrypting…" placeholder when admin-mobile hasn't yet
				// posted plaintext for this row.
				"plaintext": plaintext,
				"direction": direction,
			}
			msgs = append(msgs, row)
		}

		// Surface any pending outbound queue rows too, so admin-web shows
		// "sending…" indicators for replies it just submitted but that
		// admin-mobile hasn't drained yet. Bounded to 50; the queue
		// shouldn't realistically grow past that for a single user.
		qrows, err := d.DB.Query(r.Context(), `
			SELECT id, body, status, last_error, created_at, sent_at, server_message_id
			FROM admin_outbound_queue
			WHERE user_id=$1
			  AND (status='pending' OR (status IN ('sent','failed') AND created_at > NOW() - INTERVAL '24 hours'))
			ORDER BY created_at ASC
			LIMIT 50
		`, userID)
		pending := make([]map[string]any, 0)
		if err == nil {
			defer qrows.Close()
			for qrows.Next() {
				var qid, body, status string
				var lastErr, serverMsgID *string
				var created time.Time
				var sentAt *time.Time
				if err := qrows.Scan(&qid, &body, &status, &lastErr, &created, &sentAt, &serverMsgID); err != nil {
					continue
				}
				pending = append(pending, map[string]any{
					"id":                qid,
					"body":              body,
					"status":            status,
					"last_error":        lastErr,
					"created_at":        created,
					"sent_at":           sentAt,
					"server_message_id": serverMsgID,
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"conversation_id": convoID,
			"messages":        msgs,
			"outbound_queue":  pending,
		})
	}
}

func adminSendMessage(d Deps, svc *messages.Service, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		var in sendMessageReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		env, err := base64.StdEncoding.DecodeString(in.Envelope)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_ENVELOPE", "")
			return
		}
		sig, err := base64.StdEncoding.DecodeString(in.Signature)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_SIG", "")
			return
		}
		var convoID string
		err = d.DB.QueryRow(r.Context(), `SELECT id FROM conversations WHERE user_id=$1`, userID).Scan(&convoID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "NO_CONVERSATION", "")
			return
		}
		// The admin must own a device; the client passed the sender_device_id via JWT (c.Sub).
		// But for admin web (no per-device key), the client passes its X-Admin-Device-Id header.
		senderDevice := r.Header.Get("X-Admin-Device-Id")
		if senderDevice == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_ADMIN_DEVICE", "")
			return
		}
		var mediaID *string
		if in.MediaID != "" {
			mediaID = &in.MediaID
		}
		id, err := svc.Send(r.Context(), messages.SendInput{
			SenderDeviceID:    senderDevice,
			RecipientDeviceID: in.RecipientDeviceID,
			ConversationID:    convoID,
			ClientID:          in.ClientID,
			Envelope:          env,
			Signature:         sig,
			MediaID:           mediaID,
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, mapErr(err), err.Error())
			return
		}
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "message.reply", TargetKind: "user", TargetID: userID,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
			Metadata: map[string]any{"server_id": id},
		})
		writeJSON(w, http.StatusOK, map[string]any{"server_id": id})
	}
}

func adminListDevices(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.DB.Query(r.Context(), `
			SELECT d.id, d.owner_kind, d.owner_id, d.name, d.platform,
			       d.last_seen_at, d.revoked_at,
			       a.node_id IS NOT NULL AS online
			FROM devices d
			LEFT JOIN active_sessions a ON a.device_id = d.id
			ORDER BY d.last_seen_at DESC
			LIMIT 200
		`)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var id, kind, owner, name, platform string
			var last time.Time
			var revoked *time.Time
			var online bool
			if err := rows.Scan(&id, &kind, &owner, &name, &platform, &last, &revoked, &online); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id": id, "owner_kind": kind, "owner_id": owner,
				"name": name, "platform": platform,
				"last_seen_at": last, "revoked_at": revoked,
				"online": online,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": out})
	}
}

func adminRevokeDevice(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		_, _ = d.DB.Exec(r.Context(), `UPDATE devices SET revoked_at = NOW() WHERE id=$1`, id)
		_, _ = d.DB.Exec(r.Context(), `UPDATE refresh_tokens SET revoked_at = NOW() WHERE device_id=$1`, id)
		_ = d.Hub.Publish(r.Context(), "device:"+id, ws.RevocationEvent())
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "device.revoke", TargetKind: "device", TargetID: id,
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminGetWhatsApp(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var phone, msg string
		err := d.DB.QueryRow(r.Context(), `SELECT phone_e164, message_template FROM whatsapp_config WHERE id=1`).
			Scan(&phone, &msg)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"phone_e164":       phone,
			"message_template": msg,
		})
	}
}

func adminPutWhatsApp(d Deps, rec *audit.Recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		var in struct {
			PhoneE164       string `json:"phone_e164"`
			MessageTemplate string `json:"message_template"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		if !validE164(in.PhoneE164) {
			writeErr(w, http.StatusBadRequest, "BAD_PHONE", "expected E.164 (e.g. +14155551234)")
			return
		}
		if len(in.MessageTemplate) == 0 || len(in.MessageTemplate) > 1000 {
			writeErr(w, http.StatusBadRequest, "BAD_MESSAGE", "1-1000 chars")
			return
		}
		_, err := d.DB.Exec(r.Context(), `
			UPDATE whatsapp_config
			SET phone_e164=$1, message_template=$2, updated_by_admin=$3, updated_at=NOW()
			WHERE id=1
		`, in.PhoneE164, in.MessageTemplate, c.Sub)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		_ = rec.Record(r.Context(), audit.Event{
			ActorKind: "admin", ActorID: c.Sub,
			Action: "whatsapp_config.update", TargetKind: "config", TargetID: "whatsapp",
			IP: clientIPAddr(r), UserAgent: r.UserAgent(),
			Metadata: map[string]any{"phone_e164": in.PhoneE164},
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func adminAuditList(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, actor_kind, actor_id, action, target_kind, target_id,
			       ip::text, user_agent, metadata, created_at
			FROM audit_logs ORDER BY id DESC LIMIT 200
		`)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var (
				id                                         int64
				actorKind, actorID, action                 string
				targetKind, targetID, ip, ua               *string
				metaB                                      []byte
				created                                    time.Time
			)
			if err := rows.Scan(&id, &actorKind, &actorID, &action,
				&targetKind, &targetID, &ip, &ua, &metaB, &created); err != nil {
				continue
			}
			var meta map[string]any
			_ = json.Unmarshal(metaB, &meta)
			out = append(out, map[string]any{
				"id": id, "actor_kind": actorKind, "actor_id": actorID,
				"action": action, "target_kind": targetKind, "target_id": targetID,
				"ip": ip, "user_agent": ua, "metadata": meta, "created_at": created,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": out})
	}
}

func adminAuditCSV(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, actor_kind, actor_id, action, target_kind, target_id,
			       ip::text, user_agent, metadata::text, created_at
			FROM audit_logs ORDER BY id DESC LIMIT 10000
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		_, _ = w.Write([]byte("id,actor_kind,actor_id,action,target_kind,target_id,ip,user_agent,metadata,created_at\n"))
		for rows.Next() {
			var (
				id                                            int64
				actorKind, actorID, action                    string
				targetKind, targetID, ip, ua, meta            *string
				created                                       time.Time
			)
			if err := rows.Scan(&id, &actorKind, &actorID, &action,
				&targetKind, &targetID, &ip, &ua, &meta, &created); err != nil {
				continue
			}
			fmt.Fprintf(w, "%d,%q,%q,%q,%q,%q,%q,%q,%q,%s\n",
				id, actorKind, actorID, action,
				strOr(targetKind), strOr(targetID), strOr(ip), strOr(ua), strOr(meta),
				created.Format(time.RFC3339Nano))
		}
	}
}

func adminAnalytics(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var u, a, d24, m7d int
		_ = d.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&u)
		_ = d.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM users WHERE status='active'`).Scan(&a)
		_ = d.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&d24)
		_ = d.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '7 days'`).Scan(&m7d)
		writeJSON(w, http.StatusOK, map[string]any{
			"users_total":       u,
			"users_active":      a,
			"messages_24h":      d24,
			"messages_7d":       m7d,
		})
	}
}

func strOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func clientIPAddr(r *http.Request) net.IP {
	ip := clientIP(r)
	return net.ParseIP(ip)
}

// validE164 is a permissive but strict-ish check for E.164.
func validE164(s string) bool {
	if !strings.HasPrefix(s, "+") {
		return false
	}
	if len(s) < 8 || len(s) > 16 {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
