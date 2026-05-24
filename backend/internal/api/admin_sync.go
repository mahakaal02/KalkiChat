package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ===========================================================================
// admin-sync: the plaintext bridge between admin-mobile and admin-web.
// ===========================================================================
//
// Why this layer exists
// ─────────────────────
// KalkiChat is end-to-end encrypted. The admin's *cryptographic identity*
// (Ed25519/X25519 keypair + Double-Ratchet state) lives only on the
// admin-companion-device (admin-mobile). Admin-web has no private key
// material — by design — so the rows it can see in the `messages` table
// are opaque ciphertext envelopes.
//
// That's a problem the moment a human admin opens the web dashboard to
// read a user's message. They'd see `[ciphertext · N chars b64]` and have
// to switch to their phone to reply. Worse: when they *do* reply from the
// web, there's no device on the server that knows how to encrypt for the
// user.
//
// admin-sync is the fix: a small, audited plaintext mirror.
//
//   /v1/admin-sync/inbound          ← admin-mobile pushes plaintext after
//                                     decrypting an incoming user message.
//   /v1/admin-sync/outbound         ← admin-web pushes a plaintext reply
//                                     into a queue.
//   /v1/admin-sync/outbound/pending ← admin-mobile drains the queue.
//   /v1/admin-sync/outbound/{id}/sent
//                                   ← admin-mobile acks; we transition the
//                                     queue row to 'sent' and mirror the
//                                     plaintext into admin_plaintext so the
//                                     web UI immediately shows the reply.
//
// Auth: every endpoint goes through `adminAuthMiddleware`. That accepts
// either an `admin_session` cookie (admin web) or a Bearer JWT (admin
// mobile, post /v1/admin/devices/register). Both carry `Owner == "admin"`
// and `OwnerID == <admin id>`; bearer tokens additionally have
// `Sub == <device id>` (cookies set Sub == admin id).
//
// Privacy + retention: see migration 0003. Bodies live ≤30 days; the
// retention worker sweeps `decrypted_at < NOW() - INTERVAL '30 days'`.

// ── /v1/admin-sync/inbound ─────────────────────────────────────────────────
//
// Called by admin-mobile after it successfully decrypts a `message.recv`
// WS event (or a backfilled row from /admin/users/{id}/conversation).
//
// Body:
//
//	{
//	  "message_id": "msg_...",      // FK into messages.id
//	  "body":       "hello there"
//	}
//
// `conversation_id` and `direction` are derived server-side from the
// existing messages row — admin-mobile only needs to know which row it
// decrypted, not how the server denormalizes it.
//
// Idempotent: ON CONFLICT (message_id) DO NOTHING. Mobile clients are
// free to re-post on retry; we'll silently skip duplicates so the admin
// web view doesn't see stale plaintext flicker.
//
// Auth check: caller must be an admin owner (adminAuthMiddleware enforces),
// and the message they're posting plaintext for must involve one of their
// admin devices (sender OR recipient). Without that gate any compromised
// admin token could write fake plaintext into conversations its operator
// isn't even on.
func adminSyncInbound(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		if c == nil || c.OwnerID == "" {
			writeErr(w, http.StatusUnauthorized, "NO_CLAIMS", "")
			return
		}
		var in struct {
			MessageID string `json:"message_id"`
			Body      string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		if in.MessageID == "" || in.Body == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_FIELDS", "")
			return
		}
		// Cheap sanity guard. The retention worker (and any future audit
		// export) shouldn't have to defend against pathologically large
		// blobs being smuggled through this path.
		if len(in.Body) > 64*1024 {
			writeErr(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "")
			return
		}
		ctx := r.Context()

		// Pull conversation_id + direction in one shot; verify the caller
		// is on at least one end of the message. Direction is computed
		// from the *admin* device's perspective: "inbound" = a user sent
		// it to us; "outbound" = we sent it to the user.
		var (
			conversationID string
			direction      string
			involves       bool
		)
		err := d.DB.QueryRow(ctx, `
			SELECT m.conversation_id,
			       CASE WHEN rd.owner_kind = 'admin' THEN 'inbound' ELSE 'outbound' END,
			       (sd.owner_kind = 'admin' AND sd.owner_id = $2)
			          OR (rd.owner_kind = 'admin' AND rd.owner_id = $2)
			FROM messages m
			JOIN devices sd ON sd.id = m.sender_device_id
			JOIN devices rd ON rd.id = m.recipient_device_id
			WHERE m.id = $1
		`, in.MessageID, c.OwnerID).Scan(&conversationID, &direction, &involves)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "UNKNOWN_MESSAGE", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		if !involves {
			writeErr(w, http.StatusForbidden, "NOT_PARTICIPANT", "")
			return
		}

		_, err = d.DB.Exec(ctx, `
			INSERT INTO admin_plaintext (message_id, conversation_id, direction, body, created_at, decrypted_at)
			SELECT $1, $2, $3, $4, m.created_at, NOW()
			FROM messages m WHERE m.id = $1
			ON CONFLICT (message_id) DO NOTHING
		`, in.MessageID, conversationID, direction, in.Body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"conversation_id": conversationID,
			"direction":       direction,
		})
	}
}

// ── /v1/admin-sync/outbound ────────────────────────────────────────────────
//
// Called by admin-web (cookie auth) when an admin types a reply and hits
// Send. The body is plaintext; encryption + routing happens later when
// admin-mobile drains the queue.
//
// Body:
//
//	{
//	  "user_id": "usr_...",
//	  "body":    "Sure, I can help with that."
//	}
//
// Returns the new queue id so the caller can poll for status if desired.
func adminSyncOutboundEnqueue(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		if c == nil || c.OwnerID == "" {
			writeErr(w, http.StatusUnauthorized, "NO_CLAIMS", "")
			return
		}
		var in struct {
			UserID string `json:"user_id"`
			Body   string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		in.Body = strings.TrimSpace(in.Body)
		if in.UserID == "" || in.Body == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_FIELDS", "")
			return
		}
		if len(in.Body) > 16*1024 {
			writeErr(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "")
			return
		}

		// Validate the user exists. Catches typos in admin-web links and
		// keeps the FK from doing the error-mapping job for us.
		var exists bool
		err := d.DB.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, in.UserID).Scan(&exists)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		if !exists {
			writeErr(w, http.StatusNotFound, "USER_UNKNOWN", "")
			return
		}

		id := "oqu_" + uuid.NewString()
		_, err = d.DB.Exec(r.Context(), `
			INSERT INTO admin_outbound_queue (id, user_id, admin_id, body, status)
			VALUES ($1,$2,$3,$4,'pending')
		`, id, in.UserID, c.OwnerID, in.Body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":         id,
			"status":     "pending",
			"created_at": time.Now(),
		})
	}
}

// ── GET /v1/admin-sync/outbound/pending ────────────────────────────────────
//
// Called by admin-mobile every ~5s while the app is in the foreground.
// Returns up to 50 pending rows oldest-first.
//
// We deliberately *don't* implement a per-poller leases or row-locking
// scheme. There's exactly one admin-companion device per operator today,
// and even in a future multi-device world, the worst case is two phones
// trying to encrypt the same outbound — the messages.client_id idempotency
// path catches the duplicate write at the lower layer. Simplicity wins.
func adminSyncOutboundPending(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, user_id, body, created_at
			FROM admin_outbound_queue
			WHERE status = 'pending'
			ORDER BY created_at ASC
			LIMIT 50
		`)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var id, userID, body string
			var created time.Time
			if err := rows.Scan(&id, &userID, &body, &created); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id":         id,
				"user_id":    userID,
				"body":       body,
				"created_at": created,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

// ── POST /v1/admin-sync/outbound/{id}/sent ─────────────────────────────────
//
// Called by admin-mobile after it has successfully encrypted + posted a
// queued reply via the existing message.send WS path.
//
// Body:
//
//	{
//	  "server_message_id": "msg_...",  // optional; assigned async by the
//	                                   //   WS handler's message.persisted
//	                                   //   event. Admin-mobile may not yet
//	                                   //   have it when /sent fires.
//	  "error":             ""          // set on failure; status becomes 'failed'
//	}
//
// Side-effects on success:
//   - admin_outbound_queue row → status='sent', sent_at=NOW(); optional
//     server_message_id populated if supplied.
//   - If server_message_id IS supplied: admin_plaintext row inserted
//     (direction='outbound') so the web UI shows the reply immediately.
//     If NOT: the plaintext mirror is populated separately by admin-mobile
//     posting to /admin-sync/inbound once it correlates the WS
//     message.persisted event with the queued body.
//
// On failure, status='failed' + last_error is set.
func adminSyncOutboundAck(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if id == "" {
			writeErr(w, http.StatusBadRequest, "MISSING_ID", "")
			return
		}
		var in struct {
			ServerMessageID string `json:"server_message_id"`
			Error           string `json:"error,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		ctx := r.Context()

		// Failure path: just stamp the row. No plaintext mirror — the
		// outbound never actually went out.
		if in.Error != "" {
			_, err := d.DB.Exec(ctx, `
				UPDATE admin_outbound_queue
				SET status = 'failed', last_error = $2
				WHERE id = $1 AND status = 'pending'
			`, id, truncate(in.Error, 1024))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "DB", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "failed"})
			return
		}

		// Both updates need to be atomic when we have a server_message_id —
		// partial success would leave admin-web with a "sent" indicator
		// but no plaintext to display. When no server_message_id is
		// available yet, we just stamp the queue row and rely on
		// /admin-sync/inbound to fill in the plaintext mirror later.
		tx, err := d.DB.Begin(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var (
			userID, body string
		)
		var serverMsgArg any
		if in.ServerMessageID != "" {
			serverMsgArg = in.ServerMessageID
		} else {
			serverMsgArg = nil
		}
		err = tx.QueryRow(ctx, `
			UPDATE admin_outbound_queue
			SET status = 'sent', sent_at = NOW(), server_message_id = $2
			WHERE id = $1 AND status = 'pending'
			RETURNING user_id, body
		`, id, serverMsgArg).Scan(&userID, &body)
		if errors.Is(err, pgx.ErrNoRows) {
			// Already acked or unknown id. Treat as idempotent success so
			// the mobile client's retry loop doesn't keep spinning.
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "noop"})
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		// Mirror the plaintext immediately when we have a server_id;
		// otherwise admin-mobile will POST /admin-sync/inbound for this
		// message_id when its WS message.persisted handler fires.
		if in.ServerMessageID != "" {
			if _, err := tx.Exec(ctx, `
				INSERT INTO admin_plaintext (message_id, conversation_id, direction, body, created_at, decrypted_at)
				SELECT $1, m.conversation_id, 'outbound', $2, m.created_at, NOW()
				FROM messages m WHERE m.id = $1
				ON CONFLICT (message_id) DO NOTHING
			`, in.ServerMessageID, body); err != nil {
				writeErr(w, http.StatusInternalServerError, "DB", err.Error())
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		_ = userID // reserved for future "delivered" pub/sub fan-out
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "sent"})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
