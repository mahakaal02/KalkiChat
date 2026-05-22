package api

import (
	"net/http"
	"time"
)

// adminListConversations is the WhatsApp/Telegram-style inbox view: one row
// per user that has a conversation, sorted by most-recent activity.
//
// Returned shape (per row):
//
//	{
//	  "user_id":          "usr_…",
//	  "login":            "alice",
//	  "status":           "active",
//	  "conversation_id":  "cnv_…",
//	  "last_message_at":  "2026-05-22T13:37:01Z",  // null if no messages yet
//	  "message_count":    42,
//	  "preview_size":     248                       // ciphertext bytes of most-recent envelope
//	}
//
// Crucially this does NOT include plaintext or any decrypted content. The
// admin web UI surfaces metadata only; actual message reading requires the
// admin's device private key (see ConversationView E2E badge in admin-web).
//
// Optional `q` query param filters by login substring.
func adminListConversations(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		rows, err := d.DB.Query(r.Context(), `
			SELECT
				u.id, u.login, u.status,
				c.id AS conversation_id,
				m.last_at, m.cnt, COALESCE(OCTET_LENGTH(m.last_env), 0) AS preview_size
			FROM users u
			JOIN conversations c ON c.user_id = u.id
			LEFT JOIN LATERAL (
				SELECT
					MAX(created_at) AS last_at,
					COUNT(*)        AS cnt,
					(SELECT envelope FROM messages
					   WHERE conversation_id = c.id
					   ORDER BY created_at DESC LIMIT 1) AS last_env
				FROM messages WHERE conversation_id = c.id
			) m ON TRUE
			WHERE ($1 = '' OR LOWER(u.login) LIKE LOWER('%' || $1 || '%'))
			ORDER BY COALESCE(m.last_at, u.created_at) DESC
			LIMIT 200
		`, q)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var (
				uid, login, status, convoID string
				lastAt                      *time.Time
				cnt                         *int64
				previewSize                 int64
			)
			if err := rows.Scan(&uid, &login, &status, &convoID, &lastAt, &cnt, &previewSize); err != nil {
				continue
			}
			row := map[string]any{
				"user_id":         uid,
				"login":           login,
				"status":          status,
				"conversation_id": convoID,
				"last_message_at": lastAt,
				"preview_size":    previewSize,
			}
			if cnt != nil {
				row["message_count"] = *cnt
			} else {
				row["message_count"] = 0
			}
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, map[string]any{"conversations": out})
	}
}
