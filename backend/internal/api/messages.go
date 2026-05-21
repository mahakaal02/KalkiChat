package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kalkichat/backend/internal/messages"
)

type sendMessageReq struct {
	ClientID            string `json:"client_id"`
	RecipientDeviceID   string `json:"recipient_device_id"`
	Envelope            string `json:"envelope"`
	Signature           string `json:"signature"`
	MediaID             string `json:"media_id,omitempty"`
}

func messageSend(d Deps, svc *messages.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		var in sendMessageReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		env, err := base64.StdEncoding.DecodeString(in.Envelope)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_ENVELOPE", err.Error())
			return
		}
		sig, err := base64.StdEncoding.DecodeString(in.Signature)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_SIG", err.Error())
			return
		}

		var convoID string
		err = d.DB.QueryRow(r.Context(), `
			SELECT id FROM conversations WHERE user_id = $1
		`, c.OwnerID).Scan(&convoID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		var mediaID *string
		if in.MediaID != "" {
			mediaID = &in.MediaID
		}

		id, err := svc.Send(r.Context(), messages.SendInput{
			SenderDeviceID:    c.Sub,
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
		writeJSON(w, http.StatusOK, map[string]any{"server_id": id})
	}
}

func conversationGet(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		limit := 50
		if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 200 {
			limit = l
		}
		var convoID string
		err := d.DB.QueryRow(r.Context(), `
			SELECT id FROM conversations WHERE user_id = $1
		`, c.OwnerID).Scan(&convoID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, sender_device_id, envelope, signature, media_id, created_at
			FROM messages
			WHERE conversation_id = $1 AND (recipient_device_id = $2 OR sender_device_id = $2)
			ORDER BY created_at DESC
			LIMIT $3
		`, convoID, c.Sub, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var (
				id, sender string
				env, sig   []byte
				mediaID    *string
				createdAt  time.Time
			)
			if err := rows.Scan(&id, &sender, &env, &sig, &mediaID, &createdAt); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id":               id,
				"sender_device_id": sender,
				"envelope":         base64.StdEncoding.EncodeToString(env),
				"signature":        base64.StdEncoding.EncodeToString(sig),
				"media_id":         mediaID,
				"created_at":       createdAt.UnixMilli(),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"conversation_id": convoID,
			"messages":        out,
		})
	}
}

func mapErr(err error) string {
	switch err {
	case messages.ErrEnvelopeSize:
		return "PAYLOAD_TOO_LARGE"
	case messages.ErrInvalidSignature:
		return "INVALID_SIG"
	case messages.ErrUnknownSender, messages.ErrUnknownRecipient:
		return "RECIPIENT_UNKNOWN"
	case messages.ErrSessionRevoked:
		return "SESSION_REVOKED"
	}
	return "BAD_REQUEST"
}
