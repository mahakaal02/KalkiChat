package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/kalkichat/backend/internal/messages"
	"github.com/kalkichat/backend/internal/ws"
)

// wsHandler upgrades the connection and dispatches client events.
func wsHandler(d Deps, msgSvc *messages.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "MISSING_TOKEN", "")
			return
		}
		d.Hub.Serve(w, r, c.Sub, c.OwnerID, c.Owner,
			func(ctx context.Context, cl *ws.Client, ev ws.ClientEvent) error {
				switch ev.Type {
				case "message.send":
					return handleSend(ctx, d, msgSvc, cl, ev)
				case "message.ack":
					return handleAck(ctx, d, msgSvc, cl, ev)
				case "message.read":
					return handleRead(ctx, d, msgSvc, cl, ev)
				case "typing":
					// Pass-through. Not persisted. Limit to the conversation peer.
					var t struct {
						RecipientDeviceID string `json:"recipient_device_id"`
						IsTyping          bool   `json:"is_typing"`
					}
					_ = json.Unmarshal(ev.Data, &t)
					_ = d.Hub.Publish(ctx, "device:"+t.RecipientDeviceID, ws.ServerEvent{
						Type: "typing",
						Data: map[string]any{
							"from":      cl.DeviceID,
							"is_typing": t.IsTyping,
						},
					})
					return nil
				case "presence.ping":
					return nil
				default:
					cl.SendError(ev.ID, "UNKNOWN_TYPE")
					return nil
				}
			})
	}
}

func handleSend(ctx context.Context, d Deps, svc *messages.Service, cl *ws.Client, ev ws.ClientEvent) error {
	var in struct {
		ClientID          string `json:"client_id"`
		RecipientDeviceID string `json:"recipient_device_id"`
		Envelope          string `json:"envelope"`
		Signature         string `json:"signature"`
		MediaID           string `json:"media_id"`
	}
	if err := json.Unmarshal(ev.Data, &in); err != nil {
		cl.SendError(ev.ID, "BAD_JSON")
		return err
	}
	env, _ := base64.StdEncoding.DecodeString(in.Envelope)
	sig, _ := base64.StdEncoding.DecodeString(in.Signature)
	var convoID string
	err := d.DB.QueryRow(ctx, `SELECT id FROM conversations WHERE user_id=$1`, cl.OwnerID).Scan(&convoID)
	if err != nil {
		cl.SendError(ev.ID, "NO_CONVERSATION")
		return err
	}
	var mediaID *string
	if in.MediaID != "" {
		mediaID = &in.MediaID
	}
	id, err := svc.Send(ctx, messages.SendInput{
		SenderDeviceID:    cl.DeviceID,
		RecipientDeviceID: in.RecipientDeviceID,
		ConversationID:    convoID,
		ClientID:          in.ClientID,
		Envelope:          env,
		Signature:         sig,
		MediaID:           mediaID,
	})
	if err != nil {
		cl.SendError(ev.ID, mapErr(err))
		return err
	}
	cl.Send(ws.ServerEvent{
		Type: "message.persisted",
		ID:   ev.ID,
		Data: map[string]any{"client_id": in.ClientID, "server_id": id},
	})
	return nil
}

func handleAck(ctx context.Context, d Deps, svc *messages.Service, cl *ws.Client, ev ws.ClientEvent) error {
	var in struct {
		ServerID string `json:"server_id"`
	}
	if err := json.Unmarshal(ev.Data, &in); err != nil {
		return err
	}
	return svc.MarkDelivered(ctx, in.ServerID, cl.DeviceID)
}

func handleRead(ctx context.Context, d Deps, svc *messages.Service, cl *ws.Client, ev ws.ClientEvent) error {
	var in struct {
		ServerIDs []string `json:"server_ids"`
	}
	if err := json.Unmarshal(ev.Data, &in); err != nil {
		return err
	}
	for _, id := range in.ServerIDs {
		_ = svc.MarkRead(ctx, id, cl.DeviceID)
	}
	return nil
}
