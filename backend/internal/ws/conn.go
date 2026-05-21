package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// Time constants for the WS protocol.
const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 256 * 1024
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:    4096,
	WriteBufferSize:   4096,
	EnableCompression: false, // CRIME-style attacks; payload is already small
	CheckOrigin: func(r *http.Request) bool {
		// Origin is validated by the middleware before we get here.
		return true
	},
	Subprotocols: []string{"kalki.v1"},
}

// MessageHandler is invoked for every incoming client event.
type MessageHandler func(ctx context.Context, c *Client, ev ClientEvent) error

// Serve upgrades the HTTP request and runs the per-connection loops.
func (h *Hub) Serve(w http.ResponseWriter, r *http.Request, deviceID, ownerID, kind string, handler MessageHandler) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Warn().Err(err).Msg("ws upgrade")
		return
	}
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	c := &Client{
		DeviceID: deviceID,
		OwnerID:  ownerID,
		Kind:     kind,
		send:     make(chan ServerEvent, 64),
		hub:      h,
	}
	h.register <- c

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Write pump.
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer func() {
			ticker.Stop()
			_ = conn.Close()
		}()
		for {
			select {
			case ev, ok := <-c.send:
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				if !ok {
					_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}
				if ev.Ts == 0 {
					ev.Ts = time.Now().UnixMilli()
				}
				if err := conn.WriteJSON(ev); err != nil {
					return
				}
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Read pump.
	for {
		var ev ClientEvent
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			c.SendError("", "INVALID_JSON")
			continue
		}
		if err := handler(ctx, c, ev); err != nil {
			log.Debug().Err(err).Str("type", ev.Type).Msg("ws handler error")
		}
	}
	h.unregister <- c
}

// Send queues a server event for delivery to this client.
func (c *Client) Send(ev ServerEvent) {
	select {
	case c.send <- ev:
	default:
		// Slow client: drop. The next reconnect will backfill from DB.
	}
}

// SendError pushes a structured error to the client.
func (c *Client) SendError(correlationID, code string) {
	c.Send(ServerEvent{
		Type: "message.error",
		ID:   correlationID,
		Data: map[string]any{"code": code},
	})
}
