// Package ws is the WebSocket gateway. Each connected device gets a `Client`
// goroutine. Cross-node fan-out runs through Redis pub/sub so that a sender on
// node A reaches a recipient on node B.
package ws

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/kalkichat/backend/internal/redisx"
)

// ServerEvent is sent server → client.
type ServerEvent struct {
	Type string         `json:"type"`
	ID   string         `json:"id,omitempty"`
	Ts   int64          `json:"ts,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

// ClientEvent is sent client → server.
type ClientEvent struct {
	Type string          `json:"type"`
	ID   string          `json:"id,omitempty"`
	Ts   int64           `json:"ts,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Client represents a single connected device.
type Client struct {
	DeviceID string
	OwnerID  string
	Kind     string // "user" | "admin"

	send chan ServerEvent
	hub  *Hub
}

// Hub multiplexes Clients and bridges them to Redis pub/sub.
type Hub struct {
	rdb *redis.Client
	db  *pgxpool.Pool

	mu      sync.RWMutex
	clients map[string]*Client // device_id → client

	register   chan *Client
	unregister chan *Client
}

// NewHub constructs the hub.
func NewHub(rdb *redis.Client, db *pgxpool.Pool) *Hub {
	return &Hub{
		rdb:        rdb,
		db:         db,
		clients:    make(map[string]*Client),
		register:   make(chan *Client, 32),
		unregister: make(chan *Client, 32),
	}
}

// Run starts the hub's central loop.
func (h *Hub) Run(ctx context.Context) {
	go h.subscribe(ctx, redisx.AdminTeamChannel)

	for {
		select {
		case <-ctx.Done():
			return
		case c := <-h.register:
			h.mu.Lock()
			if old, ok := h.clients[c.DeviceID]; ok {
				// Same device reconnecting: close the old one to avoid duplicates.
				close(old.send)
			}
			h.clients[c.DeviceID] = c
			h.mu.Unlock()
			go h.subscribe(ctx, redisx.DeviceChannel(c.DeviceID))
			if c.Kind == "user" {
				go h.subscribe(ctx, redisx.UserChannel(c.OwnerID))
			}
			log.Debug().Str("device", c.DeviceID).Msg("ws register")
		case c := <-h.unregister:
			h.mu.Lock()
			if cur, ok := h.clients[c.DeviceID]; ok && cur == c {
				delete(h.clients, c.DeviceID)
				close(c.send)
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) subscribe(ctx context.Context, channel string) {
	sub := h.rdb.Subscribe(ctx, channel)
	defer func() { _ = sub.Close() }()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var ev ServerEvent
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
				continue
			}
			// Route by channel: device:<id> → that device.
			// user:<id>     → all of that user's online devices.
			// team:admins   → all online admin devices.
			h.routeByChannel(channel, ev)
		}
	}
}

func (h *Hub) routeByChannel(channel string, ev ServerEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch {
	case len(channel) > 7 && channel[:7] == "device:":
		if c := h.clients[channel[7:]]; c != nil {
			select {
			case c.send <- ev:
			default:
			}
		}
	case len(channel) > 5 && channel[:5] == "user:":
		uid := channel[5:]
		for _, c := range h.clients {
			if c.Kind == "user" && c.OwnerID == uid {
				select {
				case c.send <- ev:
				default:
				}
			}
		}
	case channel == redisx.AdminTeamChannel:
		for _, c := range h.clients {
			if c.Kind == "admin" {
				select {
				case c.send <- ev:
				default:
				}
			}
		}
	}
}

// Publish sends an event to a Redis channel.
func (h *Hub) Publish(ctx context.Context, channel string, ev ServerEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return h.rdb.Publish(ctx, channel, b).Err()
}

// Broadcast sends an event to all locally-connected clients (no Redis).
// Used during graceful shutdown.
func (h *Hub) Broadcast(ev ServerEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		select {
		case c.send <- ev:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Close finishes the hub.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, c := range h.clients {
		close(c.send)
		delete(h.clients, id)
	}
}

// ErrClosed signals a closed hub.
var ErrClosed = errors.New("ws: hub closed")
