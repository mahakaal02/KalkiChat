// Package ws is the WebSocket gateway. Each connected device gets a `Client`
// goroutine. Cross-node fan-out runs through Redis pub/sub so that a sender on
// node A reaches a recipient on node B.
package ws

import (
	"context"
	"encoding/base64"
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
			// Refresh last_seen_at on every connect. Without this the
			// devices.last_seen_at column stays frozen at the value the
			// device-register handler wrote (NOW() at registration) and
			// every downstream consumer (active-admin pool ordering,
			// "online?" indicators, retention candidates) is operating on
			// stale data. Fire-and-forget — we don't want a slow DB write
			// to delay the WS upgrade.
			go h.touchLastSeen(context.Background(), c.DeviceID)
			// Replay any messages addressed to this device that were
			// persisted while it was offline. Each one is published on
			// the device's own Redis channel, which we just subscribed
			// to above — so the client receives them through the same
			// `message.recv` path as live messages. The client is
			// expected to send `message.ack` after processing; that
			// marks delivered_at so future reconnects don't replay.
			go h.backfillMissed(context.Background(), c.DeviceID)
			log.Debug().Str("device", c.DeviceID).Msg("ws register")
		case c := <-h.unregister:
			h.mu.Lock()
			if cur, ok := h.clients[c.DeviceID]; ok && cur == c {
				delete(h.clients, c.DeviceID)
				close(c.send)
			}
			h.mu.Unlock()
			// One more touch on the way out so the column reflects "last
			// time this device was actually online" rather than the
			// connect time only.
			go h.touchLastSeen(context.Background(), c.DeviceID)
		}
	}
}

// TouchLastSeen refreshes devices.last_seen_at for the given device. Safe
// to call from any goroutine; errors are logged at debug level and
// otherwise swallowed (the function is best-effort liveness, not a
// correctness primitive).
func (h *Hub) TouchLastSeen(ctx context.Context, deviceID string) {
	h.touchLastSeen(ctx, deviceID)
}

func (h *Hub) touchLastSeen(ctx context.Context, deviceID string) {
	if h.db == nil || deviceID == "" {
		return
	}
	if _, err := h.db.Exec(ctx,
		`UPDATE devices SET last_seen_at = NOW() WHERE id = $1`, deviceID); err != nil {
		log.Debug().Err(err).Str("device", deviceID).Msg("ws: touch last_seen_at")
	}
}

// backfillMissed replays undelivered messages addressed to deviceID by
// re-publishing them on the device's own Redis channel. Bounded to 200
// rows and the last 7 days so a misbehaving client can't trigger an
// unbounded replay. Idempotent: the client's downstream dedupe (e.g.
// admin_plaintext.message_id PK) catches anything that re-arrives.
func (h *Hub) backfillMissed(ctx context.Context, deviceID string) {
	if h.db == nil || deviceID == "" {
		return
	}
	// Tiny delay so the subscribe goroutine that opened device:<id>
	// finishes wiring up before we publish. Without this, very fast
	// clients can race the subscriber and miss the first event.
	time.Sleep(50 * time.Millisecond)
	rows, err := h.db.Query(ctx, `
		SELECT id, sender_device_id, envelope, signature, media_id, created_at
		FROM messages
		WHERE recipient_device_id = $1
		  AND delivered_at IS NULL
		  AND created_at > NOW() - INTERVAL '7 days'
		ORDER BY created_at ASC
		LIMIT 200
	`, deviceID)
	if err != nil {
		log.Debug().Err(err).Str("device", deviceID).Msg("ws: backfill query")
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var (
			id, sender string
			env, sig   []byte
			mediaID    *string
			created    time.Time
		)
		if err := rows.Scan(&id, &sender, &env, &sig, &mediaID, &created); err != nil {
			continue
		}
		ev := ServerEvent{
			Type: "message.recv",
			Data: map[string]any{
				"server_id":        id,
				"sender_device_id": sender,
				"envelope":         base64.StdEncoding.EncodeToString(env),
				"signature":        base64.StdEncoding.EncodeToString(sig),
				"media_id":         mediaID,
				"created_at":       created.UnixMilli(),
				"backfilled":       true,
			},
		}
		if err := h.Publish(ctx, redisx.DeviceChannel(deviceID), ev); err != nil {
			log.Debug().Err(err).Str("device", deviceID).Msg("ws: backfill publish")
		}
		count++
	}
	if count > 0 {
		log.Info().Str("device", deviceID).Int("count", count).Msg("ws: backfilled missed messages")
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
