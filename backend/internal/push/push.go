// Package push sends "wake-up only" push notifications.
//
// Push payloads contain NO message content. They tell the device "something
// arrived; come fetch it over TLS+JWT". This is deliberate — we treat
// Google/Apple as out-of-trust-boundary parties.
package push

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/kalkichat/backend/internal/config"
)

// Pusher delivers wake notifications.
type Pusher struct {
	cfg config.PushConfig
	// fcm / apns clients constructed lazily; omitted here to keep this file
	// vendor-agnostic. In production wire `firebase.google.com/go/v4/messaging`
	// and `github.com/sideshow/apns2`.
}

// New constructs a Pusher.
func New(cfg config.PushConfig) *Pusher { return &Pusher{cfg: cfg} }

// WakeUp sends a content-free notification. Returns nil on success.
//
// The payload is always:
//   { "type": "wake", "msg_id": "<server_id>" }
// — never sender name, never preview.
func (p *Pusher) WakeUp(ctx context.Context, fcmToken, apnsToken, msgID string) error {
	if fcmToken == "" && apnsToken == "" {
		return nil
	}
	// Production implementation:
	//   if fcmToken != "" { sendFCM(ctx, fcmToken, msgID) }
	//   if apnsToken != "" { sendAPNS(ctx, apnsToken, msgID) }
	log.Debug().Str("msg", msgID).Msg("push wake (stub)")
	return nil
}
