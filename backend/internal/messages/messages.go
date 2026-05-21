// Package messages persists ciphertext envelopes and fans them out.
//
// Plaintext bodies are never seen here. The server's job is integrity check
// (Ed25519 signature) + persist + fan out.
package messages

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kalkichat/backend/internal/audit"
	kcrypto "github.com/kalkichat/backend/internal/crypto"
	"github.com/kalkichat/backend/internal/redisx"
	"github.com/kalkichat/backend/internal/ws"
)

// MaxEnvelopeBytes caps the ciphertext envelope. Larger payloads belong in
// /media and travel as `media_id`, not in-band.
const MaxEnvelopeBytes = 16 * 1024

// SendInput is the application-level input from REST or WS.
type SendInput struct {
	SenderDeviceID    string
	RecipientDeviceID string
	ConversationID    string
	ClientID          string
	Envelope          []byte
	Signature         []byte
	MediaID           *string
}

// Service holds persistent dependencies.
type Service struct {
	DB    *pgxpool.Pool
	Hub   *ws.Hub
	Audit *audit.Recorder
}

// Send validates and persists a ciphertext message, then publishes a
// `message.recv` event on the recipient's Redis channel.
func (s *Service) Send(ctx context.Context, in SendInput) (msgID string, err error) {
	if len(in.Envelope) == 0 || len(in.Envelope) > MaxEnvelopeBytes {
		return "", ErrEnvelopeSize
	}

	// 1. Look up the sender's identity_ed25519 from `devices`, verify signature.
	var senderIdentity []byte
	var revoked *time.Time
	err = s.DB.QueryRow(ctx, `
		SELECT identity_ed25519, revoked_at FROM devices WHERE id = $1
	`, in.SenderDeviceID).Scan(&senderIdentity, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUnknownSender
	}
	if err != nil {
		return "", err
	}
	if revoked != nil {
		return "", ErrSessionRevoked
	}
	if err := kcrypto.VerifyEd25519(ed25519.PublicKey(senderIdentity), in.Envelope, in.Signature); err != nil {
		return "", ErrInvalidSignature
	}

	// 2. Validate recipient is in this conversation.
	var recipExists bool
	err = s.DB.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NULL
		)
	`, in.RecipientDeviceID).Scan(&recipExists)
	if err != nil {
		return "", err
	}
	if !recipExists {
		return "", ErrUnknownRecipient
	}

	// 3. Insert (idempotent on (sender_device_id, client_id)).
	msgID = "msg_" + uuid.NewString()
	_, err = s.DB.Exec(ctx, `
		INSERT INTO messages
			(id, conversation_id, sender_device_id, recipient_device_id,
			 envelope, signature, media_id, client_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (sender_device_id, client_id) DO NOTHING
	`, msgID, in.ConversationID, in.SenderDeviceID, in.RecipientDeviceID,
		in.Envelope, in.Signature, in.MediaID, in.ClientID)
	if err != nil {
		return "", err
	}

	// 4. Publish to the recipient's Redis channel.
	ev := ws.ServerEvent{
		Type: "message.recv",
		Data: map[string]any{
			"server_id":        msgID,
			"sender_device_id": in.SenderDeviceID,
			"envelope":         base64.StdEncoding.EncodeToString(in.Envelope),
			"signature":        base64.StdEncoding.EncodeToString(in.Signature),
			"media_id":         in.MediaID,
			"created_at":       time.Now().UnixMilli(),
		},
	}
	if err := s.Hub.Publish(ctx, redisx.DeviceChannel(in.RecipientDeviceID), ev); err != nil {
		return "", err
	}

	return msgID, nil
}

// Backfill returns messages with id > cursor that target the given device.
// Used after reconnect.
func (s *Service) Backfill(ctx context.Context, recipDevice, afterID string, limit int) ([]Message, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.DB.Query(ctx, `
		SELECT id, sender_device_id, envelope, signature, media_id, created_at
		FROM messages
		WHERE recipient_device_id = $1 AND id > $2
		ORDER BY created_at ASC
		LIMIT $3
	`, recipDevice, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.SenderDeviceID, &m.Envelope, &m.Signature,
			&m.MediaID, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkDelivered sets delivered_at if not already.
func (s *Service) MarkDelivered(ctx context.Context, serverID, deviceID string) error {
	_, err := s.DB.Exec(ctx, `
		UPDATE messages SET delivered_at = NOW()
		WHERE id = $1 AND recipient_device_id = $2 AND delivered_at IS NULL
	`, serverID, deviceID)
	return err
}

// MarkRead sets read_at.
func (s *Service) MarkRead(ctx context.Context, serverID, deviceID string) error {
	_, err := s.DB.Exec(ctx, `
		UPDATE messages SET read_at = NOW()
		WHERE id = $1 AND recipient_device_id = $2 AND read_at IS NULL
	`, serverID, deviceID)
	return err
}

// Message is the persisted record (ciphertext fields are []byte).
type Message struct {
	ID             string
	SenderDeviceID string
	Envelope       []byte
	Signature      []byte
	MediaID        *string
	CreatedAt      time.Time
}

// Errors.
var (
	ErrEnvelopeSize     = errors.New("messages: envelope size out of range")
	ErrInvalidSignature = errors.New("messages: invalid signature")
	ErrUnknownSender    = errors.New("messages: unknown sender device")
	ErrUnknownRecipient = errors.New("messages: unknown recipient device")
	ErrSessionRevoked   = errors.New("messages: session revoked")
)
