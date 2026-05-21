// Package audit writes append-only audit records.
//
// Audit records NEVER contain message bodies. They contain who-did-what-when.
package audit

import (
	"context"
	"encoding/json"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Recorder appends rows to audit_logs.
type Recorder struct{ DB *pgxpool.Pool }

// Event is a single audit record.
type Event struct {
	ActorKind  string         // "admin" | "system" | "user"
	ActorID    string
	Action     string         // e.g. "user.suspend", "message.reply", "whatsapp_config.update"
	TargetKind string
	TargetID   string
	IP         net.IP
	UserAgent  string
	Metadata   map[string]any // free-form, MUST NOT contain message content
}

// Record persists an event.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	if r == nil || r.DB == nil {
		return nil
	}
	mb, _ := json.Marshal(sanitize(e.Metadata))
	_, err := r.DB.Exec(ctx, `
		INSERT INTO audit_logs
			(actor_kind, actor_id, action, target_kind, target_id, ip, user_agent, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, e.ActorKind, e.ActorID, e.Action, e.TargetKind, e.TargetID, e.IP, e.UserAgent, mb)
	return err
}

// sanitize strips known-sensitive keys from audit metadata as a defence in
// depth. Callers must already not pass message content.
func sanitize(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	const redacted = "<redacted>"
	for _, k := range []string{
		"envelope", "ciphertext", "body", "plaintext", "message",
		"password", "totp_secret", "private_key", "wrapped_key",
	} {
		if _, ok := m[k]; ok {
			m[k] = redacted
		}
	}
	return m
}
