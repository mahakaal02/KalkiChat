// Package retention deletes messages and media older than the configured TTL.
//
// Crypto-erasure: for media we delete the wrapped per-blob key row BEFORE
// deleting the S3 blob. Even if a backup copy of the blob exists, it is
// permanently undecryptable the moment the key row is gone.
package retention

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/kalkichat/backend/internal/media"
)

// Config configures the worker.
type Config struct {
	MessageTTL time.Duration
	MediaTTL   time.Duration
	Sweep      time.Duration
}

// Worker performs periodic deletion.
type Worker struct {
	db    *pgxpool.Pool
	rdb   *redis.Client
	store media.Store
	cfg   Config
}

// NewWorker constructs a Worker.
func NewWorker(db *pgxpool.Pool, rdb *redis.Client, store media.Store, cfg Config) *Worker {
	if cfg.Sweep == 0 {
		cfg.Sweep = 60 * time.Second
	}
	return &Worker{db: db, rdb: rdb, store: store, cfg: cfg}
}

// Run blocks until ctx is cancelled. Acquires a Redis lock so only one replica
// performs deletes at a time (leader election by TTL).
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Sweep)
	defer t.Stop()
	log.Info().Dur("sweep", w.cfg.Sweep).Dur("msg_ttl", w.cfg.MessageTTL).
		Dur("media_ttl", w.cfg.MediaTTL).Msg("retention worker started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ok, err := w.acquireLease(ctx); err != nil || !ok {
				continue
			}
			w.sweepOnce(ctx)
		}
	}
}

const leaseKey = "retention:leader"

func (w *Worker) acquireLease(ctx context.Context) (bool, error) {
	ttl := w.cfg.Sweep + 10*time.Second
	return w.rdb.SetNX(ctx, leaseKey, "held", ttl).Result()
}

func (w *Worker) sweepOnce(ctx context.Context) {
	w.purgeMessages(ctx)
	w.purgeMedia(ctx)
	w.purgePrekeys(ctx)
	w.purgeAuth(ctx)
}

// purgeMessages: hard-delete ciphertext older than TTL. Index makes this fast.
func (w *Worker) purgeMessages(ctx context.Context) {
	tag, err := w.db.Exec(ctx, `
		DELETE FROM messages
		WHERE created_at < NOW() - $1::interval
	`, w.cfg.MessageTTL)
	if err != nil {
		log.Error().Err(err).Msg("retention: purge messages")
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Info().Int64("rows", n).Msg("retention: messages deleted")
	}
}

// purgeMedia: crypto-erase first (drop wrapped keys), then delete blobs.
func (w *Worker) purgeMedia(ctx context.Context) {
	rows, err := w.db.Query(ctx, `
		SELECT id, s3_key FROM media_blobs
		WHERE created_at < NOW() - $1::interval
		LIMIT 500
	`, w.cfg.MediaTTL)
	if err != nil {
		log.Error().Err(err).Msg("retention: scan media")
		return
	}
	type ent struct {
		id    string
		s3Key string
	}
	var ents []ent
	for rows.Next() {
		var e ent
		if err := rows.Scan(&e.id, &e.s3Key); err != nil {
			rows.Close()
			log.Error().Err(err).Msg("retention: scan media row")
			return
		}
		ents = append(ents, e)
	}
	rows.Close()

	for _, e := range ents {
		// 1. Crypto-erase: drop ALL wrapped keys for this media.
		if _, err := w.db.Exec(ctx, `DELETE FROM media_keys WHERE media_id = $1`, e.id); err != nil {
			log.Error().Err(err).Str("media", e.id).Msg("retention: drop media keys")
			continue
		}
		// 2. Delete the blob.
		if err := w.store.Delete(ctx, e.s3Key); err != nil {
			log.Warn().Err(err).Str("media", e.id).Msg("retention: delete blob (continuing)")
		}
		// 3. Delete the metadata row.
		if _, err := w.db.Exec(ctx, `DELETE FROM media_blobs WHERE id = $1`, e.id); err != nil {
			log.Error().Err(err).Str("media", e.id).Msg("retention: drop media_blobs row")
			continue
		}
		log.Info().Str("media", e.id).Msg("retention: media erased")
	}
}

// purgePrekeys: consumed OPKs and stale signed prekeys.
func (w *Worker) purgePrekeys(ctx context.Context) {
	_, _ = w.db.Exec(ctx, `
		DELETE FROM one_time_prekeys
		WHERE consumed_at IS NOT NULL AND consumed_at < NOW() - INTERVAL '7 days'
	`)
}

// purgeAuth: refresh tokens & login failures.
func (w *Worker) purgeAuth(ctx context.Context) {
	_, _ = w.db.Exec(ctx, `
		DELETE FROM refresh_tokens
		WHERE (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '30 days')
		   OR expires_at < NOW() - INTERVAL '7 days'
	`)
	_, _ = w.db.Exec(ctx, `
		DELETE FROM login_failures WHERE attempted_at < NOW() - INTERVAL '24 hours'
	`)
}
