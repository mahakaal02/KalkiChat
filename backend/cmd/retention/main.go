// Package main runs the standalone retention worker.
//
// Deleting message ciphertext from Postgres is straightforward; deleting from
// object storage is done via *crypto-erasure*: we drop the wrapped per-blob
// AES key from the database before we delete the blob. Even if a backup of the
// blob exists somewhere, it becomes permanently undecryptable the instant the
// wrapped key vanishes.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/kalkichat/backend/internal/config"
	"github.com/kalkichat/backend/internal/db"
	"github.com/kalkichat/backend/internal/media"
	"github.com/kalkichat/backend/internal/redisx"
	"github.com/kalkichat/backend/internal/retention"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.NewConsoleWriter()).
		With().Timestamp().Str("svc", "retention").Logger()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect postgres")
	}
	defer pool.Close()

	rdb, err := redisx.Connect(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect redis")
	}
	defer rdb.Close()

	store, err := media.NewS3Store(ctx, cfg.S3)
	if err != nil {
		log.Fatal().Err(err).Msg("connect object store")
	}

	w := retention.NewWorker(pool, rdb, store, retention.Config{
		MessageTTL: cfg.RetentionDays * 24 * time.Hour,
		MediaTTL:   cfg.RetentionDays * 24 * time.Hour,
		Sweep:      cfg.RetentionSweep,
	})
	w.Run(ctx)
}
