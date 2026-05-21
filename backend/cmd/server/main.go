// Package main launches the KalkiChat API + WebSocket server.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	_ "go.uber.org/automaxprocs"

	"github.com/kalkichat/backend/internal/api"
	"github.com/kalkichat/backend/internal/config"
	"github.com/kalkichat/backend/internal/db"
	"github.com/kalkichat/backend/internal/media"
	"github.com/kalkichat/backend/internal/push"
	"github.com/kalkichat/backend/internal/redisx"
	"github.com/kalkichat/backend/internal/ws"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	log.Logger = log.Output(zerolog.NewConsoleWriter()).
		With().Timestamp().Str("svc", "backend").Logger()

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

	if err := db.Migrate(cfg.DatabaseURL, "migrations"); err != nil &&
		!errors.Is(err, db.ErrNoChange) {
		log.Fatal().Err(err).Msg("migrate")
	}

	rdb, err := redisx.Connect(ctx, cfg.RedisURL)
	if err != nil {
		log.Fatal().Err(err).Msg("connect redis")
	}
	defer rdb.Close()

	store, err := media.NewS3Store(ctx, cfg.S3)
	if err != nil {
		log.Fatal().Err(err).Msg("connect object store")
	}

	pusher := push.New(cfg.Push)

	hub := ws.NewHub(rdb, pool)
	go hub.Run(ctx)

	router := api.NewRouter(api.Deps{
		Cfg:    cfg,
		DB:     pool,
		Redis:  rdb,
		Hub:    hub,
		Media:  store,
		Push:   pusher,
	})

	srv := &http.Server{
		Addr:              cfg.ServerAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Info().Str("addr", cfg.ServerAddr).Msg("listening")
		if err := srv.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("server")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutdown signal received")

	hub.Broadcast(ws.ServerEvent{Type: "server.shutdown",
		Data: map[string]any{"retry_after_ms": 5_000}})

	shutdownCtx, cancelShutdown := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown")
	}
	hub.Close()
	log.Info().Msg("bye")
}
