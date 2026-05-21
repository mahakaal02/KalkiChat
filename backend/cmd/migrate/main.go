// Package main is a thin CLI around golang-migrate so operators can run
// migrations from a separate Job/Pod in production.
package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/kalkichat/backend/internal/config"
	"github.com/kalkichat/backend/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate up|down|version")
		os.Exit(2)
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}
	switch os.Args[1] {
	case "up":
		if err := db.Migrate(cfg.DatabaseURL, "migrations"); err != nil &&
			err != db.ErrNoChange {
			log.Fatal().Err(err).Msg("migrate up")
		}
	case "version":
		v, err := db.MigrateVersion(cfg.DatabaseURL, "migrations")
		if err != nil {
			log.Fatal().Err(err).Msg("version")
		}
		fmt.Println(v)
	default:
		// We deliberately do not expose `down` — production is forward-only.
		fmt.Fprintln(os.Stderr, "only up|version supported")
		os.Exit(2)
	}
}
