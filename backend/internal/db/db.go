// Package db wraps pgx connection management and migrations.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoChange is re-exported from golang-migrate so callers don't import it.
var ErrNoChange = migrate.ErrNoChange

// Connect opens a pgx pool. Production should set sslmode=verify-full in URL.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// Migrate applies forward migrations from the given directory.
func Migrate(url, dir string) error {
	m, err := migrate.New("file://"+dir, url)
	if err != nil {
		return fmt.Errorf("new migrate: %w", err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// MigrateVersion returns the current schema version.
func MigrateVersion(url, dir string) (uint, error) {
	m, err := migrate.New("file://"+dir, url)
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = m.Close() }()
	v, dirty, err := m.Version()
	if err != nil {
		return 0, err
	}
	if dirty {
		return v, fmt.Errorf("dirty migration at version %d", v)
	}
	return v, nil
}
