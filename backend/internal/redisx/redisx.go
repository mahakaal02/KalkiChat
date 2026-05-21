// Package redisx wraps go-redis with sane defaults and pub/sub helpers.
package redisx

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Connect opens a redis.Client and pings it.
func Connect(ctx context.Context, url string) (*redis.Client, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	opts.PoolSize = 50
	opts.MinIdleConns = 5
	opts.DialTimeout = 3 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	c := redis.NewClient(opts)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.Ping(pingCtx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return c, nil
}

// DeviceChannel is the per-device delivery channel.
func DeviceChannel(deviceID string) string { return "device:" + deviceID }

// UserChannel echoes a user's own messages across their devices.
func UserChannel(userID string) string { return "user:" + userID }

// AdminTeamChannel fans out to all online admin devices.
const AdminTeamChannel = "team:admins"
