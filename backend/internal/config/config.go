// Package config loads configuration from environment variables. Production
// deployments read secrets from a secret manager and inject them as env vars.
//
// We deliberately use plain os.Getenv instead of viper's AutomaticEnv +
// Unmarshal because the latter does not reliably read environment-only
// configuration without explicit BindEnv calls for every key.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the strongly-typed application configuration.
type Config struct {
	ServerAddr     string
	PublicBaseURL  string
	AllowedOrigins []string

	DatabaseURL string
	RedisURL    string

	S3 S3Config

	JWTPrivateKeyPEM string
	JWTPublicKeyPEM  string
	JWTAccessTTL     time.Duration
	JWTRefreshTTL    time.Duration

	Argon2 Argon2Config

	TOTPEncKeyHex string

	Push PushConfig

	RetentionDays  time.Duration
	RetentionSweep time.Duration
}

// S3Config configures the object storage backend.
type S3Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
}

// Argon2Config configures Argon2id parameters used for password hashing.
type Argon2Config struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

// PushConfig configures push notification credentials.
type PushConfig struct {
	FCMServiceAccountJSON string
	APNSKeyID             string
	APNSTeamID            string
	APNSKeyP8Path         string
	APNSTopic             string
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	c := Config{
		ServerAddr:     getEnv("SERVER_ADDR", ":8080"),
		PublicBaseURL:  getEnv("PUBLIC_BASE_URL", "http://localhost:8080"),
		AllowedOrigins: splitCSV(getEnv("ALLOWED_ORIGINS", "http://localhost:3000")),

		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    os.Getenv("REDIS_URL"),

		JWTPrivateKeyPEM: os.Getenv("JWT_PRIVATE_KEY_PEM"),
		JWTPublicKeyPEM:  os.Getenv("JWT_PUBLIC_KEY_PEM"),
		TOTPEncKeyHex:    os.Getenv("TOTP_ENC_KEY_HEX"),

		S3: S3Config{
			Endpoint:       os.Getenv("S3_ENDPOINT"),
			Region:         getEnv("S3_REGION", "us-east-1"),
			Bucket:         os.Getenv("S3_BUCKET"),
			AccessKey:      os.Getenv("S3_ACCESS_KEY"),
			SecretKey:      os.Getenv("S3_SECRET_KEY"),
			ForcePathStyle: getEnvBool("S3_FORCE_PATH_STYLE", true),
		},
		Argon2: Argon2Config{
			MemoryKiB:   getEnvUint32("ARGON2_MEMORY_KIB", 65536),
			Time:        getEnvUint32("ARGON2_TIME", 3),
			Parallelism: getEnvUint8("ARGON2_PARALLELISM", 2),
		},
		Push: PushConfig{
			FCMServiceAccountJSON: os.Getenv("FCM_SERVICE_ACCOUNT_JSON"),
			APNSKeyID:             os.Getenv("APNS_KEY_ID"),
			APNSTeamID:            os.Getenv("APNS_TEAM_ID"),
			APNSKeyP8Path:         os.Getenv("APNS_KEY_P8_PATH"),
			APNSTopic:             getEnv("APNS_TOPIC", "com.kalkichat.app"),
		},
	}

	var err error
	if c.JWTAccessTTL, err = getEnvDuration("JWT_ACCESS_TTL", 15*time.Minute); err != nil {
		return c, err
	}
	if c.JWTRefreshTTL, err = getEnvDuration("JWT_REFRESH_TTL", 168*time.Hour); err != nil {
		return c, err
	}
	if c.RetentionSweep, err = getEnvDuration("RETENTION_SWEEP_INTERVAL", 60*time.Second); err != nil {
		return c, err
	}

	// RETENTION_DAYS accepts either a Go duration ("720h") or a bare integer
	// number-of-days ("30").
	if rd := os.Getenv("RETENTION_DAYS"); rd != "" {
		if d, derr := time.ParseDuration(rd); derr == nil {
			c.RetentionDays = d
		} else if n, perr := strconv.Atoi(rd); perr == nil {
			c.RetentionDays = time.Duration(n) * 24 * time.Hour
		} else {
			return c, fmt.Errorf("RETENTION_DAYS=%q: not a duration or integer", rd)
		}
	} else {
		c.RetentionDays = 30 * 24 * time.Hour
	}

	// Allow JWT PEMs to come from a file path. Multi-line PEMs don't fit
	// cleanly in a .env file, so most operators prefer the file form.
	if path := os.Getenv("JWT_PRIVATE_KEY_PEM_FILE"); path != "" && c.JWTPrivateKeyPEM == "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("read JWT_PRIVATE_KEY_PEM_FILE: %w", err)
		}
		c.JWTPrivateKeyPEM = string(b)
	}
	if path := os.Getenv("JWT_PUBLIC_KEY_PEM_FILE"); path != "" && c.JWTPublicKeyPEM == "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("read JWT_PUBLIC_KEY_PEM_FILE: %w", err)
		}
		c.JWTPublicKeyPEM = string(b)
	}

	return c, c.validate()
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// getEnvUint32 parses an env var as an unsigned 32-bit integer, falling back
// to def if missing, malformed, or out of range. Using ParseUint with a
// bitSize lets gosec see the conversion is bounded and avoids the G115
// integer-overflow warning that a naive uint32(strconv.Atoi(...)) produces.
func getEnvUint32(key string, def uint32) uint32 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return def
}

func getEnvUint8(key string, def uint8) uint8 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 8); err == nil {
			return uint8(n)
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getEnvDuration(key string, def time.Duration) (time.Duration, error) {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("%s=%q: %w", key, v, err)
		}
		return d, nil
	}
	return def, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) validate() error {
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if c.RedisURL == "" {
		return errors.New("REDIS_URL is required")
	}
	if c.S3.Bucket == "" {
		return errors.New("S3_BUCKET is required")
	}
	return nil
}
