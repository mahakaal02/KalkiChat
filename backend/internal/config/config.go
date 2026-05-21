// Package config loads configuration from environment variables. Production
// deployments read secrets from a secret manager and inject them as env vars.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the strongly-typed application configuration.
type Config struct {
	ServerAddr    string        `mapstructure:"SERVER_ADDR"`
	PublicBaseURL string        `mapstructure:"PUBLIC_BASE_URL"`
	AllowedOrigins []string

	DatabaseURL string `mapstructure:"DATABASE_URL"`
	RedisURL    string `mapstructure:"REDIS_URL"`

	S3 S3Config

	JWTPrivateKeyPEM string        `mapstructure:"JWT_PRIVATE_KEY_PEM"`
	JWTPublicKeyPEM  string        `mapstructure:"JWT_PUBLIC_KEY_PEM"`
	JWTAccessTTL     time.Duration `mapstructure:"JWT_ACCESS_TTL"`
	JWTRefreshTTL    time.Duration `mapstructure:"JWT_REFRESH_TTL"`

	Argon2 Argon2Config

	TOTPEncKeyHex string `mapstructure:"TOTP_ENC_KEY_HEX"`

	Push PushConfig

	RetentionDays  time.Duration `mapstructure:"RETENTION_DAYS"`
	RetentionSweep time.Duration `mapstructure:"RETENTION_SWEEP_INTERVAL"`
}

// S3Config configures the object storage backend.
type S3Config struct {
	Endpoint       string `mapstructure:"S3_ENDPOINT"`
	Region         string `mapstructure:"S3_REGION"`
	Bucket         string `mapstructure:"S3_BUCKET"`
	AccessKey      string `mapstructure:"S3_ACCESS_KEY"`
	SecretKey      string `mapstructure:"S3_SECRET_KEY"`
	ForcePathStyle bool   `mapstructure:"S3_FORCE_PATH_STYLE"`
}

// Argon2Config configures Argon2id parameters used for password hashing.
type Argon2Config struct {
	MemoryKiB   uint32 `mapstructure:"ARGON2_MEMORY_KIB"`
	Time        uint32 `mapstructure:"ARGON2_TIME"`
	Parallelism uint8  `mapstructure:"ARGON2_PARALLELISM"`
}

// PushConfig configures push notification credentials.
type PushConfig struct {
	FCMServiceAccountJSON string `mapstructure:"FCM_SERVICE_ACCOUNT_JSON"`
	APNSKeyID             string `mapstructure:"APNS_KEY_ID"`
	APNSTeamID            string `mapstructure:"APNS_TEAM_ID"`
	APNSKeyP8Path         string `mapstructure:"APNS_KEY_P8_PATH"`
	APNSTopic             string `mapstructure:"APNS_TOPIC"`
}

// Load reads configuration from the environment.
func Load() (Config, error) {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("SERVER_ADDR", ":8080")
	v.SetDefault("PUBLIC_BASE_URL", "http://localhost:8080")
	v.SetDefault("ALLOWED_ORIGINS", "http://localhost:3000")
	v.SetDefault("JWT_ACCESS_TTL", "15m")
	v.SetDefault("JWT_REFRESH_TTL", "168h")
	v.SetDefault("ARGON2_MEMORY_KIB", 65536)
	v.SetDefault("ARGON2_TIME", 3)
	v.SetDefault("ARGON2_PARALLELISM", 2)
	v.SetDefault("RETENTION_DAYS", "30")
	v.SetDefault("RETENTION_SWEEP_INTERVAL", "60s")
	v.SetDefault("S3_REGION", "us-east-1")
	v.SetDefault("S3_FORCE_PATH_STYLE", true)
	v.SetDefault("APNS_TOPIC", "com.kalkichat.app")

	var c Config
	if err := v.Unmarshal(&c); err != nil {
		return c, fmt.Errorf("unmarshal: %w", err)
	}
	if err := v.Unmarshal(&c.S3); err != nil {
		return c, fmt.Errorf("unmarshal s3: %w", err)
	}
	if err := v.Unmarshal(&c.Argon2); err != nil {
		return c, fmt.Errorf("unmarshal argon2: %w", err)
	}
	if err := v.Unmarshal(&c.Push); err != nil {
		return c, fmt.Errorf("unmarshal push: %w", err)
	}

	// RETENTION_DAYS is a number-of-days; viper parses durations natively only
	// when the value is a Go-formatted string. Allow either form by parsing
	// the int suffix here.
	if rd := v.GetString("RETENTION_DAYS"); rd != "" {
		d, err := time.ParseDuration(rd)
		if err != nil {
			// fall back to integer days
			var days int
			if _, err2 := fmt.Sscanf(rd, "%d", &days); err2 == nil {
				d = time.Duration(days) * 24 * time.Hour
			} else {
				return c, fmt.Errorf("RETENTION_DAYS: %w", err)
			}
		}
		c.RetentionDays = d
	}

	c.AllowedOrigins = splitCSV(v.GetString("ALLOWED_ORIGINS"))

	return c, c.validate()
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
