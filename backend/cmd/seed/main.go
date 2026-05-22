// Package main is a dev-only seeder: inserts (or upserts) a single admin
// account into the database with an Argon2id password hash and an AES-GCM-
// encrypted TOTP secret.
//
//	go run ./cmd/seed \
//	  -email admin@kalki.local \
//	  -password 'change-me-now' \
//	  -totp JBSWY3DPEHPK3PXP
//
// On success, prints the TOTP otpauth:// URI so you can scan it into Google
// Authenticator / 1Password / Authy. DO NOT use this in production — production
// admins are provisioned via a separate process with a proper UI.
package main

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/kalkichat/backend/internal/auth"
	"github.com/kalkichat/backend/internal/config"
	"github.com/kalkichat/backend/internal/db"
)

func main() {
	var (
		email    = flag.String("email", "admin@kalki.local", "admin email")
		password = flag.String("password", "ChangeMeNow!1", "admin password")
		totpSec  = flag.String("totp", "JBSWY3DPEHPK3PXP", "TOTP base32 secret (or 'auto' to generate)")
		role     = flag.String("role", "super_admin", "admin|super_admin")
	)
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	encKey, err := hex.DecodeString(cfg.TOTPEncKeyHex)
	if err != nil || len(encKey) != 32 {
		log.Fatalf("TOTP_ENC_KEY_HEX must be 64 hex chars (32 bytes)")
	}

	// Resolve TOTP secret: 'auto' generates a fresh one, otherwise validate it.
	secret := *totpSec
	if secret == "auto" {
		k, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "KalkiChat",
			AccountName: *email,
			Period:      30,
			Digits:      otp.DigitsSix,
			Algorithm:   otp.AlgorithmSHA1,
			SecretSize:  20,
		})
		if err != nil {
			log.Fatalf("generate TOTP: %v", err)
		}
		secret = k.Secret()
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		log.Fatalf("TOTP secret must be base32 (no padding)")
	}

	hash, err := auth.Argon2idParams{
		Memory:      cfg.Argon2.MemoryKiB,
		Iterations:  cfg.Argon2.Time,
		Parallelism: cfg.Argon2.Parallelism,
	}.Hash(*password)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	sealed, err := auth.TOTPSealedSecret(encKey, secret)
	if err != nil {
		log.Fatalf("seal TOTP: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(cfg.DatabaseURL, "migrations"); err != nil && err != db.ErrNoChange {
		log.Fatalf("migrate: %v", err)
	}

	id := "adm_" + uuid.NewString()
	_, err = pool.Exec(ctx, `
		INSERT INTO admins (id, email, password_hash, totp_secret_enc, role)
		VALUES ($1, LOWER($2), $3, $4, $5)
		ON CONFLICT (email) DO UPDATE
		   SET password_hash = EXCLUDED.password_hash,
		       totp_secret_enc = EXCLUDED.totp_secret_enc,
		       role = EXCLUDED.role
	`, id, *email, hash, sealed, *role)
	if err != nil {
		log.Fatalf("insert admin: %v", err)
	}

	otpauth := buildOtpauth(*email, secret)
	fmt.Fprintln(os.Stderr, "---")
	fmt.Fprintln(os.Stderr, "Seeded admin:")
	fmt.Fprintln(os.Stderr, "  email:        ", *email)
	fmt.Fprintln(os.Stderr, "  password:     ", *password)
	fmt.Fprintln(os.Stderr, "  totp secret:  ", secret)
	fmt.Fprintln(os.Stderr, "  otpauth URI:  ", otpauth)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Add to your authenticator app. Then sign in at http://localhost:3000")
}

func buildOtpauth(account, secret string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/KalkiChat:" + account,
	}
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", "KalkiChat")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u.RawQuery = q.Encode()
	return u.String()
}
