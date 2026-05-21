// Package auth handles user/admin authentication: passwords, sessions, refresh
// tokens, and TOTP.
package auth

import (
	"errors"

	"github.com/alexedwards/argon2id"
)

// Argon2idParams holds Argon2id tuning. Defaults are minimum recommended by
// OWASP 2024: m=64MiB, t=3, p=2, salt=16, key=32.
type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// Hash returns a PHC-formatted Argon2id hash.
func (p Argon2idParams) Hash(password string) (string, error) {
	if len(password) < 10 || len(password) > 1024 {
		return "", ErrPasswordPolicy
	}
	params := &argon2id.Params{
		Memory:      p.Memory,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
		SaltLength:  16,
		KeyLength:   32,
	}
	return argon2id.CreateHash(password, params)
}

// Verify checks password against PHC-formatted hash. Constant time inside.
func Verify(password, hash string) (bool, error) {
	ok, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// ErrPasswordPolicy is returned when a password is too short/long.
var ErrPasswordPolicy = errors.New("auth: password must be 10-1024 characters")
