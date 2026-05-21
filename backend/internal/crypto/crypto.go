// Package crypto holds server-side cryptographic helpers.
//
// The server **never** sees plaintext message bodies. The primitives here are
// used for:
//   * Signing access tokens (Ed25519)
//   * Encrypting at-rest secrets we own (TOTP seeds, refresh tokens)
//   * HMAC-signing pre-signed media URLs
//   * Verifying client envelope signatures (Ed25519) — the server uses this to
//     drop forgeries cheaply, but actual confidentiality is provided by the
//     end-to-end ciphertext.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomBase64 returns a base64url-encoded random token of `byteLen` bytes.
func RandomBase64(byteLen int) (string, error) {
	b, err := RandomBytes(byteLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SHA256 returns the SHA-256 of b.
func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// HMACSHA256 returns the HMAC-SHA-256 of msg with key.
func HMACSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// VerifyEd25519 verifies a signature, returning ErrBadSignature on mismatch.
func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// ErrBadKey signals a malformed key.
var ErrBadKey = errors.New("crypto: bad key")

// ErrBadSignature signals signature verification failure.
var ErrBadSignature = errors.New("crypto: bad signature")

// AESGCMSeal encrypts plaintext with key (must be 32 bytes) using a random
// 12-byte nonce; returns nonce||ciphertext||tag.
func AESGCMSeal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrBadKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// AESGCMOpen reverses AESGCMSeal.
func AESGCMOpen(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrBadKey
	}
	if len(sealed) < 12+16 {
		return nil, fmt.Errorf("crypto: sealed too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}
