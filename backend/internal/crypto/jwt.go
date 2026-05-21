package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// JWTHeader is the standard JOSE header (Ed25519 → alg = "EdDSA").
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// JWTClaims is the application-specific claim set.
type JWTClaims struct {
	Sub      string `json:"sub"`            // device_id
	OwnerID  string `json:"oid"`            // user_id or admin_id
	Owner    string `json:"okind"`          // "user" | "admin"
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	Jti      string `json:"jti"`
	Audience string `json:"aud,omitempty"`
}

// JWTSigner signs and verifies Ed25519 JWTs.
type JWTSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
	ttl  time.Duration
}

// NewJWTSigner constructs a signer from PEM-encoded keys.
func NewJWTSigner(privPEM, pubPEM string, ttl time.Duration) (*JWTSigner, error) {
	priv, err := parsePrivateEd25519(privPEM)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicEd25519(pubPEM)
	if err != nil {
		return nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(SHA256(pub)[:8])
	return &JWTSigner{priv: priv, pub: pub, kid: kid, ttl: ttl}, nil
}

// Sign produces a compact-serialized JWT.
func (s *JWTSigner) Sign(c JWTClaims) (string, error) {
	header := JWTHeader{Alg: "EdDSA", Typ: "JWT", Kid: s.kid}
	if c.Iat == 0 {
		c.Iat = time.Now().Unix()
	}
	if c.Exp == 0 {
		c.Exp = time.Now().Add(s.ttl).Unix()
	}
	if c.Jti == "" {
		j, err := RandomBase64(16)
		if err != nil {
			return "", err
		}
		c.Jti = j
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(c)
	signingInput := b64(hb) + "." + b64(cb)
	sig := ed25519.Sign(s.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify parses, verifies, and returns the claims.
func (s *JWTSigner) Verify(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: bad shape")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad sig encoding: %w", err)
	}
	if !ed25519.Verify(s.pub, []byte(signingInput), sig) {
		return nil, ErrBadSignature
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad claims: %w", err)
	}
	var c JWTClaims
	if err := json.Unmarshal(cb, &c); err != nil {
		return nil, err
	}
	if time.Now().Unix() > c.Exp {
		return nil, errors.New("jwt: expired")
	}
	if time.Now().Unix() < c.Iat-30 {
		return nil, errors.New("jwt: issued in future")
	}
	return &c, nil
}

// JWKS returns a JSON Web Key Set document for /.well-known/jwks.json.
func (s *JWTSigner) JWKS() map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "OKP",
			"crv": "Ed25519",
			"alg": "EdDSA",
			"kid": s.kid,
			"x":   base64.RawURLEncoding.EncodeToString(s.pub),
			"use": "sig",
		}},
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func parsePrivateEd25519(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("jwt: bad private PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("jwt: not Ed25519 private key")
	}
	return priv, nil
}

func parsePublicEd25519(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("jwt: bad public PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("jwt: not Ed25519 public key")
	}
	return pub, nil
}
