package auth

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	kcrypto "github.com/kalkichat/backend/internal/crypto"
)

// TOTPGenerate creates a new shared secret + provisioning URI for QR code.
func TOTPGenerate(issuer, account string) (secretBase32, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // per RFC 6238
		SecretSize:  20,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// TOTPVerify validates a code against a base32 secret. Allows one step of
// clock skew on each side.
func TOTPVerify(secretBase32, code string) bool {
	ok, _ := totp.ValidateCustom(code, secretBase32, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return ok
}

// TOTPSealedSecret encrypts a base32 TOTP secret with AES-GCM for at-rest storage.
func TOTPSealedSecret(encKey []byte, secretBase32 string) ([]byte, error) {
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32); err != nil {
		return nil, errors.New("totp: secret not base32")
	}
	return kcrypto.AESGCMSeal(encKey, []byte(secretBase32), []byte("totp"))
}

// TOTPOpenSealed reverses TOTPSealedSecret.
func TOTPOpenSealed(encKey, sealed []byte) (string, error) {
	pt, err := kcrypto.AESGCMOpen(encKey, sealed, []byte("totp"))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ConstantTimeCodeEq compares two TOTP codes in constant time.
func ConstantTimeCodeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
