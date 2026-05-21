package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxMediaSize is the per-blob ciphertext cap (≈ plaintext + 28 bytes).
const MaxMediaSize int64 = 10 * 1024 * 1024

type uploadReq struct {
	SizeBytes        int64  `json:"size_bytes"`
	ContentHashSHA256 string `json:"content_hash_sha256"`
}

func mediaUploadURL(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		var in uploadReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		if in.SizeBytes <= 0 || in.SizeBytes > MaxMediaSize {
			writeErr(w, http.StatusBadRequest, "PAYLOAD_TOO_LARGE", "")
			return
		}
		hash, err := base64.StdEncoding.DecodeString(in.ContentHashSHA256)
		if err != nil || len(hash) != 32 {
			writeErr(w, http.StatusBadRequest, "BAD_HASH", "")
			return
		}
		mediaID := "med_" + uuid.NewString()
		s3Key := "blobs/" + mediaID[:2] + "/" + mediaID
		_, err = d.DB.Exec(r.Context(), `
			INSERT INTO media_blobs
				(id, s3_key, size_bytes, content_hash_sha256, uploader_device_id)
			VALUES ($1,$2,$3,$4,$5)
		`, mediaID, s3Key, in.SizeBytes, hash, c.Sub)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		url, err := d.Media.PresignPut(r.Context(), s3Key, in.SizeBytes, 5*time.Minute)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"media_id":   mediaID,
			"put_url":    url,
			"expires_in": 300,
		})
	}
}

type finalizeReq struct {
	WrappedKeys []struct {
		RecipientDeviceID string `json:"recipient_device_id"`
		KEMPubKey         string `json:"kem_pubkey"`
		WrappedKey        string `json:"wrapped_key"`
		Nonce             string `json:"nonce"`
	} `json:"wrapped_keys"`
}

func mediaFinalize(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mediaID := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())
		var in finalizeReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		var uploader string
		err := d.DB.QueryRow(r.Context(), `
			SELECT uploader_device_id FROM media_blobs WHERE id = $1
		`, mediaID).Scan(&uploader)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "MEDIA_UNKNOWN", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		if uploader != c.Sub {
			writeErr(w, http.StatusForbidden, "NOT_OWNER", "")
			return
		}
		tx, err := d.DB.Begin(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		for _, k := range in.WrappedKeys {
			kem, _ := base64.StdEncoding.DecodeString(k.KEMPubKey)
			wk, _ := base64.StdEncoding.DecodeString(k.WrappedKey)
			nonce, _ := base64.StdEncoding.DecodeString(k.Nonce)
			if len(kem) != 32 || len(wk) == 0 || len(nonce) < 12 {
				writeErr(w, http.StatusBadRequest, "BAD_KEY", "")
				return
			}
			_, err := tx.Exec(r.Context(), `
				INSERT INTO media_keys (media_id, recipient_device_id, wrapped_key, nonce, kem_pubkey)
				VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (media_id, recipient_device_id) DO NOTHING
			`, mediaID, k.RecipientDeviceID, wk, nonce, kem)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "DB", err.Error())
				return
			}
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func mediaDownloadURL(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mediaID := chi.URLParam(r, "id")
		c := claimsFromCtx(r.Context())

		var s3Key string
		var wrapped, nonce, kem []byte
		err := d.DB.QueryRow(r.Context(), `
			SELECT b.s3_key, k.wrapped_key, k.nonce, k.kem_pubkey
			FROM media_blobs b
			JOIN media_keys  k ON k.media_id = b.id
			WHERE b.id = $1 AND k.recipient_device_id = $2
		`, mediaID, c.Sub).Scan(&s3Key, &wrapped, &nonce, &kem)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "MEDIA_OR_KEY_GONE", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		url, err := d.Media.PresignGet(r.Context(), s3Key, 5*time.Minute)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "SIGN", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"get_url":     url,
			"expires_in":  300,
			"wrapped_key": base64.StdEncoding.EncodeToString(wrapped),
			"nonce":       base64.StdEncoding.EncodeToString(nonce),
			"kem_pubkey":  base64.StdEncoding.EncodeToString(kem),
		})
	}
}
