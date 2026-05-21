package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

type prekeyUploadReq struct {
	SignedPrekey struct {
		ID        int    `json:"id"`
		Pubkey    string `json:"pubkey_x25519"`
		Signature string `json:"signature_ed25519"`
	} `json:"signed_prekey"`
	OneTimePrekeys []struct {
		ID     int    `json:"id"`
		Pubkey string `json:"pubkey_x25519"`
	} `json:"one_time_prekeys"`
}

// prekeysUpload accepts a signed-prekey + one-time prekey batch.
func prekeysUpload(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFromCtx(r.Context())
		var in prekeyUploadReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_JSON", err.Error())
			return
		}
		spub, _ := base64.StdEncoding.DecodeString(in.SignedPrekey.Pubkey)
		ssig, _ := base64.StdEncoding.DecodeString(in.SignedPrekey.Signature)
		if len(spub) != 32 || len(ssig) != 64 {
			writeErr(w, http.StatusBadRequest, "BAD_KEY", "signed_prekey")
			return
		}
		// Replace signed prekey atomically.
		_, err := d.DB.Exec(r.Context(), `
			INSERT INTO signed_prekeys (device_id, prekey_id, pubkey, signature)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (device_id) DO UPDATE
			SET prekey_id=$2, pubkey=$3, signature=$4, created_at=NOW()
		`, c.Sub, in.SignedPrekey.ID, spub, ssig)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		if len(in.OneTimePrekeys) > 100 {
			writeErr(w, http.StatusBadRequest, "TOO_MANY_OPK", "")
			return
		}
		for _, opk := range in.OneTimePrekeys {
			pub, _ := base64.StdEncoding.DecodeString(opk.Pubkey)
			if len(pub) != 32 {
				writeErr(w, http.StatusBadRequest, "BAD_KEY", "one_time_prekeys")
				return
			}
			_, err := d.DB.Exec(r.Context(), `
				INSERT INTO one_time_prekeys (device_id, prekey_id, pubkey)
				VALUES ($1,$2,$3)
				ON CONFLICT (device_id, prekey_id) DO NOTHING
			`, c.Sub, opk.ID, pub)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "DB", err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// prekeysFetch returns a one-time-consumed bundle for a target device.
// The one-time prekey is marked consumed atomically.
func prekeysFetch(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceID := chi.URLParam(r, "device_id")
		ctx := r.Context()

		tx, err := d.DB.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var idEd, idX []byte
		err = tx.QueryRow(ctx, `
			SELECT identity_ed25519, identity_x25519 FROM devices
			WHERE id=$1 AND revoked_at IS NULL
		`, deviceID).Scan(&idEd, &idX)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "DEVICE_UNKNOWN", "")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		var spkID int
		var spkPub, spkSig []byte
		err = tx.QueryRow(ctx, `
			SELECT prekey_id, pubkey, signature FROM signed_prekeys WHERE device_id=$1
		`, deviceID).Scan(&spkID, &spkPub, &spkSig)
		if err != nil {
			writeErr(w, http.StatusGone, "NO_SIGNED_PREKEY", "")
			return
		}

		var opkRowID int64
		var opkID int
		var opkPub []byte
		err = tx.QueryRow(ctx, `
			SELECT id, prekey_id, pubkey FROM one_time_prekeys
			WHERE device_id=$1 AND consumed_at IS NULL
			ORDER BY id ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		`, deviceID).Scan(&opkRowID, &opkID, &opkPub)
		hasOPK := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		if hasOPK {
			_, err = tx.Exec(ctx, `
				UPDATE one_time_prekeys SET consumed_at = NOW() WHERE id = $1
			`, opkRowID)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "DB", err.Error())
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}

		out := map[string]any{
			"device_id":        deviceID,
			"identity_ed25519": base64.StdEncoding.EncodeToString(idEd),
			"identity_x25519":  base64.StdEncoding.EncodeToString(idX),
			"signed_prekey": map[string]any{
				"id":        spkID,
				"pubkey":    base64.StdEncoding.EncodeToString(spkPub),
				"signature": base64.StdEncoding.EncodeToString(spkSig),
			},
		}
		if hasOPK {
			out["one_time_prekey"] = map[string]any{
				"id":     opkID,
				"pubkey": base64.StdEncoding.EncodeToString(opkPub),
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}
