package api

import (
	"net/http"
	"time"
)

// adminDevicesActive returns the set of admin devices the user mobile app
// can address when sending a new support message. We deliberately do NOT
// filter on `last_seen_at` — an offline admin device is still a valid
// envelope recipient. The message will sit in the `messages` table (and on
// the admin device's Redis backfill stream) until admin-mobile reconnects
// and drains it.
//
// Filter:
//   * owner_kind = 'admin'
//   * revoked_at IS NULL
//
// We do still surface `last_seen_at` in the response so the user app can
// optionally prefer the most-recently-seen device when fanning out, but
// it's an ordering hint, not a hard cutoff.
//
// Each row carries the minimum the caller needs to start an X3DH session:
//   {
//     "device_id":       "dev_…",
//     "admin_id":        "adm_…",
//     "last_seen_at":    "2026-05-22T13:37:01Z",
//     "platform":        "ios"
//   }
//
// The caller will then fetch the prekey bundle for the device(s) it wants
// to seal to via the existing GET /v1/prekeys/{device_id} endpoint.
//
// Auth: bearer JWT (user OR admin).
//
// Privacy: we deliberately do NOT expose admin email, identity keys, or
// any other operator identifier — just the device handles needed for
// E2E routing.
func adminDevicesActive(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, owner_id, platform, last_seen_at
			FROM devices
			WHERE owner_kind = 'admin'
			  AND revoked_at IS NULL
			ORDER BY last_seen_at DESC
			LIMIT 50
		`)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0)
		for rows.Next() {
			var (
				deviceID, adminID, platform string
				lastSeen                    time.Time
			)
			if err := rows.Scan(&deviceID, &adminID, &platform, &lastSeen); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"device_id":    deviceID,
				"admin_id":     adminID,
				"platform":     platform,
				"last_seen_at": lastSeen,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": out})
	}
}
