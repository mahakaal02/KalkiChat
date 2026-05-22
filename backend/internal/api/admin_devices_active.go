package api

import (
	"net/http"
	"time"
)

// adminDevicesActive returns the set of admin devices that are currently
// considered "addressable" — i.e. the user mobile app should consider
// fanning out a new support message to them. The list is filtered to:
//
//   * owner_kind = 'admin'
//   * revoked_at IS NULL
//   * last_seen_at within the last 24 hours
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
// Auth: bearer JWT (user OR admin). We don't restrict to user-only because
// admin devices may want to enumerate peer devices on the support team
// too in a future multi-admin sync flow.
//
// Privacy: we deliberately do NOT expose admin email, identity keys, or
// any other operator identifier — just the device handles needed for
// E2E routing.
func adminDevicesActive(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cutoff := time.Now().Add(-24 * time.Hour)
		rows, err := d.DB.Query(r.Context(), `
			SELECT id, owner_id, platform, last_seen_at
			FROM devices
			WHERE owner_kind = 'admin'
			  AND revoked_at IS NULL
			  AND last_seen_at >= $1
			ORDER BY last_seen_at DESC
			LIMIT 50
		`, cutoff)
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
