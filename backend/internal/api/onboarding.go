package api

import (
	"net/http"
	"net/url"
	"strings"
)

// onboardingLink returns the current WhatsApp deep-link configuration.
//
// This endpoint is intentionally PUBLIC and unauthenticated: the user has not
// signed up yet. The response contains:
//   * phone_e164          — the admin's number in E.164 form, no leading "+"
//   * message_template    — pre-filled message
//   * wa_me_url           — fully-formed https://wa.me/<digits>?text=<urlenc>
//
// Per spec we do NOT call the WhatsApp Business API. We just build a deep
// link the client opens. Both clients use the same response, so a config
// change applies instantly.
func onboardingLink(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var phone, msg string
		err := d.DB.QueryRow(r.Context(), `
			SELECT phone_e164, message_template FROM whatsapp_config WHERE id = 1
		`).Scan(&phone, &msg)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "DB", err.Error())
			return
		}
		digits := digitsOnly(phone)
		urlStr := "https://wa.me/" + digits + "?text=" + url.QueryEscape(msg)
		writeJSON(w, http.StatusOK, map[string]any{
			"phone_e164":       phone,
			"message_template": msg,
			"wa_me_url":        urlStr,
		})
	}
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
