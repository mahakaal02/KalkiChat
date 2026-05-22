// Package api wires up the HTTP router.
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimid "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/kalkichat/backend/internal/audit"
	"github.com/kalkichat/backend/internal/config"
	"github.com/kalkichat/backend/internal/crypto"
	"github.com/kalkichat/backend/internal/media"
	"github.com/kalkichat/backend/internal/messages"
	"github.com/kalkichat/backend/internal/push"
	"github.com/kalkichat/backend/internal/ws"
)

// Deps bundles router dependencies.
type Deps struct {
	Cfg   config.Config
	DB    *pgxpool.Pool
	Redis *redis.Client
	Hub   *ws.Hub
	Media media.Store
	Push  *push.Pusher
}

// NewRouter builds the chi router.
func NewRouter(d Deps) http.Handler {
	signer, err := crypto.NewJWTSigner(d.Cfg.JWTPrivateKeyPEM, d.Cfg.JWTPublicKeyPEM, d.Cfg.JWTAccessTTL)
	if err != nil {
		// Allow startup in dev without JWT keys; in prod main.go validates these.
		signer = nil
	}
	rec := &audit.Recorder{DB: d.DB}
	msgSvc := &messages.Service{DB: d.DB, Hub: d.Hub, Audit: rec}

	r := chi.NewRouter()
	r.Use(chimid.RequestID)
	r.Use(chimid.RealIP)
	r.Use(chimid.Recoverer)
	r.Use(securityHeaders)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   d.Cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           600,
	}))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	if signer != nil {
		r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, signer.JWKS())
		})
	}

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(httprate.Limit(10, time.Minute,
				httprate.WithKeyFuncs(httprate.KeyByIP)))
			r.Post("/auth/login", authLogin(d, signer))
			r.Post("/auth/refresh", authRefresh(d, signer))
			r.Get("/onboarding/whatsapp-link", onboardingLink(d))
		})

		// Authenticated user/admin routes.
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware(signer))
			r.Post("/auth/logout", authLogout(d))
			r.Post("/auth/change-password", authChangePassword(d))
			// Active admin device pool — user mobile calls this when it
			// has no cached admin device to seal a message to.
			r.Get("/admin-devices/active", adminDevicesActive(d))
			r.Post("/prekeys", prekeysUpload(d))
			r.Get("/prekeys/{device_id}", prekeysFetch(d))
			r.Get("/conversation/me", conversationGet(d))
			r.Post("/conversation/me/messages", messageSend(d, msgSvc))
			r.Post("/media/upload-url", mediaUploadURL(d))
			r.Post("/media/{id}/finalize", mediaFinalize(d))
			r.Get("/media/{id}/download-url", mediaDownloadURL(d))
			r.Get("/ws", wsHandler(d, msgSvc))
		})

		// Admin routes (cookie auth + TOTP).
		r.Route("/admin", func(r chi.Router) {
			r.Post("/auth/login", adminLogin(d))
			r.Post("/auth/totp", adminTOTP(d, signer))
			// Single-shot device registration for the admin companion-
			// device mobile app. Authenticates with email+password+TOTP
			// in the request body and returns a Bearer JWT scoped to a
			// freshly-registered device. Unlike the cookie-based admin
			// web login, this endpoint creates a row in `devices` with
			// owner_kind='admin' so the device is addressable from the
			// user mobile app's prekey/X3DH path and the WS hub's
			// `device:<id>` channel.
			r.Post("/devices/register", adminDeviceRegister(d, signer, rec))
			r.Group(func(r chi.Router) {
				r.Use(adminAuthMiddleware(signer))
				r.Get("/users", adminListUsers(d))
				r.Post("/users", adminCreateUser(d, rec))
				r.Get("/users/{id}", adminGetUser(d))
				r.Post("/users/{id}/suspend", adminSuspendUser(d, rec))
				r.Post("/users/{id}/unsuspend", adminUnsuspendUser(d, rec))
				r.Post("/users/{id}/revoke-sessions", adminRevokeSessions(d, rec))
				r.Get("/users/{id}/conversation", adminGetConversation(d))
				r.Post("/users/{id}/messages", adminSendMessage(d, msgSvc, rec))
				r.Get("/conversations", adminListConversations(d))
				r.Get("/devices", adminListDevices(d))
				r.Post("/devices/{id}/revoke", adminRevokeDevice(d, rec))
				r.Get("/config/whatsapp", adminGetWhatsApp(d))
				r.Put("/config/whatsapp", adminPutWhatsApp(d, rec))
				r.Get("/audit", adminAuditList(d))
				r.Get("/audit.csv", adminAuditCSV(d))
				r.Get("/analytics", adminAnalytics(d))
			})
		})
	})

	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
