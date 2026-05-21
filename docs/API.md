# HTTP API

Base URL: `https://api.kalkichat.example/v1`

All endpoints require `Authorization: Bearer <jwt>` unless noted.
All responses are JSON; errors follow:

```json
{ "error": { "code": "string", "message": "human", "request_id": "..." } }
```

## Auth

### POST /auth/login
Public.
```json
{ "user_id": "alice42", "password": "...", "device": { "name": "Pixel 8", "platform": "android", "identity_ed25519": "<b64>", "identity_x25519": "<b64>" } }
```
→ `{ "access_token": "...", "refresh_token": "...", "device_id": "...", "expires_in": 900 }`

### POST /auth/refresh
Public (refresh token is the auth).
```json
{ "refresh_token": "..." }
```
→ rotated pair.

### POST /auth/logout
Authed. Revokes current device session.

## Prekeys

### POST /prekeys
Authed.
```json
{
  "signed_prekey": { "id": 17, "pubkey_x25519": "<b64>", "signature_ed25519": "<b64>" },
  "one_time_prekeys": [ { "id": 1, "pubkey_x25519": "<b64>" }, ... ]
}
```

### GET /prekeys/:device_id
Authed. Returns a *one-time-consumed* bundle. The server marks the OPK as
used atomically.

```json
{
  "device_id": "...",
  "identity_ed25519": "<b64>",
  "identity_x25519":  "<b64>",
  "signed_prekey":    { "id": 17, "pubkey": "<b64>", "signature": "<b64>" },
  "one_time_prekey":  { "id": 5, "pubkey": "<b64>" }
}
```

## Conversation

The user has exactly one conversation. Endpoints assume that.

### GET /conversation/me
Authed. Returns conversation metadata + most recent messages (ciphertext).

```json
{
  "conversation_id": "...",
  "messages": [
    { "id": "msg_01HX...", "sender_device_id": "...", "envelope": "<b64>",
      "signature": "<b64>", "media_id": null, "created_at": 1731580000 }
  ],
  "next_cursor": "..."
}
```

### POST /conversation/me/messages
Authed. Used as a fallback when WS is unavailable.
Body identical to `message.send` WS event.

## Media

### POST /media/upload-url
Authed.
```json
{ "size_bytes": 524288, "content_hash_sha256": "<b64>" }
```
→ `{ "media_id": "med_01HX...", "put_url": "https://...", "expires_in": 300 }`

### POST /media/:id/finalize
Authed. Caller posts wrapped keys for each recipient device.
```json
{
  "wrapped_keys": [
    { "recipient_device_id": "...", "kem_pubkey": "<b64>", "wrapped_key": "<b64>", "nonce": "<b64>" }
  ]
}
```

### GET /media/:id/download-url
Authed. Returns a 5-min signed URL and the wrapped key for **this** device.

## Admin

All `/admin/*` require admin auth (session cookie + 2FA verified) and emit
audit logs.

| Method | Path                                | Purpose                                |
| ------ | ----------------------------------- | -------------------------------------- |
| POST   | `/admin/auth/login`                 | Step 1 — password                      |
| POST   | `/admin/auth/totp`                  | Step 2 — TOTP code                     |
| POST   | `/admin/auth/logout`                |                                        |
| GET    | `/admin/users`                      | search, paginate                       |
| GET    | `/admin/users/:id`                  | detail + devices                       |
| POST   | `/admin/users/:id/suspend`          | suspend account                        |
| POST   | `/admin/users/:id/unsuspend`        |                                        |
| POST   | `/admin/users/:id/revoke-sessions`  | force re-login                         |
| GET    | `/admin/users/:id/conversation`     | ciphertext (admin's own device decrypts) |
| POST   | `/admin/users/:id/messages`         | reply (signed by admin device)         |
| GET    | `/admin/devices`                    | active sessions                        |
| POST   | `/admin/devices/:id/revoke`         |                                        |
| GET    | `/admin/config/whatsapp`            | onboarding config                      |
| PUT    | `/admin/config/whatsapp`            | update (audited)                       |
| GET    | `/admin/audit`                      | paginated audit log, CSV export        |
| GET    | `/admin/analytics`                  | counts (no content)                    |

### PUT /admin/config/whatsapp
```json
{ "phone_e164": "+919876543210", "message_template": "Hello, I'd like access to KalkiChat — my preferred user ID is {user_id}" }
```

### GET /onboarding/whatsapp-link
Public, unauthenticated. Returns the current admin onboarding config so the
mobile/web client can build a `wa.me` link without needing API auth.

```json
{
  "phone_e164": "+919876543210",
  "message_template": "Hello...",
  "wa_me_url": "https://wa.me/919876543210?text=Hello..."
}
```

The server URL-encodes the message and constructs `wa_me_url` for clients.

## Rate limits

| Endpoint group       | Per-IP    | Per-device   |
| -------------------- | --------- | ------------ |
| `/auth/login`        | 10/min    | n/a          |
| `/auth/refresh`      | 60/min    | 60/min       |
| `message.send` (WS)  | n/a       | 60/min       |
| `/media/upload-url`  | 30/min    | 30/min       |
| `/admin/*`           | 600/min   | 600/min      |

Exceeding limits returns 429 with `Retry-After`.
