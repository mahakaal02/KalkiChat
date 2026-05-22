# KalkiChat — Engineering Context (May 2026)

> A snapshot of where the codebase actually is, why it's shaped the way
> it is, and what the next engineer needs to know to keep building.
> Complementary to [`README.md`](README.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and the per-area docs
> under `docs/`. When this file and any of those disagree, **trust the
> code** and update both.

---

## 1. What KalkiChat is

A 1-to-admin secure messaging platform. End users (`users` table) talk to
an admin/support team via end-to-end encrypted chat. There are no
user-to-user conversations — every conversation has exactly one user and
one or more admin devices on the other side.

The platform is:
- **End-to-end encrypted by default.** The server stores ciphertext +
  signatures, never plaintext.
- **Multi-device aware.** Each owner (user or admin) has 0..N device rows
  with their own identity keys + prekeys.
- **Operationally inspectable.** Admins can suspend users, revoke
  devices, see audit logs, and (when the admin companion-device flow is
  online) read decrypted plaintext on their own device.

There is intentionally **no** federation, public-channel chat,
group-chat, voice/video, or P2P discovery. Everything is mediated by
the server, and the server's only secret-handling responsibility is
JWT signing + TOTP-secret encryption at rest.

---

## 2. Component map

```
                  ┌─────────────────────────────────────────┐
                  │              Backend (Go)               │
                  │     :8080 — chi router, no SSL in dev   │
   user mobile ──▶│  /v1/auth/*, /v1/conversation/*,        │◀── admin mobile
   (Flutter)      │  /v1/prekeys/*, /v1/ws,                 │    (Flutter, companion device)
                  │  /v1/admin/* (cookie OR bearer)         │
                  └────────┬────────────────────────────────┘
                           │                  ▲
                           ▼                  │ HttpOnly cookie
                  ┌──────────────────────────┼────────┐
                  │  Postgres :5432          │        │
                  │  Redis    :6379  (pub/sub for WS) │
                  │  MinIO    :9000  (S3 for media)   │
                  └──────────────────────────────────┘
                           ▲
                           │ Server-side fetch via /api/proxy
                           │ (rewrites /api/proxy/<x> → /v1/<x>)
                  ┌────────┴──────────────────────────┐
                  │      Admin Web (Next.js 14)       │
                  │  :3000  — /login, /users,         │
                  │  /messages, /devices, /audit, …   │
                  └───────────────────────────────────┘
```

### Containers (compose service names ↔ container names)

| Service | Container | Purpose |
|---|---|---|
| `backend` | `kalki-backend-1` | Go API |
| `admin-web` | `kalki-admin-web-1` | Next.js admin |
| `postgres` | `kalki-postgres-1` | Primary DB |
| `redis` | `kalki-redis-1` | WS fan-out pub/sub |
| `minio` | `kalki-minio-1` | S3-compatible media store |
| `minio-init` | `kalki-minio-init-1` | Bucket creator (run-once) |
| `retention` | `kalki-retention-1` | Background sweeper |

`make dev` brings all of them up. Compose file: `deploy/docker-compose.yml`,
env: `.env` at repo root.

---

## 3. Repo layout

```
.
├── backend/               # Go service — internal/api, internal/auth, internal/crypto, ...
├── admin-web/             # Next.js 14 admin dashboard (TypeScript)
├── mobile/                # User mobile app (Flutter)
├── admin-mobile/          # Admin companion-device mobile app (Flutter)
├── packages/
│   └── kalki_crypto/      # Shared Dart package — X3DH, DoubleRatchet, Envelope, IdentityKeys
├── deploy/                # docker-compose.yml, k8s manifests, retention cronjob
├── docs/                  # ARCHITECTURE.md, API.md, THREAT_MODEL.md, etc.
├── Makefile               # make dev / down / logs / migrate / seed-admin / test / lint
└── context.md             # ← you are here
```

The two Flutter apps share `packages/kalki_crypto/` via `path:` deps so
the most security-critical code (Double Ratchet + envelope format)
has exactly one implementation.

---

## 4. End-to-end crypto — the heart of the system

Everything that matters about how a message gets from a user's phone to
an admin's phone runs through this. Read this section before changing
anything in `packages/kalki_crypto/` or either app's chat controller.

### 4.1 Identity material

Each device (user OR admin) generates two keypairs on first launch and
stashes them in the platform's hardware-backed secure storage:

| Key | Bytes | Purpose |
|---|---|---|
| Ed25519 (priv + pub) | 32 + 32 | Long-term identity. Signs envelopes. Used to bind a prekey bundle to an identity. |
| X25519 (priv + pub) | 32 + 32 | Long-term identity. Used in X3DH DH1 (initiator) and DH2 (responder). |

Stored under keys `ed25519_priv`, `ed25519_pub`, `x25519_priv`,
`x25519_pub` in `HardwareKeystore` (mobile) / `AdminHardwareKeystore`
(admin-mobile). Both classes `implements KeyStorage` from
`kalki_crypto`, so `IdentityKeys.initOrLoad(storage)` handles
generation / persistence identically.

**Code**: `packages/kalki_crypto/lib/src/keys.dart`.

### 4.2 Prekey bundles (per device)

Every device uploads (and replenishes) a prekey bundle so others can
start sessions with it while it's offline:

| Item | What | Lifetime |
|---|---|---|
| Signed prekey (SPK) | 1 × X25519 keypair, signed by the device's Ed25519 identity | Months — rotated by uploading a new one |
| One-time prekeys (OPK) | 20 × X25519 keypairs | Each consumed exactly once, then deleted server-side AND client-side |

Server schema: `signed_prekeys(device_id PK, prekey_id, pubkey,
signature, created_at)`, `one_time_prekeys(device_id, prekey_id PK,
pubkey, consumed_at)`. See `backend/migrations/0001_init.up.sql`.

Server endpoints:
- `POST /v1/prekeys` (bearer auth) — uploads SPK (replaces) + batch of OPKs
- `GET /v1/prekeys/{device_id}` (bearer auth) — atomically consumes one OPK
  and returns `{identity_ed25519, identity_x25519, signed_prekey, one_time_prekey?}`

Implementation: `backend/internal/api/prekeys.go`.

### 4.3 X3DH (Extended Triple Diffie-Hellman)

Signal-spec X3DH. Implemented in `packages/kalki_crypto/lib/src/x3dh.dart`.

**Initiator side** (Alice, user-mobile sending first message to admin):
1. Fetch Bob's bundle via `GET /v1/prekeys/{bobDevId}`.
2. Verify `signed_prekey.signature` against `identity_ed25519` —
   `verifySignedPrekey()`. Refuse to send if it fails.
3. Generate ephemeral X25519 keypair `EK_A`.
4. Compute four DH shares:
   - `DH1 = X25519(IK_A_priv, SPK_B_pub)`
   - `DH2 = X25519(EK_A_priv, IK_B_pub)`
   - `DH3 = X25519(EK_A_priv, SPK_B_pub)`
   - `DH4 = X25519(EK_A_priv, OPK_B_pub)` — only if bundle had an OPK
5. `SK = HKDF-SHA256(salt = 0×32, IKM = DH1 ‖ DH2 ‖ DH3 ‖ DH4?,
   info = "KalkiChat-X3DH-v1")` → 32 bytes.

**Responder side** (Bob, admin-mobile receiving a bootstrap envelope):
1. Look up own SPK private + OPK private (by id from the bootstrap header).
2. Run the symmetric DHs against Alice's identity + ephemeral pubs.
3. HKDF produces the same `SK`.
4. **DELETE the OPK row locally** — forward-secrecy requires
   one-time use.

The `info` string is versioned (`v1`) so a future protocol revision can
be domain-separated cleanly without colliding with old sessions.

### 4.4 Double Ratchet

Same `DoubleRatchet` class in `packages/kalki_crypto/lib/src/ratchet.dart`
on both sides. Factories:

- `DoubleRatchet.initiator(sharedSecret, peerSignedPrekey)` — Alice's
  post-X3DH state. Generates a fresh ratchet sending DH, runs one root
  step against Bob's SPK, ready to produce send keys immediately.
- `DoubleRatchet.responder(sharedSecret, signedPrekeyPriv, signedPrekeyPub)`
  — Bob's post-X3DH state. Sending and receive chains are zero until
  Alice's first envelope triggers a `ratchetReceive()` which populates
  both.

Per-message key derivation: `nextSendKey()` / `nextRecvKey()` —
`mk = HMAC(chainKey, [0x01])`, then `chainKey := HMAC(chainKey, [0x02])`.

DH rotation: `ratchetReceive(newPeerPub)` — runs DH(currentSendPriv,
newPeerPub) → recvChainKey, generates a fresh send DH, runs DH again
→ new sendChainKey. The next outbound message carries the new
`ratchetPub` and the peer detects rotation on receive.

Persistence: `toMap()` / `fromMap()`. Stored in `ratchet_state` table
keyed by peer device id on both apps.

### 4.5 Envelope wire format

```
Type 0 — chat (steady-state):
  ver(1) | type=0(1) | senderDev(16) | recipientDev(16)
  ratchetPub(32) | prevChainLen(varint) | msgNumber(varint)
  nonce(12) | ciphertext(N) | tag(16)

Type 1 — bootstrap (first message of a new session):
  [same prefix as type 0, with type=1]
  identityEd25519(32) | identityX25519(32) | ephemeralX25519(32)
  signedPrekeyId(varint) | oneTimePrekeyId(varint, 0 = none used)
  nonce(12) | ciphertext(N) | tag(16)
```

- AAD = `senderDevId || recipientDevId || msgNumber(varint)`
- Cipher = AES-256-GCM
- Signature = Ed25519 over `env.toBytes()`, transmitted alongside

Implementation: `packages/kalki_crypto/lib/src/envelope.dart`.
`Envelope.seal(...)` takes a `sign:` callback (so the package doesn't
import `IdentityKeys`); `Envelope.open(...)` requires only the message
key; `Envelope.verify(...)` checks Ed25519 against a supplied identity
pubkey (for bootstraps, that's the one inside the bootstrap header
itself — trust comes from the X3DH binding, not from blind trust).

### 4.6 Where the X3DH + ratchet flow lives in app code

- **User-mobile send path** (initiator): `mobile/lib/features/chat/chat_controller.dart`
  `sendText()` — resolves peer, loads/bootstraps ratchet, `nextSendKey`,
  `Envelope.seal`, persists advanced ratchet, sends via WS.

- **User-mobile recv path**: `mobile/lib/features/chat/chat_controller.dart`
  `_handleIncoming()` — verifies signature with cached peer identity,
  detects DH rotation, `nextRecvKey`, `Envelope.open`, displays plaintext.

- **Admin-mobile send path**: `admin-mobile/lib/features/chat/admin_chat_controller.dart`
  `sendReply()` — admin-mobile is **responder-only** in v1; only sends
  WITHIN an established session triggered by an inbound bootstrap.

- **Admin-mobile recv path (the X3DH responder side)**:
  `admin-mobile/lib/features/chat/admin_chat_controller.dart`
  `_handleBootstrap()` and `_handleSteadyState()` — runs X3DH responder
  on first incoming, consumes the OPK from local DB (deletes it),
  initializes ratchet, decrypts, persists plaintext.

### 4.7 Test coverage

`packages/kalki_crypto/test/x3dh_roundtrip_test.dart` — 5 tests:

1. Single seal/open round-trip with a known key
2. Full Alice/Bob bootstrap → reply → 3 follow-up messages with DH rotation
3. X3DH without OPK still produces matching shared secrets
4. `verifySignedPrekey` rejects forged signatures
5. `Envelope.verify` rejects tampered ciphertext

Run with `cd packages/kalki_crypto && dart test`.

---

## 5. Backend (Go)

Located in `backend/`. Stack: chi v5 router, pgx/v5 for Postgres, redis
for WS fan-out, zerolog for structured logs, golang-migrate for DB,
argon2id (`alexedwards/argon2id`) for password hashing, Ed25519 JWT
signer (custom — `internal/crypto`).

### 5.1 Schema essentials

Migration source of truth: `backend/migrations/`. Two migration files:

- `0001_init.up.sql` — core tables.
- `0002_admin_user_mgmt.up.sql` — adds `users.must_change_password`.

Key tables:

| Table | What |
|---|---|
| `users` | Login + argon2id hash + status + **must_change_password** |
| `admins` | Email + argon2id + AES-GCM-sealed TOTP secret + role |
| `devices` | `(id, owner_kind ∈ {'user','admin'}, owner_id, identity_ed25519, identity_x25519, …)` |
| `signed_prekeys` | One per device |
| `one_time_prekeys` | Many per device, deleted on consume |
| `conversations` | One per user (`user_id UNIQUE`), admin team is implicit |
| `messages` | `(id, conversation_id, sender_device_id, recipient_device_id, envelope BYTEA, signature BYTEA, client_id)` |
| `refresh_tokens` | Per-device refresh-token family, hash-only |
| `active_sessions` | Server-issued session metadata |
| `audit_logs` | Append-only `(actor_kind, actor_id, action, target_kind, target_id, ip, ua, metadata)` |
| `whatsapp_config` | Admin's WhatsApp deep-link config (id=1) |

The server **never** writes plaintext into `messages` or any other
table. Plaintext lives only on user-owned devices and (per architectural
decision) in a future `admin_plaintext` table for the dashboard sync —
see §8.

### 5.2 API surface (paths only — see `docs/API.md` for full request/response shapes)

**Public:**
- `GET /healthz`
- `GET /.well-known/jwks.json`
- `POST /v1/auth/login` — user mobile sign-in + device registration in one call. Returns Bearer JWT + `must_change_password` flag.
- `POST /v1/auth/refresh`
- `GET /v1/onboarding/whatsapp-link`
- `POST /v1/admin/auth/login` — admin **web** step 1 (email + password). Sets pre-2FA cookie.
- `POST /v1/admin/auth/totp` — admin **web** step 2. Sets `admin_session` cookie.
- `POST /v1/admin/devices/register` — admin **mobile** single-shot (email + password + totp_code + device keys). Returns Bearer JWT. (Added in phase 2.3.)

**Bearer-authenticated (`authMiddleware`):**
- `POST /v1/auth/logout`
- `POST /v1/auth/change-password` (added in PR #4)
- `GET /v1/admin-devices/active` (added in phase 2.4) — for user-mobile to discover where to send
- `POST /v1/prekeys` / `GET /v1/prekeys/{device_id}`
- `GET /v1/conversation/me` / `POST /v1/conversation/me/messages`
- `POST /v1/media/upload-url` / `POST /v1/media/{id}/finalize` / `GET /v1/media/{id}/download-url`
- `GET /v1/ws` — token in `?token=…` query, see `backend/internal/api/ws.go`

**Admin-authenticated (`adminAuthMiddleware` — cookie OR bearer, added in phase 2.5a):**
- `GET /v1/admin/users` / `POST /v1/admin/users` / `GET /v1/admin/users/{id}`
- `POST /v1/admin/users/{id}/suspend|unsuspend|revoke-sessions`
- `GET /v1/admin/users/{id}/conversation` / `POST /v1/admin/users/{id}/messages`
- `GET /v1/admin/conversations` (added in PR #4) — chat-list view
- `GET /v1/admin/devices` / `POST /v1/admin/devices/{id}/revoke`
- `GET|PUT /v1/admin/config/whatsapp`
- `GET /v1/admin/audit` / `GET /v1/admin/audit.csv`
- `GET /v1/admin/analytics`

### 5.3 Auth flows side-by-side

| Flow | Endpoint(s) | Credential | What you get |
|---|---|---|---|
| **User mobile sign-in** | `POST /v1/auth/login` | login + password + device keys | Bearer JWT (owner=user), `must_change_password` |
| **Admin web sign-in** | `POST /v1/admin/auth/login` → `POST /v1/admin/auth/totp` | email + password + TOTP | `admin_session` HttpOnly cookie |
| **Admin mobile sign-in** | `POST /v1/admin/devices/register` (single round-trip) | email + password + TOTP + device keys | Bearer JWT (owner=admin), device row, audit log |

The `adminAuthMiddleware` accepts EITHER cookie OR bearer so admin web
and admin mobile can hit the same admin endpoints.

### 5.4 WebSocket hub

`backend/internal/ws/hub.go` — Redis pub/sub bridges WS clients across
backend instances. Each client subscribes to:
- `device:<deviceId>` — direct messages to that device
- `user:<ownerId>` — fan-out to all devices owned by a user
- `team:admins` — broadcast to all admin devices (used by future
  multi-admin features)

A `messages.Service.Send()` call publishes a `ServerEvent{type:
"message.recv", data:{server_id, sender_device_id, envelope, signature}}`
to `device:<recipientDeviceId>`. That's it — the hub does no
decryption, no fan-out beyond what the sender specified.

### 5.5 Notable backend conventions

- All error responses are `{"error": {"code": "MACHINE_CODE", "message": "…"}}` with stable code strings (`BAD_CREDENTIALS`, `USER_EXISTS`, `PASSWORD_REUSED`, `PRE2FA_REQUIRED`, `BAD_TOTP`, `BAD_KEY`, etc.).
- Audit log: any mutation through an admin route writes a row via `audit.Recorder{DB: d.DB}.Record(ctx, audit.Event{...})`. The `Metadata` map is automatically scrubbed for known sensitive keys.
- `clientIPAddr(r)` and `clientIP(r)` helpers exist in `backend/internal/api/admin.go` and `auth.go` — prefer the former when storing as `net.IP`.

---

## 6. User mobile app (Flutter)

Path: `mobile/`. Routing via `go_router`, state via `flutter_riverpod`,
HTTP via `dio`, secure storage via `flutter_secure_storage`, encrypted
DB via `sqflite_sqlcipher`.

### 6.1 Auth flow

1. Splash → checks if `access_token` is in `HardwareKeystore`. Routes to `/chat` or `/login`.
2. Login screen collects `user_id` + `password`, calls `POST /v1/auth/login` with freshly-generated identity keys in the body (atomic device-registration + sign-in).
3. If response `must_change_password == true`, routes to `/change-password`. That screen is a gate — no back button. Calls `POST /v1/auth/change-password`, then `context.go('/chat')`.

### 6.2 Chat flow (post phase-2.4)

`mobile/lib/features/chat/chat_controller.dart`:

- `sendText(text)`:
  1. Resolve peer admin device (cached in keystore as `admin_device_id`; if absent, `GET /v1/admin-devices/active`, pick most-recent).
  2. `db.loadRatchet(peer)`. If null: fetch bundle → `verifySignedPrekey` → `x3dhInitiate` → `DoubleRatchet.initiator` → stash peer Ed25519 identity in keystore → produce `BootstrapHeader`.
  3. `ratchet.nextSendKey()` → `Envelope.seal(...)` with optional bootstrap header.
  4. `db.saveRatchet(peer, ratchet)` **before** sending — so outbox replay uses the exact envelope, not a re-encrypted one.
  5. Send via WS or enqueue in `outbox` table for later.
- `_handleIncoming(ev)`:
  - Refuses inbound bootstraps (user-mobile is initiator-only in v1).
  - Verifies signature against `peer_ed25519_{deviceId}` from keystore.
  - Detects DH rotation, advances ratchet, decrypts, persists plaintext.

### 6.3 Local DB

`mobile/lib/data/local_db.dart` — SQLCipher AES-256-GCM page encryption,
passphrase generated on first launch and stored in
`HardwareKeystore` under `sqlcipher_pass`. Tables: `messages`,
`ratchet_state`, `outbox`.

### 6.4 Build

```bash
cd mobile && flutter build apk --debug \
  --dart-define=API_BASE=http://10.0.2.2:8080 \
  --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws \
  --dart-define=DEV_ALLOW_HTTP=true \
  --dart-define=SPKI_PIN_PRIMARY=dev-unused \
  --dart-define=SPKI_PIN_BACKUP=dev-unused
```

`10.0.2.2` is the emulator's host-loopback bridge. `DEV_ALLOW_HTTP=true`
disables SSL pinning so the emulator can hit the local non-TLS backend
— must stay false in production builds.

---

## 7. Admin web (Next.js 14)

Path: `admin-web/`. App-router (`src/app/`), Tailwind, server components
for data fetching, client components for forms/dialogs.

### 7.1 The reverse proxy at `/api/proxy/[...path]`

`admin-web/src/app/api/proxy/[...path]/route.ts`. Critical file. It:

- Maps `/api/proxy/<rest>` → `<INTERNAL>/v1/<rest>` (so the browser
  stays version-agnostic).
- Forwards the admin's `admin_session` and `admin_pre2fa` cookies to
  the backend.
- Rewrites Set-Cookie `Path=/v1/...` → `Path=/api/proxy/...` so the
  browser scopes cookies to a path it actually visits.
- Uses `getSetCookie()` so multi-cookie responses don't get comma-joined.

These three behaviours are the ones that, when missing, made the admin
login completely silently broken — see PR #3.

### 7.2 Routes

| Path | Purpose |
|---|---|
| `/login` | Two-stage email+password → TOTP form |
| `/` (dashboard root) | Overview |
| `/users` | List + create-user dialog (PR #4) |
| `/users/[id]` | Per-user detail: devices, conversation, suspend/revoke buttons |
| `/messages` | WhatsApp-style two-pane chat list (PR #4) |
| `/messages/[userId]` | Per-user conversation pane (reuses `ConversationView`) |
| `/devices` | Active device list |
| `/config/whatsapp` | WhatsApp deep-link config |
| `/audit` | Audit log |

### 7.3 The honest "cannot decrypt" state

`ConversationView.tsx` currently shows each message as a
`[ciphertext · N bytes]` chip. The Messages route also shows an
amber banner explaining that decryption needs an admin device with the
matching private key. **This is intentional** — admin web is NOT a
cryptographic endpoint. The architectural decision is documented in §8.

---

## 8. Admin Companion Device Architecture (NEW — phases 1, 2.1–2.5)

The architectural pattern that makes admins able to read user messages
**without** putting Double-Ratchet decryption in a browser.

### 8.1 The problem

Browser-side Double Ratchet is hard to get right, hard to keep in
sync with mobile, and exposes private keys to the largest attack
surface in the stack (the browser). The conventional answer is to
have a "companion device" that's a real mobile app with hardware-
backed keystore + the same crypto library as the user app. The
companion device decrypts locally and pushes plaintext to a sync
service that the dashboard reads.

### 8.2 Pieces shipped (in commit/PR order)

| Commit | Phase | Effect |
|---|---|---|
| `cb7b223` | 1 | Crypto extracted to shared `kalki_crypto` package |
| `ff121f0` | 2.1 | X3DH + bootstrap envelope + ratchet factories + 5 tests |
| `3b0b251` | 2.3 | `POST /v1/admin/devices/register` (single-shot bearer) |
| `38a8c9f` | 2.4 | User-mobile actually encrypts now; `GET /v1/admin-devices/active` |
| `bd35c2d` | 2.5a | Admin-mobile auth flow uses the new endpoint, persists bearer |
| `b01ae6e` | 2.5b | Admin-mobile DB + prekey upload + WS + decrypt + plaintext UI |

All in PR #5 against `main`.

### 8.3 Component diagram (live state)

```
USER MOBILE                  BACKEND                  ADMIN MOBILE
─────────────                ───────                  ──────────────────
"hi support"
  │
  ├─ GET /v1/admin-devices/active ──▶ returns [adev_a, ...]
  ◀──
  ├─ GET /v1/prekeys/adev_a       ──▶ returns bundle (identity + SPK + OPK)
  ◀──
  │  verifySignedPrekey ✓
  │  x3dhInitiate → SK
  │  DoubleRatchet.initiator → ratchet
  │  Envelope.seal(bootstrap=BootstrapHeader{...})
  │
  ├─ WS message.send (type=1 bootstrap) ▶ persist + publish device:adev_a
                                                                  │
                                                                  ▼
                                                       AdminChatController._handleBootstrap:
                                                         consume SPK + OPK privs from local DB
                                                         x3dhResponder → SK (matches user's)
                                                         DoubleRatchet.responder → ratchet
                                                         ratchetReceive(env.ratchetPub)
                                                         nextRecvKey → AES-GCM key
                                                         Envelope.open → plaintext
                                                         persist to local SQLCipher messages
                                                         render in user_detail_screen
```

Reply path is the same in reverse via `sendReply()`, type-0 envelope.

### 8.4 What's deliberately deferred (v2)

| Item | Why deferred |
|---|---|
| **Multi-admin fan-out** | v1 sends to single most-recent admin device. Decision #3 was "fan out to all active"; that's plumbing on top of v1, no protocol change. |
| **Admin-initiated conversations** | Admin-mobile is responder-only. To initiate, it needs the user-mobile responder path + a prekey pool for users. Symmetric work. |
| **Plaintext sync to admin-web dashboard** | Decision #1 was a 30-day-retention `admin_plaintext` table + a `dashboard:<convo>` Redis channel. The pattern is in PR #5's analysis but not yet built. |
| **Independent cryptographer review** | Code follows Signal X3DH rev 1 (2016) by construction. Production deployment with serious-adversary threat model needs a paid review against published test vectors. |
| **Prekey pool replenishment under load** | `lowWaterMark=5, targetPool=20` is hard-coded. Pilot scope is fine; production should drive these from metrics. |

---

## 9. Development setup

### 9.1 Prerequisites

- Go 1.22+ (project uses 1.22, tested on 1.24)
- Flutter 3.24+ (tested 3.44)
- Node 18+ (admin-web)
- Docker Desktop
- Android SDK + emulator (for mobile)

### 9.2 Bring the stack up

```bash
cd ~/Andriod\ App/KalkiChat
make dev                     # docker compose up -d --build everything
```

The backend auto-runs migrations on startup (`backend/cmd/server/main.go`
calls `db.Migrate(...)`). The seeder `make seed-admin` inserts the
default admin if it's not already there.

Default dev credentials:

| Identity | Login | Password | Other |
|---|---|---|---|
| Seeded admin | `admin@kalki.local` | `ChangeMeNow!1` | TOTP secret: `JBSWY3DPEHPK3PXP` |
| Test user alice | `alice` | (from PR #4 testing — auto-generated; check `must_change_password` flow) | created via admin |
| Test user bob | `bob` | `ProvidedByAdmin123` | created via admin |

Generate the current TOTP code:

```bash
python3 -c "import hmac,hashlib,struct,base64,time;s=base64.b32decode('JBSWY3DPEHPK3PXP');c=struct.pack('>Q',int(time.time()//30));h=hmac.new(s,c,hashlib.sha1).digest();o=h[-1]&15;print(f'{(struct.unpack(\">I\",h[o:o+4])[0]&0x7fffffff)%1000000:06d}')"
```

Or provision a real authenticator with:
`otpauth://totp/Kalki:admin@kalki.local?secret=JBSWY3DPEHPK3PXP&issuer=Kalki`.

### 9.3 Common bring-up pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| Admin web shows "login failed" but creds are right | Stale browser cookies from before PR #3 proxy fix | DevTools → Application → Cookies → delete all `localhost:3000` cookies, retry |
| Backend container says `dependency postgres unhealthy` | Container restart race | `make down && make dev` or wait 30s |
| Mobile build fails on AGP 9 | Old crypto plugins | Already fixed in PR #2 (`safe_device` + `screen_protector` replacements) |
| `flutter pub get` fails on `kalki_crypto` | Working dir or path mismatch | The package lives at `packages/kalki_crypto/` relative to repo root. mobile/admin-mobile pubspecs reference `../packages/kalki_crypto` |
| WebSocket can't connect from emulator | `DEV_ALLOW_HTTP` not set | Pass `--dart-define=DEV_ALLOW_HTTP=true` at build time |
| TOTP rejected after a delay | Code expired (30-second windows) | Regenerate just before clicking Verify |

### 9.4 Useful commands

```bash
# Backend logs
docker logs --tail=50 kalki-backend-1 -f

# DB shell
docker exec -it kalki-postgres-1 psql -U kalki -d kalki

# Reset everything
make down && docker volume rm kalki_postgres-data kalki_minio-data && make dev

# Run crypto round-trip tests
cd packages/kalki_crypto && dart test

# Build user APK with dev defines (see §6.4)
# Build admin APK with same defines
cd admin-mobile && flutter build apk --debug \
  --dart-define=API_BASE=http://10.0.2.2:8080 \
  --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws \
  --dart-define=DEV_ALLOW_HTTP=true \
  --dart-define=SPKI_PIN_PRIMARY=dev-unused \
  --dart-define=SPKI_PIN_BACKUP=dev-unused
```

---

## 10. Testing strategy

### 10.1 Cryptography

`packages/kalki_crypto/test/x3dh_roundtrip_test.dart` — 5 tests covering
the full happy path + two adversarial cases. **Run before any change to
x3dh.dart, ratchet.dart, or envelope.dart.** If these break, do not
ship.

```bash
cd packages/kalki_crypto && dart test
```

### 10.2 Backend

`backend/internal/api/messages_test.go` exists but coverage is thin.
The end-to-end testing pattern is `curl` against the live stack —
see §11 for the smoke-test sequence.

### 10.3 Admin web

No automated tests yet. `npx tsc --noEmit` for type-check; ESLint via
`next build`. Phase 2.6 documents an interactive smoke test.

### 10.4 Mobile / admin-mobile

`flutter analyze --no-fatal-infos` is what CI gates on. There's one
known pre-existing `withOpacity` deprecation info in
`mobile/lib/features/chat/chat_screen.dart:151` — not from any recent
PR, harmless.

---

## 11. The interactive smoke test (Phase 2.6)

The end-to-end test for the admin companion device flow. Not automated
because (a) `FLAG_SECURE` blocks `adb screencap` and (b) running both
Flutter apps simultaneously needs two emulators or a managed
package-suffix split.

Sequence:

1. `make dev` — stack up.
2. `~/Library/Android/sdk/emulator/emulator -avd Pixel_9a -no-snapshot-load &` — boot emulator.
3. Build + install **admin** APK (commands in §9.4).
4. Open admin app → sign in `admin@kalki.local` / `ChangeMeNow!1` / current TOTP.
   - Expect: route to `/users`, no error.
   - Verify in DB:
     ```sql
     SELECT id, owner_kind, last_seen_at FROM devices WHERE owner_kind='admin' ORDER BY last_seen_at DESC;
     SELECT prekey_id FROM signed_prekeys WHERE device_id = (... that id ...);
     SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = (... that id ...);
     -- Expect 20 OPKs initially.
     ```
5. Build + install **user** APK (commands in §6.4).
6. Open user app → sign in as alice (or any user the admin created).
7. Send a message in the chat screen.
   - Server-side: `SELECT id, type FROM messages WHERE conversation_id = (...alice's...) ORDER BY created_at DESC LIMIT 1;`
   - One row should exist.
8. Back to admin app → tap into alice's row in /users/<id>. The conversation pane should show alice's message **as plaintext**, not a ciphertext placeholder.
9. Type a reply, send. Switch to user app — reply should arrive decrypted.

If decrypt fails, `adb logcat -d | grep flutter` shows controller-level
error strings designed to be precise: `bootstrap referenced unknown
signed_prekey id N`, `signature invalid from <device_id>`, etc.

---

## 12. PRs / branches state (as of May 2026)

| PR | State | Branch | What's in it |
|---|---|---|---|
| #1 | Merged | `feat/initial-platform` | Initial scaffold |
| #2 | Merged | `feat/mobile-buildable` | Mobile builds on AGP 9 (safe_device, screen_protector) + Flutter native scaffolding |
| #3 | Merged | `fix/admin-login` | Admin web proxy path + cookie scoping fixes |
| #4 | Merged | `feat/admin-user-mgmt-and-messages` (phases A+B) | Admin user creation + force change pw + `/messages` chat list |
| #5 | **Open** | `feat/admin-user-mgmt-and-messages` (phases 1, 2.1, 2.3, 2.4, 2.5a, 2.5b) | Admin Companion Device — the work in §8 |

PR #5 is the active one. Its description is the authoritative phased
plan and includes the manual smoke-test commands.

---

## 13. Security model (current state)

What we trust:
- Each device's hardware-backed keystore (Android Keystore / iOS Keychain)
- The X3DH spec rev 1 (Signal) as a primitive
- argon2id (OWASP 2024 minimum params) for password hashing
- Ed25519 signatures for envelope authenticity
- AES-256-GCM for message confidentiality
- HKDF-SHA256 for chain key derivation

What we explicitly do not trust:
- The server (it sees only ciphertext + signatures + routing metadata)
- The browser (admin web is not a cryptographic endpoint)
- Network transport (mobile uses SPKI pinning in prod; dev disables via `DEV_ALLOW_HTTP`)

Known limitations of the current code:
- **No independent cryptographer review** of the X3DH wiring or ratchet edge cases. Tests cover the happy path + two adversarial cases; out-of-order delivery, future-message keys, and lost-message catch-up are NOT exercised.
- **No replay protection beyond ratchet ordering.** A WebSocket-level replay would advance the ratchet and corrupt subsequent decryption — server's responsibility to deduplicate (`(sender_device_id, client_id)` unique constraint, which exists).
- **OPK exhaustion fallback** is silent (X3DH proceeds with DH1+DH2+DH3 only). That's a real forward-secrecy reduction; the prekey manager replenishes proactively but a server-side rate-limit or "low prekey pool" notification doesn't exist.
- **Identity-key compromise** is not recoverable in v1. There's no "out-of-band identity revocation" flow.

The `docs/THREAT_MODEL.md` file goes deeper.

---

## 14. Known gaps / TODO

Things that aren't broken but should land before a real launch:

| Gap | Severity | Pointer |
|---|---|---|
| Multi-admin fan-out on user-mobile send | Med — single admin device today | `mobile/lib/features/chat/chat_controller.dart` `sendText()` |
| Admin-initiated conversations | Med — admin can only reply | `admin-mobile/lib/features/chat/admin_chat_controller.dart` `sendReply()` |
| Plaintext sync to admin web dashboard | Big v2 — admin web shows ciphertext placeholders | Decision documented in PR #5 (30-day retention `admin_plaintext` table) |
| Rotation of signed prekey on schedule | Med — never rotates today | `admin-mobile/lib/features/chat/prekey_manager.dart` `_generateAndStoreSignedPrekey()` |
| Out-of-order message handling | Low (rare on TCP WebSocket but possible) | `mobile/lib/features/chat/chat_controller.dart` `_handleIncoming()` — currently strict in-order |
| Independent crypto review | Required before serious-adversary deployment | n/a |
| Push notifications when admin offline | UX — not blocking | `backend/internal/push/` exists but not fully wired |
| Conversation reassignment UI | UX — admin web can't transfer support tickets between agents | Tied to plaintext sync work |
| Tests for backend handlers | Hygiene | `backend/internal/api/*_test.go` very thin |
| Migration to a proper monorepo tool (pnpm workspaces / Melos) | DX — current setup is hand-rolled path: deps | n/a |

---

## 15. Hand-off notes for the next engineer

1. **Start with `dart test` in `packages/kalki_crypto/`.** If those 5 tests pass, the cryptographic core is healthy. If they don't, fix that first — nothing else matters.

2. **Don't touch envelope.dart wire format without bumping the `ver` byte.** Forward-compatibility across the user and admin apps depends on it.

3. **The admin web ConversationView showing `[ciphertext · N bytes]` is intentional, not a bug.** It will start rendering plaintext once the v2 plaintext-sync work in §8.4 lands. Don't "fix" it by adding browser-side crypto.

4. **When you change the JWT shape, check both middleware paths** — `authMiddleware` (Bearer) AND `adminAuthMiddleware` (cookie OR Bearer). The latter accepts both since phase 2.5a.

5. **The X25519 private bytes leak narrowly** out of `IdentityKeys` for the X3DH initiator's DH1 (it needs the raw priv, not just a DH callback). Both chat controllers read it from the keystore directly with this comment. If you refactor `IdentityKeys` to expose a `computeDh1ForX3DH()` method, both callsites can migrate to use it.

6. **PR #5 is the live work.** Don't open a new branch off main without first checking if PR #5 has merged — if it hasn't, base off `feat/admin-user-mgmt-and-messages` instead so you don't conflict on `packages/kalki_crypto/`.

7. **Database state is fragile in dev.** `make down` keeps volumes; `docker volume rm kalki_postgres-data` wipes everything. There's no automated dev-data reseed beyond the admin seeder, so test users created during a session vanish on volume reset.

8. **When in doubt, follow the code, not the docs.** This file and `docs/*.md` are best-effort snapshots. The schema in `backend/migrations/`, the protocol in `packages/kalki_crypto/`, and the routes in `backend/internal/api/router.go` are authoritative.

---

*Last updated: 2026-05-22 after PR #5 was opened.*
*Authoritative for the state of the codebase at commit `b01ae6e`.*
