# Security Architecture

## 1. Cryptographic primitives

| Purpose                          | Algorithm                          | Library                     |
| -------------------------------- | ---------------------------------- | --------------------------- |
| Symmetric AEAD                   | AES-256-GCM                        | BoringSSL / libsodium       |
| Asymmetric (key exchange)        | X25519                             | libsodium                   |
| Signing                          | Ed25519                            | libsodium                   |
| KDF                              | HKDF-SHA-256                       | golang.org/x/crypto/hkdf    |
| Password hashing                 | Argon2id (m=64MB, t=3, p=2)        | github.com/matthewhartstonge |
| TOTP                             | RFC 6238, SHA-1, 30s, 6 digits     | github.com/pquerna/otp      |
| Random                           | OS CSPRNG (`crypto/rand`)          | stdlib                      |
| TLS                              | TLS 1.3 only (cipher suites locked)| Go stdlib + rustls (nginx)  |

> **Forbidden**: MD5, SHA-1 (except TOTP per RFC), RC4, DES/3DES, ECB,
> non-AEAD symmetric ciphers, RSA <3072 (we don't use RSA at all),
> SHA-1 signatures, custom crypto.

## 2. Identity & device model

Every install registers a **device**. A user may have multiple devices.

```
user
 ├── auth password (Argon2id)
 └── devices
      ├── device_id (uuid v7)
      ├── identity_pubkey_ed25519  ← long-term, in Keystore/Secure Enclave
      ├── identity_pubkey_x25519   ← long-term, derived once at install
      ├── signed_prekey (rotated weekly)
      └── one-time prekeys (10 published, refilled)
```

The private halves **never leave the secure hardware**. On Android we use the
`StrongBox` keystore when present, otherwise TEE-backed AndroidKeyStore. On
iOS we use the Secure Enclave for the Ed25519 identity key (P-256 alternative
when SE is present; we standardize on X25519 in software-backed Keychain when
SE is absent — documented in code).

## 3. Session establishment (X3DH-style)

When user-device `A` sends its first message to admin-device `B`:

1. `A` fetches `B`'s identity pubkey, signed prekey, and an unused one-time
   prekey from the server's prekey bundle.
2. `A` verifies the Ed25519 signature on `B`'s signed prekey.
3. `A` computes:
   - `DH1 = X25519(IK_A, SPK_B)`
   - `DH2 = X25519(EK_A, IK_B)`
   - `DH3 = X25519(EK_A, SPK_B)`
   - `DH4 = X25519(EK_A, OPK_B)`
   - `SK = HKDF-SHA256(DH1 || DH2 || DH3 || DH4, salt=0, info="KalkiChat-X3DH-v1")`
4. `SK` seeds a **Double Ratchet** chain between `A` and `B`.
5. The one-time prekey is deleted server-side immediately after fetch.

## 4. Double Ratchet

Provides:
- **Forward secrecy**: compromise of current state cannot decrypt past
  messages.
- **Post-compromise security (future secrecy)**: after one round-trip,
  compromise of an old state cannot decrypt new messages.

Each direction has its own chain key, advanced by HKDF on each message. A new
DH ratchet step happens whenever the other side responds. Message keys are
derived per-message and immediately destroyed after use.

## 5. Message envelope (wire format)

```
Envelope (binary, then base64-armored on JSON wire):

| ver:1 | type:1 | sender_dev_id:16 | recipient_dev_id:16 |
| ratchet_dh_pub:32 | prev_chain_len:varint | message_number:varint |
| nonce:12 | ciphertext:N | tag:16 |
| signature:64 (Ed25519 over all preceding bytes)         |
```

- AEAD AD includes `sender_dev_id || recipient_dev_id || message_number` →
  replay across conversations or out-of-order replays are rejected.
- Server validates only the envelope **shape** and the **Ed25519 signature**
  against the sender's published identity key. Ciphertext is opaque to the
  server.

## 6. Replay protection
- AD binds message number; recipient maintains a sliding window (last 1024
  message numbers) per chain and rejects duplicates.
- Server logs `(sender_device, message_number, server_id)` and rejects a
  second send with the same `(sender_device, client_id)`.

## 7. Integrity
- Every envelope is Ed25519-signed by the sender device.
- Receiver verifies before decryption. Bad signatures are dropped and reported
  via a `security.alert` event to the user.

## 8. Local storage

Mobile clients store:
- **Identity & ratchet state** → Keystore / Secure Enclave (or a key wrapped
  by hardware).
- **Encrypted SQLite DB** (`sqlcipher` for Flutter via `sqflite_sqlcipher`)
  with a per-install passphrase wrapped in hardware. Cipher: AES-256-GCM,
  PBKDF2-SHA512 200k iterations on first unlock.
- **Image cache** → encrypted with the same wrapped key, never as plaintext
  in app-private storage.

## 9. Server storage

| Table              | Stores             | Plaintext? |
| ------------------ | ------------------ | ---------- |
| users              | id, login, argon2  | n/a        |
| devices            | pubkeys, fcm token | pubkeys ok |
| prekeys            | X25519 pubkeys     | pubkeys ok |
| messages           | ciphertext envelope| **NO**     |
| media_blobs        | S3 path, blob_id   | path only  |
| media_keys         | wrapped K per dev  | wrapped    |
| audit_logs         | actor, event, meta | no msg body|

The Postgres backup procedure uses `pg_dump` with `--no-large-object` and the
output is encrypted with `age` to a backup public key before leaving the host.

## 10. Auto-destruction (30-day)

Three layers; all must succeed.

1. **Database**: `retention_worker` deletes `messages WHERE created_at <
   NOW() - INTERVAL '30 days'` every 60s. Index on `created_at` makes this
   O(log n). On weekly maintenance, `VACUUM FULL` reclaims TOAST pages.
2. **Object storage**: `media_keys` row is deleted **before** the S3 blob.
   Then the blob is deleted via `s3:DeleteObject`. Versioning + MFA-delete
   prevents accidental ghost copies. **Crypto-erasure** guarantees that even
   if a backup copy of the blob exists, it is permanently undecryptable.
3. **Device**: Each client runs a `RetentionDaemon` (foreground service /
   background task) that scans local SQLite at app launch and every 6h, and
   deletes anything older than 30 days. Hard-deletes rows; on commit it runs
   `VACUUM` (sqlcipher rewrites pages, which prevents undelete from raw FS).

CDN cache headers force-revalidation, so a deleted blob returns 403 within
60s of deletion regardless of edge cache.

## 11. Key rotation

- Signed prekey: rotates every 7 days, old key kept for 30 days for
  late-arriving messages, then destroyed.
- One-time prekeys: consumed once, then deleted. Client refills below
  threshold (10 remaining).
- Identity keys: rotated on device re-enrollment or admin-forced rotation
  via `key.rotate` event.
- Session tokens: 15-min JWT + rotating refresh; refresh tokens are
  one-time-use, stored hashed in DB.

## 12. SSL pinning

- Pinned to the **SPKI SHA-256 hash** of the leaf cert *and* a backup
  intermediate, both fetched at build time and embedded in the binary.
- Pin failures trigger immediate disconnect + alert; no soft-fail.
- Both pins must be present so we can rotate the leaf without bricking
  installed apps.

## 13. Root / jailbreak detection

- Multiple signals OR'd together. Any positive → app refuses to run and shows
  a security screen.
  - Android: `flutter_jailbreak_detection`, presence of `su`, Magisk paths,
    Frida/Xposed hooks, `ro.debuggable=1`, ADB on production builds.
  - iOS: presence of `/Applications/Cydia.app`, `/private/var/lib/apt`,
    sandbox escape probe (writing to `/private/`), suspicious dyld libs,
    `_MSHookFunction` symbol present.
- Detection is **defense-in-depth**, not authoritative. Server still enforces
  all access control.

## 14. Screenshot / screen-recording blocking

- Android: `FLAG_SECURE` set on the chat activity. Disables screenshots,
  screen recording (including third-party tools that use MediaProjection),
  and the app preview in the recents view (shows a blank tile).
- iOS: monitor `UIApplication.didEnterBackgroundNotification` and overlay a
  blur view. Detect `UIScreen.main.isCaptured` and blank the chat when
  screen recording starts.

## 15. Clipboard blocking

- All `Text` widgets on the chat screen use a custom `SelectionControls` that
  removes Copy / Paste / Cut / Share entries from the toolbar.
- Long-press is intercepted; copy keyboard shortcuts on physical keyboards
  raise a security event and clear the buffer.

## 16. Token rotation
- Access JWT: HS256? **No** — RS256 with rotating Ed25519 server keys, JWKs
  exposed at `/.well-known/jwks.json`. 15-min TTL.
- Refresh token: 256-bit random, stored as SHA-256 hash in DB. On each use,
  rotated; old hash deleted. Replay of an old refresh token triggers
  `family_revoke` — all tokens for that device family are invalidated and the
  user is forced to re-auth.

## 17. SQL injection protection

- All DB calls go through `sqlx` named parameters or `pgx` query args.
- A pre-commit hook (`gitleaks` + custom `find-rawsql.sh`) rejects PRs that
  use `fmt.Sprintf` to build SQL.
- A repository-level lint check (`go vet -vettool=$(which sqlclosecheck)`)
  runs in CI.

## 18. Hardened HTTP

| Header                          | Value                                    |
| ------------------------------- | ---------------------------------------- |
| Strict-Transport-Security       | `max-age=63072000; includeSubDomains; preload` |
| Content-Security-Policy         | `default-src 'none'; ... frame-ancestors 'none'` |
| X-Content-Type-Options          | `nosniff`                                |
| Referrer-Policy                 | `no-referrer`                            |
| Permissions-Policy              | `camera=(), microphone=(), geolocation=()` |
| X-Frame-Options                 | `DENY`                                   |
| Cross-Origin-Opener-Policy      | `same-origin`                            |
| Cross-Origin-Embedder-Policy    | `require-corp`                           |

## 19. Push notifications — what we don't leak

The FCM/APNs payload is **only**:

```json
{ "type": "wake", "msg_id": "01HX..." }
```

There is **no** message body, **no** sender name, **no** preview. On wake,
the app fetches the encrypted envelope from the server over TLS and decrypts
locally. Even an attacker with full FCM/APNs visibility (e.g., Google, Apple,
or someone with the FCM server key) learns only that *something* arrived for
that token at that time.

## 20. Audit logging

Every admin action emits an audit event:

- Actor (`admin_id`)
- Action (`message.reply`, `user.suspend`, `whatsapp_config.update`, ...)
- Target (`user_id` / `device_id`)
- Timestamp, source IP, user-agent
- **No message content**, ever.

Audit logs are append-only (Postgres `pgaudit`-style trigger) and exportable
to CSV. They are retained for 1 year (separate retention policy from messages).
