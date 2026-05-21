# Architecture

## 1. High-level diagram

```
                     ┌──────────────────────────────────────────────┐
                     │                INTERNET (TLS 1.3)            │
                     └──────────────────────────────────────────────┘
                                          │
                                ┌─────────┴─────────┐
                                │  Cloudflare /     │
                                │  AWS CloudFront   │ ← CDN (signed URLs, short TTL, encrypted blobs)
                                └─────────┬─────────┘
                                          │
                                ┌─────────┴─────────┐
                                │   L7 LB (NLB +    │
                                │   nginx ingress)  │ ← Sticky sessions for WS by user_id hash
                                └─────────┬─────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
       ┌──────┴───────┐           ┌───────┴───────┐           ┌───────┴───────┐
       │  backend-1   │           │   backend-2   │   ...     │  backend-N    │ ← Go (stateless API + WS)
       │  (Go + WS)   │           │   (Go + WS)   │           │  (Go + WS)    │
       └──────┬───────┘           └───────┬───────┘           └───────┬───────┘
              │                           │                           │
              └────────────┬──────────────┴──────────────┬────────────┘
                           │                             │
                  ┌────────┴──────────┐         ┌────────┴─────────┐
                  │ Redis Cluster     │         │   PostgreSQL     │
                  │ (pubsub + cache)  │         │  (primary + RR)  │
                  └───────────────────┘         └──────────────────┘
                           │
                  ┌────────┴──────────┐
                  │ Retention Worker  │ ← Independent deployment
                  │   (cron + Go)     │   30-day cryptographic erasure
                  └───────────────────┘
                           │
                  ┌────────┴──────────┐
                  │  Object storage   │ ← MinIO / S3, SSE-C + client-side AES-GCM
                  └───────────────────┘
```

## 2. Component responsibilities

### Backend (Go)
- REST API for auth, profile, conversation, media metadata, admin ops.
- WebSocket gateway for realtime messaging. One persistent WS per device.
- Redis pub/sub for cross-node delivery (sender on node-A → receiver on node-B).
- Never sees plaintext message bodies. Stores **ciphertext only**.
- Issues short-lived JWTs (15 min) + opaque refresh tokens (rotating, 7-day,
  one-time-use).
- Signs media upload/download URLs (HMAC, 5-min expiry).

### Retention worker
- Separate binary, separate deployment, separate IAM identity.
- Runs every 60s; deletes ciphertext rows older than 30 days.
- Crypto-erases media: deletes the wrapped per-blob key in Postgres before
  the blob itself, so even a stale S3 replica becomes undecryptable instantly.
- Vacuums Postgres (`VACUUM (FULL, ANALYZE)`) on a weekly window to reclaim
  TOAST pages so deleted ciphertext cannot be recovered from heap dumps.

### Mobile (Flutter)
- Holds the device's long-term identity keys (Ed25519 for signing, X25519 for
  ECDH) in **Android Keystore** / **iOS Secure Enclave**.
- Maintains a one-pair-per-conversation Double Ratchet state.
- Encrypts media client-side (AES-256-GCM with a per-blob random key, key
  wrapped to recipient).
- Implements offline outbox with persistent encrypted queue.

### Admin web (Next.js)
- Server-side admin session (HTTP-only, Secure, SameSite=Strict cookie).
- TOTP-based 2FA (RFC 6238) — enforced on every admin login.
- Admin has its own keypair too; replies are encrypted to the user's device(s).

### Admin mobile (Flutter)
- Mirror of admin web, optimized for reply-on-the-go.
- Same crypto core as user app, with admin-only screens.

## 3. Conversation model

There is exactly **one** conversation per user: `user ⇄ "admins" group`. Internally
this is one row in `conversations`. Admins are members of a virtual
"admin team" that fans out messages to any active admin device.

```
user_device ──╮
              ├── conversation_id ──── admin_team
admin_device ─╯
```

A message from a user is encrypted **once per active admin device**. Admin
replies are encrypted to **every active user device** for that user. This is
classic Signal "session-per-device" sender-side fan-out.

## 4. WebSocket event design

All events are JSON, but the `body` of `message` events is **ciphertext**
(base64) that the server never inspects.

```jsonc
// Client → Server: send a message
{
  "type": "message.send",
  "client_id": "uuid-v7-from-device",
  "recipient_device_ids": ["dev_aaa", "dev_bbb"],
  "envelope": {
    "v": 1,
    "ratchet_header": "<base64>",
    "ciphertext": "<base64-aes256gcm>",
    "media_id": null
  },
  "signature": "<base64-ed25519-sig-over-canonical-bytes>"
}

// Server → Client: acknowledge persist
{ "type": "message.ack", "client_id": "...", "server_id": "msg_01HX...", "ts": 1731580000 }

// Server → Client: deliver to recipient device
{ "type": "message.recv", "server_id": "msg_01HX...", "envelope": {...}, "signature": "..." }

// Either direction: typing indicator (server passes through, not stored)
{ "type": "typing", "is_typing": true }

// Server → Client: device session revoked
{ "type": "session.revoked", "reason": "admin_action" }

// Server → Client: forced key rotation
{ "type": "key.rotate", "epoch": 42 }
```

See [docs/WEBSOCKET.md](WEBSOCKET.md) for the full event catalog.

## 5. Scalability sizing — 500k registered / 20k concurrent

### Connection math
- 20k concurrent WS connections.
- Each Go server handles ~10–20k WS comfortably (file descriptors + goroutine
  per conn). Target 8k/server to leave headroom for bursts.
- ⇒ **3 backend nodes** active, autoscale to 6.

### Recommended sizing
| Component         | Instance                       | Count   | Notes                                  |
| ----------------- | ------------------------------ | ------- | -------------------------------------- |
| Backend (API+WS)  | 4 vCPU / 8 GiB                 | 3–6     | HPA on CPU 60% + connection count       |
| Retention worker  | 2 vCPU / 4 GiB                 | 1       | Singleton (leader election via Redis)  |
| PostgreSQL prim   | 8 vCPU / 32 GiB / 500 GB NVMe  | 1       | TLS, encrypted at rest                 |
| PostgreSQL RR     | 8 vCPU / 32 GiB                | 1       | Read replica + standby                 |
| Redis             | 4 vCPU / 16 GiB                | 3 (HA)  | Cluster, AOF every-1s                  |
| Object storage    | MinIO 4-node erasure 4+2       | 4       | Or S3                                  |
| nginx ingress     | 2 vCPU / 4 GiB                 | 2       | Behind cloud LB                         |
| Admin web         | 2 vCPU / 4 GiB                 | 2       | Stateless                              |

### Estimated monthly cost (AWS, on-demand, eu-west-1)

| Item                               | Approx USD / mo |
| ---------------------------------- | --------------- |
| 6 × c7g.xlarge backend             | ~$600           |
| 1 × c7g.large retention            | ~$50            |
| 2 × db.r6g.2xlarge Postgres (HA)   | ~$1,400         |
| 3 × cache.r7g.large Redis          | ~$450           |
| 4 × m7g.large MinIO (50TB EBS)     | ~$1,200         |
| Application LB + NLB               | ~$50            |
| CloudFront 5 TB egress             | ~$400           |
| Logs/metrics (CloudWatch)          | ~$150           |
| **Total**                          | **~$4,300 / mo**|

Costs are illustrative; switching to reserved instances + savings plans drops
this by 35–45%.

### Horizontal scaling strategy
- Backend nodes are **stateless**. Add nodes, register with LB, done.
- WebSocket fan-out via Redis pub/sub: each backend subscribes to channels
  `user:<uid>` and `device:<did>`; senders publish, receivers read.
- Postgres scales vertically up to ~64 vCPU; beyond that, shard by `user_id`
  hash (rarely needed at this scale).
- Sticky sessions on WS by `user_id` cookie hash → minimizes cross-node
  publishes, but messaging still works without stickiness.

### Redis pub/sub architecture
- Each device subscribed to `device:<id>` for direct delivery.
- Each user subscribed to `user:<id>` for cross-device echoes (e.g., a user
  with phone + tablet must see their own sent message on both).
- Admin team subscribed to `team:admins`.
- Channels are ephemeral. Persistence is in Postgres.

### CDN strategy
- Static admin assets (Next.js `_next/static`) served via CDN with immutable
  hashed names.
- Media blobs in object storage are encrypted; CDN distributes the ciphertext
  via **signed URLs** (HMAC-SHA256, expires in 5 min).
- The decryption key lives in Postgres, wrapped to each authorized device.
- Cache policy: `private, max-age=60, must-revalidate`. Short because the
  ciphertext is short-lived (30-day max anyway).

### Encrypted media architecture
1. Sender generates random AES-256 key `K`.
2. Sender encrypts blob: `ct = AES-GCM(K, blob, nonce, aad=blob_id)`.
3. Sender uploads `ct` to S3 via pre-signed PUT.
4. Sender wraps `K` to each recipient device's X25519 public key via HPKE.
5. Wrapped keys + metadata stored in `media` table.
6. Recipient downloads `ct`, fetches its wrapped `K`, unwraps, decrypts.
7. On retention, the row in `media_keys` is deleted **first** → blob becomes
   permanently undecryptable. Then the blob is deleted from S3.
