# What's left to actually run the messaging platform

Status snapshot (this branch):

| Component | Build | Runs | What's missing                                                              |
| --- | --- | --- | --- |
| **Backend (Go)**        | ✅ | ✅ | nothing critical for dev; prod hardening listed below                       |
| **Postgres / Redis / MinIO** | ✅ | ✅ | nothing                                                                   |
| **Admin web (Next.js)** | ✅ | ✅ | full UI flow works once you sign in                                         |
| **Retention worker**    | ✅ | ✅ | nothing for dev                                                             |
| **Flutter user app**    | ❌ | ❌ | Flutter SDK not installed; native project not scaffolded; crypto not wired |
| **Flutter admin app**   | ❌ | ❌ | same                                                                        |
| **Push notifications**  | ❌ | ❌ | no FCM `google-services.json` / no APNs `.p8`                                |

A new dev today gets these for free from this branch:

```bash
make dev                # boots: postgres, redis, minio, backend, retention, admin-web
make seed-admin         # inserts admin@kalki.local / ChangeMeNow!1 / TOTP JBSWY3DPEHPK3PXP
open http://localhost:3000/login
```

Backend curl smoke test (works *right now*):
```bash
curl http://localhost:8080/healthz
# {"ok":true}
curl http://localhost:8080/v1/onboarding/whatsapp-link
# {"phone_e164":"+910000000000",...,"wa_me_url":"https://wa.me/..."}
```

Admin auth end-to-end via curl (works *right now*):
```bash
curl -c /tmp/c.txt -X POST http://localhost:8080/v1/admin/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@kalki.local","password":"ChangeMeNow!1"}'
# Then the 6-digit TOTP for secret JBSWY3DPEHPK3PXP:
TOTP=$(python3 -c "import hmac,hashlib,struct,base64,time; s=base64.b32decode('JBSWY3DPEHPK3PXP'); t=int(time.time()//30); h=hmac.new(s,struct.pack('>Q',t),hashlib.sha1).digest(); o=h[-1]&0x0F; print(f'{(struct.unpack(\">I\",h[o:o+4])[0]&0x7fffffff)%1000000:06d}')")
curl -b /tmp/c.txt -c /tmp/c.txt -X POST http://localhost:8080/v1/admin/auth/totp \
     -H 'Content-Type: application/json' -d "{\"code\":\"$TOTP\"}"
curl -b /tmp/c.txt http://localhost:8080/v1/admin/users
# {"users":[]}
```

The Android emulator (Pixel_9a, Android 17) **is** booted right now and visible to `adb`:
```bash
~/Library/Android/sdk/platform-tools/adb devices
# emulator-5554   device
```

It just has no Flutter app installed because Flutter isn't on the machine.

---

## Hard blockers for the Android chat app

### 1. Flutter SDK (≥ 3.24)
Not installed on this machine. Install one of:

```bash
# Option A — Homebrew cask (fastest)
brew install --cask flutter

# Option B — direct from flutter.dev
git clone -b stable https://github.com/flutter/flutter.git ~/flutter
echo 'export PATH="$HOME/flutter/bin:$PATH"' >> ~/.zshrc
exec zsh
flutter doctor
```

`flutter doctor` should show:
- ✓ Flutter (Channel stable, ≥ 3.24, on macOS)
- ✓ Android toolchain (already installed)
- ✓ Android Studio
- The Xcode line is optional unless you also want iOS.

### 2. Native Android scaffolding under `mobile/`
The repo today has only:
```
mobile/android/app/src/main/AndroidManifest.xml
mobile/android/app/src/main/res/xml/network_security_config.xml
mobile/android/app/src/main/res/xml/data_extraction_rules.xml
```

`flutter create` will populate the rest (gradle wrappers, `MainActivity.kt`, themes, signing config):

```bash
cd mobile
flutter create --project-name kalki_chat --org com.kalkichat --platforms=android,ios .
```

This is **safe** — `flutter create` over an existing project preserves your `lib/`, `pubspec.yaml`, and `analysis_options.yaml`, and only fills missing native files. Re-run after merging the existing AndroidManifest snippets (they override `allowBackup=false` and add the `wa.me` query intent).

Repeat for `admin-mobile/` with `--project-name kalki_admin --org com.kalkichat.admin`.

### 3. Build-time env values
The Flutter app reads four env values via `--dart-define` (see `mobile/lib/env.dart`):

```bash
flutter run \
  --dart-define=API_BASE=http://10.0.2.2:8080 \
  --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws \
  --dart-define=SPKI_PIN_PRIMARY=<hash> \
  --dart-define=SPKI_PIN_BACKUP=<hash>
```

`10.0.2.2` is the Android emulator's loopback to the host machine. The backend listens on `http://localhost:8080` on the host, so the emulator reaches it at `http://10.0.2.2:8080`.

### 4. SSL pinning for dev
The app uses `http_certificate_pinning` and rejects connections whose SPKI hash doesn't match `SPKI_PIN_PRIMARY` or `SPKI_PIN_BACKUP`. With `http://` (plain) URLs in dev, **there is no TLS cert to pin** and the request will fail.

Two options:
- **Preferred (matches prod)**: front the dev backend with a self-signed TLS cert, embed its SPKI hash in `--dart-define`, hit `https://10.0.2.2:8443`.
- **Quick (dev only)**: short-circuit the pin check in `core/net/api_client.dart` when the URL scheme is `http`. Add a `_skipPinForHttp` boolean guarded by `--dart-define=DEV_ALLOW_HTTP=1`.

### 5. Firebase Cloud Messaging
The push handler imports `firebase_messaging`. It needs:
- `mobile/android/app/google-services.json` from your Firebase project console.
- `apply plugin: 'com.google.gms.google-services'` in `mobile/android/app/build.gradle`.

Without these, the app builds but `Firebase.initializeApp()` will throw at startup. For local testing, either:
- Provision a free Firebase project and add the config file, **or**
- Comment out the `firebase_*` initialization (push then silently no-ops; the WebSocket still delivers real-time messages).

---

## Soft blockers — features that exist but aren't *fully* wired

These don't prevent the app from running. They prevent a fully convincing end-to-end message exchange.

### 6. Admin device identity
The `admins` table seeds the admin *account*. There is no admin *device* registered with identity keys. Without that:
- A user device can't fetch an admin prekey bundle (`GET /v1/prekeys/<device_id>` returns 404).
- Admin web replies POST `recipient_device_id: "pick-from-prekeys"` as a placeholder.

The two ways to fix:
- **Quickest**: make the admin web also generate an X25519+Ed25519 keypair in a Web Worker on first login, register the keypair as an admin device via a new `POST /v1/admin/devices/me` endpoint, store the private halves in IndexedDB (`indexeddb-promised` + `subtle.exportKey('jwk')` → ECDH/Ed25519 are now standard in Chrome/Safari).
- **Real prod path**: every admin uses the **Flutter admin Android app** which generates and stores the keypair in the Android Keystore. The admin web is then read-only.

### 7. Prekey upload after login
The user-app login flow doesn't currently call `POST /v1/prekeys`. Add that as the next step after login succeeds:

```dart
// In login_controller.dart, after writing tokens:
await _api.post('/v1/prekeys', body: <String, dynamic>{
  'signed_prekey': {
    'id': 1,
    'pubkey_x25519': base64Encode(signedPreKeyPub),
    'signature_ed25519': base64Encode(await identity.sign(signedPreKeyPub)),
  },
  'one_time_prekeys': List.generate(10, (i) =>
      { 'id': i+1, 'pubkey_x25519': base64Encode(generateX25519Pub()) }),
});
```

### 8. Double Ratchet wired into the send path
`mobile/lib/core/crypto/ratchet.dart` exists and unit-tests will pass, but `chat_controller.sendText` currently uses a placeholder per-message random key. Replace with:

```dart
final DoubleRatchet ratchet = await _db.loadRatchet(recipient) ??
    await _x3dh(recipient);    // first-message X3DH bootstrap
final Uint8List messageKey = await ratchet.nextSendKey();
await _db.saveRatchet(recipient, ratchet);
```

And mirror in the receive path inside `_handleIncoming`.

### 9. Decryption display
`_handleIncoming` today just shows `[encrypted message · N bytes]`. Once the ratchet is wired, change it to:
```dart
final env = Envelope.fromBase64(d['envelope'] as String);
// signature verification (admin pubkey is known from prekey bundle)
final mk = await ratchet.nextRecvKey();
final pt = await Envelope.open(envelope: env, messageKey: mk);
_appendLocal(MessageDirection.incoming, utf8.decode(pt));
```

### 10. `--migrate-only` server flag
`deploy/k8s/base/jobs/migrate.yaml` runs `/server --migrate-only` but `cmd/server/main.go` doesn't implement the flag. Today the server runs migrations on every cold start, so the K8s job is redundant. Either:
- Implement the flag (`flag.Bool("migrate-only", false, ...)` → run migrate then `os.Exit(0)`), **or**
- Remove the K8s job and rely on init-on-startup.

---

## Optional / nice-to-have

| Item | Why | How |
| --- | --- | --- |
| `pubspec.lock` committed | Reproducible installs | `cd mobile && flutter pub get && git add pubspec.lock` |
| `package-lock.json` committed | Already done | ✓ |
| `go.sum` committed | Already done | ✓ |
| `.env.local.example` | Onboard new devs | Could rename / split current `.env.example` |
| Pre-commit hooks | Catch issues before CI | Use [`pre-commit`](https://pre-commit.com/) with `gosec`, `golangci-lint`, `eslint`, `flutter analyze` |
| Backend `/metrics` Prometheus endpoint | The K8s manifests scrape but the endpoint isn't wired | `import "github.com/prometheus/client_golang/prometheus/promhttp"` + `r.Handle("/metrics", promhttp.Handler())` |
| Tracing | Useful for debugging WS fan-out | `go.opentelemetry.io/otel` |
| Backend TLS for dev | Real SSL pinning testing | `mkcert -install && mkcert localhost 10.0.2.2 127.0.0.1` then nginx in front of compose |
| Web admin device-key UX | See item 6 | Browser Web Crypto + IndexedDB |

---

## Minimum path to a working chat (in order)

1. `brew install --cask flutter` — install Flutter SDK.
2. `cd mobile && flutter create --project-name kalki_chat --org com.kalkichat .` — fill in the native scaffolding.
3. Merge the existing `AndroidManifest.xml` query intents and `allowBackup=false` flag back in.
4. Either provision Firebase config OR comment out FCM initialization in `core/push/push_handler.dart`.
5. Add a `DEV_ALLOW_HTTP` shortcut in `core/net/api_client.dart` so the SPKI pin check is bypassed when the URL scheme is `http://`.
6. Implement admin-device generation in the admin web (item 6) **or** stand up the Flutter admin app first.
7. Wire the prekey upload in the user login flow (item 7).
8. Wire the Double Ratchet into send and receive (items 8 + 9).
9. `flutter run --dart-define=API_BASE=http://10.0.2.2:8080 --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws --dart-define=DEV_ALLOW_HTTP=1`.

Steps 1–4 are one-time setup. Steps 5–8 each yield a meaningful behavioural improvement and are commitable in isolation.

---

## What was changed in this dev-bringup pass

| Change | Why |
| --- | --- |
| `backend/internal/config/config.go` rewritten to use `os.Getenv` directly | viper's `AutomaticEnv` + `Unmarshal` was silently ignoring `DATABASE_URL` and friends in the container |
| `RETENTION_DAYS` accepts both Go-duration (`720h`) and integer-days (`30`) | Common operator error mode |
| `JWT_PRIVATE_KEY_PEM_FILE` / `JWT_PUBLIC_KEY_PEM_FILE` env-var support | Multi-line PEM doesn't fit in `.env` |
| `cmd/seed/main.go` + `make seed-admin` | Stack was unusable without an admin row |
| `cmd/server/main.go` migration path resolves via `migrationsDir()` | Distroless container has no shell / CWD games |
| Postgres host port → `5433`, Redis → `6380`, MinIO → `9100/9101` | Avoid conflicts with host's existing brew services |
| Removed `wget` healthcheck on the backend container | Distroless has no `wget`; the check always reported "unhealthy" |
| Created `admin-web/public/.gitkeep` | Multi-stage Dockerfile's `COPY /app/public` was failing |
| Mount `../.secrets:/secrets:ro` into backend + retention | JWT PEM file delivery |
| `.env` with real generated JWT keys + TOTP encryption key | Stack now boots clean from `make dev` |
