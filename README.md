# KalkiChat — Secure 1-to-Admin Messaging Platform

A production-ready, Signal/BBM-grade secure messaging platform where end users
communicate **only** with administrators (never with each other).

> Users cannot see each other, cannot chat with each other, cannot create groups,
> cannot forward. Admins can reply, manage users, and configure onboarding.

---

## Stack at a glance

| Layer            | Choice                                                   |
| ---------------- | -------------------------------------------------------- |
| Mobile (user)    | **Flutter** (Android + iOS, single codebase)             |
| Mobile (admin)   | **Flutter** (Android)                                    |
| Admin web        | **Next.js 14** (App Router, TypeScript)                  |
| Backend          | **Go 1.22** (chi router, gorilla/websocket)              |
| Database         | **PostgreSQL 16** (TLS, row-level encryption)            |
| Cache / PubSub   | **Redis 7** (TLS, ACL)                                   |
| Object storage   | **MinIO / S3** with SSE-C + client-side encryption       |
| Realtime         | WebSockets, sticky sessions via Redis pub/sub fan-out    |
| Push             | FCM (Android) + APNs (iOS) — payload is a wake-up only   |
| Deploy           | Docker Compose for dev, Kubernetes for prod              |
| CI/CD            | GitHub Actions                                           |

## Why Flutter over React Native

| Concern                  | Flutter                                                | React Native                                                |
| ------------------------ | ------------------------------------------------------ | ----------------------------------------------------------- |
| Crypto FFI               | Dart FFI → libsodium/BoringSSL is first-class          | JSI/turbo modules — native bridges required for every algo  |
| Secure storage           | `flutter_secure_storage` wraps Keystore / Keychain     | `react-native-keychain` works but more bridge surface       |
| Screenshot block         | `flutter_windowmanager` / iOS `secureTextEntry` hooks  | Several community libs, fragmented                          |
| Root/jailbreak detection | `flutter_jailbreak_detection`, hardened with native    | Available but mostly community-maintained                   |
| Rendering                | Skia-rendered, no platform-widget bridge for chat list | Bridges JS↔native widgets — more attack surface             |
| Binary size & cold start | Smaller AOT binary, fast first frame                   | Hermes helps but still ships JS engine                      |
| Type safety              | Dart sound nulls, strong types                         | TS adds types but runtime is still JS                       |
| Single codebase parity   | Pixel-identical across iOS/Android                     | Often platform-divergent for sensitive screens              |

**Verdict: Flutter.** Smaller attack surface (one runtime, no JS bridge for
chat), better FFI to libsodium, and identical UX across iOS/Android — which
matters when the support burden is on a small admin team.

## Why a dedicated native app, not WebView

- **Keystore / Secure Enclave**: WebView cannot use hardware-backed keys for
  message encryption. Native code can pin keys to TEE/SE; WebView keys live in
  JS heap, dumpable from a debug-attached process or a malicious extension.
- **SSL pinning**: WebView trusts the system CA store; bypassable by user-added
  CAs or MDM profiles. Native HTTP clients pin to the server's SPKI hash.
- **Screenshot suppression**: `FLAG_SECURE` on Android + iOS snapshot blanking
  cannot be reliably applied to WebView content.
- **Clipboard control**: Native UI text fields can hide copy/paste menus; web
  text fields cannot reliably do this.
- **Push token handling**: APNs/FCM tokens must be processed natively before any
  network call; WebView adds an extra extraction hop.
- **Performance**: Animated chat lists, image decoding, scroll perf — native
  beats WebView on low-end Android.

WebView is used **only** for a few isolated admin help/legal pages, never for
auth, chat, or media.

## Repository layout

```
KalkiChat/
├── backend/          Go API + websocket + retention workers
├── mobile/           Flutter user app (Android + iOS)
├── admin-web/        Next.js admin dashboard
├── admin-mobile/     Flutter admin app (Android)
├── deploy/           docker-compose, nginx, k8s, monitoring
├── docs/             Architecture, security, threat model, runbooks
└── .github/          CI/CD pipelines
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for diagrams,
[docs/SECURITY.md](docs/SECURITY.md) for the crypto design, and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model.

## Quick start (dev)

```bash
cp .env.example .env
make dev          # boots postgres, redis, minio, backend, admin-web
cd mobile && flutter run
```

## Production

```bash
make build
docker compose -f deploy/docker-compose.prod.yml up -d
# or
kubectl apply -k deploy/k8s/overlays/prod
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
