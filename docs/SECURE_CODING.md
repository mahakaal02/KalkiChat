# Secure Coding Practices

A short, enforceable rule set. CI enforces what it can; reviewers enforce the rest.

## Go (backend)

1. **Parameterize all SQL.** `pgx`/`pgxpool` query args only. No `fmt.Sprintf` into a query. CI runs a custom `find-rawsql.sh` lint.
2. **Validate at the edge.** Every JSON-decoded struct is checked for shape (`validPlatform`, length caps, base64-decode-or-reject) before it reaches a query.
3. **Constant-time secret compares.** Use `crypto/subtle` or `hmac.Equal`. Refresh tokens are SHA-256-hashed before storage and compared with `subtle.ConstantTimeCompare`.
4. **Never log secrets.** Sentry / log middleware redacts `password`, `totp_secret`, `wrapped_key`, `envelope`, `ciphertext`, `private_key`. See `internal/audit/audit.go:sanitize`.
5. **Bound everything.** `MaxEnvelopeBytes = 16 KiB`, `MaxMediaSize = 10 MiB`, 100 OPKs/device, 60 msgs/min/device. Unbounded = DoS.
6. **No unsafe.** `golangci-lint` enforces `forbidigo` for `unsafe.Pointer` in non-FFI packages.
7. **`go vet -vettool=sqlclosecheck`** in CI to catch leaked `*sql.Rows`.
8. **Wrap errors with context.** `fmt.Errorf("verb noun: %w", err)`. Errors crossing the API boundary become `error_code` strings, never raw `err.Error()` in production.

## TypeScript (admin web)

1. **No `any`.** `noUncheckedIndexedAccess` and `strict` enforce most paths. PRs that add `as any` need a TODO with a date.
2. **No client-side secrets.** The admin session is an HttpOnly cookie. The browser never sees the JWT.
3. **CSP** with `frame-ancestors 'none'` and a strict `connect-src`. The build fails CI if a page adds inline `<script>` without a nonce.
4. **Server actions only for state-changing ops.** Or use the `/api/proxy` route. No direct fetch-with-cookie to `api.kalkichat.example` (would expose CORS surface).
5. **All inputs validated with `zod`.** Especially anything POSTed by the browser to a server action.

## Dart (mobile)

1. **No `dynamic`.** `analysis_options.yaml` enforces `strict-casts`, `strict-raw-types`, `strict-inference`.
2. **No `print`** in production code (`avoid_print: true`).
3. **No copy/paste** on chat fields: `enableInteractiveSelection: false`.
4. **No screenshot leaks**: `FLAG_SECURE` (Android) + `screen_protector` (iOS).
5. **No plaintext on disk**: ratchet state, message cache, and outbox all live in `sqflite_sqlcipher` with a hardware-wrapped key.
6. **Keys never leave the keystore**: `IdentityKeys.sign` and `.dh` are the only paths through which private bytes are momentarily read.
7. **Network only via `ApiClient`/`WsClient`** with embedded SPKI pins.
8. **Root/JB detection** runs on cold start and on every resume.

## Crypto

1. **No custom crypto.** Use `libsodium`, BoringSSL, or `golang.org/x/crypto`. Period.
2. **AEAD only** for symmetric encryption (AES-256-GCM or ChaCha20-Poly1305). No bare AES.
3. **Generate nonces with the OS CSPRNG.** Never use counters across reboots.
4. **Verify before decrypt.** Every envelope is Ed25519-signature-verified before the decryption code path runs.
5. **HKDF for key derivation.** Salt is the root key; info is a context string like `"kalki-root"`.

## Dependencies

1. **Pin top-level versions** in `go.mod` / `package.json` / `pubspec.yaml`. Renovate auto-PRs for upgrades.
2. **`go.sum` and `package-lock.json` checked in.**
3. **Trivy scan** on every container image. HIGH or CRITICAL = CI fail.
4. **SBOM** produced via `cyclonedx-gomod` / `cyclonedx-npm` and attached to GitHub Releases.

## Process

1. **Two reviewers** on anything touching `internal/crypto/`, `internal/auth/`, or `migrations/`.
2. **No `down` migrations** in production. Forward-only.
3. **No `--no-verify` commits.** CI rejects merges with skipped hooks.
4. **Quarterly key rotation** drill (signed prekey + JWT signing key).
5. **Quarterly retention restore drill** — restore from backup, verify crypto-erasure is intact, document outcome.
