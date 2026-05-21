# Threat Model (STRIDE)

## Assets
1. Message plaintext & images.
2. User identity keys (private).
3. Admin identity keys (private).
4. User credentials (passwords).
5. Admin session tokens.
6. Audit logs.
7. WhatsApp onboarding configuration.

## Trust boundaries
- Client device ↔ Backend (untrusted network).
- Backend ↔ Database / Redis (trusted VPC, but TLS everywhere).
- Backend ↔ Object storage (TLS + signed URLs).
- Admin browser ↔ Admin web (TLS + auth cookie).

## Adversaries
- **A1 — Network attacker** (passive + active MITM, ISP-level).
- **A2 — Server operator / cloud provider** (insider with DB access, cold
  storage access, but no client device).
- **A3 — App-store delivered attacker** (malicious app on same device).
- **A4 — Physical device thief** (has handset but not unlock PIN).
- **A5 — Stolen admin laptop**.
- **A6 — Compromised admin account** (correct password, no 2FA).
- **A7 — Compromised user account** (correct user ID + password).
- **A8 — Supply-chain attacker** (poisoned dependency).

## STRIDE × Adversary

### Spoofing
| Threat                                       | Adversary | Mitigation                                                       |
| -------------------------------------------- | --------- | ---------------------------------------------------------------- |
| Pretending to be another user device         | A1, A2    | Ed25519 envelope signature + per-device prekey bundle published once on enrollment |
| Pretending to be admin                       | A1, A2    | Admin identity key pinned in app at first contact (TOFU) + admin Ed25519 signature on prekey bundle |
| Forged FCM / APNs push                       | A1        | Push is only a wake signal — payload is fetched over TLS+JWT     |
| Forged WhatsApp config (admin number swap)   | A2        | Config writes require admin auth + audit event + 2FA             |

### Tampering
| Threat                                       | Adversary | Mitigation                                                       |
| -------------------------------------------- | --------- | ---------------------------------------------------------------- |
| Modify ciphertext in transit                 | A1        | AES-GCM AEAD + Ed25519 envelope signature                        |
| Modify ciphertext on server disk             | A2        | Same — receiver verifies, server cannot forge                    |
| Roll back a message (replay)                 | A1, A2    | Message-number AD + sliding-window dedup at receiver             |
| Alter audit logs                             | A2        | Append-only table, daily SHA-256 hash chain written to remote bucket |

### Repudiation
| Threat                                  | Adversary | Mitigation                                                       |
| --------------------------------------- | --------- | ---------------------------------------------------------------- |
| User denies sending a message           | All       | Ed25519 signature on the envelope persists for retention window  |
| Admin denies an action                  | A2, A5    | Every admin action audit-logged with IP + UA + actor ID          |

### Information disclosure
| Threat                                  | Adversary | Mitigation                                                       |
| --------------------------------------- | --------- | ---------------------------------------------------------------- |
| Read messages from server DB            | A2        | Ciphertext-only storage; server has no key material              |
| Read messages from media storage        | A2        | Client-side AES-GCM before upload; wrapped keys in DB; crypto-erasure on retention |
| Read messages from device backups       | A4        | Local DB is sqlcipher; iOS Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; `allowBackup=false` on Android |
| Read messages from screenshots          | A3        | FLAG_SECURE + iOS background blur + capture detection            |
| Read messages from clipboard            | A3        | Copy/paste suppressed on chat fields                             |
| Leak in push notifications              | A2 (Google/Apple) | No content in push payload — wake only                  |
| TLS interception by MDM                 | A1        | SPKI pinning, two pins (leaf + backup)                           |
| Side-channel via app preview            | A3        | Blank snapshot on background                                     |
| Memory dump on rooted phone             | A3        | Root detection blocks app launch                                 |

### Denial of service
| Threat                              | Adversary | Mitigation                                                       |
| ----------------------------------- | --------- | ---------------------------------------------------------------- |
| Connection flood                    | A1        | Per-IP and per-device rate limits in nginx + token bucket in Go  |
| Auth brute force                    | A1        | 5/min then exponential backoff per user_id; Argon2id raises cost |
| Message flood from a user           | A7        | 60 msgs/min per device; soft suspend on breach                   |
| Large media upload                  | A1, A7    | Hard cap 10 MB; ratelimited; quota per user per day              |
| Pre-key exhaustion attack           | A7        | Each device caps to 100 one-time prekeys; refill rate-limited    |

### Elevation of privilege
| Threat                                    | Adversary | Mitigation                                                                |
| ----------------------------------------- | --------- | ------------------------------------------------------------------------- |
| User accesses another user's messages     | A7        | All endpoints scoped by `device_id` from JWT; row-level checks            |
| Admin without 2FA gets in                 | A6        | 2FA enforced on every login (configurable per-admin)                      |
| Privilege escalation via SQLi             | A7        | Parametrized queries only; CI lint                                        |
| Admin token theft via XSS                 | A1        | Admin cookie is HttpOnly+Secure+SameSite=Strict; CSP `default-src 'none'` |
| Supply chain                              | A8        | `go.sum` + `npm ci` + Renovate + Dependabot; SBOM produced in CI          |

## Out of scope
- Resisting a fully compromised device with active root.
- Resisting a state actor that can compel Apple/Google to push a signed
  malicious app update to a specific phone.
- Steganographic exfiltration by a malicious user (the message *is* content).

## Open risks (accepted)
- **Metadata leakage**: Server knows that user X talked to admins at time T,
  and the ciphertext size. This is inherent to a 1-to-admin model.
- **WhatsApp deep-link onboarding** crosses out of our trust boundary. We
  mitigate by treating WhatsApp identity as an out-of-band claim that the
  admin must verify before issuing credentials.
