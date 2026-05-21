# Production Deployment Guide

## Prerequisites
- Kubernetes 1.28+ (EKS, GKE, AKS, or self-managed)
- A managed Postgres with TLS (RDS, Cloud SQL, or self-managed with `pg_tle`)
- Redis with TLS + ACL
- Object storage with SSE (MinIO or S3)
- Domain + ACME / Let's Encrypt
- A push key/cert (APNs `.p8` + FCM server key)

## 1. Secrets

Never commit `.env`. Production secrets live in your cloud secret manager
(AWS Secrets Manager, GCP Secret Manager, Vault). Mount into Kubernetes via
`external-secrets-operator`.

Required secrets:
- `POSTGRES_URL` (with `sslmode=verify-full`)
- `REDIS_URL` (`rediss://`)
- `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`
- `JWT_SIGNING_KEY_ED25519` (PEM)
- `JWT_PREV_SIGNING_KEYS` (rotation grace)
- `ADMIN_TOTP_ENCRYPTION_KEY` (32-byte AES key for TOTP-secret encryption at rest)
- `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_KEY_P8`
- `FCM_SERVER_KEY` or `FCM_SERVICE_ACCOUNT_JSON`
- `BACKUP_AGE_RECIPIENTS` (one or more age public keys)
- `BACKEND_TLS_CERT_PEM`, `BACKEND_TLS_KEY_PEM` (if TLS-terminating in pod)

## 2. Build & push

```bash
make backend-image     TAG=$(git rev-parse --short HEAD)
make admin-web-image   TAG=$(git rev-parse --short HEAD)
make retention-image   TAG=$(git rev-parse --short HEAD)
```

Each image:
- Multi-stage Dockerfile, distroless base.
- Non-root UID 65532.
- Read-only root FS at runtime.
- `HEALTHCHECK` set.
- Signed with `cosign sign --key cosign.key` and a Rekor entry.

## 3. Apply manifests

```bash
kubectl apply -k deploy/k8s/overlays/prod
```

This creates:
- `Namespace: kalki`
- `Deployment: backend` (3 replicas, HPA on CPU 60% + WS conn count via custom adapter)
- `Deployment: retention-worker` (1 replica, singleton)
- `Deployment: admin-web` (2 replicas)
- `StatefulSet: postgres` (optional — prefer managed)
- `StatefulSet: redis` (optional — prefer managed)
- `Service: backend-headless` (for WS sticky routing via consistent hashing)
- `Ingress: nginx` with SSL termination, HSTS, CSP, rate limits

## 4. Database migrations

Migrations are baked into the `migrate` job. It runs once per release before
the new backend pods become Ready (`initContainer: wait-migrate`).

```bash
kubectl apply -f deploy/k8s/base/jobs/migrate.yaml
kubectl wait --for=condition=complete job/migrate --timeout=180s
```

## 5. TLS

Two options:
- **Edge-terminate** at nginx-ingress with cert-manager (Let's Encrypt). Cheap.
- **mTLS to pods** via a service mesh (Linkerd / Istio). Defense in depth; pods
  refuse plaintext.

We recommend both: edge TLS for the public endpoint + mTLS pod-to-pod.

## 6. Observability

- Metrics: Prometheus + Grafana. Dashboards in `deploy/grafana/`.
- Logs: stdout JSON → Loki / CloudWatch.
- Traces: OpenTelemetry → Tempo / X-Ray.
- Alerts: see `deploy/alerts/` — page on `ws_connection_drop_rate > 1%`,
  `retention_lag > 5min`, `db_replication_lag > 30s`.

## 7. Backups

- Postgres: WAL streaming to `wal-g`; daily base backup; **all** outputs
  encrypted via `age -R $BACKUP_AGE_RECIPIENTS` before leaving the host.
- Redis: AOF every-1s with daily rdb snapshot.
- Object storage: cross-region replication, but media is already
  client-encrypted so the bucket itself isn't a confidentiality risk.
- Test restore quarterly. Document in runbook.

## 8. Disaster recovery RTO/RPO

| Tier             | RTO | RPO |
| ---------------- | --- | --- |
| Auth + new messages (read-only) | 15 min | 5 min |
| Full read/write                  | 1 hr   | 15 min |

Steps in `deploy/runbooks/disaster-recovery.md`.

## 9. Zero-downtime deploy

- Backend uses graceful shutdown: `SIGTERM` → stop accepting new connections,
  send `server.shutdown` event to live WS clients, drain in 30s, exit.
- Clients reconnect with exponential backoff. The new pod accepts them.
- Postgres migrations are **expand-then-contract**: add nullable column →
  deploy code that writes both → backfill → deploy code that reads new only
  → drop old. Never break the previous version's schema in a single release.

## 10. Rollback

```bash
kubectl rollout undo deployment/backend -n kalki
```

Database rollbacks: never `down` migrate in production. If a column is bad,
write a new forward migration. The forward-only rule is enforced in CI.

## 11. Mobile release

- Android: signed AAB → Play Internal Testing → Closed → Open → Production.
  Use Play App Signing; key never leaves Google.
- iOS: TestFlight → App Store. Use `xcrun altool` from CI.
- Both: ship every release with the **new** SSL pin + a **30-day grace** for
  the old pin. Never ship a single-pin release.
