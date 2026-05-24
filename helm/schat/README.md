# schat Helm chart

End-to-end-encrypted messaging platform deployment. Three services
(backend, admin-web, retention) plus in-cluster Postgres and MinIO,
external Redis. Mirrors the conventions used by the parallel `kalki`
chart in `mahakaal02/bet` so a single operator can run both with the
same mental model.

## What this chart deploys

| Resource | What | Gated by |
|---|---|---|
| `schat-backend` | Deployment + Service + Traefik IngressRoute | always |
| `schat-admin-web` | Deployment + Service + Traefik IngressRoute | always |
| `schat-retention` | Deployment (worker, no service) | always |
| `schat-postgres` | StatefulSet + Service + initdb ConfigMap | `postgres.enabled: true` |
| `schat-minio` | Deployment + PVC + Service + bucket-init Job | `minio.enabled: true` |
| `schat-shared` | Secret with JWT keys + TOTP encryption key | always |
| `schat-postgres` (Secret) | Postgres root credentials | `postgres.enabled` |
| `schat-minio` (Secret) | MinIO root credentials | `minio.enabled` |
| `schat-backend` / `schat-admin-web` (PDB) | minAvailable=1 PodDisruptionBudgets | always |
| `schat-admin-seed` (Job) | One-shot helm-hook Job that runs `/seed` to insert/upsert an admin row | `adminSeed.enabled: true` |

Public Traefik hostnames default to `kalki-chat-<svc>.<global.domain>` —
i.e. `kalki-chat-backend.cloud.podstack.ai` and
`kalki-chat-admin-web.cloud.podstack.ai`. The `kalki-chat-` prefix
avoids colliding with the bet stack's `kalki-backend` / `kalki-admin` /
`kalki-aviator` / `kalki-bet` / `kalki-auctions` hosts that share the
same namespace.

Image refs are formed as
`docker.io/saurav7055/<image>:<imageTag>`. Each per-service `imageTag`
in `values.yaml` carries a `{"$imagepolicy": ...}` marker so Flux's
`ImageUpdateAutomation` can rewrite the value in place when a new image
appears on Docker Hub.

## Quick local lint / dry-run

```bash
helm lint helm/schat
helm template schat helm/schat | wc -l
helm template schat helm/schat --debug | less    # inspect rendered manifests
```

## Installation (cluster — managed by Flux, not by hand)

The chart is installed by the `HelmRelease` in `clusters/schat/helmrelease.yaml`.
You do **not** `helm install` directly in prod. Flow:

1. Cluster operator runs `kubectl apply -f clusters/schat/_bootstrap.yaml` once
   (after completing the prereqs in that file's comment block: SSH deploy key,
   `schat-helm-values` Secret with real credentials, `schat-redis-creds` Secret,
   namespace creation).
2. Flux picks up the `HelmRelease`, reconciles this chart against the
   `schat-helm-values` in-cluster overlay Secret, and creates all resources.
3. GitHub Actions builds + pushes new images on every main-branch commit.
4. Flux `ImageRepository` polls Docker Hub every 2m, `ImagePolicy` selects
   the newest tag matching the regex, `ImageUpdateAutomation` rewrites the
   matching `imageTag` field in `helm/schat/values.yaml`, commits + pushes
   back to git. The next reconcile applies the new image.

## Values you'll override per environment

Anything in `values.yaml` flagged `CHANGE_ME_*` must be overridden in the
in-cluster `schat-helm-values` Secret (per the `_bootstrap.yaml` runbook).
Common overrides:

| Path | What | Why override |
|---|---|---|
| `sharedSecret.jwtPrivateKeyPem` / `jwtPublicKeyPem` | Ed25519 keypair | Stable per cluster; never in git |
| `sharedSecret.totpEncKeyHex` | 32-byte hex | TOTP secrets at rest |
| `postgres.password` | Postgres root | Rotate in-cluster, never in git |
| `minio.rootPassword` / `s3.secretKey` | MinIO creds (must match) | One-time random on first install |
| `s3.endpoint` | http://schat-minio:9000 OR managed | Flip to managed S3 in prod |
| `redis.host` | in-cluster service OR managed | Wherever your Redis lives |
| `global.domain` / `global.hostnamePrefix` | DNS | Per-cluster |
| `backend.allowedOrigins` | CORS | Add prod admin URL |
| `minio.enabled` | bool | false if using managed S3 |
| `postgres.enabled` | bool | false if using managed Postgres |
| `adminSeed.enabled` + `adminSeed.password` + `adminSeed.totpSecret` | bool + strings | Bootstrap admin login. Default OFF. Flip on for first install only; the Job is idempotent on subsequent reconciles. |

### Provisioning the first admin

After first install with sensible `schat-helm-values` overrides:

```bash
# Inside the in-cluster schat-helm-values Secret values.yaml blob, add:
adminSeed:
  enabled: true
  email: "admin@kalki.local"
  password: "<a strong password you'll remember>"
  totpSecret: "<base32 no-padding TOTP secret — share with admin via secure channel>"

# Then trigger a HelmRelease reconcile to fire the Job:
flux reconcile helmrelease schat -n kalki

# Verify:
kubectl -n kalki logs job/schat-admin-seed
kubectl -n kalki exec sts/schat-postgres -- psql -U schat -d schat -c \
  "SELECT email, role, created_at FROM admins;"
```

The Job re-fires on every subsequent HelmRelease upgrade. Because the seed
code uses `INSERT … ON CONFLICT (email) DO UPDATE`, that's idempotent — the
password + TOTP secret in `schat-helm-values` are the source of truth. To
rotate either, edit the Secret and reconcile.

## Render diff between two versions of the chart

```bash
git stash
helm template schat helm/schat > /tmp/schat-before.yaml
git stash pop
helm template schat helm/schat > /tmp/schat-after.yaml
diff -u /tmp/schat-before.yaml /tmp/schat-after.yaml | less
```

## Known issues

- **`postgres.password` literal default.** Same caveat as /bet's kalki chart:
  the password baked into the PV on first boot can't be `ALTER USER`-rotated
  without an in-cluster shell. Treat the CHANGE_ME default as "must override
  before first install"; the `schat-helm-values` Secret is the only
  acceptable source of the real value.

- **No leader election yet on retention.** `retention.replicas: 1` is the
  correct default. Running >1 will double-fire every sweep tick. The data
  model is forgiving (idempotent deletes) but extra delete batches are
  pointless work.

- **`app.kubernetes.io/name` is unprefixed.** Each workload sets the label
  to its bare role (`backend`, `admin-web`, `retention`, `postgres`,
  `minio`). In a shared namespace this clashes with other charts that
  also have a `backend` — selector-immutable on Deployment makes renaming
  costly. Always disambiguate with `app.kubernetes.io/part-of=schat` when
  querying:
  `kubectl -n kalki get pods -l app.kubernetes.io/name=backend,app.kubernetes.io/part-of=schat`
