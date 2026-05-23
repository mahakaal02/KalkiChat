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
