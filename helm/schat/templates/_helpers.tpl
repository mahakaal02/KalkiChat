{{/*
Service hostname helper — returns `schat-<svc>.cloud.podstack.ai`.
Usage: {{ include "schat.host" (dict "svc" "backend" "ctx" .) }}
*/}}
{{- define "schat.host" -}}
{{- $ctx := .ctx -}}
{{- printf "%s%s.%s" $ctx.Values.global.hostnamePrefix .svc $ctx.Values.global.domain -}}
{{- end -}}

{{/*
Image reference — image: schat-backend → docker.io/mahakaal02/schat-backend:tag
Per-service `tag` overrides `global.imageTag` so Flux ImageUpdateAutomation
can bump each service independently.
Usage: {{ include "schat.image" (dict "image" .Values.backend.image "tag" .Values.backend.imageTag "ctx" .) }}
*/}}
{{- define "schat.image" -}}
{{- $ctx := .ctx -}}
{{- $tag := default $ctx.Values.global.imageTag .tag -}}
{{- printf "%s/%s:%s" $ctx.Values.global.imageRegistry .image $tag -}}
{{- end -}}

{{/*
Standard labels applied to every workload.
*/}}
{{- define "schat.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/part-of: schat
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
{{- end -}}

{{/*
Pod-spec fragment: anti-affinity excluding any nodes listed in
.Values.excludeNodes (typically the L40s GPU node + any storage node
that holds a single-attach volume).
*/}}
{{- define "schat.nodeAffinity" -}}
{{- if .Values.excludeNodes }}
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: NotIn
              values:
{{- range .Values.excludeNodes }}
                - {{ . | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
DATABASE_URL env value, computed from postgres.{user,password} unless an
override is set in the consuming service's `databaseUrl` field.
Args: dict "override" .Values.backend.databaseUrl "ctx" .
*/}}
{{- define "schat.databaseUrl" -}}
{{- $ctx := .ctx -}}
{{- if .override -}}
{{ .override }}
{{- else -}}
postgresql://{{ $ctx.Values.postgres.user }}:{{ $ctx.Values.postgres.password }}@schat-postgres:5432/{{ index $ctx.Values.postgres.databases 0 }}?sslmode=disable
{{- end -}}
{{- end -}}

{{/*
Redis env block. The password is pulled from `schat-redis-creds`
(out-of-git Secret, see clusters/schat/_bootstrap.yaml step 3).
*/}}
{{- define "schat.redisEnv" -}}
- name: REDIS_HOST
  value: {{ .Values.redis.host | quote }}
- name: REDIS_PORT
  value: {{ .Values.redis.port | quote }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: schat-redis-creds
      key: redis-password
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: schat-redis-creds
      key: redis-url
- name: REDIS_KEY_PREFIX
  value: {{ .Values.redis.keyPrefix | quote }}
{{- end -}}

{{/*
Hardened container-level securityContext applied to every schat
workload container. Drops ALL Linux capabilities, blocks privilege
escalation, enforces non-root, and pins the seccomp profile to the
runtime default. Pod-level UID/GID is set per-template (some images
require specific UIDs — postgres needs 999, the Go images use 1001,
Next.js node uses 1000).
*/}}
{{- define "schat.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
InitContainer that blocks pod start until schat-postgres accepts
connections. Eliminates the startup race where backend / retention
crashloop a few times before DNS resolves the postgres Service.
*/}}
{{- define "schat.waitForPostgres" -}}
- name: wait-for-postgres
  image: {{ .Values.postgres.image | quote }}
  imagePullPolicy: {{ .Values.global.imagePullPolicy }}
  command:
    - sh
    - -c
    - |
      until pg_isready -h schat-postgres -p 5432 -U {{ .Values.postgres.user }}; do
        echo "waiting for schat-postgres..."
        sleep 2
      done
  securityContext:
    {{- include "schat.containerSecurityContext" . | nindent 4 }}
    runAsUser: 999
    runAsGroup: 999
  resources:
    requests: {cpu: 10m, memory: 16Mi}
    limits: {cpu: 100m, memory: 64Mi}
{{- end -}}

{{/*
S3 / MinIO env block. The backend reads S3_ENDPOINT, S3_REGION,
S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY, S3_FORCE_PATH_STYLE at boot.
*/}}
{{- define "schat.s3Env" -}}
- name: S3_ENDPOINT
  value: {{ .Values.s3.endpoint | quote }}
- name: S3_REGION
  value: {{ .Values.s3.region | quote }}
- name: S3_BUCKET
  value: {{ .Values.s3.bucket | quote }}
- name: S3_ACCESS_KEY
  value: {{ .Values.s3.accessKey | quote }}
- name: S3_SECRET_KEY
  value: {{ .Values.s3.secretKey | quote }}
- name: S3_FORCE_PATH_STYLE
  value: {{ .Values.s3.forcePathStyle | quote }}
{{- end -}}
