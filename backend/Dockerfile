# syntax=docker/dockerfile:1.7
# ── builder ────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS build

RUN apk add --no-cache git ca-certificates
WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/server ./cmd/server && \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/seed   ./cmd/seed

# ── runtime ────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/server /server
# Optional seed binary, invoked by the helm chart's schat-admin-seed Job
# (gated by adminSeed.enabled). Runtime is still distroless/static:nonroot
# — the seeder is a Go binary with no shell dependency.
COPY --from=build /out/seed /seed
COPY --from=build /src/migrations /migrations

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
