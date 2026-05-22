SHELL := /usr/bin/env bash
TAG   ?= dev

ADMIN_EMAIL    ?= admin@kalki.local
ADMIN_PASSWORD ?= ChangeMeNow!1
ADMIN_TOTP     ?= JBSWY3DPEHPK3PXP

# When seeding from the host machine, point at the published postgres port.
HOST_DATABASE_URL ?= postgres://kalki:kalki_dev@localhost:5433/kalki?sslmode=disable

.PHONY: help dev down logs build backend-image admin-web-image retention-image migrate seed-admin test lint

help:
	@echo "Targets:"
	@echo "  dev                  - boot full stack via docker compose"
	@echo "  down                 - stop stack"
	@echo "  logs                 - tail all services"
	@echo "  seed-admin           - insert a dev admin"
	@echo "                          override: ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_TOTP"
	@echo "  backend-image        - build backend container ($(TAG))"
	@echo "  admin-web-image      - build admin web container ($(TAG))"
	@echo "  retention-image      - build retention worker container ($(TAG))"
	@echo "  migrate              - run database migrations against \$$DATABASE_URL"
	@echo "  test                 - run all test suites"
	@echo "  lint                 - run all linters"

dev:
	docker compose -f deploy/docker-compose.yml --env-file .env up -d --build

down:
	docker compose -f deploy/docker-compose.yml down

logs:
	docker compose -f deploy/docker-compose.yml logs -f --tail=100

backend-image:
	docker build -t kalki/backend:$(TAG) -f backend/Dockerfile backend

admin-web-image:
	docker build -t kalki/admin-web:$(TAG) -f admin-web/Dockerfile admin-web

retention-image:
	docker build -t kalki/retention:$(TAG) -f backend/Dockerfile.retention backend

migrate:
	cd backend && go run ./cmd/migrate up

# Seed a dev admin from the host. Reads .env, points DATABASE_URL at the
# published postgres port (so we don't need a container shell).
seed-admin:
	cd backend && \
	  set -a && source ../.env && set +a && \
	  DATABASE_URL='$(HOST_DATABASE_URL)' \
	  JWT_PRIVATE_KEY_PEM_FILE=$$(pwd)/../.secrets/jwt_ed25519.pem \
	  JWT_PUBLIC_KEY_PEM_FILE=$$(pwd)/../.secrets/jwt_ed25519.pub.pem \
	  go run ./cmd/seed \
	    -email '$(ADMIN_EMAIL)' \
	    -password '$(ADMIN_PASSWORD)' \
	    -totp '$(ADMIN_TOTP)'

test:
	cd backend && go test ./... -race -count=1
	cd admin-web && npm test
	cd mobile && flutter test

lint:
	cd backend && golangci-lint run ./...
	cd admin-web && npm run lint
	cd mobile && flutter analyze --no-fatal-infos
