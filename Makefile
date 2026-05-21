SHELL := /usr/bin/env bash
TAG   ?= dev

.PHONY: help dev down logs build backend-image admin-web-image retention-image migrate test lint

help:
	@echo "Targets:"
	@echo "  dev                  - boot full stack via docker compose"
	@echo "  down                 - stop stack"
	@echo "  logs                 - tail all services"
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

test:
	cd backend && go test ./... -race -count=1
	cd admin-web && pnpm test --run
	cd mobile && flutter test

lint:
	cd backend && golangci-lint run ./...
	cd admin-web && pnpm lint
	cd mobile && dart analyze
