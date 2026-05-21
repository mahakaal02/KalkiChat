module github.com/kalkichat/backend

go 1.22

require (
	github.com/alexedwards/argon2id v1.0.0
	github.com/aws/aws-sdk-go-v2 v1.30.3
	github.com/aws/aws-sdk-go-v2/config v1.27.27
	github.com/aws/aws-sdk-go-v2/credentials v1.17.27
	github.com/aws/aws-sdk-go-v2/service/s3 v1.58.2
	github.com/go-chi/chi/v5 v5.1.0
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/httprate v0.14.1
	github.com/golang-migrate/migrate/v4 v4.17.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/jackc/pgx/v5 v5.6.0
	github.com/pquerna/otp v1.4.0
	github.com/redis/go-redis/v9 v9.6.1
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
	go.uber.org/automaxprocs v1.5.3
	golang.org/x/crypto v0.26.0
)
