// Package media handles encrypted blob storage. The server only ever sees
// ciphertext bytes; the per-blob AES key is wrapped client-side to each
// recipient device via HPKE-X25519 and stored in `media_keys`.
package media

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kalkichat/backend/internal/config"
)

// Store is an encrypted-blob backend.
type Store interface {
	PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (string, error)
	PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error)
	Delete(ctx context.Context, key string) error
}

// S3Store is an AWS-S3 / MinIO Store.
type S3Store struct {
	client   *s3.Client
	presign  *s3.PresignClient
	bucket   string
}

// NewS3Store constructs an S3 client suitable for MinIO (path-style) or AWS.
func NewS3Store(ctx context.Context, cfg config.S3Config) (*S3Store, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	clientOpts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = cfg.ForcePathStyle
			if cfg.Endpoint != "" {
				o.BaseEndpoint = aws.String(cfg.Endpoint)
			}
		},
	}
	c := s3.NewFromConfig(awsCfg, clientOpts...)
	return &S3Store{
		client:  c,
		presign: s3.NewPresignClient(c),
		bucket:  cfg.Bucket,
	}, nil
}

// PresignPut returns a short-lived URL the client can PUT to.
//
// We require Content-Length so the storage can reject oversize uploads.
// AES-GCM ciphertext is at most 16 bytes longer than the plaintext, so a
// 10 MiB plaintext cap → 10 MiB + 28 bytes ciphertext.
func (s *S3Store) PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (string, error) {
	out, err := s.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(size),
	}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if err != nil {
		return "", err
	}
	return out.URL, nil
}

// PresignGet returns a short-lived signed GET URL.
func (s *S3Store) PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	out, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if err != nil {
		return "", err
	}
	// Defensively validate URL (paranoia: we hand this to clients).
	if _, perr := url.Parse(out.URL); perr != nil {
		return "", perr
	}
	return out.URL, nil
}

// Delete removes a blob.
func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	return err
}
