// Package session issues and stores opaque proxy sessions.
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// TokenPrefix identifies proxy-only bearer tokens.
	TokenPrefix = "bkgp_"
	tokenBytes  = 32
	minHashKey  = 32
)

var (
	// ErrNotFound means the supplied token is not a live proxy session.
	ErrNotFound = errors.New("session not found")
	// ErrExpired means the stored session has passed its application expiry.
	ErrExpired = errors.New("session expired")
	// ErrAssertionReplayed means an OIDC assertion was already exchanged.
	ErrAssertionReplayed = errors.New("OIDC assertion already exchanged")
)

// Record is the authority bound to one opaque proxy token.
type Record struct {
	OrganizationID    string            `json:"organization_id"`
	PipelineID        string            `json:"pipeline_id"`
	BuildID           string            `json:"build_id"`
	JobID             string            `json:"job_id"`
	BuildBranch       string            `json:"build_branch"`
	BuildSource       string            `json:"build_source"`
	RunnerEnvironment string            `json:"runner_environment"`
	RepositoryID      int64             `json:"repository_id"`
	Repository        string            `json:"repository"`
	InstallationID    int64             `json:"installation_id"`
	Surface           string            `json:"surface"`
	Permissions       map[string]string `json:"permissions"`
	IssuedAt          time.Time         `json:"issued_at"`
	ExpiresAt         time.Time         `json:"expires_at"`
}

// RedisClient is the subset of go-redis used by RedisStore.
type RedisClient interface {
	Get(context.Context, string) *redis.StringCmd
	Set(context.Context, string, any, time.Duration) *redis.StatusCmd
	SetNX(context.Context, string, any, time.Duration) *redis.BoolCmd
}

// RedisStore stores only HMAC-derived session keys and JSON authority records.
type RedisStore struct {
	client  RedisClient
	hashKey []byte
	now     func() time.Time
	random  io.Reader
}

// Option customises RedisStore dependencies, primarily for tests.
type Option func(*RedisStore)

// WithNow overrides the store clock.
func WithNow(now func() time.Time) Option {
	return func(store *RedisStore) {
		store.now = now
	}
}

// WithRandom overrides the cryptographic random source.
func WithRandom(random io.Reader) Option {
	return func(store *RedisStore) {
		store.random = random
	}
}

// NewRedisStore creates a session store using a dedicated HMAC key.
func NewRedisStore(client RedisClient, hashKey []byte, options ...Option) (*RedisStore, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if len(hashKey) < minHashKey {
		return nil, fmt.Errorf("session hash key must be at least %d bytes", minHashKey)
	}

	store := &RedisStore{
		client:  client,
		hashKey: append([]byte(nil), hashKey...),
		now:     time.Now,
		random:  rand.Reader,
	}
	for _, option := range options {
		option(store)
	}
	return store, nil
}

// Issue creates and stores a new opaque token for record.
func (s *RedisStore) Issue(ctx context.Context, record Record) (string, error) {
	ttl := record.ExpiresAt.Sub(s.now())
	if ttl <= 0 {
		return "", ErrExpired
	}
	if err := validateRecord(record); err != nil {
		return "", err
	}

	random := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, random); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(random)
	value, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode session: %w", err)
	}
	if err := s.client.Set(ctx, s.sessionKey(token), value, ttl).Err(); err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}
	return token, nil
}

// Lookup returns the authority bound to token.
func (s *RedisStore) Lookup(ctx context.Context, token string) (Record, error) {
	if !validTokenShape(token) {
		return Record{}, ErrNotFound
	}

	value, err := s.client.Get(ctx, s.sessionKey(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("load session: %w", err)
	}

	var record Record
	if err := json.Unmarshal(value, &record); err != nil {
		return Record{}, fmt.Errorf("decode session: %w", err)
	}
	if !s.now().Before(record.ExpiresAt) {
		return Record{}, ErrExpired
	}
	return record, nil
}

// ConsumeAssertion atomically records that an OIDC assertion has been used.
func (s *RedisStore) ConsumeAssertion(ctx context.Context, assertion string, expiresAt time.Time) error {
	ttl := expiresAt.Sub(s.now())
	if ttl <= 0 {
		return ErrExpired
	}
	digest := sha256.Sum256([]byte(assertion))
	key := "assertion:" + hex.EncodeToString(digest[:])
	created, err := s.client.SetNX(ctx, key, "used", ttl).Result()
	if err != nil {
		return fmt.Errorf("record OIDC assertion: %w", err)
	}
	if !created {
		return ErrAssertionReplayed
	}
	return nil
}

func (s *RedisStore) sessionKey(token string) string {
	mac := hmac.New(sha256.New, s.hashKey)
	_, _ = mac.Write([]byte(token))
	return "session:" + hex.EncodeToString(mac.Sum(nil))
}

func validTokenShape(token string) bool {
	if !strings.HasPrefix(token, TokenPrefix) {
		return false
	}
	encoded := strings.TrimPrefix(token, TokenPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == tokenBytes
}

func validateRecord(record Record) error {
	if record.OrganizationID == "" || record.PipelineID == "" || record.BuildID == "" || record.JobID == "" {
		return errors.New("session identity is incomplete")
	}
	if record.RepositoryID <= 0 || record.Repository == "" || record.InstallationID <= 0 {
		return errors.New("session repository authority is incomplete")
	}
	if record.Surface == "" || len(record.Permissions) == 0 {
		return errors.New("session grant is incomplete")
	}
	return nil
}
