package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisStoreIssueAndLookup(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := NewRedisStore(client, []byte("a sufficiently long dedicated session hash key"), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	record := Record{
		OrganizationID:    "org-id",
		PipelineID:        "pipeline-id",
		BuildID:           "build-id",
		JobID:             "job-id",
		BuildBranch:       "main",
		BuildSource:       "ui",
		RunnerEnvironment: "buildkite-hosted",
		RepositoryID:      123456789,
		Repository:        "example/repository",
		InstallationID:    987654321,
		Surface:           "ci-v1",
		Permissions:       map[string]string{"contents": "read"},
		IssuedAt:          now,
		ExpiresAt:         now.Add(15 * time.Minute),
	}

	token, err := store.Issue(context.Background(), record)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("Issue() token = %q, want prefix %q", token, TokenPrefix)
	}
	if strings.Contains(redisServer.Dump(), token) {
		t.Fatal("Redis contains the plaintext session token")
	}

	got, err := store.Lookup(context.Background(), token)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got.Repository != record.Repository || got.JobID != record.JobID {
		t.Fatalf("Lookup() = %#v, want repository %q and job %q", got, record.Repository, record.JobID)
	}
	if got.Permissions["contents"] != "read" {
		t.Fatalf("Lookup() permissions = %#v, want contents:read", got.Permissions)
	}
}

func TestRedisStoreRejectsExpiredRecordEvenWhenRedisReturnsIt(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := NewRedisStore(client, []byte("a sufficiently long dedicated session hash key"), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	token, err := store.Issue(context.Background(), validRecord(now))
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	now = now.Add(16 * time.Minute)

	_, err = store.Lookup(context.Background(), token)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Lookup() error = %v, want %v", err, ErrExpired)
	}
}

func TestRedisStoreConsumesAssertionOnce(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := NewRedisStore(client, []byte("a sufficiently long dedicated session hash key"), WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	if err := store.ConsumeAssertion(context.Background(), "signed.jwt.value", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("first ConsumeAssertion() error = %v", err)
	}
	if err := store.ConsumeAssertion(context.Background(), "signed.jwt.value", now.Add(5*time.Minute)); !errors.Is(err, ErrAssertionReplayed) {
		t.Fatalf("second ConsumeAssertion() error = %v, want %v", err, ErrAssertionReplayed)
	}
}

func TestRedisStoreRejectsInvalidTokenWithoutRedisLookup(t *testing.T) {
	t.Parallel()

	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	store, err := NewRedisStore(client, []byte("a sufficiently long dedicated session hash key"))
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	_, err = store.Lookup(context.Background(), "github-token-shaped-value")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup() error = %v, want %v", err, ErrNotFound)
	}
}

func validRecord(now time.Time) Record {
	return Record{
		OrganizationID:    "org-id",
		PipelineID:        "pipeline-id",
		BuildID:           "build-id",
		JobID:             "job-id",
		BuildBranch:       "main",
		BuildSource:       "ui",
		RunnerEnvironment: "buildkite-hosted",
		RepositoryID:      123456789,
		Repository:        "example/repository",
		InstallationID:    987654321,
		Surface:           "ci-v1",
		Permissions:       map[string]string{"contents": "read"},
		IssuedAt:          now,
		ExpiresAt:         now.Add(15 * time.Minute),
	}
}
