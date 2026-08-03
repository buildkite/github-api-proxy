package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buildkite/github-api-proxy/internal/oidc"
	"github.com/buildkite/github-api-proxy/internal/policy"
	"github.com/buildkite/github-api-proxy/internal/session"
)

func TestHandlerExchangesOIDCForBoundOpaqueSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	handler, err := NewHandler(Config{
		Verifier: verifierFunc(func(context.Context, string) (oidc.Identity, error) {
			return validIdentity(now), nil
		}),
		Authorizer: authorizerFunc(func(identity policy.Identity, request policy.Request) (policy.Grant, error) {
			if identity.PipelineID != "pipeline-id" || request.Repository != "example/repository" {
				t.Fatalf("Authorize() identity/request = %#v / %#v", identity, request)
			}
			return policy.Grant{
				RepositoryID:   123456789,
				Repository:     request.Repository,
				InstallationID: 987654321,
				Surface:        request.Surface,
				Permissions:    request.Permissions,
			}, nil
		}),
		Sessions:   store,
		APIURL:     "https://proxy.example/api/v3",
		GraphQLURL: "https://proxy.example/api/graphql",
		SessionTTL: 15 * time.Minute,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://proxy.example/v1/token", strings.NewReader(`{
		"repository":"example/repository",
		"surface":"ci-v1",
		"permissions":{"contents":"read"}
	}`))
	request.Header.Set("Authorization", "Bearer signed.buildkite.oidc")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var payload Response
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.AccessToken != validIssuedToken || payload.TokenType != "Bearer" || payload.ExpiresIn != 300 {
		t.Fatalf("response = %#v, want five-minute opaque session", payload)
	}
	if store.assertion != "signed.buildkite.oidc" || !store.assertionExpiry.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("consumed assertion = %q until %s", store.assertion, store.assertionExpiry)
	}
	if store.record.RepositoryID != 123456789 || store.record.Permissions["contents"] != "read" || !store.record.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("issued record = %#v, want OIDC-bounded grant", store.record)
	}
	if strings.Contains(response.Body.String(), "signed.buildkite.oidc") {
		t.Fatal("exchange response leaks the OIDC assertion")
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestHandlerRejectsPolicyDenialWithoutIssuingSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	handler, err := NewHandler(Config{
		Verifier: verifierFunc(func(context.Context, string) (oidc.Identity, error) {
			return validIdentity(now), nil
		}),
		Authorizer: authorizerFunc(func(policy.Identity, policy.Request) (policy.Grant, error) {
			return policy.Grant{}, policy.ErrDenied
		}),
		Sessions:   store,
		APIURL:     "https://proxy.example/api/v3",
		GraphQLURL: "https://proxy.example/api/graphql",
		SessionTTL: 15 * time.Minute,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://proxy.example/v1/token", strings.NewReader(`{"repository":"example/other","surface":"ci-v1","permissions":{"contents":"read"}}`))
	request.Header.Set("Authorization", "Bearer signed.buildkite.oidc")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if store.assertion != "" || store.record.JobID != "" {
		t.Fatal("policy denial consumed an assertion or issued a session")
	}
}

func TestHandlerReportsAssertionStoreOutageAsUnavailable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{consumeErr: errors.New("Redis unavailable")}
	handler, err := NewHandler(Config{
		Verifier: verifierFunc(func(context.Context, string) (oidc.Identity, error) {
			return validIdentity(now), nil
		}),
		Authorizer: authorizerFunc(func(_ policy.Identity, request policy.Request) (policy.Grant, error) {
			return policy.Grant{
				RepositoryID:   123456789,
				Repository:     request.Repository,
				InstallationID: 987654321,
				Surface:        request.Surface,
				Permissions:    request.Permissions,
			}, nil
		}),
		Sessions:   store,
		APIURL:     "https://proxy.example/api/v3",
		GraphQLURL: "https://proxy.example/api/graphql",
		SessionTTL: 15 * time.Minute,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/token", strings.NewReader(`{"repository":"example/repository","surface":"ci-v1","permissions":{"contents":"read"}}`))
	request.Header.Set("Authorization", "Bearer signed.buildkite.oidc")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

const validIssuedToken = "bkgp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type verifierFunc func(context.Context, string) (oidc.Identity, error)

func (function verifierFunc) Verify(ctx context.Context, raw string) (oidc.Identity, error) {
	return function(ctx, raw)
}

type authorizerFunc func(policy.Identity, policy.Request) (policy.Grant, error)

func (function authorizerFunc) Authorize(identity policy.Identity, request policy.Request) (policy.Grant, error) {
	return function(identity, request)
}

type recordingStore struct {
	assertion       string
	assertionExpiry time.Time
	record          session.Record
	consumeErr      error
}

func (store *recordingStore) ConsumeAssertion(_ context.Context, assertion string, expiresAt time.Time) error {
	if store.consumeErr != nil {
		return store.consumeErr
	}
	if store.assertion != "" {
		return session.ErrAssertionReplayed
	}
	store.assertion = assertion
	store.assertionExpiry = expiresAt
	return nil
}

func (store *recordingStore) Issue(_ context.Context, record session.Record) (string, error) {
	if record.JobID == "" {
		return "", errors.New("missing job ID")
	}
	store.record = record
	return validIssuedToken, nil
}

func validIdentity(now time.Time) oidc.Identity {
	return oidc.Identity{
		Subject:           "job-id",
		OrganizationID:    "org-id",
		PipelineID:        "pipeline-id",
		BuildID:           "build-id",
		JobID:             "job-id",
		BuildBranch:       "main",
		BuildSource:       "ui",
		RunnerEnvironment: "buildkite-hosted",
		IssuedAt:          now,
		ExpiresAt:         now.Add(5 * time.Minute),
	}
}
