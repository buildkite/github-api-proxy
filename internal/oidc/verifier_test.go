package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestVerifierAcceptsBuildkiteIdentity(t *testing.T) {
	t.Parallel()

	fixture := newOIDCFixture(t)
	verifier := fixture.verifier(t)
	token := fixture.sign(t, claimsAt(fixture.now))

	identity, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if identity.Subject != "job-id" || identity.PipelineID != "pipeline-id" || identity.BuildBranch != "main" {
		t.Fatalf("Verify() = %#v, want signed Buildkite identity", identity)
	}
}

func TestVerifierFailsClosedOnInvalidClaims(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*tokenClaims){
		"wrong issuer":             func(claims *tokenClaims) { claims.Issuer = "https://attacker.example" },
		"additional audience":      func(claims *tokenClaims) { claims.Audience = jwt.Audience{testAudience, "another-audience"} },
		"subject differs from job": func(claims *tokenClaims) { claims.Subject = "another-job" },
		"missing pipeline ID":      func(claims *tokenClaims) { claims.PipelineID = "" },
		"missing build branch":     func(claims *tokenClaims) { claims.BuildBranch = "" },
		"missing build source":     func(claims *tokenClaims) { claims.BuildSource = "" },
		"missing runner":           func(claims *tokenClaims) { claims.RunnerEnvironment = "" },
		"future issued-at": func(claims *tokenClaims) {
			claims.IssuedAt = jwt.NewNumericDate(claims.IssuedAt.Time().Add(time.Minute))
		},
		"not enough lifetime": func(claims *tokenClaims) {
			claims.Expiry = jwt.NewNumericDate(claims.IssuedAt.Time().Add(20 * time.Second))
		},
	}

	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newOIDCFixture(t)
			verifier := fixture.verifier(t)
			claims := claimsAt(fixture.now)
			change(&claims)
			if _, err := verifier.Verify(context.Background(), fixture.sign(t, claims)); err == nil {
				t.Fatal("Verify() error = nil, want claim validation error")
			}
		})
	}
}

func TestVerifierRefreshesUnknownKeyAtMostOncePerInterval(t *testing.T) {
	t.Parallel()

	fixture := newOIDCFixture(t)
	verifier := fixture.verifier(t)
	unknownKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	if _, err := verifier.Verify(context.Background(), signToken(t, unknownKey, "unknown-1", claimsAt(fixture.now))); err == nil {
		t.Fatal("Verify() error = nil, want unknown key error")
	}
	if _, err := verifier.Verify(context.Background(), signToken(t, unknownKey, "unknown-2", claimsAt(fixture.now))); err == nil {
		t.Fatal("Verify() error = nil, want unknown key error")
	}
	if got := fixture.requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch plus one bounded refresh", got)
	}
}

func TestVerifierRefreshesKnownKeyAfterRefreshInterval(t *testing.T) {
	t.Parallel()

	fixture := newOIDCFixture(t)
	retiredKey := fixture.key
	verifier := fixture.verifier(t)
	replacementKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	fixture.key = replacementKey
	fixture.now = fixture.now.Add(6 * time.Minute)
	claims := claimsAt(fixture.now)

	if _, err := verifier.Verify(context.Background(), signToken(t, replacementKey, "buildkite-key", claims)); err != nil {
		t.Fatalf("Verify() replacement key error = %v", err)
	}
	if _, err := verifier.Verify(context.Background(), signToken(t, retiredKey, "buildkite-key", claims)); err == nil {
		t.Fatal("Verify() retired key error = nil, want signature rejection")
	}
	if got := fixture.requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch plus cache refresh", got)
	}
}

func TestVerifierDoesNotUseExpiredKeysWhenRefreshFails(t *testing.T) {
	t.Parallel()

	fixture := newOIDCFixture(t)
	verifier := fixture.verifier(t)
	fixture.jwksStatus.Store(http.StatusServiceUnavailable)
	fixture.now = fixture.now.Add(6 * time.Minute)

	if _, err := verifier.Verify(context.Background(), fixture.sign(t, claimsAt(fixture.now))); err == nil {
		t.Fatal("Verify() error = nil, want stale key rejection")
	}
	if got := fixture.requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch plus failed cache refresh", got)
	}
}

const (
	testIssuer   = "https://agent.buildkite.com"
	testAudience = "https://github-api-proxy.buildkite.com"
)

type oidcFixture struct {
	now        time.Time
	key        *rsa.PrivateKey
	server     *httptest.Server
	requests   atomic.Int64
	jwksStatus atomic.Int64
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	fixture := &oidcFixture{
		now: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
		key: key,
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fixture.requests.Add(1)
		if status := fixture.jwksStatus.Load(); status != 0 {
			response.WriteHeader(int(status))
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &fixture.key.PublicKey,
			KeyID:     "buildkite-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *oidcFixture) verifier(t *testing.T) *Verifier {
	t.Helper()

	verifier, err := NewVerifier(context.Background(), Config{
		Issuer:          testIssuer,
		Audience:        testAudience,
		JWKSURL:         f.server.URL,
		HTTPClient:      f.server.Client(),
		Now:             func() time.Time { return f.now },
		ClockSkew:       30 * time.Second,
		MinimumLifetime: 30 * time.Second,
		RefreshInterval: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func (f *oidcFixture) sign(t *testing.T, claims tokenClaims) string {
	t.Helper()
	return signToken(t, f.key, "buildkite-key", claims)
}

func claimsAt(now time.Time) tokenClaims {
	return tokenClaims{
		Claims: jwt.Claims{
			Issuer:    testIssuer,
			Subject:   "job-id",
			Audience:  jwt.Audience{testAudience},
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		OrganizationID:    "org-id",
		PipelineID:        "pipeline-id",
		BuildID:           "build-id",
		JobID:             "job-id",
		BuildBranch:       "main",
		BuildSource:       "ui",
		RunnerEnvironment: "buildkite-hosted",
	}
}

func signToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims tokenClaims) string {
	t.Helper()

	options := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}
	return token
}
