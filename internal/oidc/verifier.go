// Package oidc verifies Buildkite Job OIDC identity assertions.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	maxAssertionBytes  = 16 << 10
	maxJWKSBytes       = 1 << 20
	defaultHTTPTimeout = 5 * time.Second
)

// Config fixes the OIDC trust anchor and validation bounds.
type Config struct {
	Issuer             string
	Audience           string
	JWKSURL            string
	HTTPClient         *http.Client
	Now                func() time.Time
	ClockSkew          time.Duration
	MinimumLifetime    time.Duration
	MinRefreshInterval time.Duration
}

// Identity contains the signed Buildkite workload and policy inputs.
type Identity struct {
	Subject           string
	OrganizationID    string
	PipelineID        string
	BuildID           string
	JobID             string
	BuildBranch       string
	BuildSource       string
	RunnerEnvironment string
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

// Verifier validates assertions against a bounded fixed JWKS source.
type Verifier struct {
	issuer          string
	audience        string
	jwksURL         string
	client          *http.Client
	now             func() time.Time
	clockSkew       time.Duration
	minimumLifetime time.Duration
	refreshInterval time.Duration

	mu              sync.RWMutex
	keys            map[string]*rsa.PublicKey
	lastMissRefresh time.Time
}

type tokenClaims struct {
	jwt.Claims
	OrganizationID    string `json:"organization_id"`
	PipelineID        string `json:"pipeline_id"`
	BuildID           string `json:"build_id"`
	JobID             string `json:"job_id"`
	BuildBranch       string `json:"build_branch"`
	BuildSource       string `json:"build_source"`
	RunnerEnvironment string `json:"runner_environment"`
}

// NewVerifier loads the initial fixed JWKS before accepting assertions.
func NewVerifier(ctx context.Context, config Config) (*Verifier, error) {
	if config.Issuer == "" || config.Audience == "" || config.JWKSURL == "" {
		return nil, errors.New("OIDC issuer, audience, and JWKS URL are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ClockSkew < 0 || config.MinimumLifetime <= 0 || config.MinRefreshInterval <= 0 {
		return nil, errors.New("OIDC validation durations are invalid")
	}

	client := &http.Client{Timeout: defaultHTTPTimeout}
	if config.HTTPClient != nil {
		clone := *config.HTTPClient
		client = &clone
		if client.Timeout == 0 {
			client.Timeout = defaultHTTPTimeout
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	verifier := &Verifier{
		issuer:          config.Issuer,
		audience:        config.Audience,
		jwksURL:         config.JWKSURL,
		client:          client,
		now:             config.Now,
		clockSkew:       config.ClockSkew,
		minimumLifetime: config.MinimumLifetime,
		refreshInterval: config.MinRefreshInterval,
	}
	keys, err := verifier.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	verifier.keys = keys
	return verifier, nil
}

// Verify validates signature, exact audience, time bounds, and required claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if len(raw) == 0 || len(raw) > maxAssertionBytes {
		return Identity{}, errors.New("OIDC assertion has invalid size")
	}
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Identity{}, fmt.Errorf("parse OIDC assertion: %v", err)
	}
	if len(token.Headers) != 1 || token.Headers[0].KeyID == "" || token.Headers[0].Algorithm != string(jose.RS256) {
		return Identity{}, errors.New("OIDC assertion has invalid protected headers")
	}
	key, err := v.key(ctx, token.Headers[0].KeyID)
	if err != nil {
		return Identity{}, err
	}

	var claims tokenClaims
	if err := token.Claims(key, &claims); err != nil {
		return Identity{}, errors.New("verify OIDC assertion")
	}
	if err := v.validateClaims(claims); err != nil {
		return Identity{}, err
	}
	return Identity{
		Subject:           claims.Subject,
		OrganizationID:    claims.OrganizationID,
		PipelineID:        claims.PipelineID,
		BuildID:           claims.BuildID,
		JobID:             claims.JobID,
		BuildBranch:       claims.BuildBranch,
		BuildSource:       claims.BuildSource,
		RunnerEnvironment: claims.RunnerEnvironment,
		IssuedAt:          claims.IssuedAt.Time(),
		ExpiresAt:         claims.Expiry.Time(),
	}, nil
}

func (v *Verifier) key(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[keyID]
	lastMissRefresh := v.lastMissRefresh
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if !lastMissRefresh.IsZero() && v.now().Sub(lastMissRefresh) < v.refreshInterval {
		return nil, errors.New("OIDC signing key not found")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if key = v.keys[keyID]; key != nil {
		return key, nil
	}
	if !v.lastMissRefresh.IsZero() && v.now().Sub(v.lastMissRefresh) < v.refreshInterval {
		return nil, errors.New("OIDC signing key not found")
	}
	v.lastMissRefresh = v.now()
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	v.keys = keys
	key = keys[keyID]
	if key == nil {
		return nil, errors.New("OIDC signing key not found")
	}
	return key, nil
}

func (v *Verifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("read JWKS: response too large")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, webKey := range set.Keys {
		if webKey.KeyID == "" || webKey.Use != "sig" || webKey.Algorithm != string(jose.RS256) {
			continue
		}
		publicKey, ok := webKey.Key.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if _, duplicate := keys[webKey.KeyID]; duplicate {
			return nil, fmt.Errorf("decode JWKS: duplicate key ID %q", webKey.KeyID)
		}
		keys[webKey.KeyID] = publicKey
	}
	if len(keys) == 0 {
		return nil, errors.New("decode JWKS: no RS256 signing keys")
	}
	return keys, nil
}

func (v *Verifier) validateClaims(claims tokenClaims) error {
	if claims.Issuer != v.issuer {
		return errors.New("OIDC assertion has invalid issuer")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != v.audience {
		return errors.New("OIDC assertion has invalid audience")
	}
	if claims.Subject == "" || claims.Subject != claims.JobID {
		return errors.New("OIDC assertion subject must equal job_id")
	}
	if claims.OrganizationID == "" || claims.PipelineID == "" || claims.BuildID == "" || claims.JobID == "" ||
		claims.BuildBranch == "" || claims.BuildSource == "" || claims.RunnerEnvironment == "" {
		return errors.New("OIDC assertion is missing required claims")
	}
	if claims.Expiry == nil || claims.NotBefore == nil || claims.IssuedAt == nil {
		return errors.New("OIDC assertion is missing required time claims")
	}

	now := v.now()
	expiresAt := claims.Expiry.Time()
	if !now.Before(expiresAt.Add(v.clockSkew)) {
		return errors.New("OIDC assertion has expired")
	}
	if now.Add(v.clockSkew).Before(claims.NotBefore.Time()) {
		return errors.New("OIDC assertion is not yet valid")
	}
	if now.Add(v.clockSkew).Before(claims.IssuedAt.Time()) {
		return errors.New("OIDC assertion was issued in the future")
	}
	if expiresAt.Sub(now) < v.minimumLifetime {
		return errors.New("OIDC assertion has insufficient remaining lifetime")
	}
	return nil
}
