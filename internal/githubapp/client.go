// Package githubapp mints repository-attenuated GitHub App installation tokens.
package githubapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	defaultBaseURL     = "https://api.github.com"
	defaultHTTPTimeout = 10 * time.Second
	maxResponseBytes   = 1 << 20
)

// Config contains the dedicated GitHub App signing identity.
type Config struct {
	AppID      int64
	PrivateKey *rsa.PrivateKey
	BaseURL    string
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client mints GitHub App installation tokens without exposing them to callers outside the service.
type Client struct {
	appID      int64
	privateKey *rsa.PrivateKey
	baseURL    *url.URL
	client     *http.Client
	now        func() time.Time
}

// TokenRequest is an exact repository and permission attenuation request.
type TokenRequest struct {
	InstallationID int64
	RepositoryID   int64
	Permissions    map[string]string
}

// Token is a short-lived GitHub installation credential for internal proxy use.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

type mintRequest struct {
	RepositoryIDs []int64           `json:"repository_ids"`
	Permissions   map[string]string `json:"permissions"`
}

type mintResponse struct {
	Token        string            `json:"token"`
	ExpiresAt    time.Time         `json:"expires_at"`
	Permissions  map[string]string `json:"permissions"`
	Repositories []struct {
		ID int64 `json:"id"`
	} `json:"repositories"`
}

// NewClient creates a dedicated GitHub App client with redirects disabled.
func NewClient(config Config) (*Client, error) {
	if config.AppID <= 0 || config.PrivateKey == nil {
		return nil, errors.New("GitHub App ID and private key are required")
	}
	if config.BaseURL == "" {
		config.BaseURL = defaultBaseURL
	}
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("invalid GitHub API base URL")
	}
	if config.Now == nil {
		config.Now = time.Now
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
	return &Client{
		appID:      config.AppID,
		privateKey: config.PrivateKey,
		baseURL:    baseURL,
		client:     client,
		now:        config.Now,
	}, nil
}

// InstallationToken mints a token for one immutable repository ID and exact permissions.
func (c *Client) InstallationToken(ctx context.Context, request TokenRequest) (Token, error) {
	if request.InstallationID <= 0 || request.RepositoryID <= 0 || len(request.Permissions) == 0 {
		return Token{}, errors.New("installation token request is incomplete")
	}
	for name, level := range request.Permissions {
		if name == "" || (level != "read" && level != "write") {
			return Token{}, errors.New("installation token request has invalid permissions")
		}
	}

	appJWT, err := c.signAppJWT()
	if err != nil {
		return Token{}, err
	}
	body, err := json.Marshal(mintRequest{
		RepositoryIDs: []int64{request.RepositoryID},
		Permissions:   request.Permissions,
	})
	if err != nil {
		return Token{}, fmt.Errorf("encode installation token request: %w", err)
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/app/installations/" + strconv.FormatInt(request.InstallationID, 10) + "/access_tokens"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return Token{}, fmt.Errorf("create installation token request: %w", err)
	}
	httpRequest.Header.Set("Accept", "application/vnd.github+json")
	httpRequest.Header.Set("Authorization", "Bearer "+appJWT)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "buildkite-github-api-proxy")
	httpRequest.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	response, err := c.client.Do(httpRequest)
	if err != nil {
		return Token{}, fmt.Errorf("mint installation token: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return Token{}, fmt.Errorf("mint installation token: unexpected status %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return Token{}, fmt.Errorf("read installation token response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
		return Token{}, errors.New("read installation token response: response too large")
	}
	var payload mintResponse
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return Token{}, errors.New("decode installation token response")
	}
	if payload.Token == "" || !payload.ExpiresAt.After(c.now()) || !matchesAuthority(payload, request) {
		return Token{}, errors.New("installation token response is incomplete")
	}
	return Token{Value: payload.Token, ExpiresAt: payload.ExpiresAt}, nil
}

func matchesAuthority(response mintResponse, request TokenRequest) bool {
	if len(response.Repositories) != 1 || response.Repositories[0].ID != request.RepositoryID {
		return false
	}
	for name, level := range request.Permissions {
		if response.Permissions[name] != level {
			return false
		}
	}
	for name, level := range response.Permissions {
		if requested, ok := request.Permissions[name]; ok && requested == level {
			continue
		}
		if name != "metadata" || level != "read" {
			return false
		}
	}
	return true
}

func (c *Client) signAppJWT() (string, error) {
	now := c.now()
	claims := jwt.Claims{
		Issuer:   strconv.FormatInt(c.appID, 10),
		IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)),
		Expiry:   jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: c.privateKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("create GitHub App signer: %w", err)
	}
	value, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return value, nil
}
