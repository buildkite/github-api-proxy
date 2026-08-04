// Package proxy forwards a narrow GitHub REST surface using server-side credentials.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buildkite/github-api-proxy/internal/githubapp"
	"github.com/buildkite/github-api-proxy/internal/session"
	"github.com/buildkite/github-api-proxy/internal/surface"
)

const (
	defaultUpstream    = "https://api.github.com"
	defaultHTTPTimeout = 30 * time.Second
	apiPrefix          = "/api/v3"
	maxResponseBytes   = 8 << 20
)

var requestHeaders = []string{"Accept", "User-Agent", "X-GitHub-Api-Version"}

var responseHeaders = []string{
	"Content-Type",
	"Content-Disposition",
	"ETag",
	"Last-Modified",
	"Retry-After",
	"X-GitHub-Request-Id",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-RateLimit-Resource",
	"X-RateLimit-Used",
}

// SessionStore resolves an opaque proxy token to its bound authority.
type SessionStore interface {
	Lookup(context.Context, string) (session.Record, error)
}

// TokenMinter returns an attenuated GitHub App token for internal use.
type TokenMinter interface {
	InstallationToken(context.Context, githubapp.TokenRequest) (githubapp.Token, error)
}

// Config contains the fixed upstream and handler dependencies.
type Config struct {
	Sessions   SessionStore
	Tokens     TokenMinter
	Upstream   string
	HTTPClient *http.Client
}

// Handler implements Slice 1's exact read-only GitHub route.
type Handler struct {
	sessions SessionStore
	tokens   TokenMinter
	upstream *url.URL
	client   *http.Client
}

// NewHandler creates a fixed-origin proxy that never follows redirects.
func NewHandler(config Config) (*Handler, error) {
	if config.Sessions == nil || config.Tokens == nil {
		return nil, errors.New("proxy session store and token minter are required")
	}
	if config.Upstream == "" {
		config.Upstream = defaultUpstream
	}
	upstream, err := url.Parse(config.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("invalid GitHub upstream URL")
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
	return &Handler{
		sessions: config.Sessions,
		tokens:   config.Tokens,
		upstream: upstream,
		client:   client,
	}, nil
}

// ServeHTTP authenticates the proxy session and forwards one exact repository read.
func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	token, ok := proxyToken(request.Header.Get("Authorization"))
	if !ok {
		writeError(response, http.StatusUnauthorized, "invalid proxy authentication")
		return
	}
	record, err := h.sessions.Lookup(request.Context(), token)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
			writeError(response, http.StatusUnauthorized, "invalid proxy authentication")
		} else {
			writeError(response, http.StatusServiceUnavailable, "session unavailable")
		}
		return
	}
	if !validRequestShape(request) {
		writeError(response, http.StatusForbidden, "route denied")
		return
	}
	escapedPath := request.URL.EscapedPath()
	if !strings.HasPrefix(escapedPath, apiPrefix) {
		writeError(response, http.StatusForbidden, "route denied")
		return
	}
	relativePath := strings.TrimPrefix(escapedPath, apiPrefix)
	if record.Surface != "ci-v1" || record.Permissions["contents"] != "read" || surface.MatchRepositoryRead(request.Method, relativePath, record.Repository) != nil {
		writeError(response, http.StatusForbidden, "route denied")
		return
	}

	installationToken, err := h.tokens.InstallationToken(request.Context(), githubapp.TokenRequest{
		InstallationID: record.InstallationID,
		RepositoryID:   record.RepositoryID,
		Permissions:    record.Permissions,
	})
	if err != nil {
		writeError(response, http.StatusBadGateway, "GitHub authentication failed")
		return
	}
	upstreamResponse, err := h.forward(request, relativePath, installationToken.Value)
	if err != nil {
		writeError(response, http.StatusBadGateway, "GitHub request failed")
		return
	}
	defer func() { _ = upstreamResponse.Body.Close() }()
	if upstreamResponse.StatusCode >= http.StatusMultipleChoices && upstreamResponse.StatusCode < http.StatusBadRequest {
		writeError(response, http.StatusBadGateway, "GitHub redirect denied")
		return
	}
	body, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		writeError(response, http.StatusBadGateway, "GitHub response invalid")
		return
	}

	copyResponseHeaders(response.Header(), upstreamResponse.Header)
	response.WriteHeader(upstreamResponse.StatusCode)
	_, _ = response.Write(body)
}

func validRequestShape(request *http.Request) bool {
	return !request.URL.IsAbs() && request.URL.Host == "" && request.URL.Opaque == "" &&
		request.URL.RawQuery == "" && !request.URL.ForceQuery &&
		(request.Body == nil || request.Body == http.NoBody)
}

func (h *Handler) forward(original *http.Request, escapedPath, installationToken string) (*http.Response, error) {
	upstream := *h.upstream
	upstream.Path = escapedPath
	upstream.RawPath = escapedPath
	upstream.RawQuery = ""
	request, err := http.NewRequestWithContext(original.Context(), http.MethodGet, upstream.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	for _, name := range requestHeaders {
		if value := original.Header.Get(name); value != "" {
			request.Header.Set(name, value)
		}
	}
	userAgent := strings.TrimSpace(request.Header.Get("User-Agent"))
	if userAgent == "" {
		userAgent = "buildkite-github-api-proxy"
	} else {
		userAgent += " buildkite-github-api-proxy"
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Authorization", "Bearer "+installationToken)
	request.Header.Set("Accept-Encoding", "identity")
	return h.client.Do(request)
}

func proxyToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || (!strings.EqualFold(parts[0], "Bearer") && !strings.EqualFold(parts[0], "token")) || !strings.HasPrefix(parts[1], session.TokenPrefix) {
		return "", false
	}
	return parts[1], true
}

func copyResponseHeaders(destination, source http.Header) {
	for _, name := range responseHeaders {
		for _, value := range source.Values(name) {
			destination.Add(name, value)
		}
	}
}

func writeError(response http.ResponseWriter, status int, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = fmt.Fprintf(response, "{\"message\":%q}\n", message)
}
