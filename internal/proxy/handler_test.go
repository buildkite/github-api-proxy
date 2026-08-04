package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buildkite/github-api-proxy/internal/githubapp"
	"github.com/buildkite/github-api-proxy/internal/session"
)

func TestHandlerForwardsOnlyTheBoundRepositoryAndAllowedHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/repos/example/repository" || request.URL.RawQuery != "" {
			t.Errorf("upstream request = %s %s?%s", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer github-installation-secret" {
			t.Errorf("Authorization = %q, want internal installation token", got)
		}
		if got := request.Header.Get("Cookie"); got != "" {
			t.Errorf("Cookie = %q, want stripped", got)
		}
		if got := request.Header.Get("X-Forwarded-Host"); got != "" {
			t.Errorf("X-Forwarded-Host = %q, want stripped", got)
		}
		if got := request.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q, want identity", got)
		}
		if got := request.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q, want forwarded", got)
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("ETag", `"repository-version"`)
		response.Header().Set("Set-Cookie", "secret=unexpected")
		response.Header().Set("X-GitHub-Request-Id", "github-request-id")
		_, _ = io.WriteString(response, `{"full_name":"example/repository"}`)
	}))
	t.Cleanup(upstream.Close)

	handler := newTestHandler(t, upstream, staticSessionStore{})
	request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository", nil)
	request.Header.Set("Authorization", "Bearer "+validProxyToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Cookie", "customer=secret")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("ETag"); got != `"repository-version"` {
		t.Fatalf("ETag = %q, want upstream ETag", got)
	}
	if got := response.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("Set-Cookie = %q, want stripped", got)
	}
	if got := response.Header().Get("X-GitHub-Request-Id"); got != "github-request-id" {
		t.Fatalf("X-GitHub-Request-Id = %q, want correlation ID", got)
	}
}

func TestHandlerRejectsCrossRepositoryRequestBeforeGitHub(t *testing.T) {
	t.Parallel()

	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	t.Cleanup(upstream.Close)
	handler := newTestHandler(t, upstream, staticSessionStore{})
	request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/other", nil)
	request.Header.Set("Authorization", "Bearer "+validProxyToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("GitHub upstream was called for a cross-repository request")
	}
}

func TestHandlerFailsClosedOnGitHubRedirect(t *testing.T) {
	t.Parallel()

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target received a GitHub credential")
	}))
	t.Cleanup(redirectTarget.Close)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", redirectTarget.URL)
		response.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(upstream.Close)
	handler := newTestHandler(t, upstream, staticSessionStore{})
	request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository", nil)
	request.Header.Set("Authorization", "Bearer "+validProxyToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if strings.Contains(response.Body.String(), redirectTarget.URL) {
		t.Fatal("response leaks redirect target")
	}
}

func TestHandlerRejectsUnsupportedRequestShapeBeforeGitHub(t *testing.T) {
	t.Parallel()

	tests := map[string]*http.Request{
		"query parameters": httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository?ref=main", nil),
		"request body":     httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository", strings.NewReader("unexpected")),
		"absolute form":    httptest.NewRequest(http.MethodGet, "https://proxy.example/api/v3/repos/example/repository", nil),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var called bool
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			t.Cleanup(upstream.Close)
			handler := newTestHandler(t, upstream, staticSessionStore{})
			request.Header.Set("Authorization", "Bearer "+validProxyToken)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
			if called {
				t.Fatal("GitHub upstream was called for an unsupported request")
			}
		})
	}
}

func TestHandlerRejectsOversizedGitHubResponseWithoutReturningPartialSuccess(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1))
	}))
	t.Cleanup(upstream.Close)
	handler := newTestHandler(t, upstream, staticSessionStore{})
	request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository", nil)
	request.Header.Set("Authorization", "Bearer "+validProxyToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if response.Body.Len() > 1024 {
		t.Fatalf("response body length = %d, want a bounded proxy error", response.Body.Len())
	}
}

func TestHandlerReportsSessionStoreOutageAsUnavailable(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(upstream.Close)
	handler := newTestHandler(t, upstream, failingSessionStore{})
	request := httptest.NewRequest(http.MethodGet, "/api/v3/repos/example/repository", nil)
	request.Header.Set("Authorization", "Bearer "+validProxyToken)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

const validProxyToken = "bkgp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type staticSessionStore struct{}

func (staticSessionStore) Lookup(context.Context, string) (session.Record, error) {
	return session.Record{
		RepositoryID:   123456789,
		Repository:     "example/repository",
		InstallationID: 987654321,
		Surface:        "ci-v1",
		Permissions:    map[string]string{"contents": "read"},
	}, nil
}

type failingSessionStore struct{}

func (failingSessionStore) Lookup(context.Context, string) (session.Record, error) {
	return session.Record{}, errors.New("Redis unavailable")
}

type staticTokenMinter struct{}

func (staticTokenMinter) InstallationToken(context.Context, githubapp.TokenRequest) (githubapp.Token, error) {
	return githubapp.Token{Value: "github-installation-secret", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func newTestHandler(t *testing.T, upstream *httptest.Server, sessions SessionStore) *Handler {
	t.Helper()
	handler, err := NewHandler(Config{
		Sessions:   sessions,
		Tokens:     staticTokenMinter{},
		Upstream:   upstream.URL,
		HTTPClient: upstream.Client(),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}
