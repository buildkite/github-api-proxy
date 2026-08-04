package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouteHandlerDoesNotCanonicalizeRequestPaths(t *testing.T) {
	t.Parallel()

	exchange := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
	})
	proxy := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
	})
	ready := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	handler := routeHandler(exchange, proxy, ready)

	tests := map[string]struct {
		target     string
		wantStatus int
	}{
		"exchange":       {target: "/v1/token", wantStatus: http.StatusCreated},
		"proxy":          {target: "/api/v3/repos/example/repository", wantStatus: http.StatusForbidden},
		"dot path":       {target: "/api/v3/repos/example/../other", wantStatus: http.StatusForbidden},
		"duplicate path": {target: "//api/v3/repos/example/repository", wantStatus: http.StatusNotFound},
		"readiness":      {target: "/readyz", wantStatus: http.StatusNoContent},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if location := response.Header().Get("Location"); location != "" {
				t.Fatalf("Location = %q, want no canonical redirect", location)
			}
		})
	}
}

func TestLoadConfigRejectsPublicURLWithPath(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"GITHUB_API_PROXY_PUBLIC_URL":             "https://proxy.example/base/",
		"GITHUB_API_PROXY_REDIS_URL":              "redis://redis.example/0",
		"GITHUB_API_PROXY_POLICY_PATH":            "policy.yml",
		"GITHUB_API_PROXY_SESSION_HASH_KEY":       "a sufficiently long dedicated session hash key",
		"GITHUB_API_PROXY_GITHUB_APP_ID":          "1234",
		"GITHUB_API_PROXY_GITHUB_APP_PRIVATE_KEY": "private key",
	}

	_, err := loadConfig(func(name string) string { return values[name] })
	if err == nil {
		t.Fatal("loadConfig() error = nil, want invalid public URL error")
	}
}
