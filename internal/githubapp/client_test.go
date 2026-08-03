package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientMintsRepositoryAttenuatedInstallationToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

	var got mintRequest
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/app/installations/987654321/access_tokens" {
			t.Errorf("request = %s %s, want installation token endpoint", request.Method, request.URL.Path)
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("Authorization = %q, want Bearer app JWT", request.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"token":                "github-installation-secret",
			"expires_at":           now.Add(time.Hour).Format(time.RFC3339),
			"permissions":          map[string]string{"contents": "read", "metadata": "read"},
			"repository_selection": "selected",
			"repositories":         []map[string]any{{"id": int64(123456789)}},
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(Config{
		AppID:      1234,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	token, err := client.InstallationToken(context.Background(), TokenRequest{
		InstallationID: 987654321,
		RepositoryID:   123456789,
		Permissions:    map[string]string{"contents": "read"},
	})
	if err != nil {
		t.Fatalf("InstallationToken() error = %v", err)
	}
	if token.Value != "github-installation-secret" || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("InstallationToken() = %#v, want upstream token and expiry", token)
	}
	if len(got.RepositoryIDs) != 1 || got.RepositoryIDs[0] != 123456789 {
		t.Fatalf("repository_ids = %#v, want numeric repository ID only", got.RepositoryIDs)
	}
	if got.Permissions["contents"] != "read" {
		t.Fatalf("permissions = %#v, want exact contents:read", got.Permissions)
	}
}

func TestClientRejectsInstallationTokenWithUnexpectedAuthority(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"token":                "github-installation-secret",
			"expires_at":           now.Add(time.Hour).Format(time.RFC3339),
			"permissions":          map[string]string{"contents": "write", "metadata": "read"},
			"repository_selection": "selected",
			"repositories":         []map[string]any{{"id": int64(123456789)}},
		})
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{
		AppID:      1234,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.InstallationToken(context.Background(), TokenRequest{
		InstallationID: 987654321,
		RepositoryID:   123456789,
		Permissions:    map[string]string{"contents": "read"},
	})
	if err == nil {
		t.Fatal("InstallationToken() error = nil, want unexpected authority error")
	}
}

func TestClientRejectsInstallationWideToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"token":                "github-installation-secret",
			"expires_at":           now.Add(time.Hour).Format(time.RFC3339),
			"permissions":          map[string]string{"contents": "read", "metadata": "read"},
			"repository_selection": "all",
			"repositories":         []map[string]any{{"id": int64(123456789)}},
		})
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{
		AppID:      1234,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.InstallationToken(context.Background(), TokenRequest{
		InstallationID: 987654321,
		RepositoryID:   123456789,
		Permissions:    map[string]string{"contents": "read"},
	})
	if err == nil {
		t.Fatal("InstallationToken() error = nil, want installation-wide authority error")
	}
}

func TestClientDoesNotLeakInstallationTokenInErrors(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"message":"token github-installation-secret rejected"}`))
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{
		AppID:      1234,
		PrivateKey: privateKey,
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		Now:        time.Now,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	_, err = client.InstallationToken(context.Background(), TokenRequest{
		InstallationID: 987654321,
		RepositoryID:   123456789,
		Permissions:    map[string]string{"contents": "read"},
	})
	if err == nil {
		t.Fatal("InstallationToken() error = nil, want upstream error")
	}
	if strings.Contains(err.Error(), "github-installation-secret") {
		t.Fatalf("InstallationToken() error leaks upstream body: %v", err)
	}
}
