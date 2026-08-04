package surface

import (
	"errors"
	"net/http"
	"testing"
)

func TestMatchRepositoryRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method      string
		escapedPath string
		repository  string
		wantErr     error
	}{
		"exact route": {
			method:      http.MethodGet,
			escapedPath: "/repos/example/repository",
			repository:  "example/repository",
		},
		"wrong method": {
			method:      http.MethodPost,
			escapedPath: "/repos/example/repository",
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
		"different repository": {
			method:      http.MethodGet,
			escapedPath: "/repos/example/other",
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
		"encoded path": {
			method:      http.MethodGet,
			escapedPath: "/repos/example%2Frepository",
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
		"duplicate slash": {
			method:      http.MethodGet,
			escapedPath: "/repos//example/repository",
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
		"backslash": {
			method:      http.MethodGet,
			escapedPath: `/repos/example\repository`,
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
		"extra path": {
			method:      http.MethodGet,
			escapedPath: "/repos/example/repository/issues",
			repository:  "example/repository",
			wantErr:     ErrRouteDenied,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := MatchRepositoryRead(test.method, test.escapedPath, test.repository)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("MatchRepositoryRead() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestMatchRepositoryReadRejectsInvalidPolicyRepository(t *testing.T) {
	t.Parallel()

	err := MatchRepositoryRead(http.MethodGet, "/repos/example/repository/extra", "example/repository/extra")
	if !errors.Is(err, ErrInvalidRepository) {
		t.Fatalf("MatchRepositoryRead() error = %v, want %v", err, ErrInvalidRepository)
	}
}
