// Package surface defines the versioned GitHub REST routes a session may use.
package surface

import (
	"errors"
	"net/http"
	"strings"
)

var (
	// ErrRouteDenied means a request is outside the selected API surface.
	ErrRouteDenied = errors.New("route denied")
	// ErrInvalidRepository means server policy contains an unsafe repository name.
	ErrInvalidRepository = errors.New("invalid policy repository")
)

// MatchRepositoryRead accepts only Slice 1's exact repository-read route.
func MatchRepositoryRead(method, escapedPath, repository string) error {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(repository, `%\`) {
		return ErrInvalidRepository
	}
	if method != http.MethodGet || strings.Contains(escapedPath, "%") || strings.Contains(escapedPath, `\`) || strings.Contains(escapedPath, "//") {
		return ErrRouteDenied
	}
	if escapedPath != "/repos/"+repository {
		return ErrRouteDenied
	}
	return nil
}
