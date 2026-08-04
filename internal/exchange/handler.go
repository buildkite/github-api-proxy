// Package exchange exchanges Buildkite OIDC assertions for opaque proxy sessions.
package exchange

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buildkite/github-api-proxy/internal/oidc"
	"github.com/buildkite/github-api-proxy/internal/policy"
	"github.com/buildkite/github-api-proxy/internal/session"
)

const maxRequestBytes = 16 << 10

// Verifier authenticates a Buildkite OIDC assertion.
type Verifier interface {
	Verify(context.Context, string) (oidc.Identity, error)
}

// Authorizer intersects the signed identity and requested grant with server policy.
type Authorizer interface {
	Authorize(policy.Identity, policy.Request) (policy.Grant, error)
}

// SessionStore consumes assertions and issues opaque sessions.
type SessionStore interface {
	ConsumeAssertion(context.Context, string, time.Time) error
	Issue(context.Context, session.Record) (string, error)
}

// Config contains exchange dependencies and public proxy URLs.
type Config struct {
	Verifier   Verifier
	Authorizer Authorizer
	Sessions   SessionStore
	APIURL     string
	GraphQLURL string
	SessionTTL time.Duration
	Now        func() time.Time
}

// Handler validates and exchanges one Buildkite OIDC assertion.
type Handler struct {
	verifier   Verifier
	authorizer Authorizer
	sessions   SessionStore
	apiURL     string
	graphqlURL string
	sessionTTL time.Duration
	now        func() time.Time
}

// Request is the exact proxy grant requested by a client.
type Request struct {
	Repository  string                  `json:"repository"`
	Surface     string                  `json:"surface"`
	Permissions map[string]policy.Level `json:"permissions"`
}

// Response is an OAuth-shaped opaque proxy credential response.
type Response struct {
	AccessToken string                  `json:"access_token"`
	TokenType   string                  `json:"token_type"`
	ExpiresIn   int64                   `json:"expires_in"`
	APIURL      string                  `json:"api_url"`
	GraphQLURL  string                  `json:"graphql_url"`
	Repository  string                  `json:"repository"`
	Surface     string                  `json:"surface"`
	Permissions map[string]policy.Level `json:"permissions"`
}

// NewHandler creates a fail-closed token exchange handler.
func NewHandler(config Config) (*Handler, error) {
	if config.Verifier == nil || config.Authorizer == nil || config.Sessions == nil {
		return nil, errors.New("exchange verifier, authorizer, and session store are required")
	}
	if !validPublicURL(config.APIURL) || !validPublicURL(config.GraphQLURL) {
		return nil, errors.New("exchange API URLs are invalid")
	}
	if config.SessionTTL <= 0 {
		return nil, errors.New("exchange session TTL must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Handler{
		verifier:   config.Verifier,
		authorizer: config.Authorizer,
		sessions:   config.Sessions,
		apiURL:     config.APIURL,
		graphqlURL: config.GraphQLURL,
		sessionTTL: config.SessionTTL,
		now:        config.Now,
	}, nil
}

// ServeHTTP exchanges an authenticated and authorised workload assertion.
func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	if request.Method != http.MethodPost || request.URL.EscapedPath() != "/v1/token" {
		writeError(response, http.StatusNotFound, "not found")
		return
	}
	assertion, ok := bearerToken(request.Header.Get("Authorization"))
	if !ok {
		writeError(response, http.StatusUnauthorized, "invalid OIDC authentication")
		return
	}
	exchangeRequest, err := decodeRequest(response, request)
	if err != nil {
		writeError(response, http.StatusBadRequest, "invalid exchange request")
		return
	}
	identity, err := h.verifier.Verify(request.Context(), assertion)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "invalid OIDC authentication")
		return
	}
	grant, err := h.authorizer.Authorize(policy.Identity{
		OrganizationID:    identity.OrganizationID,
		PipelineID:        identity.PipelineID,
		BuildID:           identity.BuildID,
		JobID:             identity.JobID,
		BuildBranch:       identity.BuildBranch,
		BuildSource:       identity.BuildSource,
		RunnerEnvironment: identity.RunnerEnvironment,
	}, policy.Request{
		Repository:  exchangeRequest.Repository,
		Surface:     exchangeRequest.Surface,
		Permissions: exchangeRequest.Permissions,
	})
	if err != nil {
		writeError(response, http.StatusForbidden, "request denied by policy")
		return
	}
	if err := h.sessions.ConsumeAssertion(request.Context(), assertion, identity.ExpiresAt); err != nil {
		if errors.Is(err, session.ErrAssertionReplayed) || errors.Is(err, session.ErrExpired) {
			writeError(response, http.StatusUnauthorized, "OIDC assertion unavailable")
		} else {
			writeError(response, http.StatusServiceUnavailable, "session unavailable")
		}
		return
	}

	now := h.now()
	expiresAt := now.Add(h.sessionTTL)
	if identity.ExpiresAt.Before(expiresAt) {
		expiresAt = identity.ExpiresAt
	}
	permissions := make(map[string]string, len(grant.Permissions))
	for name, level := range grant.Permissions {
		permissions[name] = string(level)
	}
	proxyToken, err := h.sessions.Issue(request.Context(), session.Record{
		OrganizationID:    identity.OrganizationID,
		PipelineID:        identity.PipelineID,
		BuildID:           identity.BuildID,
		JobID:             identity.JobID,
		BuildBranch:       identity.BuildBranch,
		BuildSource:       identity.BuildSource,
		RunnerEnvironment: identity.RunnerEnvironment,
		RepositoryID:      grant.RepositoryID,
		Repository:        grant.Repository,
		InstallationID:    grant.InstallationID,
		Surface:           grant.Surface,
		Permissions:       permissions,
		IssuedAt:          now,
		ExpiresAt:         expiresAt,
	})
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, "session unavailable")
		return
	}
	writeJSON(response, http.StatusOK, Response{
		AccessToken: proxyToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(expiresAt.Sub(now).Seconds()),
		APIURL:      h.apiURL,
		GraphQLURL:  h.graphqlURL,
		Repository:  grant.Repository,
		Surface:     grant.Surface,
		Permissions: grant.Permissions,
	})
}

func decodeRequest(response http.ResponseWriter, request *http.Request) (Request, error) {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var exchangeRequest Request
	if err := decoder.Decode(&exchangeRequest); err != nil {
		return Request{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("exchange request must contain one JSON object")
	}
	if exchangeRequest.Repository == "" || exchangeRequest.Surface == "" || len(exchangeRequest.Permissions) == 0 {
		return Request{}, errors.New("exchange request is incomplete")
	}
	return exchangeRequest, nil
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	returnValue := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		returnValue = parts[1]
	}
	return returnValue, returnValue != ""
}

func validPublicURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"message": message})
}
