// Package service wires and runs the GitHub API proxy HTTP service.
package service

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/buildkite/github-api-proxy/internal/exchange"
	"github.com/buildkite/github-api-proxy/internal/githubapp"
	"github.com/buildkite/github-api-proxy/internal/oidc"
	"github.com/buildkite/github-api-proxy/internal/policy"
	"github.com/buildkite/github-api-proxy/internal/proxy"
	"github.com/buildkite/github-api-proxy/internal/session"
	"github.com/redis/go-redis/v9"
)

const (
	defaultListenAddress = ":8080"
	defaultPublicURL     = "https://github-api-proxy.buildkite.com"
	oidcIssuer           = "https://agent.buildkite.com"
	oidcJWKSURL          = "https://agent.buildkite.com/.well-known/jwks"
	maxHeaderBytes       = 32 << 10
)

// Getenv returns one environment variable.
type Getenv func(string) string

// Run loads configuration, starts the service, and shuts it down with ctx.
func Run(ctx context.Context, getenv Getenv) error {
	config, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	policyFile, err := os.Open(config.policyPath)
	if err != nil {
		return fmt.Errorf("open policy: %w", err)
	}
	staticPolicy, err := policy.Load(policyFile)
	closeErr := policyFile.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("close policy: %w", closeErr)
	}

	redisOptions, err := redis.ParseURL(config.redisURL)
	if err != nil {
		return fmt.Errorf("parse Redis URL: %w", err)
	}
	redisClient := redis.NewClient(redisOptions)
	defer func() { _ = redisClient.Close() }()
	startupContext, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStartup()
	if err := redisClient.Ping(startupContext).Err(); err != nil {
		return fmt.Errorf("connect to Redis: %w", err)
	}

	sessions, err := session.NewRedisStore(redisClient, []byte(config.sessionHashKey))
	if err != nil {
		return err
	}
	verifier, err := oidc.NewVerifier(startupContext, oidc.Config{
		Issuer:          oidcIssuer,
		Audience:        config.publicURL,
		JWKSURL:         oidcJWKSURL,
		ClockSkew:       30 * time.Second,
		MinimumLifetime: 30 * time.Second,
		RefreshInterval: time.Minute,
	})
	if err != nil {
		return err
	}
	privateKey, err := parsePrivateKey(config.githubAppPrivateKey)
	if err != nil {
		return err
	}
	github, err := githubapp.NewClient(githubapp.Config{
		AppID:      config.githubAppID,
		PrivateKey: privateKey,
	})
	if err != nil {
		return err
	}
	exchangeHandler, err := exchange.NewHandler(exchange.Config{
		Verifier:   verifier,
		Authorizer: staticPolicy,
		Sessions:   sessions,
		APIURL:     config.publicURL + "/api/v3",
		GraphQLURL: config.publicURL + "/api/graphql",
		SessionTTL: 15 * time.Minute,
	})
	if err != nil {
		return err
	}
	proxyHandler, err := proxy.NewHandler(proxy.Config{
		Sessions: sessions,
		Tokens:   github,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              config.listenAddress,
		Handler:           routeHandler(exchangeHandler, proxyHandler, readiness(redisClient)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	errorChannel := make(chan error, 1)
	go func() {
		slog.Info("github-api-proxy listening", "address", config.listenAddress)
		errorChannel <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		return nil
	case err := <-errorChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	}
}

type config struct {
	listenAddress       string
	publicURL           string
	redisURL            string
	policyPath          string
	sessionHashKey      string
	githubAppID         int64
	githubAppPrivateKey string
}

func loadConfig(getenv Getenv) (config, error) {
	result := config{
		listenAddress:       valueOrDefault(getenv("GITHUB_API_PROXY_LISTEN_ADDRESS"), defaultListenAddress),
		publicURL:           valueOrDefault(getenv("GITHUB_API_PROXY_PUBLIC_URL"), defaultPublicURL),
		redisURL:            getenv("GITHUB_API_PROXY_REDIS_URL"),
		policyPath:          getenv("GITHUB_API_PROXY_POLICY_PATH"),
		sessionHashKey:      getenv("GITHUB_API_PROXY_SESSION_HASH_KEY"),
		githubAppPrivateKey: getenv("GITHUB_API_PROXY_GITHUB_APP_PRIVATE_KEY"),
	}
	appID, err := strconv.ParseInt(getenv("GITHUB_API_PROXY_GITHUB_APP_ID"), 10, 64)
	if err != nil || appID <= 0 {
		return config{}, errors.New("GITHUB_API_PROXY_GITHUB_APP_ID must be a positive integer")
	}
	result.githubAppID = appID
	if result.redisURL == "" || result.policyPath == "" || result.sessionHashKey == "" || result.githubAppPrivateKey == "" {
		return config{}, errors.New("redis URL, policy path, session hash key, and GitHub App private key are required")
	}
	if !validPublicOrigin(result.publicURL) {
		return config{}, errors.New("GITHUB_API_PROXY_PUBLIC_URL must be an HTTPS origin without a path")
	}
	return result, nil
}

func validPublicOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" &&
		parsed.User == nil && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == ""
}

func routeHandler(exchangeHandler, proxyHandler, readinessHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := request.URL.EscapedPath()
		switch {
		case path == "/v1/token":
			exchangeHandler.ServeHTTP(response, request)
		case strings.HasPrefix(path, "/api/v3/"):
			proxyHandler.ServeHTTP(response, request)
		case path == "/api/graphql":
			unsupportedGraphQL(response, request)
		case path == "/healthz":
			health(response, request)
		case path == "/readyz":
			readinessHandler.ServeHTTP(response, request)
		default:
			http.NotFound(response, request)
		}
	})
}

func parsePrivateKey(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("decode GitHub App private key: invalid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("decode GitHub App private key: invalid RSA private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("decode GitHub App private key: not RSA")
	}
	return key, nil
}

func health(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	response.WriteHeader(http.StatusOK)
}

func readiness(client *redis.Client) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusOK)
	}
}

func unsupportedGraphQL(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusNotImplemented)
	_, _ = response.Write([]byte("{\"message\":\"GraphQL is not supported by ci-v1\"}\n"))
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
