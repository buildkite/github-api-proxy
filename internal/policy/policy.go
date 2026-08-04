// Package policy evaluates static pipeline and repository grants.
package policy

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"go.yaml.in/yaml/v4"
)

var (
	// ErrDenied means policy does not permit the exact requested grant.
	ErrDenied = errors.New("request denied by policy")
)

// Level is a GitHub App repository permission level.
type Level string

const (
	LevelNone  Level = "none"
	LevelRead  Level = "read"
	LevelWrite Level = "write"
)

// Identity contains signed Buildkite OIDC policy inputs.
type Identity struct {
	OrganizationID    string
	PipelineID        string
	BuildID           string
	JobID             string
	BuildBranch       string
	BuildSource       string
	RunnerEnvironment string
}

// Request is the exact repository grant requested by a client.
type Request struct {
	Repository  string
	Surface     string
	Permissions map[string]Level
}

// Grant contains server-owned GitHub authority after policy evaluation.
type Grant struct {
	RepositoryID   int64
	Repository     string
	InstallationID int64
	Surface        string
	Permissions    map[string]Level
}

// Config is a static policy keyed by immutable pipeline UUID.
type Config struct {
	Pipelines map[string]Pipeline `yaml:"pipelines"`
}

// Pipeline constrains a pipeline to trusted execution contexts and repositories.
type Pipeline struct {
	OrganizationID     string                `yaml:"organization_id"`
	BuildSources       []string              `yaml:"build_sources"`
	Branches           []string              `yaml:"branches"`
	RunnerEnvironments []string              `yaml:"runner_environments"`
	Repositories       map[string]Repository `yaml:"repositories"`
}

// Repository is the maximum server-owned GitHub grant for a repository.
type Repository struct {
	GitHubRepositoryID int64            `yaml:"github_repository_id"`
	InstallationID     int64            `yaml:"installation_id"`
	Surfaces           []string         `yaml:"surfaces"`
	Permissions        map[string]Level `yaml:"permissions"`
}

// Load decodes and validates a static YAML policy.
func Load(reader io.Reader) (*Config, error) {
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

// Authorize returns the exact requested grant when every policy constraint passes.
func (c *Config) Authorize(identity Identity, request Request) (Grant, error) {
	pipeline, ok := c.Pipelines[identity.PipelineID]
	if !ok || pipeline.OrganizationID != identity.OrganizationID {
		return Grant{}, ErrDenied
	}
	if !slices.Contains(pipeline.BuildSources, identity.BuildSource) ||
		!slices.Contains(pipeline.Branches, identity.BuildBranch) ||
		!slices.Contains(pipeline.RunnerEnvironments, identity.RunnerEnvironment) {
		return Grant{}, ErrDenied
	}

	repository, ok := pipeline.Repositories[request.Repository]
	if !ok || !slices.Contains(repository.Surfaces, request.Surface) || len(request.Permissions) == 0 {
		return Grant{}, ErrDenied
	}
	for name, requested := range request.Permissions {
		maximum, ok := repository.Permissions[name]
		if !ok || !validLevel(requested) || !allows(maximum, requested) || requested == LevelNone {
			return Grant{}, ErrDenied
		}
	}

	permissions := make(map[string]Level, len(request.Permissions))
	for name, level := range request.Permissions {
		permissions[name] = level
	}
	return Grant{
		RepositoryID:   repository.GitHubRepositoryID,
		Repository:     request.Repository,
		InstallationID: repository.InstallationID,
		Surface:        request.Surface,
		Permissions:    permissions,
	}, nil
}

func (c *Config) validate() error {
	if len(c.Pipelines) == 0 {
		return errors.New("policy has no pipelines")
	}
	for pipelineID, pipeline := range c.Pipelines {
		if pipelineID == "" || pipeline.OrganizationID == "" || len(pipeline.BuildSources) == 0 || len(pipeline.Branches) == 0 || len(pipeline.RunnerEnvironments) == 0 {
			return fmt.Errorf("pipeline %q is incomplete", pipelineID)
		}
		if len(pipeline.Repositories) == 0 {
			return fmt.Errorf("pipeline %q has no repositories", pipelineID)
		}
		for name, repository := range pipeline.Repositories {
			if name == "" || repository.GitHubRepositoryID <= 0 || repository.InstallationID <= 0 || len(repository.Surfaces) == 0 || len(repository.Permissions) == 0 {
				return fmt.Errorf("pipeline %q repository %q is incomplete", pipelineID, name)
			}
			for permission, level := range repository.Permissions {
				if permission == "" || !validLevel(level) || level == LevelNone {
					return fmt.Errorf("pipeline %q repository %q has invalid permission %q=%q", pipelineID, name, permission, level)
				}
			}
		}
	}
	return nil
}

func allows(maximum, requested Level) bool {
	return permissionRank(maximum) >= permissionRank(requested)
}

func validLevel(level Level) bool {
	return level == LevelNone || level == LevelRead || level == LevelWrite
}

func permissionRank(level Level) int {
	switch level {
	case LevelRead:
		return 1
	case LevelWrite:
		return 2
	default:
		return 0
	}
}
