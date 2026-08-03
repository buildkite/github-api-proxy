package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestLoadAndAuthorize(t *testing.T) {
	t.Parallel()

	config, err := Load(strings.NewReader(`
pipelines:
  pipeline-id:
    organization_id: org-id
    build_sources: [ui]
    branches: [main]
    runner_environments: [buildkite-hosted]
    repositories:
      example/repository:
        github_repository_id: 123456789
        installation_id: 987654321
        surfaces: [ci-v1]
        permissions:
          contents: read
          statuses: write
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	grant, err := config.Authorize(validIdentity(), Request{
		Repository: "example/repository",
		Surface:    "ci-v1",
		Permissions: map[string]Level{
			"contents": LevelRead,
		},
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if grant.RepositoryID != 123456789 || grant.InstallationID != 987654321 {
		t.Fatalf("Authorize() = %#v, want configured numeric IDs", grant)
	}
	if grant.Permissions["contents"] != LevelRead {
		t.Fatalf("Authorize() permissions = %#v, want contents:read", grant.Permissions)
	}
}

func TestAuthorizeFailsClosed(t *testing.T) {
	t.Parallel()

	config := Config{Pipelines: map[string]Pipeline{
		"pipeline-id": {
			OrganizationID:     "org-id",
			BuildSources:       []string{"ui"},
			Branches:           []string{"main"},
			RunnerEnvironments: []string{"buildkite-hosted"},
			Repositories: map[string]Repository{
				"example/repository": {
					GitHubRepositoryID: 123456789,
					InstallationID:     987654321,
					Surfaces:           []string{"ci-v1"},
					Permissions:        map[string]Level{"contents": LevelRead},
				},
			},
		},
	}}

	tests := map[string]struct {
		identity Identity
		request  Request
	}{
		"different organisation": {
			identity: withIdentity(func(identity *Identity) { identity.OrganizationID = "another-org" }),
			request:  validRequest(),
		},
		"different pipeline": {
			identity: withIdentity(func(identity *Identity) { identity.PipelineID = "another-pipeline" }),
			request:  validRequest(),
		},
		"untrusted build source": {
			identity: withIdentity(func(identity *Identity) { identity.BuildSource = "webhook" }),
			request:  validRequest(),
		},
		"different branch": {
			identity: withIdentity(func(identity *Identity) { identity.BuildBranch = "feature" }),
			request:  validRequest(),
		},
		"self-hosted runner": {
			identity: withIdentity(func(identity *Identity) { identity.RunnerEnvironment = "self-hosted" }),
			request:  validRequest(),
		},
		"different repository": {
			identity: validIdentity(),
			request:  withRequest(func(request *Request) { request.Repository = "example/other" }),
		},
		"unsupported surface": {
			identity: validIdentity(),
			request:  withRequest(func(request *Request) { request.Surface = "admin-v1" }),
		},
		"permission exceeds maximum": {
			identity: validIdentity(),
			request: withRequest(func(request *Request) {
				request.Permissions["contents"] = LevelWrite
			}),
		},
		"invalid permission level": {
			identity: validIdentity(),
			request: withRequest(func(request *Request) {
				request.Permissions["contents"] = Level("owner")
			}),
		},
		"unknown permission": {
			identity: validIdentity(),
			request: withRequest(func(request *Request) {
				request.Permissions["administration"] = LevelRead
			}),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.Authorize(test.identity, test.request)
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("Authorize() error = %v, want %v", err, ErrDenied)
			}
		})
	}
}

func TestLoadRejectsInvalidPermission(t *testing.T) {
	t.Parallel()

	_, err := Load(strings.NewReader(`
pipelines:
  pipeline-id:
    organization_id: org-id
    build_sources: [ui]
    branches: [main]
    runner_environments: [buildkite-hosted]
    repositories:
      example/repository:
        github_repository_id: 123456789
        installation_id: 987654321
        surfaces: [ci-v1]
        permissions:
          contents: owner
`))
	if err == nil {
		t.Fatal("Load() error = nil, want invalid permission error")
	}
}

func validIdentity() Identity {
	return Identity{
		OrganizationID:    "org-id",
		PipelineID:        "pipeline-id",
		BuildID:           "build-id",
		JobID:             "job-id",
		BuildBranch:       "main",
		BuildSource:       "ui",
		RunnerEnvironment: "buildkite-hosted",
	}
}

func validRequest() Request {
	return Request{
		Repository:  "example/repository",
		Surface:     "ci-v1",
		Permissions: map[string]Level{"contents": LevelRead},
	}
}

func withIdentity(change func(*Identity)) Identity {
	identity := validIdentity()
	change(&identity)
	return identity
}

func withRequest(change func(*Request)) Request {
	request := validRequest()
	change(&request)
	return request
}
