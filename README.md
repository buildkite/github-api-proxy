# github-api-proxy

`github-api-proxy` is an experimental standalone service for giving Buildkite
jobs narrowly scoped GitHub API access without exposing a GitHub credential to
job code.

Jobs authenticate with Buildkite Job OIDC. The service evaluates static
pipeline and repository policy, returns a short-lived opaque proxy token, and
uses an attenuated GitHub App installation token only inside the proxy.

The first implementation slice supports one read-only endpoint:

```text
GET /api/v3/repos/{owner}/{repo}
```

The full design and delivery sequence are in
[`docs/plans/github-api-proxy.md`](docs/plans/github-api-proxy.md).

## Development

The repository pins Go and golangci-lint with mise:

```sh
mise trust mise.toml
mise install
mise run check
```

## Running the prototype

The service currently reads configuration from the environment:

```sh
export GITHUB_API_PROXY_REDIS_URL=redis://127.0.0.1:6379/0
export GITHUB_API_PROXY_POLICY_PATH=config/policy.example.yml
export GITHUB_API_PROXY_SESSION_HASH_KEY="$(openssl rand -base64 32)"
export GITHUB_API_PROXY_GITHUB_APP_ID=1234
export GITHUB_API_PROXY_GITHUB_APP_PRIVATE_KEY="$(cat path/to/github-app.pem)"

mise exec -- go run ./cmd/github-api-proxy
```

`GITHUB_API_PROXY_PUBLIC_URL` defaults to
`https://github-api-proxy.buildkite.com`; its exact value is also the required
Buildkite OIDC audience. `GITHUB_API_PROXY_LISTEN_ADDRESS` defaults to `:8080`.

## Trying the job protocol

From a Buildkite job whose pipeline and repository are present in the policy:

```sh
set -euo pipefail

proxy_url="https://github-api-proxy.buildkite.com"

oidc_assertion="$(
  buildkite-agent oidc request-token \
    --audience "$proxy_url" \
    --lifetime 900 \
    --subject-claim job_id \
    --claim "organization_id,pipeline_id,build_id"
)"

proxy_token="$(
  curl --fail-with-body --silent --show-error \
    --request POST "$proxy_url/v1/token" \
    --header "Authorization: Bearer $oidc_assertion" \
    --header "Content-Type: application/json" \
    --data '{
      "repository": "example/repository",
      "surface": "ci-v1",
      "permissions": {"contents": "read"}
    }' |
    jq --raw-output .access_token
)"
printf '%s\n' "$proxy_token" | buildkite-agent redactor add

curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer $proxy_token" \
  "$proxy_url/api/v3/repos/example/repository"
```

The exchange assertion is single-use. The returned `bkgp_…` credential is an
opaque proxy token, not a GitHub token: it works only against the returned API
base URL and cannot be used for Git transport or directly against GitHub.
Buildkite Agent v3.104.0 and newer redact requested OIDC tokens automatically;
the example explicitly registers the newly issued proxy token before using it.

## Status

The service is an experimental prototype and is not ready for production use.
