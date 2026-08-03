---
status: active
last_reviewed: 2026-08-03
---

# Standalone GitHub API proxy for Buildkite jobs

## Summary

Buildkite should prototype `github-api-proxy` as a standalone Go service. Running Buildkite jobs authenticate to it with Buildkite Job OIDC, exchange that signed identity assertion for an opaque proxy-only bearer token, and use that token against a deliberately small GitHub-compatible REST surface. The service holds and injects repository- and permission-attenuated GitHub App installation tokens; workloads never receive a GitHub credential.

The service has two first-class consumers:

1. `buildkite-gha`, where GitHub workflow `permissions:` become a constrained request and the runtime exposes the resulting proxy credential through normal GitHub Actions contexts.
2. Ordinary Buildkite jobs, using a small plugin or `exec` helper to request OIDC, exchange it, configure the proxy environment, and run a command.

The first API surface, `ci-v1`, will support repository and pull-request reads plus commit-status and check-run writes. Existing `buildkite-gha` adapters for checkout, caches, and artifacts remain specialised. GraphQL, Git transport, releases, uploads, administration, user credentials, and arbitrary GitHub endpoints stay out of scope until the narrow service proves useful.

The prototype must answer two questions with evidence:

- Can `buildkite-gha` run a real API-using action without workflow authors handling OIDC or credentials?
- Does the same service materially simplify safe GitHub access from an ordinary Buildkite command step?

## Context

Public interfaces relevant to this plan:

- [Buildkite Agent OIDC command](https://buildkite.com/docs/agent/cli/reference/oidc)
- [`buildkite/buildkite-gha`](https://github.com/buildkite/buildkite-gha)

The proxy boundary belongs in a standalone Go service: HTTP forwarding, OIDC exchange, opaque sessions, policy evaluation, GitHub App token handling, and CI route enforcement form one independently deployable capability rather than a `buildkite-gha` implementation detail.

## Current state

### Buildkite OIDC

Running jobs can already request a short-lived JWT from `https://agent.buildkite.com`:

```bash
buildkite-agent oidc request-token \
  --audience "https://github-api-proxy.buildkite.com" \
  --subject-claim "job_id" \
  --claim "organization_id,pipeline_id,build_id"
```

The token is signed by Buildkite's published JWKS and includes immutable Buildkite identity. Agent v3.104.0 and newer automatically add generated OIDC tokens to the build log redactor.

OIDC proves which Buildkite workload is calling. It does not by itself prove that the workload may access a particular GitHub repository or permission.

### `buildkite-gha`

Proxy access should remain opt-in and preserve tokenless behaviour for workflows that do not request supported permissions. When enabled, the integration should expose the opaque credential only through standard GitHub Actions token and API URL contexts, register it with the Buildkite redactor, and leave the existing checkout, cache, and artifact adapters unchanged.

## Problem

Buildkite jobs commonly need GitHub API access for CI reporting and repository metadata. Today they typically use long-lived PATs in secrets or receive a short-lived GitHub token directly. Both approaches hand a GitHub credential to arbitrary job code.

A standalone proxy can improve that boundary:

- GitHub installation tokens remain server-side.
- Every operation is associated with a Buildkite workload identity and proxy session.
- A token copied out of a job is useful only against the proxy, for its bound repository and API surface.
- The service can enforce a smaller operation set than the underlying GitHub App permission set.
- The same protocol works for converted GitHub Actions workflows and ordinary Buildkite steps.

The proxy does not make a malicious running job safe. A workload can perform every operation granted to its proxy session while that session remains active. Repository policy, permission policy, event trust, and API-surface restrictions remain the primary security controls.

## Goals

- Build a standalone, deployable Go service with no control-plane request-forwarding path.
- Authenticate running jobs using Buildkite's existing OIDC issuer and JWKS.
- Exchange OIDC identity assertions for opaque, revocable, proxy-only bearer tokens.
- Bind each proxy session to one Buildkite identity, repository, API surface, permission request, and expiry.
- Mint GitHub App installation tokens internally with native repository and permission attenuation.
- Offer a versioned `ci-v1` REST surface sufficient for common CI reads and status/check reporting.
- Integrate with `buildkite-gha` without workflow authors writing OIDC or exchange commands.
- Expose normal GitHub Actions context values rather than inventing action-input name heuristics.
- Offer an ergonomic plugin or helper for ordinary Buildkite command steps.
- Produce safe per-request audit and operational telemetry.
- Reach a measured proceed, narrow, or stop decision before building a customer policy UI or broad GitHub compatibility layer.

## Non-goals for the prototype

- Arbitrary GitHub REST API forwarding.
- GraphQL execution.
- Git smart HTTP, SSH clone/push, submodules, or git credential-helper support.
- Release assets, archives, raw-content downloads, or `uploads.github.com`.
- GitHub Actions private Results, cache, artifact, OIDC, or workflow-control API emulation.
- Replacing the existing `buildkite-gha` checkout, cache, or artifact adapters.
- GitHub Enterprise Server or customer-provided GitHub Apps.
- User OAuth/PAT credentials or user-attributed GitHub operations.
- Organisation, team, repository-administration, secrets, variables, environment, or package APIs.
- Complete GitHub event-payload compatibility in `buildkite-gha`.
- Transparent support for actions that hardcode `https://api.github.com`.
- A customer-facing policy model, management UI, or persisted control-plane policy model.
- Immediate revocation tied to Buildkite job cancellation in the first standalone deployment.

## Product model

```text
buildkite-gha runtime                         ordinary Buildkite job
        |                                              |
        | Buildkite Job OIDC                           | Buildkite Job OIDC
        v                                              v
                    github-api-proxy /v1/token
                    - verify OIDC/JWKS
                    - evaluate pipeline policy
                    - bind repo + ci-v1 + permissions
                    - return opaque bkgp_ token
                              |
                              v
                  github-api-proxy /api/v3/*
                    - resolve opaque session
                    - enforce ci-v1 route
                    - mint/cache attenuated App token
                    - forward raw HTTP
                              |
                              v
                         api.github.com
```

### Identity assertion

Clients request OIDC with:

```text
iss = https://agent.buildkite.com
aud = https://github-api-proxy.buildkite.com
sub = <job UUID>
organization_id = <immutable UUID>
pipeline_id = <immutable UUID>
build_id = <immutable UUID>
job_id = <immutable UUID>
build_branch = <branch>
build_source = <source>
runner_environment = <environment>
```

The service must:

- Pin the issuer and exact audience.
- Allow only expected signing algorithms.
- Validate `kid`, signature, `exp`, `nbf`, and `iat` using cached Buildkite JWKS.
- Refresh JWKS on an unknown `kid` while bounding refresh frequency.
- Require `sub == job_id` and all required immutable claims.
- Require `build_branch`, `build_source`, and `runner_environment`, evaluate them against pipeline policy at exchange time, and record them in the session and exchange audit event. A missing policy input denies the exchange rather than skipping the check.
- Reject tokens whose remaining lifetime is below a small exchange threshold.
- Never forward or return the OIDC JWT after exchange.

Buildkite documents `build_id` as an optional claim available through `--claim`.

### Opaque proxy session

The token exchange returns a cryptographically random token with a recognisable non-secret prefix such as `bkgp_`. Store only a keyed hash of the token in Redis, mapping it to:

```text
organization_id
pipeline_id
build_id
job_id
repository_id and owner/name
surface = ci-v1
granted permissions
issued_at and expires_at
GitHub App installation ID
```

The opaque token must:

- Carry at least 256 bits of randomness.
- Be accepted only by the proxy API, never by Buildkite Agent API endpoints.
- Expire no later than the OIDC assertion used for exchange during the prototype.
- Be rate-limited by session and installation.
- Be redacted before any child process receives it.
- Be revocable by deleting its Redis record.

The concrete token and storage contract is:

```text
token = "bkgp_" + base64url(32 bytes from crypto/rand)
redis key = "session:" + hex(HMAC-SHA-256(session_hash_key, token))
```

`session_hash_key` is a dedicated deployment secret. Store no plaintext or reversible token form and perform lookup only by the derived key. Set the Redis record TTL to `expires_at`, and independently reject an expired record after lookup. Both exchange and proxy requests fail closed when Redis is unavailable.

The first service does not query Buildkite for live job state. A job can therefore retain proxy access until the shorter of its OIDC/session expiry even if cancelled. Keep the lifetime short, record this limitation, and add control-plane introspection only if the experiment demonstrates a need.

### Policy

OIDC authenticates the caller but does not authorise its requested repository. The effective grant is:

```text
requested repository and permissions
intersect pipeline policy
intersect signed build source/branch/runner constraints
intersect API surface
intersect GitHub App installation access
intersect GitHub App permissions
```

For the prototype, use static configuration keyed by immutable pipeline UUID:

```yaml
pipelines:
  0184990a-0000-0000-0000-000000000001:
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
          pull_requests: read
          checks: write
          statuses: write
```

Do not accept repository ownership, installation IDs, maximum permissions, or trust classification from the client. For the prototype, enable writes only on a purpose-built pipeline and trusted branch that cannot execute unreviewed pull-request code. The current OIDC claims do not identify fork provenance strongly enough to reproduce GitHub's fork-PR downgrade safely.

A production service can replace the static adapter with synchronised Buildkite control-plane policy and independently verified event provenance without changing the exchange or proxy protocols.

## External API contract

### Token exchange

```http
POST /v1/token
Authorization: Bearer <Buildkite OIDC JWT>
Content-Type: application/json

{
  "repository": "example/repository",
  "surface": "ci-v1",
  "permissions": {
    "contents": "read",
    "pull_requests": "read",
    "checks": "write",
    "statuses": "write"
  }
}
```

Successful response:

```json
{
  "access_token": "bkgp_opaque-random-value",
  "token_type": "Bearer",
  "expires_in": 900,
  "api_url": "https://github-api-proxy.buildkite.com/api/v3",
  "graphql_url": "https://github-api-proxy.buildkite.com/api/graphql",
  "repository": "example/repository",
  "surface": "ci-v1",
  "permissions": {
    "contents": "read",
    "pull_requests": "read",
    "checks": "write",
    "statuses": "write"
  }
}
```

Reject the exchange if policy cannot satisfy the exact request. Do not silently widen permissions or fall back to an installation-wide token. For the prototype, prefer an explicit denial over returning a weaker grant that actions may misinterpret.

Accept each OIDC assertion at most once. Before issuing a session, store `SHA-256(compact JWT)` in Redis with `SETNX` and a TTL equal to the assertion's remaining lifetime. Deny and audit a repeated exchange; a job needing another session must request a fresh assertion.

### Proxy authentication

For client compatibility, normalise these inbound forms before opaque-token lookup:

```text
Authorization: Bearer <token>
Authorization: token <token>
Authorization: Basic base64(x-access-token:<token>)
```

Strip inbound authentication before creating the GitHub request. Set the internal installation token only after all caller-controlled headers have been filtered.

### `ci-v1` REST surface

Read operations:

```text
GET /repos/{owner}/{repo}
GET /repos/{owner}/{repo}/commits/{sha}
GET /repos/{owner}/{repo}/git/ref/{ref}
GET /repos/{owner}/{repo}/contents/{path}
GET /repos/{owner}/{repo}/compare/{base}...{head}
GET /repos/{owner}/{repo}/pulls/{number}
GET /repos/{owner}/{repo}/pulls/{number}/files
GET /repos/{owner}/{repo}/commits/{ref}/check-runs
GET /repos/{owner}/{repo}/check-runs/{id}
GET /repos/{owner}/{repo}/commits/{ref}/status
GET /repos/{owner}/{repo}/commits/{ref}/statuses
```

CI reporting operations:

```text
POST  /repos/{owner}/{repo}/statuses/{sha}
POST  /repos/{owner}/{repo}/check-runs
PATCH /repos/{owner}/{repo}/check-runs/{id}
```

The route matcher must canonicalise the path and require `{owner}/{repo}` to equal the session-bound repository. Reject encoded slash ambiguity, traversal, duplicate escaping, absolute URLs, scheme-relative paths, and all unrecognised methods/routes.

GitHub's installation token must independently be scoped to the same repository and the exact granted permission set. The route allowlist is the product boundary; GitHub-native attenuation is the security backstop.

`/api/graphql` should return a stable unsupported response in `ci-v1`. Exposing the URL preserves GitHub Actions context shape without pretending GraphQL is authorised.

## Raw forwarding contract

The service is a reverse proxy, not a JSON wrapper:

- Use a fixed `https://api.github.com` upstream and never a caller-supplied host.
- Support only the methods and routes in the selected surface.
- Forward a small request-header allowlist: `Accept`, `Content-Type`, `If-Match`, `If-None-Match`, `Range`, `User-Agent`, and `X-GitHub-Api-Version`.
- Add a Buildkite-identifying `User-Agent` suffix.
- Preserve query parameters but never log query values.
- Impose explicit request and response body limits suitable for the CI surface.
- Send `Accept-Encoding: identity` upstream to avoid decompression/framing ambiguity.
- Stream raw response bytes and preserve upstream status codes.
- Forward `Content-Type`, `Content-Disposition`, `ETag`, `Last-Modified`, `Retry-After`, `X-RateLimit-*`, and `X-GitHub-Request-Id`.
- Strip hop-by-hop, forwarding, `Content-Length`, `Content-Encoding`, and `Transfer-Encoding` headers before writing the downstream response; let Go's HTTP server calculate framing.
- Rewrite same-origin `Link` URLs to the proxy origin if a supported endpoint paginates.
- Do not automatically follow redirects. Reject alternate-host redirects fail-closed during the prototype.
- Never record request or response bodies.

The service must not expose GitHub's App-token mint endpoint through the proxy. Minting happens through a separate GitHub client that fails closed on unexpected status or response shape.

## GitHub App handling

Use a dedicated GitHub App for the prototype.

For the prototype:

- Configure the App ID, private key, installation ID, and repository mapping through deployment secrets/static policy.
- Request installation tokens with `repository_ids: [<github_repository_id from policy>]` and the exact session permission set. Never use name-based `repositories:` scoping; `owner/name` exists only for route matching and audit display, while the numeric repository ID is the authorisation identifier.
- Cache tokens only by exact App, installation, repository, and permission set; keep the cache within the service.
- Never return, log, or include installation tokens in errors.
- Record GitHub request IDs and rate-limit headers for correlation.

All GitHub operations will appear as the App actor. Buildkite proxy audit identifies the job, but GitHub CODEOWNERS, review, and branch-rule semantics may still distinguish App activity from user activity.

## `buildkite-gha` integration

### Compiler and plan

Retain and normalise workflow- and job-level GitHub Actions `permissions:` instead of discarding them. For the first profile, support only:

```text
contents: read|none
pull-requests: read|none
checks: read|write|none
statuses: read|write|none
```

Implement GitHub's workflow-level inheritance and job-level replacement semantics for those keys. Reject unsupported permission keys and aggregate forms such as `write-all` with a clear compatibility error rather than silently ignoring them.

Require an explicit non-empty supported permission declaration for proxy access in the prototype. No declaration preserves today's tokenless behaviour.

Compile the request into a versioned capability:

```json
{
  "required_capabilities": ["github-api-v1"],
  "github_api": {
    "surface": "ci-v1",
    "permissions": {
      "contents": "read",
      "statuses": "write"
    }
  }
}
```

The compiled plan communicates what the workflow asks for; it is never the final server grant. Keep the capability opt-in so workflows without a supported permission request remain tokenless.

### Runtime provider

Add `GitHubCredentialProvider` beside the cache credential provider. If `github-api-v1` is absent, do not request OIDC or configure proxy context.

When present, the provider should:

1. Request OIDC through `buildkite-agent oidc request-token`, without exposing any underlying agent credential to action code.
2. Exchange OIDC with `github-api-proxy` using the event repository and compiled permission request.
3. Add the opaque token to both the Agent redactor and local action command processor before expression evaluation or process execution.
4. Keep the token only in memory for the job lifecycle.
5. Fail the job before running user/action code if exchange, policy, installation, or redaction setup fails.

### Actions contexts and environment

Expose the same in-memory token through:

```text
github.token
secrets.GITHUB_TOKEN
```

Treat `secrets.GITHUB_TOKEN` as a runtime-owned compatibility alias while proxy access is enabled. Never resolve that alias from a user-provided Buildkite secret with the same name.

Expose:

```text
github.api_url       = proxy REST URL
github.graphql_url   = proxy unsupported GraphQL URL
github.server_url    = https://github.com
GITHUB_API_URL       = proxy REST URL
GITHUB_GRAPHQL_URL   = proxy unsupported GraphQL URL
GITHUB_SERVER_URL    = https://github.com
```

Do not invent an ambient `GITHUB_TOKEN` environment variable. GitHub Actions exposes the automatic token through `github.token` and `secrets.GITHUB_TOKEN`; workflows map it into action inputs or command environment explicitly.

Normal action metadata defaults such as `${{ github.token }}` will then resolve through the existing input evaluator. Do not auto-fill arbitrary inputs named `token` or `github-token`.

### Compatibility boundary

Actions that respect `GITHUB_API_URL`, `github.api_url`, and the standard token contexts can work. Actions that hardcode `https://api.github.com` remain unsupported: the opaque token is not valid at GitHub and will fail safely.

Because action source is locked to immutable commits, `buildkite-gha` may later maintain a tested compatibility catalogue or warn when bundled code contains obvious hardcoded GitHub API hosts. Do not add DNS interception, TLS termination, Node preload rewriting, or broad action patching to the first version.

`github.event` and `GITHUB_EVENT_PATH` remain incomplete in `buildkite-gha`. The first proxy test must use an action that can operate from repository and SHA context alone. Event-payload compatibility should be planned separately rather than folded into the proxy.

### Existing adapters remain unchanged

- `actions/checkout` remains the credential-free exact-event-SHA adapter.
- `actions/cache` continues using the existing cache adapter.
- Upload/download artifact actions continue using Buildkite artifact adapters.
- Private checkout, submodules, cross-repository actions, and GitHub Actions private service APIs remain unsupported.

## Ordinary Buildkite job integration

The standalone project should expose a small client package and command suitable for a plugin. Proposed user experience:

```yaml
steps:
  - command: ./scripts/report-status
    plugins:
      - buildkite/github-api-proxy#v1:
          repository: example/repository
          permissions:
            contents: read
            statuses: write
```

The plugin/helper should:

- Obtain OIDC with the exact proxy audience and required immutable claims.
- Exchange it for an opaque session.
- Register the opaque token with `buildkite-agent redactor add` before command execution.
- Export `GITHUB_API_URL` and a clearly named proxy token variable.
- Offer an `exec` form that sets client-specific variables only for the child command.

Possible direct helper:

```bash
github-api-proxy exec \
  --repository example/repository \
  --permission contents:read \
  --permission statuses:write \
  -- ./scripts/report-status
```

Do not silently set a GitHub-looking token for commands that may ignore the proxy URL. Provide explicit presets for known clients only after they are tested.

## Proposed Go project boundaries

Keep the module small and explicit:

```text
cmd/github-api-proxy       server and local development entrypoint
cmd/github-api-proxy-auth  optional exchange/exec helper
internal/oidc              issuer/JWKS verification
internal/session           opaque token generation and Redis records
internal/policy            static prototype policy interface
internal/githubapp         App JWT and attenuated installation tokens
internal/surface           canonical ci-v1 method/path matching
internal/proxy             request filtering and raw forwarding
internal/audit             structured redacted events and metrics
```

Avoid a generic provider framework in the first repository. The product is intentionally GitHub-specific, and another provider is unlikely to share GitHub's permissions, installations, clients, or HTTP semantics.

## Auditing and observability

Record per exchange:

- immutable Buildkite organisation, pipeline, build, and job IDs
- requested and granted repository, surface, and permissions
- session hash prefix or generated session ID, never the bearer token
- expiry and policy decision
- denial reason

Record per proxied request:

- session ID and immutable Buildkite identity
- GitHub installation and repository IDs
- granted surface and permissions
- method and normalised route template
- query key names, not values
- status, duration, and byte counts
- GitHub request ID
- primary/secondary rate-limit state
- proxy rejection reason

Never record OIDC assertions, bearer tokens, installation tokens, query values, request bodies, response bodies, or arbitrary headers.

Metrics should cover exchange outcomes, active sessions, request latency, response classes, route denials, repository mismatches, OIDC/JWKS errors, GitHub token mint failures, primary/secondary rate limiting, and internal token-cache behaviour.

## Progress snapshot

The first standalone implementation is active. The repository currently includes:

- A runnable Go service with environment configuration, graceful shutdown, health, Redis-backed readiness, and the fixed Buildkite OIDC/GitHub origins.
- Strict RS256 OIDC verification with exact issuer/audience, required immutable and policy claims, bounded JWKS responses, and rate-limited unknown-key refresh.
- Static typed YAML policy with exact repository, surface, permission, branch, source, runner, organisation, and pipeline checks.
- HMAC-keyed Redis sessions, 256-bit opaque tokens, independent expiry checks, and atomic one-time assertion records.
- Numeric-repository-ID GitHub App token minting with exact permissions, effective-authority response checks, and redacted upstream errors.
- The `/v1/token` exchange and exact read-only `/api/v3/repos/{owner}/{repo}` proxy path with request/response header allowlists, bounded bodies, no query forwarding, no path-cleaning redirects, and fail-closed upstream redirects.

Slice 1 is not yet complete. GitHub installation-token caching, structured audit events, metrics, deployment configuration, and the real Buildkite/GitHub smoke test remain.

## Delivery strategy

### Slice 1: standalone read-only vertical path

Create the Go service and prove the complete trust path against a disposable internal repository.

Scope:

- OIDC verifier with exact Buildkite issuer/audience, immutable identity claims, required branch/source/runner policy claims, bounded JWKS refresh, and single-use assertion enforcement.
- Static pipeline-to-repository/App policy.
- Redis-backed opaque session exchange using the fixed token/HMAC/TTL contract.
- Dedicated App token minting by numeric repository ID for `contents:read` on one repository.
- Fixed-host raw proxy for `GET /repos/{owner}/{repo}`. Accept only an exact `GET` whose escaped path byte-equals the session repository path; reject `%`, `\\`, and `//`, and do not forward query parameters in this slice.
- Allow only `Accept`, `User-Agent`, and `X-GitHub-Api-Version` request headers, append the Buildkite user-agent suffix, strip caller authentication/cookies/forwarding headers, and send `Accept-Encoding: identity` upstream.
- Apply the response-header allowlist and framing-header stripping from the raw forwarding contract.
- Configure the upstream client to reject redirects rather than follow them.
- Safe audit logs, health, readiness, and basic metrics.
- Manual `curl` smoke test from a real Buildkite job.

Definition of done:

- A real job exchanges OIDC and reads its configured repository without receiving a GitHub token.
- Another pipeline, repository, audience, route, or expired token is denied.
- A replayed OIDC assertion is denied.
- Redirects and disallowed request headers fail closed and never carry the App credential to another origin.
- No credential appears in logs, errors, responses, metrics, or stored plaintext.

### Slice 2: complete `ci-v1` and transport hardening

Scope:

- Add the remaining read, status, and check routes.
- Add exact GitHub permission attenuation for each session request.
- Add full path canonicalisation, the broader route-specific header set, body bounds, raw error preservation, rate limits, query forwarding, `Link` rewriting, and Basic-auth normalisation.
- Add a small local exchange/exec helper for smoke tests.

Definition of done:

- Repository/PR reads and commit-status/check-run writes work through the proxy.
- Unsupported routes, methods, repositories, and permissions fail consistently.
- GitHub 304, 403, 404, 422, 429, and 5xx responses preserve useful client semantics without leaking internals.

### Slice 3: `buildkite-gha` integration

Scope:

- Retain and normalise the supported `permissions:` subset.
- Add the versioned plan request and compiler authorisation evidence.
- Add gated runtime admission and `GitHubCredentialProvider`.
- Add OIDC exchange, redaction, GitHub/secrets contexts, and API URL environment.
- Ensure existing checkout/cache/artifact adapters remain unchanged.
- Run a real pinned `actions/github-script` action through the proxy.

Definition of done:

- A workflow declaring `contents:read` and `statuses:write` writes a commit status through `actions/github-script` without explicit OIDC or credentials.
- `${{ github.token }}` and `${{ secrets.GITHUB_TOKEN }}` resolve to the same redacted opaque token.
- The action cannot access another repository or unsupported API route.
- A tokenless workflow remains tokenless and does not contact the exchange service.

### Slice 4: ordinary Buildkite job integration

Scope:

- Package the exchange/exec helper for Buildkite agents.
- Add a small experimental plugin or documented command flow.
- Test `curl` and a common GitHub client that honours a custom API base URL.
- Document the hardcoded-host limitation clearly.

Definition of done:

- A normal Buildkite step can request the same `ci-v1` grant and report status without managing a GitHub PAT.
- The helper handles OIDC, exchange, redaction, environment, and cleanup without exposing the Agent access token.

### Slice 5: evidence and direction decision

Publish an experiment report covering ergonomics, compatible clients/actions, endpoint gaps, latency, GitHub rate limits, operational cost, and security limitations.

Choose:

1. **Proceed:** build public installation and policy management around the standalone service.
2. **Narrow:** retain it for `buildkite-gha` and curated clients only.
3. **Stop:** endpoint/client incompatibility outweighs the benefit; use direct short-lived GitHub installation tokens instead.

## Verification

### Service unit tests

- OIDC issuer, audience, algorithm, signature, `kid`, expiry, not-before, subject, and required claims.
- JWKS cache refresh and unknown-key behaviour.
- Exchange policy intersection and exact-satisfaction failures.
- Opaque-token entropy, hashing, expiry, lookup, revocation, and Redis TTL.
- Session repository/surface/permission binding.
- GitHub installation-token body contains the exact repository and permissions.
- Canonical method/path matching, repository equality, traversal, encoding, and absolute-host rejection.
- Authentication scheme normalisation and caller header stripping.
- Request and response header allowlists and raw status/body preservation.
- Redirect, oversized body, unsupported GraphQL, and unknown route failures.
- Audit/log redaction under success and error paths.

### Service integration tests

- Real Buildkite OIDC from a dedicated test pipeline.
- Real dedicated GitHub App installation on a disposable repository.
- Repository read, commit/PR read, commit status, and check-run lifecycle.
- Cross-pipeline and cross-repository denial.
- Expiry while a client holds a token.
- Primary/secondary rate-limit response behaviour.
- Concurrent sessions sharing one installation.

### `buildkite-gha` tests

- Workflow/job permission parsing, inheritance, replacement, unsupported key, and empty semantics.
- Plan schema, deterministic permission encoding, capability admission, and compiler authorisation evidence.
- `secrets.GITHUB_TOKEN` is not treated as a user Buildkite secret.
- Runtime exchange occurs only when capability is present.
- `github.token`, `secrets.GITHUB_TOKEN`, API URL contexts, standard environment, and redaction.
- Action metadata default `${{ github.token }}` becomes the expected input.
- Explicit action token input wins; arbitrary token inputs are never auto-filled.
- JavaScript pre/main/post and composite children share the job session safely.
- Existing checkout, cache, and artifact compatibility tests remain green.
- Hardcoded `api.github.com` test fails with an explicit supported limitation.

### Ordinary-build tests

- Helper requests correct OIDC audience/claims and never exposes the Agent token.
- Opaque token is redacted before the child starts.
- Child receives only the requested client environment.
- Exchange failure prevents command execution.
- Token is unavailable after helper exit where the execution environment permits cleanup.

## Success and stop criteria

Proceed or narrow if:

- A real `buildkite-gha` action uses the proxy through standard token/API contexts without workflow-specific credential plumbing.
- A normal Buildkite job uses the same service through one concise helper/plugin configuration.
- No successful path exposes a GitHub installation token.
- Cross-repository and unsupported-route attempts fail closed.
- The standalone service remains a small fixed-host `ci-v1` proxy rather than a general GitHub reimplementation.
- Added latency and rate-limit concentration are acceptable for CI reporting operations.

Stop or restrict if:

- Target actions routinely hardcode GitHub hosts or require unsupported event context.
- Useful CI requires GraphQL, uploads, Git transport, or broad API coverage immediately.
- Static/persisted repository policy becomes more complex than direct token issuance before ergonomics are proven.
- Maintaining wire-compatible error/header behaviour dominates the implementation.
- Shared installation rate limits make central proxying unreliable.
- A direct attenuated installation token provides almost the same practical security for the tested workloads.

## Key learnings from pressure-testing

- **A standalone service needs an authority source.** OIDC proves workload identity but not repository access. The prototype uses immutable pipeline-keyed static policy and keeps the policy interface replaceable.
- **The opaque token narrows rather than removes bearer-token risk.** A stolen session can call the granted proxy surface until expiry. Short lifetime, repository binding, API allowlisting, redaction, and revocation limit the damage.
- **Avoiding a live job-state dependency changes cancellation semantics.** The first service accepts bounded post-cancellation access until expiry. This is explicit rather than claiming immediate revocation it cannot enforce.
- **`buildkite-gha` must preserve workflow permissions before runtime integration matters.** Its proxy integration must also keep the provider-owned token alias separate from user-provided secrets.
- **Specialised compatibility remains simpler.** Checkout, caches, and artifacts stay native; the proxy handles only public GitHub repository APIs needed by CI.
- **REST allowlisting and GitHub attenuation serve different purposes.** The versioned route surface defines supported product behaviour, while the repository-scoped installation token protects against matcher mistakes.
- **A live App token requires transport hardening in the first slice.** Exact route matching, header filtering, response framing controls, and fail-closed redirects move into the read-only vertical path rather than waiting for the expanded API surface.
- **Policy inputs must be signed and mandatory.** Branch, source, and runner constraints are required OIDC claims; absent inputs deny access rather than weakening policy.
- **OIDC exchange is single-use and session storage has one concrete contract.** Redis replay keys and HMAC-derived session keys prevent assertion replay and plaintext bearer-token storage.
- **Hardcoded GitHub endpoints are an honest compatibility limit.** Interception or TLS rewriting would erase much of the security and simplicity gained by a standalone service.
- **Direct installation-token minting remains the fallback.** The proxy must demonstrate useful controls and good ergonomics for both target consumers, not merely prove that Go can forward HTTP.

## Resolved decisions

- Implement `github-api-proxy` as a standalone Go service.
- Make `buildkite-gha` and ordinary Buildkite jobs separate first-class consumers of the same protocol.
- Use Buildkite Job OIDC as the workload identity assertion.
- Exchange OIDC for an opaque proxy-only bearer token.
- Accept each OIDC assertion for exchange only once.
- Keep GitHub App installation tokens server-side.
- Mint installation tokens by immutable numeric repository ID, never repository name.
- Use static immutable pipeline/repository policy for the prototype.
- Restrict prototype writes to a purpose-built trusted pipeline/branch; do not infer fork safety from incomplete OIDC claims.
- Define a narrow, versioned `ci-v1` REST surface.
- Defer GraphQL, Git transport, uploads, releases, administration, user credentials, GHES, and broad API compatibility.
- Preserve `buildkite-gha` checkout/cache/artifact adapters.
- Expose proxy credentials through normal GitHub Actions contexts, not arbitrary input-name injection.
- Require an explicit supported workflow permission declaration in the first `buildkite-gha` experiment.
- Decide public product direction only after both consumer paths are exercised.

## Open questions

### Blocking the standalone vertical slice

1. **Where will the prototype service run?** Recommended default: one deployment with Redis and deployment-secret configuration before adding multi-region requirements.
2. **Which test pipeline/repository and GitHub App installation will anchor static policy?** Recommended default: purpose-built fixtures for repository reads and status/check tests.
3. **What OIDC/session lifetime should the experiment use?** Recommended default: request 15 minutes and issue a session no longer than the assertion. Increase only when a measured command requires it.

### Blocking the general-build slice

4. **Plugin or standalone helper first?** Recommended default: land the helper in the Go repository and wrap it with a thin experimental plugin, keeping all exchange and redaction logic in one binary.
5. **Which non-Actions client should be certified first?** Recommended default: `curl` for protocol fidelity, followed by a Go/Octokit client that accepts an explicit base URL. Defer `gh` until its custom-host token conventions are tested.

### Deferred until after the experiment

- Public policy persistence and Buildkite UI/API.
- GitHub App installation lifecycle and webhooks owned by the service.
- Buildkite job-state introspection and immediate cancellation revocation.
- Fork-PR trust downgrade and broader event provenance policy.
- Cross-repository grants.
- User OAuth/PAT credentials and attribution.
- GraphQL policy.
- GHES and BYO Apps.
- Downloads, release uploads, packages/GHCR, and Git smart HTTP.
- Multi-region session storage and multi-App rate-limit routing.

## Prior art

- [Fly Tokenizer](https://github.com/superfly/tokenizer): active Go credential-injecting HTTP proxy with sealed credentials and host restrictions. Useful transport prior art, but its GitHub App exchange does not currently request repository/permission attenuation.
- [Google Magic GitHub Proxy](https://github.com/google/magic-github-proxy): fixed-origin reverse-proxy proof of concept. It demonstrates both the ergonomics and danger of encrypted bearer credentials, regex-only policy, permissive redirects, and unsafe logging.
- [OctoSTS](https://github.com/octo-sts/app): active OIDC-to-GitHub installation-token exchange with repository and permission attenuation, audit correlation, and rate-limit-aware routing. Strong authorisation prior art, but it returns the GitHub credential to the workload rather than proxying operations.
- [`buildkite-gha` cache credentials](https://github.com/buildkite/buildkite-gha): existing Buildkite pattern for runtime-only compatibility credentials, redaction, and keeping the Agent access token out of action code.
