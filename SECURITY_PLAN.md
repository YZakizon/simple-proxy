# Security Hardening Plan

This plan tracks the findings from the July 2026 security review. A checked
item is implemented on the `security/hardening` branch; validation results are
recorded at the bottom of this file.

## P0: Trust boundaries and credential safety

- [x] Derive the client address from the TCP peer by default.
- [x] Trust `Forwarded`/`X-Forwarded-For`/`X-Real-IP` only from explicitly
      configured proxy CIDRs.
- [x] Strip proxy credentials and all hop-by-hop headers before forwarding.
- [x] Use constant-time proxy credential comparison.
- [x] Redact credentials, cookies, and tokens from logs.
- [x] Support file-based proxy credentials so production secrets do not need
      to appear in process arguments or container metadata.
- [x] Make an unauthenticated, non-loopback listener an explicit opt-in.
- [x] Refuse plaintext Basic proxy authentication unless explicitly allowed.

## P1: Destination and denial-of-service controls

- [x] Canonicalize destination hostnames, IP literals, and optional ports.
- [x] Resolve and dial destinations through one policy-enforcing path to
      prevent DNS rebinding between authorization and connection.
- [x] Block loopback, private, link-local, multicast, unspecified, and
      carrier-grade NAT destinations by default.
- [x] Apply destination allowlists independently of source allowlists.
- [x] Add server header/idle timeouts and outbound response/TLS timeouts.
- [x] Add tunnel idle deadlines and safe CONNECT hijack error handling.
- [x] Limit concurrent client connections.
- [x] Return generic client errors while retaining detailed server-side logs.

## P1: Dependency and container hardening

- [x] Upgrade `golang.org/x/net` beyond the version affected by GO-2026-4918.
- [x] Build and test with a patched Go toolchain.
- [x] Run `govulncheck` in CI.
- [x] Use a non-root, minimal runtime image and exact toolchain version.
- [x] Make the container filesystem and certificate mounts read-only.
- [x] Drop Linux capabilities and enable `no-new-privileges`.
- [x] Bind the published Compose port to loopback by default.
- [x] Replace command-line credentials with a Compose secret.
- [x] Add `.dockerignore` and a correctly named `.env.example`.

## P2: Regression coverage and operational improvements

- [x] Cover forwarding-header spoofing and trusted proxy chains.
- [x] Verify proxy credentials and hop-by-hop headers never reach origins.
- [x] Cover destination canonicalization and prohibited address ranges.
- [x] Cover authenticated HTTP forwarding and CONNECT tunneling.
- [x] Cover slow-origin timeout behavior and hijack failures.
- [x] Add a self-contained healthcheck mode for minimal container images.
- [x] Add graceful process shutdown.
- [x] Document secure deployment defaults and compatibility overrides.

## Validation

- [x] `gofmt` and `git diff --check`
- [x] `go vet ./...`
- [x] `go test -race ./...`
- [x] `govulncheck ./...`
- [x] Docker image build
- [x] `docker compose config`
- [x] Local smoke test
