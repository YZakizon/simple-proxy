# Plans

## Support Spaces in Comma-Separated Environment Values

Status: Implemented

### Summary

Accept values such as `ALLOW_SRC_IP=1.1.1.1, 2.2.2.2` and
`ALLOW_DEST_HOST=one.test, two.test` by preserving each full value through
Docker Compose and trimming whitespace during parsing.

### Implementation Changes

- Use the shared `splitNonempty` parser in `main.go` to trim surrounding whitespace
  from every item and ignores empty items.
- Use it for both `--allow-src-ip` and `--allow-dest-host`, covering direct CLI
  and `.env`-derived values.
- Change `docker-compose.yml` from a whitespace-split command string to YAML
  argument-list form so values containing spaces reach the application as
  single arguments.
- Preserve the security-hardening listener and destination-policy controls.

### Interfaces

- No new flags or exported Go APIs.
- Existing allowlist flags gain support for whitespace around comma-separated
  entries.

### Test Plan

- Add unit cases for lists with no spaces, spaces after commas,
  leading/trailing whitespace, tabs, and empty entries.
- Verify both source-IP and destination-host parsing use normalized values.
- Confirm `docker compose config` represents each complete allowlist value as
  one argument.
- Run `go test ./...`.

### Assumptions

- "Spaces" means surrounding whitespace around individual list entries, not
  whitespace inside valid host or IP text.
- The corrected `.env.example` documents values without storing credentials.

### Validation

- `make test`
- `git diff --check`
- `docker compose config` with spaced source-IP and destination-host values
