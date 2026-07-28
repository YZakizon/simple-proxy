# Simple Proxy

Simple Proxy is a small HTTP/HTTPS forward proxy distributed as a
self-contained Go binary. It supports HTTP forwarding, CONNECT tunnels,
optional SOCKS5 forwarding, source and destination allowlists, TLS, and Basic
proxy authentication.

## Secure defaults

- The listener binds to `127.0.0.1`, not every interface.
- An unauthenticated non-loopback listener is rejected unless
  `-allow-open-proxy` is explicitly supplied.
- Basic proxy authentication over plaintext HTTP is rejected unless
  `-allow-insecure-auth` is explicitly supplied.
- Client forwarding headers are ignored unless the TCP peer is in
  `-trusted-proxy-cidr`.
- Loopback, private, link-local, multicast, unspecified, and carrier-grade NAT
  destinations are blocked unless `-allow-private-destinations` is supplied.
- Proxy credentials and hop-by-hop headers are removed before origin requests.
- Sensitive request headers are redacted when header logging is enabled.

These controls reduce accidental open-proxy exposure and server-side request
forgery. Operators are still responsible for firewalling the listener and
using strong credentials.

## Build and test

Go 1.25.12 or newer is required.

```sh
go build -o simple-proxy .
make verify
```

Release archives are also available from the repository's
[releases page](https://github.com/jthomperoo/simple-proxy/releases).

## Local usage

The default listener is an unauthenticated loopback HTTP proxy:

```sh
./simple-proxy
curl --proxy http://127.0.0.1:8888 https://example.com/
```

For a network listener, use TLS and file-based authentication:

```sh
printf '%s\n' 'proxy-user:replace-with-a-long-random-password' \
  > /secure/path/proxy-auth
chmod 600 /secure/path/proxy-auth

./simple-proxy \
  -protocol https \
  -bind 0.0.0.0 \
  -port 8888 \
  -cert /secure/path/fullchain.pem \
  -key /secure/path/privkey.pem \
  -basic-auth-file /secure/path/proxy-auth \
  -deny-all \
  -allow-src-ip 192.0.2.10/32 \
  -allow-dest-host example.com,example.com:443
```

A destination rule without a port permits that canonical hostname on any
port. A `host:port` rule restricts both. DNS results are checked immediately
before dialing and prohibited address ranges are never selected by default.

## Reverse proxy deployment

Forwarding headers affect source authorization only when the direct TCP peer is
trusted:

```sh
./simple-proxy \
  -trusted-proxy-cidr 10.0.0.0/8,2001:db8:1234::/48 \
  -deny-all \
  -allow-src-ip 192.0.2.0/24
```

The proxy walks RFC `Forwarded` or `X-Forwarded-For` from right to left and
stops at the nearest untrusted address. Do not trust a CIDR containing ordinary
clients.

## Container deployment

Copy `.env.example` to `.env`, create the files described in
`secrets/README.md`, and run:

```sh
docker compose up --build -d
```

The Compose service:

- runs as non-root with all Linux capabilities dropped;
- uses a read-only root filesystem and read-only TLS mounts;
- obtains proxy credentials from a Compose secret;
- publishes only on loopback by default; and
- uses the binary's loopback-only healthcheck mode.

## Important options

```text
-bind string
    listener address (default "127.0.0.1")
-port string
    listener port (default "8888")
-protocol string
    listener protocol: http or https (default "http")
-basic-auth-file string
    file containing username:password
-deny-all
    deny sources not present in -allow-src-ip
-allow-src-ip string
    comma-separated source IPs or CIDRs
-allow-dest-host string
    comma-separated destination hosts or host:port pairs
-trusted-proxy-cidr string
    comma-separated reverse-proxy CIDRs trusted for forwarding headers
-allow-private-destinations
    permit private and otherwise prohibited destination ranges
-response-header-timeout int
    origin response header timeout in seconds (default 15)
-tunnel-idle-timeout int
    CONNECT idle timeout in seconds (default 300)
-max-connections int
    maximum concurrent client connections (default 256)
```

Run `./simple-proxy -help` for the complete flag list. The legacy
`-basic-auth` and `-socks5-auth` flags remain for compatibility, but expose
credentials through process metadata. Use `-basic-auth-file` and
`-socks5-auth-file` in production.

## Healthcheck

`GET /health` in origin form returns `OK`. Absolute-form proxy requests whose
destination path happens to be `/health` are forwarded normally.

Minimal containers can invoke:

```sh
simple-proxy -healthcheck-url https://127.0.0.1:8888/health
```

The healthcheck URL is restricted to loopback targets.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
