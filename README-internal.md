# Internal deployment

Use `docker compose` with credentials and TLS material supplied as files. Do
not pass credentials on the command line.

```sh
cp .env.example .env
mkdir -p secrets
printf '%s\n' 'proxy-user:replace-with-a-long-random-password' \
  > secrets/proxy_basic_auth
chmod 600 secrets/proxy_basic_auth
```

## Install and renew a TLS certificate

On a Debian or Ubuntu server using systemd, point the domain's DNS record at the
server and ensure inbound TCP port 80 is open and unused during certificate
issuance and renewal. Then run:

```bash
sudo ./scripts/install-cert.sh \
  --domain pr.your-domain.com \
  --email admin@your-domain.com
```

The script installs Certbot, obtains the certificate, enables the systemd
renewal timer, and copies renewed material into `secrets/tls-cert.pem` and
`secrets/tls-key.pem` before restarting the `simple-proxy` container. Those
fixed files match the hardened read-only Compose mounts.

To use existing certificate material instead:

```sh
cp /secure/source/fullchain.pem secrets/tls-cert.pem
cp /secure/source/privkey.pem secrets/tls-key.pem
```

The container runs as UID/GID `65532`. Ensure all three secret files are
readable by that identity using narrowly scoped ownership or ACLs. Compose
publishes only on `127.0.0.1` unless `PROXY_PUBLISH_ADDRESS` is deliberately
changed.

```sh
docker compose up --build -d
```
