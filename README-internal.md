# Deploy

rsync -avz --exclude .git --exclude .env . td340:~/simple-proxy

## Install TLS certificate

On a Debian or Ubuntu server using systemd, point the domain's DNS record at the
server and ensure inbound TCP port 80 is open and unused during certificate
issuance and renewal. Then run:

```bash
sudo ./scripts/install-cert.sh \
  --domain pr.your-domain.com \
  --email admin@your-domain.com
```

The script installs Certbot, obtains a Let's Encrypt certificate, enables the
systemd renewal timer, and installs a deploy hook that restarts the
`simple-proxy` container after a successful renewal. Copy the `SSL_CERT` and
`SSL_KEY` values printed by the script into `.env` before starting the service.
