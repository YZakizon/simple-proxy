#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Install a Let's Encrypt certificate and enable automatic renewal.

Usage:
  sudo ./scripts/install-cert.sh --domain proxy.example.com --email admin@example.com

Options:
  -d, --domain DOMAIN  Domain that points to this server
  -e, --email EMAIL    Email used for Let's Encrypt expiry and security notices
      --staging        Use Let's Encrypt's staging environment (for testing)
  -h, --help           Show this help

The HTTP-01 challenge requires inbound TCP port 80 to reach this server.
After a successful renewal, the running "simple-proxy" Docker container is
restarted so it loads the new certificate.
EOF
}

log() {
  printf '[install-cert] %s\n' "$*"
}

die() {
  printf '[install-cert] error: %s\n' "$*" >&2
  exit 1
}

domain=""
email=""
staging=false

while (($# > 0)); do
  case "$1" in
    -d|--domain)
      (($# >= 2)) || die "$1 requires a value"
      domain=$2
      shift 2
      ;;
    -e|--email)
      (($# >= 2)) || die "$1 requires a value"
      email=$2
      shift 2
      ;;
    --staging)
      staging=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (run with --help for usage)"
      ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this script as root (for example, with sudo)"
[[ -n $domain ]] || die "--domain is required"
[[ -n $email ]] || die "--email is required"
[[ $domain =~ ^([[:alnum:]]([[:alnum:]-]*[[:alnum:]])?\.)+[[:alpha:]]{2,}$ ]] ||
  die "invalid domain: $domain"
[[ $email =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
  die "invalid email address: $email"

if ! command -v certbot >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 ||
    die "certbot is not installed and this system does not provide apt-get"

  log "Installing Certbot"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
fi

deploy_hook_dir=/etc/letsencrypt/renewal-hooks/deploy
deploy_hook="$deploy_hook_dir/restart-simple-proxy"

install -d -m 0755 "$deploy_hook_dir"
temporary_hook=$(mktemp)
trap 'rm -f "$temporary_hook"' EXIT

cat >"$temporary_hook" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

container_name=simple-proxy

# The first certificate may be obtained before the container is created.
if ! command -v docker >/dev/null 2>&1 ||
  ! docker container inspect "$container_name" >/dev/null 2>&1; then
  exit 0
fi

if [[ $(docker inspect --format '{{.State.Running}}' "$container_name") == "true" ]]; then
  docker restart "$container_name"
fi
EOF

install -m 0755 "$temporary_hook" "$deploy_hook"

certbot_args=(
  certonly
  --standalone
  --preferred-challenges http
  --non-interactive
  --agree-tos
  --keep-until-expiring
  --cert-name "$domain"
  --domain "$domain"
  --email "$email"
)

if [[ $staging == true ]]; then
  certbot_args+=(--staging)
fi

log "Requesting certificate for $domain"
certbot "${certbot_args[@]}"

if command -v systemctl >/dev/null 2>&1; then
  log "Enabling Certbot's automatic renewal timer"
  systemctl enable --now certbot.timer
  systemctl is-active --quiet certbot.timer ||
    die "certbot.timer was enabled but is not active"
else
  die "systemd is required to schedule automatic renewal on this server"
fi

log "Testing the renewal configuration"
certbot renew --dry-run --cert-name "$domain"

cat <<EOF

Certificate installed and automatic renewal enabled.

Set these values in the project's .env file:
SSL_CERT=/etc/letsencrypt/live/$domain/fullchain.pem
SSL_KEY=/etc/letsencrypt/live/$domain/privkey.pem

Then start or recreate the proxy with:
docker compose up -d --build
EOF
