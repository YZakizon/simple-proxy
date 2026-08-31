#!/usr/bin/env sh
set -eu

env_file="${ENV_FILE:-.env}"

read_env_value() {
	key="$1"
	value="$(
		awk -v key="$key" '
			index($0, key "=") == 1 {
				print substr($0, length(key) + 2)
				exit
			}
		' "$env_file"
	)"

	case "$value" in
		\"*\")
			value="${value#\"}"
			value="${value%\"}"
			;;
		\'*\')
			value="${value#\'}"
			value="${value%\'}"
			;;
	esac
	printf '%s' "$value"
}

if [ ! -f "$env_file" ]; then
	printf 'Live test failed: environment file %s does not exist\n' "$env_file" >&2
	exit 1
fi

ssl_cert_file="${SSL_CERT_FILE:-$(read_env_value SSL_CERT_FILE)}"
ssl_key_file="${SSL_KEY_FILE:-$(read_env_value SSL_KEY_FILE)}"
basic_auth_file="${BASIC_AUTH_FILE:-$(read_env_value BASIC_AUTH_FILE)}"
allow_dest_host="${ALLOW_DEST_HOST:-$(read_env_value ALLOW_DEST_HOST)}"
proxy_port="${PROXY_PORT:-$(read_env_value PROXY_PORT)}"
proxy_port="${proxy_port:-8888}"
proxy_url="${LIVE_PROXY_URL:-https://127.0.0.1:$proxy_port}"
proxy_container="${LIVE_PROXY_CONTAINER:-}"
docker_gateway=""

if [ -z "$ssl_cert_file" ]; then
	printf '%s\n' "Live test failed: SSL_CERT_FILE is empty" >&2
	exit 1
fi
if [ -z "$ssl_key_file" ]; then
	printf '%s\n' "Live test failed: SSL_KEY_FILE is empty" >&2
	exit 1
fi
if [ -z "$basic_auth_file" ]; then
	printf '%s\n' "Live test failed: BASIC_AUTH_FILE is empty" >&2
	exit 1
fi
if [ -z "$allow_dest_host" ]; then
	printf '%s\n' "Live test failed: ALLOW_DEST_HOST is empty" >&2
	exit 1
fi
if [ ! -e "$ssl_cert_file" ]; then
	printf 'Live test failed: SSL_CERT_FILE path does not exist: %s\n' "$ssl_cert_file" >&2
	exit 1
fi
if [ ! -e "$ssl_key_file" ]; then
	printf 'Live test failed: SSL_KEY_FILE path does not exist: %s\n' "$ssl_key_file" >&2
	exit 1
fi
if [ ! -e "$basic_auth_file" ]; then
	printf 'Live test failed: BASIC_AUTH_FILE path does not exist: %s\n' "$basic_auth_file" >&2
	exit 1
fi

basic_auth="$(tr -d '\r\n' <"$basic_auth_file")"
if [ -z "$basic_auth" ]; then
	printf 'Live test failed: BASIC_AUTH_FILE is empty: %s\n' "$basic_auth_file" >&2
	exit 1
fi

if [ -z "$proxy_container" ] &&
	[ "$proxy_url" = "https://127.0.0.1:$proxy_port" ] &&
	command -v docker >/dev/null 2>&1; then
	proxy_container="$(docker compose ps -q proxy 2>/dev/null || true)"
fi

if [ -n "$proxy_container" ]; then
	docker_gateway="$(
		docker container inspect "$proxy_container" \
			--format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' \
			2>/dev/null || true
	)"
fi

curl_error_file="$(mktemp)"
trap 'rm -f "$curl_error_file"' EXIT HUP INT TERM

destination_count=0
destination_lines="$(printf '%s' "$allow_dest_host" | tr ',' '\n')"

while IFS= read -r raw_destination; do
	destination="$(
		printf '%s' "$raw_destination" |
			sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
	)"
	if [ -z "$destination" ]; then
		continue
	fi

	case "$destination" in
		http://* | https://*)
			destination_url="$destination"
			;;
		*)
			destination_url="https://$destination"
			;;
	esac

	printf 'Testing %s through %s\n' "$destination_url" "$proxy_url"
	if curl_result="$(
		curl \
			--fail \
			--silent \
			--show-error \
			--output /dev/null \
			--write-out '%{http_code} %{http_connect}' \
			--connect-timeout 10 \
			--max-time 30 \
			--noproxy "" \
			--proxy-insecure \
			--proxy-user "$basic_auth" \
			--proxy "$proxy_url" \
			"$destination_url" 2>"$curl_error_file"
	)"; then
		:
	else
		curl_status=$?
		cat "$curl_error_file" >&2
		connect_status="${curl_result#* }"
		if [ "$connect_status" = "403" ] && [ -n "$docker_gateway" ]; then
			printf '%s\n' \
				"Live test Docker source: $docker_gateway" \
				"Ensure ALLOW_SRC_IP includes this Compose gateway; local traffic to $proxy_url is NATed through it." >&2
		fi
		exit "$curl_status"
	fi

	status_code="${curl_result%% *}"
	printf 'Passed: %s returned HTTP %s\n' "$destination_url" "$status_code"
	destination_count=$((destination_count + 1))
done <<EOF
$destination_lines
EOF

if [ "$destination_count" -eq 0 ]; then
	printf '%s\n' "Live test failed: ALLOW_DEST_HOST contains no destinations" >&2
	exit 1
fi

printf 'Live test passed: checked %d destination(s)\n' "$destination_count"
