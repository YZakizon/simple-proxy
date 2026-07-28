#!/usr/bin/env sh
set -eu

smoke_dir="$(mktemp -d)"
smoke_port="${SMOKE_PORT:-$((20000 + ($$ % 20000)))}"
proxy_pid=""

cleanup() {
	if [ -n "$proxy_pid" ]; then
		kill "$proxy_pid" 2>/dev/null || true
		wait "$proxy_pid" 2>/dev/null || true
	fi
	rm -rf "$smoke_dir"
}
trap cleanup EXIT INT TERM

go build -o "$smoke_dir/simple-proxy" .
"$smoke_dir/simple-proxy" -bind 127.0.0.1 -port "$smoke_port" >"$smoke_dir/proxy.log" 2>&1 &
proxy_pid=$!

attempt=0
while [ "$attempt" -lt 20 ]; do
	if response="$(
		curl --fail --silent --show-error "http://127.0.0.1:$smoke_port/health" 2>/dev/null |
			tr -d '\r\n'
	)"; then
		if [ "$response" = "OK" ]; then
			printf '%s\n' "Smoke test passed: health endpoint returned OK"
			exit 0
		fi
	fi
	if ! kill -0 "$proxy_pid" 2>/dev/null; then
		printf '%s\n' "Smoke test failed: simple-proxy exited early" >&2
		sed -n '1,120p' "$smoke_dir/proxy.log" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 0.25
done

printf '%s\n' "Smoke test failed: health endpoint did not become ready" >&2
sed -n '1,120p' "$smoke_dir/proxy.log" >&2
exit 1
