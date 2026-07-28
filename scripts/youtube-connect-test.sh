#!/usr/bin/env sh
set -eu

test_dir="$(mktemp -d)"
test_port="${YOUTUBE_TEST_PORT:-$((20000 + ($$ % 20000)))}"
test_url="${YOUTUBE_TEST_URL:-https://www.youtube.com/generate_204}"
proxy_pid=""

cleanup() {
	if [ -n "$proxy_pid" ]; then
		kill "$proxy_pid" 2>/dev/null || true
		wait "$proxy_pid" 2>/dev/null || true
	fi
	rm -rf "$test_dir"
}
trap cleanup EXIT INT TERM

go build -buildvcs=false -o "$test_dir/simple-proxy" .
"$test_dir/simple-proxy" \
	-bind 127.0.0.1 \
	-port "$test_port" \
	>"$test_dir/proxy.log" 2>&1 &
proxy_pid=$!

attempt=0
while [ "$attempt" -lt 20 ]; do
	if curl \
		--fail \
		--silent \
		--output /dev/null \
		"http://127.0.0.1:$test_port/health"; then
		break
	fi
	if ! kill -0 "$proxy_pid" 2>/dev/null; then
		printf '%s\n' "YouTube test failed: simple-proxy exited early" >&2
		sed -n '1,120p' "$test_dir/proxy.log" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 0.25
done

if [ "$attempt" -eq 20 ]; then
	printf '%s\n' "YouTube test failed: proxy did not become ready" >&2
	sed -n '1,120p' "$test_dir/proxy.log" >&2
	exit 1
fi

if ! status_code="$(
	curl \
		--fail \
		--silent \
		--show-error \
		--output /dev/null \
		--write-out '%{http_code}' \
		--connect-timeout 10 \
		--max-time 20 \
		--noproxy "" \
		--proxy "http://127.0.0.1:$test_port" \
		"$test_url"
)"; then
	printf '%s\n' "YouTube test failed: could not reach $test_url through the proxy" >&2
	sed -n '1,120p' "$test_dir/proxy.log" >&2
	exit 1
fi

printf '%s\n' "YouTube test passed: $test_url returned HTTP $status_code through the proxy"
