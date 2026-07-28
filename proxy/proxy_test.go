package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBasicAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		auth     string
		username string
		password string
		ok       bool
	}{
		{
			name:     "valid credentials",
			auth:     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret")),
			username: "user",
			password: "secret",
			ok:       true,
		},
		{
			name:     "password may contain colon",
			auth:     "basic " + base64.StdEncoding.EncodeToString([]byte("user:secret:value")),
			username: "user",
			password: "secret:value",
			ok:       true,
		},
		{name: "wrong scheme", auth: "Bearer token"},
		{name: "invalid base64", auth: "Basic !!!"},
		{
			name: "missing separator",
			auth: "Basic " + base64.StdEncoding.EncodeToString([]byte("user")),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			username, password, ok := parseBasicAuth(tt.auth)
			if username != tt.username || password != tt.password || ok != tt.ok {
				t.Fatalf(
					"parseBasicAuth() = (%q, %q, %v), want (%q, %q, %v)",
					username,
					password,
					ok,
					tt.username,
					tt.password,
					tt.ok,
				)
			}
		})
	}
}

func TestGetUserIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		headers    http.Header
		want       string
	}{
		{
			name:       "real IP takes precedence",
			remoteAddr: "192.0.2.1:1234",
			headers: http.Header{
				"X-Real-Ip":       []string{"203.0.113.10"},
				"X-Forwarded-For": []string{"203.0.113.11"},
			},
			want: "203.0.113.10",
		},
		{
			name:       "forwarded IP is used",
			remoteAddr: "192.0.2.1:1234",
			headers: http.Header{
				"X-Forwarded-For": []string{"203.0.113.11"},
			},
			want: "203.0.113.11",
		},
		{
			name:       "remote address fallback",
			remoteAddr: "192.0.2.1:1234",
			headers:    make(http.Header),
			want:       "192.0.2.1",
		},
		{
			name:       "IPv6 loopback",
			remoteAddr: "[::1]:1234",
			headers:    make(http.Header),
			want:       "[::1]",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			request := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     tt.headers,
			}
			if got := GetUserIP(request); got != tt.want {
				t.Fatalf("GetUserIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProxyHandlerAccessRules(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "http://example.test/resource", nil)
	request.Host = "example.test"

	tests := []struct {
		name    string
		handler ProxyHandler
		ip      string
		want    bool
	}{
		{
			name:    "requests are allowed by default",
			handler: ProxyHandler{},
			ip:      "192.0.2.1",
			want:    true,
		},
		{
			name: "deny all permits allowlisted source",
			handler: ProxyHandler{
				DenyAll:           true,
				AllowSrcIPAddress: []string{"192.0.2.1"},
			},
			ip:   "192.0.2.1",
			want: true,
		},
		{
			name: "deny all blocks unknown source",
			handler: ProxyHandler{
				DenyAll:           true,
				AllowSrcIPAddress: []string{"192.0.2.1"},
			},
			ip: "192.0.2.2",
		},
		{
			name: "destination allowlist permits matching host",
			handler: ProxyHandler{
				DenyAll:           true,
				AllowSrcIPAddress: []string{"192.0.2.1"},
				AllowDestHost:     []string{"example.test"},
			},
			ip:   "192.0.2.1",
			want: true,
		},
		{
			name: "destination allowlist blocks other host",
			handler: ProxyHandler{
				DenyAll:           true,
				AllowSrcIPAddress: []string{"192.0.2.1"},
				AllowDestHost:     []string{"other.test"},
			},
			ip: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.handler.isAllowed(request, tt.ip); got != tt.want {
				t.Fatalf("isAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	handler := NewProxyHandler(1)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Server"); got != "simple-proxy" {
		t.Fatalf("Server header = %q, want %q", got, "simple-proxy")
	}
	if got := response.Body.String(); got != "OK\r\n" {
		t.Fatalf("body = %q, want %q", got, "OK\r\n")
	}
}
