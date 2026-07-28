package integration_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jthomperoo/simple-proxy/proxy"
)

func TestHTTPProxyEndToEnd(t *testing.T) {
	t.Parallel()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "reached")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("proxied response"))
	}))
	t.Cleanup(origin.Close)

	proxyServer := httptest.NewServer(proxy.NewProxyHandler(2))
	t.Cleanup(proxyServer.Close)

	client := proxyClient(t, proxyServer.URL)
	response, err := client.Get(origin.URL + "/through-proxy")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	if got := response.Header.Get("X-Origin"); got != "reached" {
		t.Fatalf("X-Origin header = %q, want %q", got, "reached")
	}
	if got := string(body); got != "proxied response" {
		t.Fatalf("body = %q, want %q", got, "proxied response")
	}
}

func TestHTTPProxyAuthentication(t *testing.T) {
	t.Parallel()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)

	username, password := "proxy-user", "proxy-password"
	handler := proxy.NewProxyHandler(2)
	handler.Username = &username
	handler.Password = &password
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	client := proxyClient(t, proxyServer.URL)
	unauthorized, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("unauthenticated request: %v", err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf(
			"unauthenticated status = %d, want %d",
			unauthorized.StatusCode,
			http.StatusProxyAuthRequired,
		)
	}

	request, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("create authenticated request: %v", err)
	}
	request.Header.Set(
		"Proxy-Authorization",
		"Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)),
	)
	authorized, err := client.Do(request)
	if err != nil {
		t.Fatalf("authenticated request: %v", err)
	}
	authorized.Body.Close()
	if authorized.StatusCode != http.StatusNoContent {
		t.Fatalf("authenticated status = %d, want %d", authorized.StatusCode, http.StatusNoContent)
	}
}

func proxyClient(t *testing.T, proxyAddress string) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}
