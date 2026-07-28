package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGetUserIPIgnoresForwardingHeaders(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Real-Ip", "203.0.113.7")
	request.Header.Set("X-Forwarded-For", "203.0.113.8")

	if got := GetUserIP(request); got != "192.0.2.10" {
		t.Fatalf("GetUserIP() = %q, want TCP peer", got)
	}
}

func TestClientIPTrustBoundary(t *testing.T) {
	t.Parallel()
	_, trusted, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	handler := &ProxyHandler{TrustedProxyCIDRs: []*net.IPNet{trusted}}

	tests := []struct {
		name       string
		remoteAddr string
		standard   string
		forwarded  string
		realIP     string
		want       string
	}{
		{
			name:       "untrusted peer cannot spoof",
			remoteAddr: "192.0.2.10:1234",
			forwarded:  "203.0.113.8",
			realIP:     "203.0.113.7",
			want:       "192.0.2.10",
		},
		{
			name:       "standard forwarded chain is supported",
			remoteAddr: "10.0.0.2:1234",
			standard:   `for=203.0.113.9;proto=https, for="10.0.0.1:443"`,
			want:       "203.0.113.9",
		},
		{
			name:       "trusted chain returns nearest untrusted client",
			remoteAddr: "10.0.0.2:1234",
			forwarded:  "203.0.113.8, 10.0.0.1",
			want:       "203.0.113.8",
		},
		{
			name:       "trusted peer may supply real IP",
			remoteAddr: "10.0.0.2:1234",
			realIP:     "203.0.113.7",
			want:       "203.0.113.7",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("Forwarded", test.standard)
			request.Header.Set("X-Forwarded-For", test.forwarded)
			request.Header.Set("X-Real-Ip", test.realIP)
			if got := ipString(handler.clientIP(request)); got != test.want {
				t.Fatalf("clientIP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSourceAllowlistSupportsAddressesAndCIDRs(t *testing.T) {
	t.Parallel()
	handler := &ProxyHandler{
		DenyAll:           true,
		AllowSrcIPAddress: []string{"192.0.2.1", "2001:db8::/32"},
	}
	if !handler.sourceAllowed(net.ParseIP("192.0.2.1")) {
		t.Fatal("exact IPv4 address should be allowed")
	}
	if !handler.sourceAllowed(net.ParseIP("2001:db8::5")) {
		t.Fatal("IPv6 address inside CIDR should be allowed")
	}
	if handler.sourceAllowed(net.ParseIP("198.51.100.1")) {
		t.Fatal("unknown source should be denied")
	}
}

func TestDestinationCanonicalizationAndAllowlist(t *testing.T) {
	t.Parallel()
	handler := &ProxyHandler{
		AllowDestHost: []string{"Example.COM.", "example.net:443", "[2001:db8::1]:8443"},
	}
	tests := []struct {
		address string
		want    bool
	}{
		{"example.com:80", true},
		{"EXAMPLE.COM.:443", true},
		{"example.net:443", true},
		{"example.net:80", false},
		{"[2001:db8::1]:8443", true},
		{"[2001:db8::1]:443", false},
	}
	for _, test := range tests {
		host, port, err := canonicalAuthority(test.address)
		if err != nil {
			t.Fatalf("canonicalAuthority(%q): %v", test.address, err)
		}
		if got := handler.destinationAllowed(host, port); got != test.want {
			t.Errorf("destinationAllowed(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}

func TestProhibitedDestinationRanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"::1", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"2606:4700:4700::1111", false},
	}
	for _, test := range tests {
		if got := prohibitedDestination(net.ParseIP(test.ip)); got != test.want {
			t.Errorf("prohibitedDestination(%s) = %v, want %v", test.ip, got, test.want)
		}
	}
}

func TestParseBasicAuth(t *testing.T) {
	t.Parallel()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret:value"))
	username, password, ok := parseBasicAuth(auth)
	if !ok || username != "user" || password != "secret:value" {
		t.Fatalf("parseBasicAuth() = (%q, %q, %v)", username, password, ok)
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"Connection":          {"Keep-Alive, X-Remove-Me"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"secret"},
		"X-Remove-Me":         {"value"},
		"X-Keep-Me":           {"value"},
	}
	removeHopByHopHeaders(headers)
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "X-Remove-Me"} {
		if headers.Get(name) != "" {
			t.Errorf("%s was not removed", name)
		}
	}
	if headers.Get("X-Keep-Me") != "value" {
		t.Fatal("end-to-end header was removed")
	}
}

func TestSensitiveHeadersAreRecognized(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"Authorization",
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		"X-API-Key",
		"X-Access-Token",
		"X-Client-Secret",
	} {
		if !sensitiveHeader(name) {
			t.Errorf("%s should be redacted", name)
		}
	}
	if sensitiveHeader("Content-Type") {
		t.Fatal("ordinary header should not be redacted")
	}
}

func TestHealthOnlyHandlesOriginFormGET(t *testing.T) {
	t.Parallel()
	originForm := httptest.NewRequest(http.MethodGet, "/health", nil)
	if !isLocalHealthRequest(originForm) {
		t.Fatal("origin-form health request should be handled locally")
	}
	absoluteForm := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
	if isLocalHealthRequest(absoluteForm) {
		t.Fatal("proxy request to a /health destination must not be intercepted")
	}
}

func TestAuthenticatedHTTPProxyStripsCredentialsAndHopHeaders(t *testing.T) {
	t.Parallel()
	received := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.Header().Set("Connection", "X-Origin-Hop")
		w.Header().Set("X-Origin-Hop", "remove")
		w.Header().Set("X-End-To-End", "keep")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)

	username, password := "proxy-user", "proxy-password"
	handler := NewProxyHandler(2)
	handler.Username = &username
	handler.Password = &password
	handler.AllowPrivateDestinations = true
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword(username, password)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
	request, err := http.NewRequest(http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "remove")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	headers := <-received
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Connection", "X-Remove-Me"} {
		if headers.Get(name) != "" {
			t.Errorf("origin received forbidden header %s", name)
		}
	}
	if response.Header.Get("X-Origin-Hop") != "" {
		t.Fatal("client received connection-nominated origin header")
	}
	if response.Header.Get("X-End-To-End") != "keep" {
		t.Fatal("client did not receive end-to-end origin header")
	}
}

func TestResponseHeaderTimeout(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)

	handler := NewProxyHandler(2)
	handler.ResponseHeaderTimeout = 25 * time.Millisecond
	handler.AllowPrivateDestinations = true
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	client := proxyHTTPClient(t, proxyServer.URL)
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestPrivateDestinationBlockedByDefault(t *testing.T) {
	t.Parallel()
	originReached := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originReached <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(origin.Close)

	proxyServer := httptest.NewServer(NewProxyHandler(2))
	t.Cleanup(proxyServer.Close)
	response, err := proxyHTTPClient(t, proxyServer.URL).Get(origin.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	select {
	case <-originReached:
		t.Fatal("prohibited loopback origin was reached")
	default:
	}
}

func TestConnectHijackFailureReturnsError(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	handler := NewProxyHandler(2)
	handler.AllowPrivateDestinations = true
	request := httptest.NewRequest(http.MethodConnect, "http://"+listener.Addr().String(), nil)
	request.Host = listener.Addr().String()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func TestConnectTunnel(t *testing.T) {
	t.Parallel()
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echoListener.Close() })
	go func() {
		conn, acceptErr := echoListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	handler := NewProxyHandler(2)
	handler.AllowPrivateDestinations = true
	handler.AllowDestHost = []string{echoListener.Addr().String()}
	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	proxyAddress := strings.TrimPrefix(proxyServer.URL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT "+echoListener.Addr().String()+" HTTP/1.1\r\nHost: "+echoListener.Addr().String()+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d", response.StatusCode, http.StatusOK)
	}

	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q, want ping", echo)
	}
}

func proxyHTTPClient(t *testing.T, proxyAddress string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
}
