package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCredentialPair(t *testing.T) {
	t.Parallel()
	username, password, configured, err := parseCredentialPair("user:secret:value")
	if err != nil || !configured || username != "user" || password != "secret:value" {
		t.Fatalf("parseCredentialPair() = (%q, %q, %v, %v)", username, password, configured, err)
	}
	if _, _, _, err := parseCredentialPair("missing-separator"); err == nil {
		t.Fatal("malformed credentials should fail")
	}
}

func TestParseCIDRs(t *testing.T) {
	t.Parallel()
	networks, err := parseCIDRs([]string{"192.0.2.1", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if !networks[0].Contains(net.ParseIP("192.0.2.1")) {
		t.Fatal("single IP was not converted to a host prefix")
	}
	if !networks[1].Contains(net.ParseIP("2001:db8::5")) {
		t.Fatal("IPv6 CIDR was not parsed")
	}
}

func TestLoopbackBind(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"127.0.0.1", "::1", "[::1]", "localhost"} {
		if !loopbackBind(address) {
			t.Errorf("%q should be considered loopback", address)
		}
	}
	for _, address := range []string{"0.0.0.0", "::", "192.0.2.1", ""} {
		if loopbackBind(address) {
			t.Errorf("%q should not be considered loopback", address)
		}
	}
}

func TestCheckHealthRejectsRemoteTargets(t *testing.T) {
	t.Parallel()
	if err := checkHealth("https://example.com/health"); err == nil {
		t.Fatal("remote healthcheck target should be rejected")
	}
}

func TestValidateListenerSecurity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		bind          string
		protocol      string
		auth          bool
		denyAll       bool
		allowOpen     bool
		allowInsecure bool
		wantError     bool
	}{
		{name: "loopback default is safe", bind: "127.0.0.1", protocol: "http"},
		{name: "open network listener is rejected", bind: "0.0.0.0", protocol: "http", wantError: true},
		{name: "source allowlist secures network listener", bind: "0.0.0.0", protocol: "https", denyAll: true},
		{name: "authenticated TLS listener is safe", bind: "0.0.0.0", protocol: "https", auth: true},
		{name: "plaintext auth is rejected", bind: "127.0.0.1", protocol: "http", auth: true, wantError: true},
		{name: "explicit plaintext auth override", bind: "127.0.0.1", protocol: "http", auth: true, allowInsecure: true},
		{name: "explicit open proxy override", bind: "0.0.0.0", protocol: "http", allowOpen: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateListenerSecurity(
				test.bind,
				test.protocol,
				test.auth,
				test.denyAll,
				test.allowOpen,
				test.allowInsecure,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("validateListenerSecurity() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestReadCredentialFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("user:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if value != "user:secret" {
		t.Fatalf("readCredentialFile() = %q", value)
	}

	largePath := filepath.Join(t.TempDir(), "large-credentials")
	if err := os.WriteFile(largePath, []byte(strings.Repeat("x", 4097)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(largePath); err == nil {
		t.Fatal("oversized credential file should be rejected")
	}
}

func TestSplitNonempty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{name: "values without whitespace", value: "192.0.2.1,198.51.100.2", want: []string{"192.0.2.1", "198.51.100.2"}},
		{name: "spaces after commas", value: "192.0.2.1, 198.51.100.2", want: []string{"192.0.2.1", "198.51.100.2"}},
		{name: "surrounding whitespace", value: "  example.test,\tapi.example.test \n", want: []string{"example.test", "api.example.test"}},
		{name: "empty entries", value: "192.0.2.1, ,198.51.100.2,", want: []string{"192.0.2.1", "198.51.100.2"}},
		{name: "empty value", value: "", want: nil},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := splitNonempty(test.value); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("splitNonempty(%q) = %#v, want %#v", test.value, got, test.want)
			}
		})
	}
}

func TestValidateTLSFilesReportsMissingPath(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()
	certPath := filepath.Join(testDir, "fullchain.pem")
	keyPath := filepath.Join(testDir, "privkey.pem")

	err := validateTLSFiles(certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "TLS certificate file") {
		t.Fatalf("missing certificate error = %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing certificate error %q does not wrap os.ErrNotExist", err)
	}

	if err := os.WriteFile(certPath, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = validateTLSFiles(certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "TLS private key file") {
		t.Fatalf("missing private key error = %v", err)
	}
}

func TestServeUntilSignalAddsTLSStartupContext(t *testing.T) {
	t.Parallel()

	server := &http.Server{Addr: "127.0.0.1:8888"}
	err := serveUntilSignal(
		server,
		httpsProtocol,
		"/missing/fullchain.pem",
		"/missing/privkey.pem",
		1,
	)
	if err == nil {
		t.Fatal("serveUntilSignal() error = nil, want TLS startup failure")
	}
	for _, want := range []string{
		"cannot start HTTPS proxy",
		"127.0.0.1:8888",
		"/missing/fullchain.pem",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}
