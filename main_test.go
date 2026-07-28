package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCommaSeparatedList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "values without whitespace",
			value: "192.0.2.1,198.51.100.2",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "spaces after commas",
			value: "192.0.2.1, 198.51.100.2",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "surrounding whitespace",
			value: "  example.test,\tapi.example.test \n",
			want:  []string{"example.test", "api.example.test"},
		},
		{
			name:  "empty entries",
			value: "192.0.2.1, ,198.51.100.2,",
			want:  []string{"192.0.2.1", "198.51.100.2"},
		},
		{
			name:  "empty value",
			value: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseCommaSeparatedList(tt.value); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseCommaSeparatedList(%q) = %#v, want %#v", tt.value, got, tt.want)
			}
		})
	}
}

func TestValidateStartupConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol string
		certPath string
		keyPath  string
		want     string
	}{
		{name: "HTTP needs no TLS files", protocol: httpProtocol},
		{name: "HTTPS has both files", protocol: httpsProtocol, certPath: "cert.pem", keyPath: "key.pem"},
		{name: "invalid protocol", protocol: "ftp", want: `protocol must be either "http" or "https"`},
		{name: "missing both TLS files", protocol: httpsProtocol, want: "HTTPS proxy requires --cert and --key"},
		{
			name:     "missing certificate",
			protocol: httpsProtocol,
			keyPath:  "key.pem",
			want:     "HTTPS proxy requires --cert",
		},
		{
			name:     "missing private key",
			protocol: httpsProtocol,
			certPath: "cert.pem",
			want:     "HTTPS proxy requires --key",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateStartupConfig(tt.protocol, tt.certPath, tt.keyPath)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validateStartupConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateStartupConfig() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateTLSFilesReportsMissingPath(t *testing.T) {
	t.Parallel()

	testDir := t.TempDir()
	certPath := filepath.Join(testDir, "fullchain.pem")
	keyPath := filepath.Join(testDir, "privkey.pem")

	tests := []struct {
		name       string
		prepare    func(t *testing.T)
		wantPath   string
		wantDetail string
	}{
		{
			name:       "missing certificate",
			prepare:    func(*testing.T) {},
			wantPath:   certPath,
			wantDetail: "TLS certificate file",
		},
		{
			name: "missing private key",
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.WriteFile(certPath, []byte("certificate"), 0o600); err != nil {
					t.Fatalf("write certificate fixture: %v", err)
				}
			},
			wantPath:   keyPath,
			wantDetail: "TLS private key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.prepare(t)
			err := validateTLSFiles(certPath, keyPath)
			if err == nil {
				t.Fatal("validateTLSFiles() error = nil, want an unavailable-file error")
			}
			if !strings.Contains(err.Error(), tt.wantDetail) {
				t.Fatalf("error %q does not contain %q", err, tt.wantDetail)
			}
			if !strings.Contains(err.Error(), tt.wantPath) {
				t.Fatalf("error %q does not contain path %q", err, tt.wantPath)
			}
		})
	}
}

func TestServeProxyAddsStartupContext(t *testing.T) {
	t.Parallel()

	server := &http.Server{Addr: "127.0.0.1:8888"}
	err := serveProxy(server, httpsProtocol, "/missing/fullchain.pem", "/missing/privkey.pem")
	if err == nil {
		t.Fatal("serveProxy() error = nil, want startup failure")
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
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error %q does not wrap os.ErrNotExist", err)
	}
}
