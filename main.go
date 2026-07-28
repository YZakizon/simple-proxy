package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jthomperoo/simple-proxy/proxy"
	"golang.org/x/net/netutil"
)

var Version = "development"

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

func init() {
	_ = flag.Set("logtostderr", "true")
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("simple-proxy is exiting because the server could not run: %v", err)
	}
}

func run() error {
	var version bool
	flag.BoolVar(&version, "version", false, "print the current simple-proxy version")
	var protocol string
	flag.StringVar(&protocol, "protocol", httpProtocol, "proxy listener protocol (http or https)")
	var bind string
	flag.StringVar(&bind, "bind", "127.0.0.1", "address to bind the proxy server to")
	var port string
	flag.StringVar(&port, "port", "8888", "proxy port to listen on")
	var socks5 string
	flag.StringVar(&socks5, "socks5", "", "SOCKS5 proxy for tunneling")
	var socks5Auth string
	flag.StringVar(&socks5Auth, "socks5-auth", "", "deprecated: SOCKS5 credentials as username:password")
	var socks5AuthFile string
	flag.StringVar(&socks5AuthFile, "socks5-auth-file", "", "path to a file containing SOCKS5 credentials as username:password")
	var certPath string
	flag.StringVar(&certPath, "cert", "", "path to the TLS certificate")
	var keyPath string
	flag.StringVar(&keyPath, "key", "", "path to the TLS private key")
	var basicAuth string
	flag.StringVar(&basicAuth, "basic-auth", "", "deprecated: proxy credentials as username:password")
	var basicAuthFile string
	flag.StringVar(&basicAuthFile, "basic-auth-file", "", "path to a file containing proxy credentials as username:password")
	var logAuth bool
	flag.BoolVar(&logAuth, "log-auth", false, "log failed proxy authentication usernames")
	var logHeaders bool
	flag.BoolVar(&logHeaders, "log-headers", false, "log request headers with sensitive values redacted")
	var timeoutSecs int
	flag.IntVar(&timeoutSecs, "timeout", 10, "outbound dial and TLS handshake timeout in seconds")
	var responseHeaderTimeoutSecs int
	flag.IntVar(&responseHeaderTimeoutSecs, "response-header-timeout", 15, "outbound response header timeout in seconds")
	var tunnelIdleTimeoutSecs int
	flag.IntVar(&tunnelIdleTimeoutSecs, "tunnel-idle-timeout", 300, "CONNECT tunnel idle timeout in seconds")
	var readHeaderTimeoutSecs int
	flag.IntVar(&readHeaderTimeoutSecs, "read-header-timeout", 10, "client request header timeout in seconds")
	var idleTimeoutSecs int
	flag.IntVar(&idleTimeoutSecs, "idle-timeout", 60, "client keep-alive idle timeout in seconds")
	var maxConnections int
	flag.IntVar(&maxConnections, "max-connections", 256, "maximum concurrent client connections")
	var allowIPAddress string
	flag.StringVar(&allowIPAddress, "allow-src-ip", "", "allowed source IPs or CIDRs, comma separated")
	var allowDestHost string
	flag.StringVar(&allowDestHost, "allow-dest-host", "", "allowed destination hosts or host:port pairs, comma separated")
	var trustedProxyCIDR string
	flag.StringVar(&trustedProxyCIDR, "trusted-proxy-cidr", "", "trusted reverse-proxy CIDRs allowed to supply forwarding headers")
	var denyAll bool
	flag.BoolVar(&denyAll, "deny-all", false, "deny sources not present in --allow-src-ip")
	var allowOpenProxy bool
	flag.BoolVar(&allowOpenProxy, "allow-open-proxy", false, "explicitly allow an unauthenticated non-loopback listener")
	var allowInsecureAuth bool
	flag.BoolVar(&allowInsecureAuth, "allow-insecure-auth", false, "allow Basic proxy authentication over plaintext HTTP")
	var allowPrivateDestinations bool
	flag.BoolVar(&allowPrivateDestinations, "allow-private-destinations", false, "allow loopback, private, link-local, and carrier-grade NAT destinations")
	var healthcheckURL string
	flag.StringVar(&healthcheckURL, "healthcheck-url", "", "check a loopback simple-proxy health URL and exit")
	flag.Parse()

	if version {
		fmt.Println(Version)
		return nil
	}
	if healthcheckURL != "" {
		return checkHealth(healthcheckURL)
	}
	if protocol != httpProtocol && protocol != httpsProtocol {
		return errors.New("protocol must be either http or https")
	}
	if protocol == httpsProtocol && (certPath == "" || keyPath == "") {
		return errors.New("--cert and --key are required for an HTTPS listener")
	}
	if timeoutSecs <= 0 || responseHeaderTimeoutSecs <= 0 || tunnelIdleTimeoutSecs <= 0 ||
		readHeaderTimeoutSecs <= 0 || idleTimeoutSecs <= 0 || maxConnections <= 0 {
		return errors.New("all timeout and connection limit values must be greater than zero")
	}

	if basicAuth == "" {
		basicAuth = os.Getenv("BASIC_AUTH")
	}
	if basicAuthFile == "" {
		basicAuthFile = os.Getenv("BASIC_AUTH_FILE")
	}
	if basicAuth != "" && basicAuthFile != "" {
		return errors.New("configure only one of --basic-auth/BASIC_AUTH or --basic-auth-file/BASIC_AUTH_FILE")
	}
	if basicAuthFile != "" {
		contents, err := readCredentialFile(basicAuthFile)
		if err != nil {
			return fmt.Errorf("read proxy authentication file: %w", err)
		}
		basicAuth = contents
	}

	username, password, authConfigured, err := parseCredentialPair(basicAuth)
	if err != nil {
		return fmt.Errorf("invalid proxy authentication configuration: %w", err)
	}
	if err := validateListenerSecurity(bind, protocol, authConfigured, denyAll, allowOpenProxy, allowInsecureAuth); err != nil {
		return err
	}

	if socks5AuthFile == "" {
		socks5AuthFile = os.Getenv("SOCKS5_AUTH_FILE")
	}
	if socks5Auth != "" && socks5AuthFile != "" {
		return errors.New("configure only one of --socks5-auth or --socks5-auth-file/SOCKS5_AUTH_FILE")
	}
	if socks5AuthFile != "" {
		socks5Auth, err = readCredentialFile(socks5AuthFile)
		if err != nil {
			return fmt.Errorf("read SOCKS5 authentication file: %w", err)
		}
	}
	socks5Forward, err := parseSocks5Forward(socks5, socks5Auth)
	if err != nil {
		return err
	}

	if allowIPAddress == "" {
		allowIPAddress = os.Getenv("ALLOW_SRC_IP")
	}
	if allowDestHost == "" {
		allowDestHost = os.Getenv("ALLOW_DEST_HOST")
	}
	if trustedProxyCIDR == "" {
		trustedProxyCIDR = os.Getenv("TRUSTED_PROXY_CIDR")
	}
	allowIPs := splitNonempty(allowIPAddress)
	allowHosts := splitNonempty(allowDestHost)
	trustedNetworks, err := parseCIDRs(splitNonempty(trustedProxyCIDR))
	if err != nil {
		return err
	}
	if denyAll && len(allowIPs) == 0 {
		return errors.New("--deny-all requires at least one --allow-src-ip entry")
	}

	handler := proxy.NewProxyHandler(timeoutSecs)
	handler.ResponseHeaderTimeout = time.Duration(responseHeaderTimeoutSecs) * time.Second
	handler.TunnelIdleTimeout = time.Duration(tunnelIdleTimeoutSecs) * time.Second
	handler.LogAuth = logAuth
	handler.LogHeaders = logHeaders
	handler.Socks5Forward = socks5Forward
	handler.AllowSrcIPAddress = allowIPs
	handler.AllowDestHost = allowHosts
	handler.TrustedProxyCIDRs = trustedNetworks
	handler.DenyAll = denyAll
	handler.AllowPrivateDestinations = allowPrivateDestinations
	if authConfigured {
		handler.Username = &username
		handler.Password = &password
	}

	server := &http.Server{
		Addr:              net.JoinHostPort(strings.Trim(bind, "[]"), port),
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(readHeaderTimeoutSecs) * time.Second,
		IdleTimeout:       time.Duration(idleTimeoutSecs) * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		// CONNECT relies on HTTP/1.1 connection hijacking.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	glog.Infof("Allowed source addresses: %v", allowIPs)
	glog.Infof("Allowed destination hosts: %v", allowHosts)
	glog.Infof("Trusted proxy networks: %v", splitNonempty(trustedProxyCIDR))
	glog.Infof("Listening on %s over %s", server.Addr, protocol)
	if socks5Forward != nil {
		glog.Infof("Forwarding connections through SOCKS5 proxy %s", socks5Forward.Address)
	}
	return serveUntilSignal(server, protocol, certPath, keyPath, maxConnections)
}

func parseCredentialPair(value string) (username, password string, configured bool, err error) {
	if value == "" {
		return "", "", false, nil
	}
	username, password, ok := strings.Cut(value, ":")
	if !ok || username == "" || password == "" {
		return "", "", false, errors.New("credentials must use non-empty username:password format")
	}
	return username, password, true, nil
}

func readCredentialFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(contents) > 4096 {
		return "", errors.New("credential file exceeds 4096 bytes")
	}
	return strings.TrimRight(string(contents), "\r\n"), nil
}

func parseSocks5Forward(address, credentials string) (*proxy.Socks5Forward, error) {
	if address == "" {
		if credentials != "" {
			return nil, errors.New("--socks5-auth requires --socks5")
		}
		return nil, nil
	}
	forward := &proxy.Socks5Forward{Address: address}
	username, password, configured, err := parseCredentialPair(credentials)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 authentication configuration: %w", err)
	}
	if configured {
		forward.Username = &username
		forward.Password = &password
	}
	return forward, nil
}

func splitNonempty(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseCIDRs(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q", value)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func loopbackBind(bind string) bool {
	if strings.EqualFold(bind, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(bind, "[]"))
	return ip != nil && ip.IsLoopback()
}

func validateListenerSecurity(bind, protocol string, authConfigured, denyAll, allowOpenProxy, allowInsecureAuth bool) error {
	if authConfigured && protocol == httpProtocol && !allowInsecureAuth {
		return errors.New("basic proxy authentication over HTTP is disabled; use HTTPS or --allow-insecure-auth")
	}
	if !loopbackBind(bind) && !authConfigured && !denyAll && !allowOpenProxy {
		return errors.New("refusing an unauthenticated non-loopback proxy; configure authentication or an allowlist, or use --allow-open-proxy")
	}
	return nil
}

func serveUntilSignal(server *http.Server, protocol, certPath, keyPath string, maxConnections int) error {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if protocol == httpsProtocol {
		if err := validateTLSFiles(certPath, keyPath); err != nil {
			return fmt.Errorf("cannot start HTTPS proxy on %s: %w", server.Addr, err)
		}
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.Addr, err)
	}
	limitedListener := netutil.LimitListener(listener, maxConnections)

	serveErrors := make(chan error, 1)
	go func() {
		if protocol == httpsProtocol {
			serveErrors <- server.ServeTLS(limitedListener, certPath, keyPath)
			return
		}
		serveErrors <- server.Serve(limitedListener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("%s proxy on %s stopped unexpectedly: %w", strings.ToUpper(protocol), server.Addr, err)
	case <-signalContext.Done():
		glog.Info("Shutting down proxy")
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

func validateTLSFiles(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("TLS certificate file %q is unavailable: %w", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("TLS private key file %q is unavailable: %w", keyPath, err)
	}
	return nil
}

func checkHealth(rawURL string) error {
	healthURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse healthcheck URL: %w", err)
	}
	hostname := healthURL.Hostname()
	ip := net.ParseIP(hostname)
	if !strings.EqualFold(hostname, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return errors.New("healthcheck URL must target localhost or a loopback address")
	}
	if healthURL.Scheme != httpProtocol && healthURL.Scheme != httpsProtocol {
		return errors.New("healthcheck URL must use HTTP or HTTPS")
	}

	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			// The healthcheck is restricted to loopback, while the listener's
			// certificate commonly names its public endpoint.
			InsecureSkipVerify: true, // #nosec G402
		},
	}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(rawURL)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil {
		return fmt.Errorf("read healthcheck response: %w", err)
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "OK" {
		return fmt.Errorf("healthcheck failed with status %d", response.StatusCode)
	}
	return nil
}
