package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/idna"
	netProxy "golang.org/x/net/proxy"
)

const (
	defaultResponseHeaderTimeout = 15 * time.Second
	defaultTunnelIdleTimeout     = 5 * time.Minute
)

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ProxyHandler applies authentication and network policy before forwarding.
type ProxyHandler struct {
	Timeout                  time.Duration
	ResponseHeaderTimeout    time.Duration
	TunnelIdleTimeout        time.Duration
	Username                 *string
	Password                 *string
	LogAuth                  bool
	LogHeaders               bool
	Socks5Forward            *Socks5Forward
	AllowSrcIPAddress        []string
	AllowDestHost            []string
	TrustedProxyCIDRs        []*net.IPNet
	DenyAll                  bool
	AllowPrivateDestinations bool
	Resolver                 *net.Resolver

	transportOnce sync.Once
	transport     *http.Transport
}

type Socks5Forward struct {
	Address  string
	Username *string
	Password *string
}

func NewProxyHandler(timeoutSeconds int) *ProxyHandler {
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ProxyHandler{
		Timeout:               timeout,
		ResponseHeaderTimeout: defaultResponseHeaderTimeout,
		TunnelIdleTimeout:     defaultTunnelIdleTimeout,
		Resolver:              net.DefaultResolver,
	}
}

// GetUserIP returns the TCP peer address. Forwarding headers are deliberately
// ignored here because they are untrusted unless the peer is a configured
// reverse proxy.
func GetUserIP(r *http.Request) string {
	ip := remoteIP(r.RemoteAddr)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = strings.Trim(remoteAddr, "[]")
	}
	return net.ParseIP(host)
}

func (p *ProxyHandler) clientIP(r *http.Request) net.IP {
	peer := remoteIP(r.RemoteAddr)
	if peer == nil || !ipInNetworks(peer, p.TrustedProxyCIDRs) {
		return peer
	}

	if candidate := nearestUntrusted(parseForwardedFor(r.Header.Values("Forwarded")), p.TrustedProxyCIDRs); candidate != nil {
		return candidate
	}
	if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
		chain := strings.Split(strings.Join(forwarded, ","), ",")
		addresses := make([]net.IP, 0, len(chain))
		for i := len(chain) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(chain[i]))
			if candidate != nil {
				addresses = append(addresses, candidate)
			}
		}
		if candidate := nearestUntrusted(addresses, p.TrustedProxyCIDRs); candidate != nil {
			return candidate
		}
	}

	if candidate := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-Ip"))); candidate != nil {
		return candidate
	}
	return peer
}

func parseForwardedFor(values []string) []net.IP {
	var result []net.IP
	elements := strings.Split(strings.Join(values, ","), ",")
	for i := len(elements) - 1; i >= 0; i-- {
		for _, parameter := range strings.Split(elements[i], ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if !ok || !strings.EqualFold(name, "for") {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"`)
			if strings.EqualFold(value, "unknown") || strings.HasPrefix(value, "_") {
				break
			}
			if host, _, err := net.SplitHostPort(value); err == nil {
				value = host
			}
			if candidate := net.ParseIP(strings.Trim(value, "[]")); candidate != nil {
				result = append(result, candidate)
			}
			break
		}
	}
	return result
}

func nearestUntrusted(addresses []net.IP, trusted []*net.IPNet) net.IP {
	for _, candidate := range addresses {
		if !ipInNetworks(candidate, trusted) {
			return candidate
		}
	}
	return nil
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *ProxyHandler) sourceAllowed(ip net.IP) bool {
	if !p.DenyAll {
		return true
	}
	if ip == nil {
		return false
	}

	for _, rule := range p.AllowSrcIPAddress {
		rule = strings.TrimSpace(rule)
		if _, network, err := net.ParseCIDR(rule); err == nil && network.Contains(ip) {
			return true
		}
		if allowedIP := net.ParseIP(strings.Trim(rule, "[]")); allowedIP != nil && allowedIP.Equal(ip) {
			return true
		}
	}
	return false
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isLocalHealthRequest(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Server", "simple-proxy")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK\r\n")
		return
	}

	clientIP := p.clientIP(r)
	if !p.sourceAllowed(clientIP) {
		glog.V(1).Infof("BLOCKED %q request from %q to %q: source is not allowed", r.Method, ipString(clientIP), r.Host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if p.Username != nil && p.Password != nil {
		username, password, ok := proxyBasicAuth(r)
		if !ok || !credentialsEqual(username, password, *p.Username, *p.Password) {
			if p.LogAuth && username != "" {
				glog.Warningf("Unauthorized proxy authentication attempt for username %q", username)
			} else {
				glog.Warning("Unauthorized proxy authentication attempt")
			}
			w.Header().Set("Proxy-Authenticate", `Basic realm="simple-proxy"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}

	glog.V(1).Infof("SERVING %q request from %q to %q", r.Method, ipString(clientIP), r.Host)
	if p.LogHeaders {
		logRequestHeaders(r.Header)
	}

	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func isLocalHealthRequest(r *http.Request) bool {
	return !r.URL.IsAbs() && r.Method == http.MethodGet && r.URL.Path == "/health"
}

func ipString(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

func credentialsEqual(gotUser, gotPassword, wantUser, wantPassword string) bool {
	got := sha256.Sum256([]byte(gotUser + "\x00" + gotPassword))
	want := sha256.Sum256([]byte(wantUser + "\x00" + wantPassword))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func logRequestHeaders(headers http.Header) {
	for name, values := range headers {
		if sensitiveHeader(name) {
			glog.V(1).Infof("%q: [REDACTED]", name)
			continue
		}
		for i, value := range values {
			glog.V(1).Infof("%q: [%d] %s", name, i, value)
		}
	}
}

func sensitiveHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie":
		return true
	default:
		return strings.Contains(strings.ToLower(name), "token") ||
			strings.Contains(strings.ToLower(name), "secret") ||
			strings.Contains(strings.ToLower(name), "api-key")
	}
}

func (p *ProxyHandler) handleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := p.dialDestination(r.Context(), "tcp", r.Host)
	if err != nil {
		glog.Warningf("CONNECT to %q failed: %v", r.Host, err)
		http.Error(w, "Destination unavailable", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = destConn.Close()
		glog.Error("Response writer does not support connection hijacking")
		http.Error(w, "CONNECT is not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = destConn.Close()
		glog.Warningf("Failed to hijack CONNECT connection: %v", err)
		return
	}

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = destConn.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		_ = clientConn.Close()
		_ = destConn.Close()
		return
	}

	if buffered.Reader.Buffered() > 0 {
		if _, err := io.CopyN(destConn, buffered, int64(buffered.Reader.Buffered())); err != nil {
			_ = clientConn.Close()
			_ = destConn.Close()
			return
		}
	}
	relayConnections(clientConn, destConn, p.tunnelIdleTimeout())
}

func relayConnections(client, destination net.Conn, idleTimeout time.Duration) {
	touchConnections(client, destination, idleTimeout)
	done := make(chan struct{}, 2)
	go func() {
		copyWithIdle(destination, client, idleTimeout)
		done <- struct{}{}
	}()
	go func() {
		copyWithIdle(client, destination, idleTimeout)
		done <- struct{}{}
	}()

	<-done
	_ = client.Close()
	_ = destination.Close()
	<-done
}

func copyWithIdle(destination, source net.Conn, idleTimeout time.Duration) {
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			touchConnections(source, destination, idleTimeout)
			if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
				return
			}
			touchConnections(source, destination, idleTimeout)
		}
		if readErr != nil {
			return
		}
	}
}

func touchConnections(first, second net.Conn, idleTimeout time.Duration) {
	if idleTimeout <= 0 {
		return
	}
	deadline := time.Now().Add(idleTimeout)
	_ = first.SetDeadline(deadline)
	_ = second.SetDeadline(deadline)
}

func (p *ProxyHandler) tunnelIdleTimeout() time.Duration {
	if p.TunnelIdleTimeout > 0 {
		return p.TunnelIdleTimeout
	}
	return defaultTunnelIdleTimeout
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	outbound := req.Clone(req.Context())
	outbound.RequestURI = ""
	removeHopByHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	outbound.Header.Del("Proxy-Connection")

	resp, err := p.outboundTransport().RoundTrip(outbound)
	if err != nil {
		glog.Warningf("Failed to proxy request to %q: %v", req.Host, err)
		http.Error(w, "Destination unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		glog.V(1).Infof("Response stream to client ended: %v", err)
	}
}

func (p *ProxyHandler) outboundTransport() *http.Transport {
	p.transportOnce.Do(func() {
		responseTimeout := p.ResponseHeaderTimeout
		if responseTimeout <= 0 {
			responseTimeout = defaultResponseHeaderTimeout
		}
		timeout := p.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		p.transport = &http.Transport{
			Proxy:                 nil,
			DialContext:           p.dialDestination,
			DisableCompression:    true,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: responseTimeout,
			ExpectContinueTimeout: time.Second,
		}
	})
	return p.transport
}

func (p *ProxyHandler) dialDestination(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := canonicalAuthority(address)
	if err != nil || port == "" {
		return nil, fmt.Errorf("invalid destination address")
	}
	if !p.destinationAllowed(host, port) {
		return nil, fmt.Errorf("destination is not allowlisted")
	}

	ips, err := p.resolveAllowedIPs(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), port)
		conn, dialErr := p.dialResolved(ctx, network, target)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("destination has no permitted addresses")
	}
	return nil, lastErr
}

func (p *ProxyHandler) dialResolved(ctx context.Context, network, address string) (net.Conn, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

	if p.Socks5Forward == nil {
		return dialer.DialContext(ctx, network, address)
	}

	var auth *netProxy.Auth
	if p.Socks5Forward.Username != nil && p.Socks5Forward.Password != nil {
		auth = &netProxy.Auth{
			User:     *p.Socks5Forward.Username,
			Password: *p.Socks5Forward.Password,
		}
	}
	socksDialer, err := netProxy.SOCKS5("tcp", p.Socks5Forward.Address, auth, dialer)
	if err != nil {
		return nil, fmt.Errorf("configure SOCKS5 forwarder: %w", err)
	}
	return socksDialer.Dial(network, address)
}

func (p *ProxyHandler) resolveAllowedIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !p.AllowPrivateDestinations && prohibitedDestination(ip) {
			return nil, errors.New("destination address range is prohibited")
		}
		return []net.IP{ip}, nil
	}

	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}

	allowed := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if !p.AllowPrivateDestinations && prohibitedDestination(address.IP) {
			continue
		}
		allowed = append(allowed, address.IP)
	}
	if len(allowed) == 0 {
		return nil, errors.New("destination has no permitted addresses")
	}
	return allowed, nil
}

func prohibitedDestination(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	_, carrierGradeNAT, _ := net.ParseCIDR("100.64.0.0/10")
	return carrierGradeNAT.Contains(ip)
}

func (p *ProxyHandler) destinationAllowed(host, port string) bool {
	if len(p.AllowDestHost) == 0 {
		return true
	}
	for _, rule := range p.AllowDestHost {
		ruleHost, rulePort, err := canonicalAuthority(strings.TrimSpace(rule))
		if err != nil {
			continue
		}
		if host == ruleHost && (rulePort == "" || rulePort == port) {
			return true
		}
	}
	return false
}

func canonicalAuthority(authority string) (host, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", errors.New("empty authority")
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(authority); splitErr == nil {
		host, err = canonicalHost(parsedHost)
		if err != nil {
			return "", "", err
		}
		if err := validPort(parsedPort); err != nil {
			return "", "", err
		}
		return host, parsedPort, nil
	}

	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		authority = strings.Trim(authority, "[]")
	}
	host, err = canonicalHost(authority)
	return host, "", err
}

func canonicalHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return "", errors.New("empty host")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("invalid hostname: %w", err)
	}
	return strings.ToLower(ascii), nil
}

func validPort(port string) error {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("invalid destination port")
	}
	return nil
}

func removeHopByHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHopHeaders {
		headers.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func proxyBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	username, password, ok = strings.Cut(string(decoded), ":")
	return username, password, ok
}
