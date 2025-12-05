package proxy

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"slices"

	"github.com/golang/glog"
	netProxy "golang.org/x/net/proxy"
)

func NewProxyHandler(timeoutSeconds int) *ProxyHandler {
	return &ProxyHandler{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

type ProxyHandler struct {
	Timeout       time.Duration
	Username      *string
	Password      *string
	LogAuth       bool
	LogHeaders    bool
	Socks5Forward *Socks5Forward
	AllowSrcIPAddress []string
	AllowDestHost	[]string
	DenyAll			bool
}

type Socks5Forward struct {
	Address  string
	Username *string
	Password *string
}
func GetUserIP(r *http.Request) string {
    IPAddress := r.Header.Get("X-Real-Ip")
    if IPAddress == "" {
        IPAddress = r.Header.Get("X-Forwarded-For")
    }
    if IPAddress == "" {
		if strings.HasPrefix(r.RemoteAddr, "[::1]") {
			IPAddress = "[::1]"
		} else {
			ipaddr := strings.Split(r.RemoteAddr,":")
			if len(ipaddr) > 0 {
				IPAddress = ipaddr[0]
			}
		}
    }
	
    return IPAddress
}

func (p *ProxyHandler) isAllowed(r *http.Request, ipaddr string) bool {
	if p.DenyAll &&
	 	slices.Contains(p.AllowSrcIPAddress, ipaddr) {

			// If allow dest host is specified then check the dest host
			if (len(p.AllowDestHost) != 0) {
				if slices.Contains(p.AllowDestHost, r.Host) {
					glog.V(3).Infof("ALLOWED host: %v", r.Host)
					return true
				} else {
					glog.V(3).Infof("BLOCKED host: %v, host is not in AllowDestHost: %v", r.Host, p.AllowDestHost)
					return false
				}
			}

			// Allow dest host is not specified, that means all dest host is allowed as long as src ip is allowed
			return true
		}

		// Denied
		return false
}



func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Server", "Ban All")
		w.Write([]byte("OK\r\n"))
		return
	}
	if r.TLS != nil {
				glog.V(1).Infof("TLS Handshake Complete %v", r.TLS.HandshakeComplete)
				glog.V(1).Infof("TLS Version: %x", r.TLS.Version)
				glog.V(1).Infof("Cipher Suite: %x", r.TLS.CipherSuite)

				if len(r.TLS.PeerCertificates) > 0 {
					clientCert := r.TLS.PeerCertificates[0]
					glog.V(1).Infof("Client CN: %s", clientCert.Subject.CommonName)
					glog.V(1).Infof("Client Issuer: %s", clientCert.Issuer.CommonName)
					glog.V(1).Infof("Client Serial: %s", clientCert.SerialNumber)
					io.WriteString(w, "Hello, verified client!\n")
					
				} else {
					glog.V(1).Infof("No client certificate presented")
					// http.Error(w, "Client certificate required", http.StatusUnauthorized)
				}
			}

	ipaddr := GetUserIP(r)
	
	if p.isAllowed(r, ipaddr) == false {
		glog.V(1).Infof("BLOCKED '%s' request from '%s' to '%s'. IP Address or dest host not allowed\n", r.Method, ipaddr, r.Host)	
		http.Error(w, "Forbidden", 403)
		return
	}

	glog.V(1).Infof("SERVING '%s' request from '%s' to '%s'\n", r.Method, ipaddr, r.Host)
	if p.LogHeaders {
		for name, values := range r.Header {
			for i, value := range values {
				glog.V(1).Infof("'%s': [%d] %s", name, i, value)
			}
		}
	}
	if p.Username != nil && p.Password != nil {
		username, password, ok := proxyBasicAuth(r)
		if !ok || username != *p.Username || password != *p.Password {
			if p.LogAuth {
				glog.Errorf("Unauthorized, username: %s, password: %s\n", username, password)
			} else {
				glog.Errorln("Unauthorized")
			}
			w.Header().Set("Proxy-Authenticate", "Basic")
			http.Error(w, "Unauthorized", http.StatusProxyAuthRequired)
			return
		}
	}
	if r.Method == http.MethodConnect {
		handleTunneling(w, r, p.Timeout, p.Socks5Forward)
	} else {
		handleHTTP(w, r)
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request, timeout time.Duration, socks5Forward *Socks5Forward) {
	var destConn net.Conn
	var err error

	if socks5Forward == nil {
		destConn, err = net.DialTimeout("tcp", r.Host, timeout)
	} else {
		var socks5Auth *netProxy.Auth
		if socks5Forward.Username != nil && socks5Forward.Password != nil {
			socks5Auth = &netProxy.Auth{
				User:     *socks5Forward.Username,
				Password: *socks5Forward.Password,
			}
		}

		var socks5Dialer netProxy.Dialer
		socks5Dialer, err = netProxy.SOCKS5("tcp", socks5Forward.Address, socks5Auth, &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		})

		if err != nil {
			glog.Errorf("Failed to dial socks5 proxy %s, %s\n", socks5Forward.Address, err.Error())
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		destConn, err = socks5Dialer.Dial("tcp", r.Host)
	}

	if err != nil {
		glog.Errorf("Failed to dial host, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		glog.Errorln("Attempted to hijack connection that does not support it")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		glog.Errorf("Failed to hijack connection, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		glog.Errorf("Failed to proxy request, %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func proxyBasicAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	return parseBasicAuth(auth)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !equalFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
