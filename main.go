package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/jthomperoo/simple-proxy/proxy"
)

var (
	Version = "development"
)

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

func init() {
	flag.Set("logtostderr", "true")
}

func parseCommaSeparatedList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func validateStartupConfig(protocol, certPath, keyPath string) error {
	if protocol != httpProtocol && protocol != httpsProtocol {
		return fmt.Errorf("protocol must be either %q or %q, got %q", httpProtocol, httpsProtocol, protocol)
	}
	if protocol != httpsProtocol {
		return nil
	}

	var missing []string
	if certPath == "" {
		missing = append(missing, "--cert")
	}
	if keyPath == "" {
		missing = append(missing, "--key")
	}
	if len(missing) != 0 {
		return fmt.Errorf("HTTPS proxy requires %s", strings.Join(missing, " and "))
	}
	return nil
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

func serveProxy(server *http.Server, protocol, certPath, keyPath string) error {
	if protocol == httpsProtocol {
		if err := validateTLSFiles(certPath, keyPath); err != nil {
			return fmt.Errorf("cannot start HTTPS proxy on %s: %w", server.Addr, err)
		}
		if err := server.ListenAndServeTLS(certPath, keyPath); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTPS proxy on %s stopped unexpectedly: %w", server.Addr, err)
		}
		return nil
	}

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP proxy on %s stopped unexpectedly: %w", server.Addr, err)
	}
	return nil
}

func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "prints current simple-proxy version")
	var protocol string
	flag.StringVar(&protocol, "protocol", httpProtocol, "proxy protocol (http or https)")
	var bind string
	flag.StringVar(&bind, "bind", "0.0.0.0", "address to bind the proxy server to")
	var port string
	flag.StringVar(&port, "port", "8888", "proxy port to listen on")
	var socks5 string
	flag.StringVar(&socks5, "socks5", "", "SOCKS5 proxy for tunneling, not used if not provided")
	var socks5Auth string
	flag.StringVar(&socks5Auth, "socks5-auth", "", "basic auth for socks5, format 'username:password', no auth if not provided")
	var certPath string
	flag.StringVar(&certPath, "cert", "", "path to cert file")
	var keyPath string
	flag.StringVar(&keyPath, "key", "", "path to key file")
	var basicAuth string
	flag.StringVar(&basicAuth, "basic-auth", "", "basic auth, format 'username:password', no auth if not provided")
	var logAuth bool
	flag.BoolVar(&logAuth, "log-auth", false, "log failed proxy auth details")
	var logHeaders bool
	flag.BoolVar(&logHeaders, "log-headers", false, "log request headers")
	var timeoutSecs int
	flag.IntVar(&timeoutSecs, "timeout", 10, "timeout in seconds")
	var allowIPAddress string
	flag.StringVar(&allowIPAddress, "allow-src-ip", "", "allow source ip address in comma separated, ie: 192.168.0.10,192.168.0.20")
	var allowDestHost string
	flag.StringVar(&allowDestHost, "allow-dest-host", "", "allow destination host or ip address, ie: www.google.com,google.com")
	var denyAll bool
	flag.BoolVar(&denyAll, "deny-all", false, "deny all source ip address. Make sure you have a whitelist ip address or whitelist dest host")
	flag.Parse()

	if version {
		fmt.Println(Version)
		os.Exit(0)
	}

	if err := validateStartupConfig(protocol, certPath, keyPath); err != nil {
		log.Fatalf("simple-proxy is exiting because configuration is invalid: %v", err)
	}

	var socks5Forward *proxy.Socks5Forward
	if socks5 != "" {
		socks5Forward = &proxy.Socks5Forward{
			Address: socks5,
		}
		if socks5Auth != "" {
			parts := strings.Split(socks5Auth, ":")
			if len(parts) < 2 {
				log.Fatal(
					"simple-proxy is exiting because SOCKS5 authentication is invalid; " +
						"expected username:password",
				)
			}

			socks5Forward.Username = &parts[0]
			socks5Forward.Password = &parts[1]
		}
	}

	var allowIps []string
	if allowIPAddress == "" {
		allowIPAddress = os.Getenv("ALLOW_SRC_IP")
	}

	if allowIPAddress != "" {
		allowIps = parseCommaSeparatedList(allowIPAddress)
	}

	var allowHosts []string
	if allowDestHost == "" {
		allowDestHost = os.Getenv("ALLOW_DEST_HOST")
	}
	if allowDestHost != "" {
		allowHosts = parseCommaSeparatedList(allowDestHost)
	}

	glog.V(0).Infof("Allow source ip address %s", allowIps)
	glog.V(0).Infof("Allow dest host %s", allowHosts)
	glog.V(0).Infof("Deny all %v", denyAll)
	glog.V(0).Infof("Listening on %v:%v", bind, port)

	var handler http.Handler
	if basicAuth == "" {
		handler = &proxy.ProxyHandler{
			Timeout:           time.Duration(timeoutSecs) * time.Second,
			LogAuth:           logAuth,
			LogHeaders:        logHeaders,
			Socks5Forward:     socks5Forward,
			AllowSrcIPAddress: allowIps,
			AllowDestHost:     allowHosts,
			DenyAll:           denyAll,
		}
	} else {
		parts := strings.Split(basicAuth, ":")
		if len(parts) < 2 {
			log.Fatal(
				"simple-proxy is exiting because proxy authentication is invalid; " +
					"expected username:password",
			)
		}
		handler = &proxy.ProxyHandler{
			Timeout:           time.Duration(timeoutSecs) * time.Second,
			Username:          &parts[0],
			Password:          &parts[1],
			LogAuth:           logAuth,
			LogHeaders:        logHeaders,
			Socks5Forward:     socks5Forward,
			AllowSrcIPAddress: allowIps,
			AllowDestHost:     allowHosts,
			DenyAll:           denyAll,
		}
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", bind, port),
		Handler: handler,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	if protocol == httpProtocol {
		glog.V(0).Infoln("Starting HTTP proxy...")
		if socks5 != "" {
			glog.V(0).Infof("Tunneling HTTP requests to SOCKS5 proxy: %s\n", socks5)
		}
	} else {
		glog.V(0).Infoln("Starting HTTPS proxy...")
	}

	if err := serveProxy(server, protocol, certPath, keyPath); err != nil {
		log.Fatalf("simple-proxy is exiting because the server could not run: %v", err)
	}
}
