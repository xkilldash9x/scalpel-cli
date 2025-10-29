// browser/network/dialer.go
package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DialerConfig holds configuration for the low-level dialer.
type DialerConfig struct {
	Timeout   time.Duration
	KeepAlive time.Duration
	TLSConfig *tls.Config
	// NoDelay controls TCP_NODELAY. Crucial for browser responsiveness.
	NoDelay bool
	// Resolver allows specifying custom DNS resolution logic.
	Resolver *net.Resolver
	// ProxyURL specifies the proxy server to use (e.g., "http://user:pass@proxy.example.com:8080").
	// Only HTTP/HTTPS proxies using the CONNECT method are supported.
	ProxyURL *url.URL
}

// Clone returns a deep copy of the DialerConfig.
func (c *DialerConfig) Clone() *DialerConfig {
	if c == nil {
		// Return a safe default if the original is nil
		return NewDialerConfig()
	}
	clone := *c
	if c.TLSConfig != nil {
		clone.TLSConfig = c.TLSConfig.Clone()
	}
	// Note: net.Resolver is synchronized and safe for concurrent use, so a shallow copy is fine.
	if c.ProxyURL != nil {
		// url.URL needs a deep copy if mutable parts (like User) are used, but generally safe to copy struct.
		proxyURLCopy := *c.ProxyURL
		clone.ProxyURL = &proxyURLCopy
	}
	return &clone
}

// NewDialerConfig creates a default, secure configuration optimized for a browser.
func NewDialerConfig() *DialerConfig {
	// Enforcing strong security defaults (PFS mandatory, modern curves, TLS 1.2+).
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519, // Prefer modern curves
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			// TLS 1.3 suites
			tls.TLS_AES_128_GCM_SHA256, // Often prioritized for speed/security balance
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			// TLS 1.2 suites with PFS (ECDHE)
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		// Enable TLS session resumption for performance.
		ClientSessionCache: tls.NewLRUClientSessionCache(512),
	}

	return &DialerConfig{
		Timeout:   15 * time.Second, // Standard browser connection timeout
		KeepAlive: 30 * time.Second,
		TLSConfig: tlsConfig,
		NoDelay:   true,                // Default to true for browser responsiveness
		Resolver:  net.DefaultResolver, // Use the system resolver by default.
		ProxyURL:  nil,                 // No proxy by default.
	}
}

// DialTCPContext establishes a raw TCP connection, potentially through a proxy. Suitable for http.Transport.DialContext.
// It returns the established tunnel (if proxied) or the raw TCP connection (if direct).
func DialTCPContext(ctx context.Context, network, address string, config *DialerConfig) (net.Conn, error) {
	if config == nil {
		config = NewDialerConfig()
	}

	// If a proxy is configured, delegate to the proxy dialer.
	if config.ProxyURL != nil {
		return dialViaProxy(ctx, network, address, config)
	}

	// Standard direct dialing
	return dialDirect(ctx, network, address, config)
}

// dialDirect establishes a direct TCP connection to the target address.
func dialDirect(ctx context.Context, network, address string, config *DialerConfig) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   config.Timeout,
		KeepAlive: config.KeepAlive,
		// Enable Happy Eyeballs (RFC 8305) for faster IPv4/IPv6 fallback.
		FallbackDelay: 300 * time.Millisecond,
		Resolver:      config.Resolver,
	}

	// Step 1: Establish the raw TCP connection.
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Step 2: Configure TCP options.
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := configureTCP(tcpConn, config); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
	}
	return rawConn, nil
}

// dialViaProxy establishes a connection through an HTTP/HTTPS proxy using CONNECT.
func dialViaProxy(ctx context.Context, network, targetAddress string, config *DialerConfig) (net.Conn, error) {
	proxyURL := config.ProxyURL
	proxyAddress := proxyURL.Host

	// 1. Dial the proxy server.
	var proxyConn net.Conn
	var err error

	switch proxyURL.Scheme {
	case "http":
		// Dial the proxy directly over TCP.
		proxyConn, err = dialDirect(ctx, network, proxyAddress, config)
	case "https":
		// Dial the proxy over TCP and upgrade to TLS.
		// We need a modified DialerConfig for the connection *to* the proxy.
		proxyDialerConfig := config.Clone()
		// Ensure TLSConfig is present for the HTTPS proxy connection. Use secure defaults if the main config didn't have one.
		if proxyDialerConfig.TLSConfig == nil {
			proxyDialerConfig.TLSConfig = NewDialerConfig().TLSConfig.Clone()
		}
		// We must not use the ALPN settings intended for the target server (e.g., "h2") when connecting to the proxy itself.
		proxyDialerConfig.TLSConfig.NextProtos = nil

		rawConn, err := dialDirect(ctx, network, proxyAddress, proxyDialerConfig)
		if err != nil {
			return nil, err
		}
		// wrapTLS handles the TLS handshake with the proxy.
		proxyConn, err = wrapTLS(ctx, rawConn, proxyAddress, proxyDialerConfig)
	default:
		// SOCKS5 or other schemes are not implemented.
		return nil, fmt.Errorf("unsupported proxy scheme: %s (only http/https supported)", proxyURL.Scheme)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddress, err)
	}

	// 2. Perform the CONNECT handshake.
	return establishProxyTunnel(ctx, proxyConn, targetAddress, config.ProxyURL)
}

// establishProxyTunnel sends the HTTP CONNECT request and verifies the response.
// It returns the connection ready for use, handling potential buffered data.
func establishProxyTunnel(ctx context.Context, conn net.Conn, targetAddress string, proxyURL *url.URL) (net.Conn, error) {
	// Construct the CONNECT request.
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddress},
		Host:   targetAddress,
		Header: make(http.Header),
	}

	// Add Proxy-Authorization if credentials are provided in the ProxyURL.
	if proxyURL.User != nil {
		if password, ok := proxyURL.User.Password(); ok {
			auth := proxyURL.User.Username() + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			connectReq.Header.Set("Proxy-Authorization", basicAuth)
		}
	}

	// Use the context deadline for the handshake operations.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{}) // Reset deadline after tunnel is established.
	}

	// Send the request.
	if err := connectReq.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	// Read the response.
	// Use bufio.Reader to efficiently parse the response and handle potential buffering.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close() // Body should be empty for successful CONNECT.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy responded with non-200 status for CONNECT: %s", resp.Status)
	}

	// 4. Handle buffered data.
	// If bufio.Reader read more data than just the HTTP response (e.g., the start of the TLS ClientHello if the caller initiated it quickly),
	// we must ensure that data is available when the returned connection is read.
	if br.Buffered() > 0 {
		// Wrap the connection with a reader that first consumes the buffered data.
		return &prefixedConn{Conn: conn, prefix: br}, nil
	}

	return conn, nil
}

// prefixedConn wraps a net.Conn, reading first from an internal buffer (io.Reader) before the underlying Conn.
type prefixedConn struct {
	net.Conn
	prefix io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if c.prefix != nil {
		n, err := c.prefix.Read(p)
		if err == io.EOF {
			c.prefix = nil // Buffer exhausted
			if n > 0 {
				return n, nil
			}
			// If prefix is exhausted and read 0 bytes, proceed to the underlying connection.
		} else if n > 0 || err != nil {
			return n, err
		}
	}
	return c.Conn.Read(p)
}

// DialContext creates connections manually (e.g., for WebSockets or Pipelining), including TLS upgrade.
func DialContext(ctx context.Context, network, address string, config *DialerConfig) (net.Conn, error) {
	if config == nil {
		config = NewDialerConfig()
	}

	// DialTCPContext handles the TCP connection and potential proxy tunneling.
	conn, err := DialTCPContext(ctx, network, address, config)
	if err != nil {
		return nil, err
	}

	// Step 3: Handle TLS upgrade for the target connection if configured.
	// This happens over the established connection/tunnel.
	// If the target scheme is "https", config.TLSConfig should be set by the caller (H1Client/H2Client).
	if config.TLSConfig != nil {
		return wrapTLS(ctx, conn, address, config)
	}

	return conn, nil
}

// configureTCP applies TCP specific settings.
func configureTCP(conn *net.TCPConn, config *DialerConfig) error {
	// Attempt to set keep-alive, but don't treat failure as fatal as it may not be supported by the OS/network.
	if err := conn.SetKeepAlive(true); err != nil {
		// Log or ignore
	}
	if config.KeepAlive > 0 {
		if err := conn.SetKeepAlivePeriod(config.KeepAlive); err != nil {
			// Log or ignore
		}
	}

	// Setting NoDelay is often crucial for responsiveness.
	if err := conn.SetNoDelay(config.NoDelay); err != nil {
		return fmt.Errorf("failed to set TCP NoDelay: %w", err)
	}
	return nil
}

// wrapTLS handles the TLS client handshake.
func wrapTLS(ctx context.Context, conn net.Conn, address string, config *DialerConfig) (net.Conn, error) {
	// Clone the TLS config to ensure modifications (like ServerName) don't leak back to the DialerConfig.
	tlsConfig := config.TLSConfig.Clone()

	// Ensure ServerName is set for SNI (Server Name Indication).
	if tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// Handle cases where address might not have a port.
			host = address
		}

		// Basic validation: SNI should not be an IP address.
		// Handle potential brackets for IPv6 literals before parsing IP.
		sniHost := host
		if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
			sniHost = host[1 : len(host)-1]
		}

		if net.ParseIP(sniHost) == nil {
			tlsConfig.ServerName = sniHost
		}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Apply timeout specifically to the handshake process.
	// Use the Dialer Timeout as a base, but cap it to prevent excessively long handshakes.
	handshakeTimeout := config.Timeout
	if handshakeTimeout == 0 || handshakeTimeout > DefaultTLSHandshakeTimeout {
		handshakeTimeout = DefaultTLSHandshakeTimeout
	}

	// If the context already has a shorter deadline, use that instead.
	handshakeCtx := ctx
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > handshakeTimeout {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
	}

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	return tlsConn, nil
}
