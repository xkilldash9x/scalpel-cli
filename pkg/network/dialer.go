// pkg/network/dialer.go
package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DialerConfig holds configuration for the robust, low-level dialer.
type DialerConfig struct {
	Timeout      time.Duration
	KeepAlive    time.Duration
	TLSConfig    *tls.Config
	ForceNoDelay bool // Crucial for latency-sensitive operations like TimeSlip H1 analysis (TCP_NODELAY).
}

// NewDialerConfig creates a default, secure configuration for low-level dialing.
func NewDialerConfig() *DialerConfig {
	// Enforcing strong security defaults (PFS mandatory, modern curves, TLS 1.2+).
	return &DialerConfig{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519, // Prefer modern curves
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				// TLS 1.3 suites
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				// TLS 1.2 suites with PFS (ECDHE)
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		ForceNoDelay: false,
	}
}

// DialContext is the project standard function for creating secure and resilient TCP connections manually.
func DialContext(ctx context.Context, network, address string, config *DialerConfig) (net.Conn, error) {
	if config == nil {
		config = NewDialerConfig()
	}

	dialer := &net.Dialer{
		Timeout:   config.Timeout,
		KeepAlive: config.KeepAlive,
		// Enable Happy Eyeballs (RFC 8305).
		FallbackDelay: 300 * time.Millisecond,
	}

	// Step 1: Establish the raw TCP connection.
	rawConn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Step 2: Configure TCP options.
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := configureTCP(tcpConn, config); err != nil {
			// Ensure no connection leak if configuration fails.
			tcpConn.Close()
			return nil, err
		}
	}

	// Step 3: Handle TLS upgrade if configured.
	if config.TLSConfig != nil {
		return wrapTLS(ctx, rawConn, address, config)
	}

	return rawConn, nil
}

// configureTCP applies TCP specific settings.
func configureTCP(conn *net.TCPConn, config *DialerConfig) error {
	// Enabling Keep-Alive helps detect dead peers.
	if err := conn.SetKeepAlive(true); err != nil {
		return fmt.Errorf("failed to enable TCP keep-alive: %w", err)
	}
	if config.KeepAlive > 0 {
		if err := conn.SetKeepAlivePeriod(config.KeepAlive); err != nil {
			return fmt.Errorf("failed to set keep-alive period: %w", err)
		}
	}
	
	// Disabling Nagle's algorithm (SetNoDelay) when requested.
	if config.ForceNoDelay {
		if err := conn.SetNoDelay(true); err != nil {
			return fmt.Errorf("failed to set TCP NoDelay: %w", err)
		}
	}
	return nil
}

// wrapTLS handles the TLS client handshake.
func wrapTLS(ctx context.Context, conn net.Conn, address string, config *DialerConfig) (net.Conn, error) {
	// Clone the config to avoid mutating the shared configuration.
	tlsConfig := config.TLSConfig.Clone()

	// Ensure ServerName is set for SNI (Server Name Indication).
	if tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address // Fallback if no port is specified.
		}
		tlsConfig.ServerName = host
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// Use a specific context for the handshake, respecting the dialer timeout.
	handshakeCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		conn.Close() // Close the underlying connection on handshake failure.
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	return tlsConn, nil
}
