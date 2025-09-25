// File: internal/network/httpclient.go
package network

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"

	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Constants for default optimized TCP/HTTP settings.
const (
	DefaultDialTimeout           = 5 * time.Second
	DefaultKeepAliveInterval     = 15 * time.Second
	DefaultTLSHandshakeTimeout   = 5 * time.Second
	DefaultResponseHeaderTimeout = 10 * time.Second
	DefaultRequestTimeout        = 30 * time.Second

	// Connection Pool Configuration tuned for scanning workloads.
	// These values are set higher than standard library defaults to accommodate
	// the higher concurrency typical of a security scanner.
	DefaultMaxIdleConns        = 100
	DefaultMaxIdleConnsPerHost = 20
	DefaultMaxConnsPerHost     = 50
	DefaultIdleConnTimeout     = 30 * time.Second
)

// ClientConfig holds the configuration for the HTTP client and transport layers.
type ClientConfig struct {
	// Security settings
	IgnoreTLSErrors bool
	TLSConfig       *tls.Config // Allows advanced customization if needed

	// Timeout settings
	RequestTimeout        time.Duration // Overall client timeout
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration

	// Dialer configuration (TCP Layer) - Centralized configuration
	DialerConfig *DialerConfig

	// Connection pool settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration

	// Protocol settings
	ForceHTTP2         bool
	DisableKeepAlives  bool
	DisableCompression bool

	// Proxy settings
	ProxyURL *url.URL

	// Logger
	Logger *zap.Logger
}

// Client is a wrapper around the standard http.Client.
//
// By embedding the standard client, we inherit all its methods (like Do, Get, Post),
// allowing it to be used as a drop in replacement.
//
// This client is safe for concurrent use by multiple goroutines.
//
// CRITICAL USAGE NOTE: The caller is responsible for closing the Response.Body
// after consuming it. Forgetting to do so will lead to connection leaks.
// A common pattern is:
//   resp, err := client.Get("http://example.com")
//   if err != nil { /* handle error */ }
//   defer resp.Body.Close()
//   body, err := io.ReadAll(resp.Body)
type Client struct {
	*http.Client
}

// NewDefaultClientConfig creates a configuration optimized for general-purpose scanning.
func NewDefaultClientConfig() *ClientConfig {
	// Configure the standardized dialer with HTTP specific defaults
	dialerCfg := NewDialerConfig()
	dialerCfg.Timeout = DefaultDialTimeout
	dialerCfg.KeepAlive = DefaultKeepAliveInterval
	// Crucial: Enable ForceNoDelay (TCP_NODELAY) by default for HTTP clients.
	// This disables Nagle's algorithm, reducing latency for small, frequent requests
	// which is a common pattern in security testing.
	dialerCfg.ForceNoDelay = true

	return &ClientConfig{
		DialerConfig:          dialerCfg,
		IgnoreTLSErrors:       false,
		RequestTimeout:        DefaultRequestTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		ForceHTTP2:            true, // Prefer H2 by default for performance.
		DisableKeepAlives:     false,
		DisableCompression:    false,
		Logger:                observability.GetLogger().Named("httpclient"),
	}
}

// NewHTTPTransport creates and configures an http.Transport based on the provided configuration.
func NewHTTPTransport(config *ClientConfig) *http.Transport {
	if config == nil {
		config = NewDefaultClientConfig()
	}

	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}

	if config.DialerConfig == nil {
		config.DialerConfig = NewDefaultClientConfig().DialerConfig
	}

	tlsConfig := configureTLS(config)

	// Create a copy of the DialerConfig for the transport, ensuring we don't modify the original.
	transportDialerConfig := *config.DialerConfig
	// TLSConfig is handled separately by the http.Transport, not the TCP dialer here.
	transportDialerConfig.TLSConfig = nil

	transport := &http.Transport{
		// Use our custom TCP dialer for all connections.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialTCPContext(ctx, network, addr, &transportDialerConfig)
		},
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		DisableCompression:    config.DisableCompression,
		ForceAttemptHTTP2:     config.ForceHTTP2,
	}

	if config.ProxyURL != nil {
		transport.Proxy = http.ProxyURL(config.ProxyURL)
	}

	if config.ForceHTTP2 {
		// http2.ConfigureTransport modifies the transport in place to add HTTP/2 support.
		if err := http2.ConfigureTransport(transport); err != nil {
			config.Logger.Warn("Failed to configure HTTP/2 transport, falling back to HTTP/1.1", zap.Error(err))
		}
	} else {
		// Ensure HTTP/1.1 is explicitly set for ALPN negotiation if HTTP/2 is disabled.
		if tlsConfig != nil && len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}
	}

	return transport
}

// NewClient creates our custom client wrapper using the configured transport.
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = NewDefaultClientConfig()
	}

	transport := NewHTTPTransport(config)

	standardClient := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		// For security scanning, we almost always want to inspect redirects manually
		// rather than following them automatically. This prevents the client from
		// blindly navigating to out of scope domains or leaking information.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		Client: standardClient,
	}
}

// configureTLS sets up the TLS configuration with strong defaults and optimizations.
func configureTLS(config *ClientConfig) *tls.Config {
	// Guard against nil config to prevent panics.
	if config == nil {
		config = NewDefaultClientConfig()
	}

	var tlsConfig *tls.Config

	if config.TLSConfig != nil {
		// Clone the provided config to avoid modifying the original object.
		tlsConfig = config.TLSConfig.Clone()
	} else {
		// Create a secure default configuration if none is provided.
		tlsConfig = &tls.Config{
			// Enforce TLS 1.2 as the minimum version.
			MinVersion: tls.VersionTLS12,
			// Prioritize strong, modern, forward secret cipher suites.
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			// Enable a session resumption cache for performance on subsequent connections.
			ClientSessionCache: tls.NewLRUClientSessionCache(512),
		}
	}

	// Apply the security override if requested. This is useful for environments
	// with self signed certificates, like during testing or when proxying traffic.
	tlsConfig.InsecureSkipVerify = config.IgnoreTLSErrors

	return tlsConfig
}

