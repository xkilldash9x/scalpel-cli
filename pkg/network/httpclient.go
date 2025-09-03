// pkg/network/httpclient.go
package network

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
)

// Constants for default optimized TCP/HTTP settings.
const (
	DefaultDialTimeout           = 5 * time.Second
	DefaultKeepAliveInterval     = 15 * time.Second
	DefaultTLSHandshakeTimeout   = 5 * time.Second
	DefaultResponseHeaderTimeout = 10 * time.Second
	DefaultRequestTimeout        = 30 * time.Second

	// Connection Pool Configuration tuned for scanning workloads
	DefaultMaxIdleConns        = 100
	DefaultMaxIdleConnsPerHost = 20 // Increased to support higher concurrency
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
	DialTimeout           time.Duration
	KeepAliveInterval     time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration

	// Connection pool settings
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration

	// Protocol settings
	ForceHTTP2        bool
	DisableKeepAlives bool
	DisableCompression bool

	// Proxy settings
	ProxyURL *url.URL

	// Logger
	Logger *zap.Logger
}

// NewDefaultClientConfig creates a configuration optimized for general-purpose scanning.
func NewDefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		IgnoreTLSErrors:       false,
		RequestTimeout:        DefaultRequestTimeout,
		DialTimeout:           DefaultDialTimeout,
		KeepAliveInterval:     DefaultKeepAliveInterval,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		ForceHTTP2:            true, // Prefer H2 by default
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

	// 1. Configure the Dialer (TCP Layer)
	dialer := &net.Dialer{
		Timeout:   config.DialTimeout,
		KeepAlive: config.KeepAliveInterval,
		// Enable dual-stack (IPv4/IPv6) with Happy Eyeballs (RFC 8305) for faster connection establishment.
		FallbackDelay: 300 * time.Millisecond,
	}

	// 2. Configure TLS (Security Layer)
	tlsConfig := configureTLS(config)

	// 3. Configure HTTP Transport (Application Layer)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: config.TLSHandshakeTimeout,
		
		// Connection Pooling and Management
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableKeepAlives:   config.DisableKeepAlives,

		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		DisableCompression:    config.DisableCompression,

		// Protocol selection
		ForceAttemptHTTP2: config.ForceHTTP2,
	}

	// Configure Proxy if set
	if config.ProxyURL != nil {
		transport.Proxy = http.ProxyURL(config.ProxyURL)
	}

	// 4. Explicitly configure HTTP/2 if enabled
	if config.ForceHTTP2 {
		// Attempt to configure H2 transport. 
		if err := http2.ConfigureTransport(transport); err != nil {
			// If configuration fails, log it and proceed (graceful fallback to H1.1).
			config.Logger.Warn("Failed to configure HTTP/2 transport, falling back to HTTP/1.1", zap.Error(err))
		}
	} else {
        // If H2 is disabled, ensure ALPN only advertises HTTP/1.1 if NextProtos hasn't been customized.
        if len(tlsConfig.NextProtos) == 0 {
            tlsConfig.NextProtos = []string{"http/1.1"}
        }
    }

	return transport
}

// NewClient creates an http.Client using the configured transport.
func NewClient(config *ClientConfig) *http.Client {
	if config == nil {
		config = NewDefaultClientConfig()
	}
	
	transport := NewHTTPTransport(config)

	client := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
		// Security: Do not follow redirects automatically. The scanner must analyze the redirect first.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client
}

// configureTLS sets up the TLS configuration with strong defaults and optimizations.
func configureTLS(config *ClientConfig) *tls.Config {
	var tlsConfig *tls.Config

	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
	} else {
		// Default strong TLS configuration
		tlsConfig = &tls.Config{
			// Support only modern, strong protocols
			MinVersion: tls.VersionTLS12,
			// Prioritize forward-secret and authenticated encryption (AEAD) ciphers
			CipherSuites: []uint16{
				// TLS 1.3 (automatically preferred if supported by server)
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				// TLS 1.2
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			// Optimization: Cache TLS session tickets for resumption
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		}
	}
	
	// Apply the override for TLS verification.
	tlsConfig.InsecureSkipVerify = config.IgnoreTLSErrors
	
	return tlsConfig
}
