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
	DefaultMaxIdleConns        = 100
	DefaultMaxIdleConnsPerHost = 20
	DefaultMaxConnsPerHost     = 50
	DefaultIdleConnTimeout     = 30 * time.Second
)

// Default secure TLS settings.
const requiredMinTLSVersion = tls.VersionTLS12

// Default secure cipher suites prioritized for security, performance, and HTTP/2 compatibility.
var defaultSecureCipherSuites = []uint16{
	// TLS 1.3 suites
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256, // Corrected constant
	tls.TLS_AES_128_GCM_SHA256,

	// TLS 1.2 suites with Perfect Forward Secrecy (PFS)
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

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
type Client struct {
	*http.Client
}

// NewDefaultClientConfig creates a configuration optimized for general-purpose scanning.
func NewDefaultClientConfig() *ClientConfig {
	dialerCfg := NewDialerConfig()
	dialerCfg.Timeout = DefaultDialTimeout
	dialerCfg.KeepAlive = DefaultKeepAliveInterval
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
		ForceHTTP2:            true,
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

	// configureTLS now returns a fully-baked config, including all hardening and ALPN settings.
	tlsConfig := configureTLS(config)

	transportDialerConfig := *config.DialerConfig
	transportDialerConfig.TLSConfig = nil

	transport := &http.Transport{
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		Client: standardClient,
	}
}

// configureTLS sets up the TLS configuration by cloning any provided configuration
// and ensuring strong defaults are applied.
func configureTLS(config *ClientConfig) *tls.Config {
	if config == nil {
		config = NewDefaultClientConfig()
	}

	var tlsConfig *tls.Config
	if config.TLSConfig != nil {
		// Restored Clone() to robustly preserve all user-provided settings.
		tlsConfig = config.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}

	// Apply security hardening, respecting user settings if they are already strong enough.
	if tlsConfig.MinVersion < requiredMinTLSVersion {
		tlsConfig.MinVersion = requiredMinTLSVersion
	}
	if len(tlsConfig.CipherSuites) == 0 {
		tlsConfig.CipherSuites = defaultSecureCipherSuites
	}

	// Apply performance optimizations if not already configured.
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(512)
	}

	// Configure ALPN if the user hasn't specified their own list.
	// This is done here to ensure the config is complete before the transport uses it.
	if len(tlsConfig.NextProtos) == 0 {
		if config.ForceHTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		} else {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}
	}

	// Apply the final override.
	tlsConfig.InsecureSkipVerify = config.IgnoreTLSErrors

	return tlsConfig
}