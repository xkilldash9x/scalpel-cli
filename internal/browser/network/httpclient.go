// browser/network/httpclient.go
package network

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// Logger defines a simple interface for logging.
type Logger interface {
	Warn(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// NopLogger is a default logger that does nothing.
type NopLogger struct{}

func (n *NopLogger) Warn(msg string, args ...interface{})  {}
func (n *NopLogger) Info(msg string, args ...interface{})  {}
func (n *NopLogger) Debug(msg string, args ...interface{}) {}
func (n *NopLogger) Error(msg string, args ...interface{}) {}

// Constants optimized for browser behavior.
const (
	DefaultDialTimeout           = 15 * time.Second
	DefaultKeepAliveInterval     = 30 * time.Second
	DefaultTLSHandshakeTimeout   = 10 * time.Second
	DefaultResponseHeaderTimeout = 30 * time.Second
	DefaultRequestTimeout        = 120 * time.Second // Overall timeout for resource loading

	// Connection Pool Configuration for a browser.
	DefaultMaxIdleConns        = 200 // Total connections across all hosts
	DefaultMaxIdleConnsPerHost = 10  // Common browser limit
	DefaultMaxConnsPerHost     = 15
	DefaultIdleConnTimeout     = 90 * time.Second
)

// SecureMinTLSVersion defines the lowest TLS version considered secure by default.
const SecureMinTLSVersion = tls.VersionTLS12

// ClientConfig holds the configuration for the browser's HTTP client.
type ClientConfig struct {
	// Security
	InsecureSkipVerify bool
	TLSConfig          *tls.Config

	// Timeouts
	RequestTimeout time.Duration

	// Dialer configuration (TCP Layer)
	DialerConfig *DialerConfig

	// Connection pool and behavior
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration

	// DisableKeepAlives prevents the transport from reusing TCP connections (HTTP Keep-Alive).
	// This is useful for specific testing scenarios like race condition "dogpiling".
	DisableKeepAlives bool

	// Proxy
	ProxyURL *url.URL

	// State Management
	CookieJar http.CookieJar

	// Logger
	Logger Logger
}

// NewBrowserClientConfig creates a configuration optimized for web browsing.
func NewBrowserClientConfig() *ClientConfig {
	dialerCfg := NewDialerConfig()
	dialerCfg.Timeout = DefaultDialTimeout
	dialerCfg.KeepAlive = DefaultKeepAliveInterval

	// Initialize a default in-memory cookie jar.
	jar, _ := cookiejar.New(nil) // cookiejar.New only errors if options are invalid (we pass nil).

	return &ClientConfig{
		DialerConfig:        dialerCfg,
		InsecureSkipVerify:  false,
		DisableKeepAlives:   false, // Default to allowing connection reuse
		RequestTimeout:      DefaultRequestTimeout,
		MaxIdleConns:        DefaultMaxIdleConns,
		MaxIdleConnsPerHost: DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:     DefaultMaxConnsPerHost,
		IdleConnTimeout:     DefaultIdleConnTimeout,
		CookieJar:           jar,
		Logger:              &NopLogger{},
	}
}

// NewHTTPTransport creates and configures the base http.Transport.
func NewHTTPTransport(config *ClientConfig) *http.Transport {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	// Ensure defaults are set if components are missing
	if config.Logger == nil {
		config.Logger = &NopLogger{}
	}
	if config.DialerConfig == nil {
		config.DialerConfig = NewBrowserClientConfig().DialerConfig
	}

	tlsConfig := configureTLS(config)

	// Prepare the dialer config for the transport's DialContext.
	// We must set TLSConfig to nil here, as http.Transport manages the TLS handshake separately using TLSClientConfig.
	// Create a copy to avoid mutating the original config.DialerConfig.
	transportDialerConfig := *config.DialerConfig
	transportDialerConfig.TLSConfig = nil

	transport := &http.Transport{
		// Use our custom low-level TCP dialer.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialTCPContext(ctx, network, addr, &transportDialerConfig)
		},
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		DisableKeepAlives:     config.DisableKeepAlives, // Apply the configuration
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		// CRITICAL: We must disable the transport's built-in Gzip handling
		// because our CompressionMiddleware handles Gzip, Deflate, and Brotli robustly.
		DisableCompression: true,
		ForceAttemptHTTP2:  true, // Always prefer H2
	}

	if config.ProxyURL != nil {
		transport.Proxy = http.ProxyURL(config.ProxyURL)
	}

	return transport
}

// NewClient creates the configured http.Client for the browser.
func NewClient(config *ClientConfig) *http.Client {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	baseTransport := NewHTTPTransport(config)

	// Wrap the transport with our middleware to handle compression.
	wrappedTransport := NewCompressionMiddleware(baseTransport)

	client := &http.Client{
		Transport: wrappedTransport,
		Timeout:   config.RequestTimeout,
		Jar:       config.CookieJar,
		// For an automation browser, handle redirects manually to track navigation precisely.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client
}

// configureTLS sets up the TLS configuration and ensures strong defaults and ALPN settings.
func configureTLS(config *ClientConfig) *tls.Config {
	var tlsConfig *tls.Config
	// 1. Get a base config, prioritizing user-supplied ClientConfig.TLSConfig, then DialerConfig.TLSConfig.
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
	} else if config.DialerConfig != nil && config.DialerConfig.TLSConfig != nil {
		tlsConfig = config.DialerConfig.TLSConfig.Clone()
	} else {
		// No user config, so start with a fresh, secure default.
		tlsConfig = NewDialerConfig().TLSConfig.Clone()
	}

	// 2. Get the secure defaults to merge from.
	defaults := NewDialerConfig().TLSConfig

	// 3. Merge missing defaults into the user's config.
	if len(tlsConfig.CipherSuites) == 0 {
		tlsConfig.CipherSuites = defaults.CipherSuites
	}
	if len(tlsConfig.CurvePreferences) == 0 {
		tlsConfig.CurvePreferences = defaults.CurvePreferences
	}
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = defaults.ClientSessionCache
	}
	if len(tlsConfig.NextProtos) == 0 {
		// Configure ALPN: "h2" must be listed before "http/1.1" to prefer HTTP/2.
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	// 4. Apply security hardening and verification.
	// If the user didn't specify a MinVersion (MinVersion == 0), set the secure default.
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = SecureMinTLSVersion
	}

	// Warn if the resulting configuration uses an insecure TLS version.
	if tlsConfig.MinVersion < SecureMinTLSVersion {
		config.Logger.Warn("Insecure TLS configuration detected: Minimum TLS version is set below TLS 1.2. Connections may be vulnerable.",
			"configured_version", tlsConfig.MinVersion)
	}

	// 5. Apply the final override for ignoring TLS errors.
	tlsConfig.InsecureSkipVerify = config.InsecureSkipVerify

	return tlsConfig
}
