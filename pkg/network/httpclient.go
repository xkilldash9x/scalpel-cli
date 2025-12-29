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

// Logger defines a minimal logging interface that this package uses to report
// warnings, errors, and informational messages. This allows users to integrate
// the client with their own logging framework (e.g., zap, logrus).
type Logger interface {
	// Warn logs a warning message.
	Warn(msg string, args ...interface{})
	// Info logs an informational message.
	Info(msg string, args ...interface{})
	// Debug logs a debug message.
	Debug(msg string, args ...interface{})
	// Error logs an error message.
	Error(msg string, args ...interface{})
}

// NopLogger is a no-op implementation of the Logger interface that discards
// all log messages. It is used as the default logger to prevent nil panics if
// no logger is provided.
type NopLogger struct{}

// Warn does nothing.
func (n *NopLogger) Warn(msg string, args ...interface{}) {}

// Info does nothing.
func (n *NopLogger) Info(msg string, args ...interface{}) {}

// Debug does nothing.
func (n *NopLogger) Debug(msg string, args ...interface{}) {}

// Error does nothing.
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

// ClientConfig holds the high-level configuration for creating a customized
// HTTP client. It consolidates settings for security, timeouts, connection pooling,
// proxying, and state management (cookies).
type ClientConfig struct {
	// InsecureSkipVerify controls whether the client will skip TLS certificate
	// verification. Setting this to true is insecure and should only be used in
	// controlled testing environments.
	InsecureSkipVerify bool
	// TLSConfig provides a custom TLS configuration for the client. If nil, a
	// secure default configuration will be generated.
	TLSConfig *tls.Config

	// RequestTimeout specifies the total time limit for a single HTTP request,
	// including connection time, redirects, and reading the response body.
	RequestTimeout time.Duration

	// DialerConfig provides the low-level configuration for establishing TCP
	// connections.
	DialerConfig *DialerConfig

	// MaxIdleConns is the maximum number of idle (keep-alive) connections across all hosts.
	MaxIdleConns int
	// MaxIdleConnsPerHost is the maximum number of idle connections to a single host.
	MaxIdleConnsPerHost int
	// MaxConnsPerHost is the maximum number of connections (idle + active) to a single host.
	MaxConnsPerHost int
	// IdleConnTimeout is the maximum amount of time an idle connection will remain
	// in the pool before being closed.
	IdleConnTimeout time.Duration

	// DisableKeepAlives, if true, prevents the transport from reusing TCP
	// connections after a request has completed.
	DisableKeepAlives bool

	// ProxyURL specifies the proxy server for the client to use.
	ProxyURL *url.URL

	// CookieJar is the cookie jar used to store and send cookies for HTTP requests.
	// If nil, cookies will not be handled automatically.
	CookieJar http.CookieJar

	// Logger is the logger instance for the client to use.
	Logger Logger
}

// NewBrowserClientConfig creates a new ClientConfig with settings specifically
// optimized for emulating a modern web browser. This includes a large connection
// pool, aggressive keep-alives, a default in-memory cookie jar, and a secure
// low-level dialer configuration.
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
		ProxyURL:            nil,
	}
}

// NewHTTPTransport creates a new `http.Transport` based on the provided
// ClientConfig. It is the foundational layer of the HTTP client, responsible
// for connection pooling, dialing, TLS handshakes, and proxying.
//
// This function configures the transport with the custom dialer (`DialTCPContext`),
// a secure TLS configuration, and robust connection pool settings. It also
// explicitly disables the transport's built-in compression handling, as that
// functionality is managed by the `CompressionMiddleware` which wraps this transport.
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
	// Use Clone() for a deep copy to avoid mutating the original config.DialerConfig and ensure thread safety.
	transportDialerConfig := config.DialerConfig.Clone()
	transportDialerConfig.TLSConfig = nil

	// Determine the primary proxy configuration source.
	proxyURL := config.ProxyURL
	if proxyURL == nil && config.DialerConfig.ProxyURL != nil {
		proxyURL = config.DialerConfig.ProxyURL
	}

	// CRITICAL: If http.Transport.Proxy is used, the DialContext is responsible for the TCP connection *to* the proxy.
	// We must ensure the DialerConfig used by DialContext does not also attempt to proxy the connection, preventing loops or double-proxying.
	if proxyURL != nil {
		// Assume the connection to the proxy itself should be direct.
		transportDialerConfig.ProxyURL = nil
	}

	transport := &http.Transport{
		// Use our custom low-level TCP dialer with the prepared configuration.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialTCPContext(ctx, network, addr, transportDialerConfig)
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

	// Apply the determined proxy configuration to the transport.
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return transport
}

// NewClient creates a new `http.Client` fully configured according to the
// provided ClientConfig. It builds a layered transport stack, starting with the
// base `http.Transport` from `NewHTTPTransport`, and wraps it with the
// `CompressionMiddleware` to provide transparent decompression.
//
// The returned client is configured to not follow redirects automatically,
// allowing the caller to inspect and handle redirect responses manually, which
// is a common requirement in browser automation and security scanning.
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
	// FIX: Enforce the secure minimum version if the configured version is lower (including unset/0).
	// The previous logic failed to override explicitly insecure settings (e.g., setting TLS 1.0).
	if tlsConfig.MinVersion < SecureMinTLSVersion {
		// Log if we are overriding an explicit (non-zero) user configuration.
		if tlsConfig.MinVersion != 0 {
			config.Logger.Warn("Security Hardening: Overriding insecure TLS configuration. Minimum TLS version upgraded to secure minimum.",
				"configured_version", tlsConfig.MinVersion, "enforced_version", SecureMinTLSVersion)
		}
		// Enforce the secure version.
		tlsConfig.MinVersion = SecureMinTLSVersion
	}

	// 5. Apply the final override for ignoring TLS errors.
	// This overrides any setting potentially present in the base TLSConfig.
	tlsConfig.InsecureSkipVerify = config.InsecureSkipVerify

	return tlsConfig
}
