package customhttp

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// ErrCredentialsNotFound is returned when credentials for a specific realm/host are unavailable.
var ErrCredentialsNotFound = errors.New("credentials not found")

// CredentialsProvider is an interface for retrieving authentication credentials dynamically.
type CredentialsProvider interface {
	// GetCredentials retrieves credentials for a given host and authentication realm.
	// isProxy indicates if the challenge is from a proxy (407) or the origin server (401).
	GetCredentials(host string, realm string) (username string, password string, err error)
}

// RetryPolicy defines the strategy for retrying requests.
type RetryPolicy struct {
	// MaxRetries is the maximum number of times a request will be retried after the initial attempt.
	MaxRetries int
	// InitialBackoff is the duration to wait before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff is the maximum duration to wait between retries.
	MaxBackoff time.Duration
	// BackoffFactor determines the rate of backoff increase (e.g., 2.0 for exponential backoff).
	BackoffFactor float64
	// Jitter adds randomization to the backoff duration to prevent thundering herd problem.
	Jitter bool
	// RetryableStatusCodes defines which HTTP status codes should trigger a retry for idempotent requests.
	RetryableStatusCodes map[int]bool
}

// NewDefaultRetryPolicy creates a sensible default retry policy suitable for browser-like behavior.
func NewDefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries:     3,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		BackoffFactor:  2.0,
		Jitter:         true,
		RetryableStatusCodes: map[int]bool{
			http.StatusRequestTimeout:  true, // 408
			http.StatusTooManyRequests: true, // 429 (handled specially if Retry-After is present)
			// 5xx errors are often retryable for idempotent operations.
			// We exclude 500 (Internal Server Error) by default as it often indicates a non-transient issue,
			// but include common transient gateway errors.
			http.StatusBadGateway:         true, // 502
			http.StatusServiceUnavailable: true, // 503 (handled specially if Retry-After is present)
			http.StatusGatewayTimeout:     true, // 504
		},
	}
}

// H2Settings holds configuration specific to HTTP/2 connections.
type H2Settings struct {
	// PingInterval is the duration between sending PING frames for keep-alive.
	PingInterval time.Duration
	// PingTimeout is the duration to wait for a PING acknowledgment before closing the connection.
	PingTimeout time.Duration
}

// DefaultH2Settings provides standard HTTP/2 configuration.
func DefaultH2Settings() H2Settings {
	return H2Settings{
		PingInterval: 30 * time.Second,
		PingTimeout:  5 * time.Second,
	}
}

// ClientConfig holds the complete network configuration for a custom client.
type ClientConfig struct {
	// DialerConfig is the configuration for low-level TCP/TLS connections.
	// Proxy settings (ProxyURL) should be configured within DialerConfig.
	DialerConfig *network.DialerConfig

	// CookieJar stores and manages cookies. If nil, cookies are not stored.
	CookieJar http.CookieJar

	// RequestTimeout is the timeout for a single request/response cycle (one attempt).
	RequestTimeout time.Duration

	// IdleConnTimeout is the duration to wait before closing an idle H1 or H2 connection.
	// If zero, idle connections are not automatically closed.
	IdleConnTimeout time.Duration

	// InsecureSkipVerify controls whether to skip TLS certificate verification.
	InsecureSkipVerify bool

	// CheckRedirect defines the policy for handling redirects.
	// If nil, the CustomClient's default policy (up to 10 redirects) is used.
	CheckRedirect func(req *http.Request, via []*http.Request) error

	// RetryPolicy defines the strategy for retrying failed requests.
	RetryPolicy *RetryPolicy

	// CredentialsProvider is used to handle authentication challenges (e.g., Basic Auth).
	CredentialsProvider CredentialsProvider

	// H2Config configuration for HTTP/2 connections.
	H2Config H2Settings
}

// NewBrowserClientConfig creates a default configuration optimized for browser behavior.
func NewBrowserClientConfig() *ClientConfig {
	// Create a default cookie jar
	jar, _ := cookiejar.New(nil) // Error is only if PublicSuffixList is provided and invalid.

	return &ClientConfig{
		DialerConfig:        network.NewDialerConfig(),
		CookieJar:           jar,
		RequestTimeout:      30 * time.Second,
		IdleConnTimeout:     90 * time.Second, // Standard browser idle timeout
		InsecureSkipVerify:  false,
		CheckRedirect:       nil, // Use CustomClient's default redirect logic.
		RetryPolicy:         NewDefaultRetryPolicy(),
		CredentialsProvider: nil, // No credentials provider by default.
		H2Config:            DefaultH2Settings(),
	}
}

// SetProxy configures the proxy URL in the underlying DialerConfig.
func (c *ClientConfig) SetProxy(proxyURL *url.URL) {
	if c.DialerConfig == nil {
		c.DialerConfig = network.NewDialerConfig()
	}
	c.DialerConfig.ProxyURL = proxyURL
}
