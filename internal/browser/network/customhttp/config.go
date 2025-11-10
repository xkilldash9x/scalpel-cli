package customhttp

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// ErrCredentialsNotFound is a sentinel error returned by a CredentialsProvider
// when it does not have credentials for a given host and realm. This signals
// to the client that authentication cannot be handled and the original 401/407
// response should be returned.
var ErrCredentialsNotFound = errors.New("credentials not found")

// CredentialsProvider defines an interface for dynamically supplying credentials
// in response to an HTTP authentication challenge (e.g., Basic Auth). This allows
// the client to support authentication without hardcoding usernames and passwords.
type CredentialsProvider interface {
	// GetCredentials is called when the client receives a 401 (Unauthorized) or
	// 407 (Proxy Authentication Required) response.
	//
	// Parameters:
	//   - host: The host (e.g., "example.com:443") that issued the challenge.
	//   - realm: The authentication realm specified in the WWW-Authenticate header.
	//
	// It should return the username, password, and nil on success. If credentials
	// are not available, it must return ErrCredentialsNotFound. Other errors
	// will halt the request.
	GetCredentials(host string, realm string) (username string, password string, err error)
}

// RetryPolicy encapsulates the rules for retrying failed or transient HTTP requests.
// It supports exponential backoff with jitter to prevent overwhelming a server
// that is temporarily unavailable.
type RetryPolicy struct {
	// MaxRetries is the maximum number of retry attempts after the initial request fails.
	MaxRetries int
	// InitialBackoff is the base duration to wait before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff is the upper limit for the backoff duration, preventing excessively long waits.
	MaxBackoff time.Duration
	// BackoffFactor is the multiplier for the exponential backoff calculation (e.g., 2.0).
	BackoffFactor float64
	// Jitter, if true, adds a random factor to the backoff duration to prevent
	// multiple clients from retrying in synchronized waves (thundering herd problem).
	Jitter bool
	// RetryableStatusCodes is a set of HTTP status codes that should trigger a
	// retry for idempotent requests (e.g., GET, PUT, DELETE).
	RetryableStatusCodes map[int]bool
}

// NewDefaultRetryPolicy creates and returns a RetryPolicy with sensible defaults,
// such as 3 max retries, exponential backoff starting at 500ms, and retries for
// common transient server errors like 502, 503, and 504.
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

// H2Settings defines configuration parameters specific to HTTP/2 connections.
type H2Settings struct {
	// PingInterval specifies the time between sending HTTP/2 PING frames to the
	// server to check for connection liveness.
	PingInterval time.Duration
	// PingTimeout is the maximum time to wait for a PING acknowledgment before
	// considering the connection dead and closing it.
	PingTimeout time.Duration
}

// DefaultH2Settings returns a default H2Settings configuration with a 30-second
// ping interval and a 5-second ping timeout.
func DefaultH2Settings() H2Settings {
	return H2Settings{
		PingInterval: 30 * time.Second,
		PingTimeout:  5 * time.Second,
	}
}

// ClientConfig is the primary configuration struct for a CustomClient. It aggregates
// all configurable aspects of the client, including dialing, cookies, timeouts,
// redirection, retries, authentication, and HTTP/2 settings.
type ClientConfig struct {
	// DialerConfig holds the low-level configuration for establishing TCP and
	// TLS connections, including proxy settings.
	DialerConfig *network.DialerConfig

	// CookieJar specifies the cookie jar for the client. If nil, cookies are not managed.
	CookieJar http.CookieJar

	// RequestTimeout sets the timeout for a single HTTP request attempt.
	RequestTimeout time.Duration

	// IdleConnTimeout is the maximum duration a connection can remain idle in the
	// pool before it is closed and evicted.
	IdleConnTimeout time.Duration

	// InsecureSkipVerify controls whether to skip TLS certificate verification.
	InsecureSkipVerify bool

	// CheckRedirect provides a function to define a custom redirect policy. If nil,
	// the client's default policy is used.
	CheckRedirect func(req *http.Request, via []*http.Request) error

	// RetryPolicy defines the rules for retrying failed requests.
	RetryPolicy *RetryPolicy

	// CredentialsProvider is an interface for dynamically supplying credentials for
	// HTTP authentication.
	CredentialsProvider CredentialsProvider

	// H2Config holds settings specific to HTTP/2 connections.
	H2Config H2Settings
}

// NewBrowserClientConfig creates a new ClientConfig with defaults that are
// optimized to emulate the behavior of a modern web browser. This includes
// a pre-configured cookie jar, sensible timeouts, a default retry policy,
// and standard HTTP/2 settings.
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

// SetProxy is a convenience method to configure an HTTP/HTTPS proxy for the
// client. It sets the `ProxyURL` field in the underlying `DialerConfig`.
func (c *ClientConfig) SetProxy(proxyURL *url.URL) {
	if c.DialerConfig == nil {
		c.DialerConfig = network.NewDialerConfig()
	}
	c.DialerConfig.ProxyURL = proxyURL
}
