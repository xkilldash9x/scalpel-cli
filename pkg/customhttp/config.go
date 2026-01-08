package customhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/network"
)

/*
Sentinel error returned when credentials are not available for a given host and realm.

	Signals to the client that authentication cannot be handled and the original 401/407
	response should be returned.
*/
var ErrCredentialsNotFound = errors.New("credentials not found")

/*
Defines an interface for dynamically supplying credentials in response to an

	HTTP authentication challenge (e.g., Basic Auth). Allows the client to support
	authentication without hardcoding usernames and passwords. *
*/
type CredentialsProvider interface {
	/** Called when the client receives a 401 (Unauthorized) or 407 (Proxy Authentication Required)
	  response.

	  Parameters:
	    - host: The host (e.g., "example.com:443") that issued the challenge.
	    - realm: The authentication realm specified in the WWW-Authenticate header.

	  Should return the username, password, and nil on success. If credentials
	  are not available, it must return ErrCredentialsNotFound. Other errors
	  will halt the request. */
	GetCredentials(host string, realm string) (username string, password string, err error)
}

/*
Encapsulates the rules for retrying failed or transient HTTP requests. Supports

	exponential backoff with jitter to prevent overwhelming a server that is
	temporarily unavailable. *
*/
type RetryPolicy struct {
	// Maximum number of retry attempts after the initial request fails.
	MaxRetries int
	// Base duration to wait before the first retry.
	InitialBackoff time.Duration
	// Upper limit for the backoff duration, preventing excessively long waits.
	MaxBackoff time.Duration
	// Multiplier for the exponential backoff calculation (e.g., 2.0).
	BackoffFactor float64
	// If true, adds a random factor to the backoff duration to prevent multiple
	// clients from retrying in synchronized waves (thundering herd problem).
	Jitter bool
	// Set of HTTP status codes that should trigger a retry for idempotent requests
	// (e.g., GET, PUT, DELETE).
	RetryableStatusCodes map[int]bool
}

// Creates and returns a policy with sensible defaults, such as 3 max retries,
// exponential backoff starting at 500ms, and retries for common transient server
// errors like 502, 503, and 504.
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

// Defines configuration parameters specific to HTTP/2 connections.
type H2Settings struct {
	// Time between sending PING frames to the server to check for connection liveness.
	PingInterval time.Duration
	// Maximum time to wait for a PING acknowledgment before considering the
	// connection dead and closing it.
	PingTimeout time.Duration
}

// Returns a default configuration with a 30-second ping interval and a 5-second
// ping timeout.
func DefaultH2Settings() H2Settings {
	return H2Settings{
		PingInterval: 30 * time.Second,
		PingTimeout:  5 * time.Second,
	}
}

// Defines configuration parameters specific to HTTP/3 (QUIC) connections.
type H3Settings struct {
	// Frequency of keep-alive packets sent to maintain the QUIC connection and
	// prevent NAT timeouts.
	KeepAlivePeriod time.Duration
	// Maximum duration the connection can remain idle before being closed by the
	// QUIC layer.
	MaxIdleTimeout time.Duration
}

// Returns standard QUIC parameters optimized for robustness.
func DefaultH3Settings() H3Settings {
	return H3Settings{
		KeepAlivePeriod: 10 * time.Second,
		MaxIdleTimeout:  30 * time.Second,
	}
}

/*
The primary configuration struct for a CustomClient. Aggregates all configurable

	aspects of the client, including dialing, cookies, timeouts, redirection, retries,
	authentication, and protocol-specific settings. *
*/
type ClientConfig struct {
	// Low-level configuration for establishing TCP and TLS connections, including
	// proxy settings.
	DialerConfig *network.DialerConfig

	// Optional custom dial context for advanced connection control.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Specifies the cookie jar for the client. If nil, cookies are not managed.
	CookieJar http.CookieJar

	// Sets the timeout for a single HTTP request attempt.
	RequestTimeout time.Duration

	// Maximum duration a connection can remain idle in the pool before it is closed
	// and evicted.
	IdleConnTimeout time.Duration

	// Controls whether to skip TLS certificate verification.
	InsecureSkipVerify bool

	/* Provides a function to define a custom redirect policy. If nil, the client's
	default policy is used.*/
	CheckRedirect func(req *http.Request, via []*http.Request) error

	// Defines the rules for retrying failed requests.
	RetryPolicy *RetryPolicy

	// Interface for dynamically supplying credentials for HTTP authentication.
	CredentialsProvider CredentialsProvider

	// Settings specific to HTTP/2 connections.
	H2Config H2Settings

	// Settings specific to HTTP/3 connections.
	H3Config H3Settings

	/* Controls the injection of padding bytes into HTTP/2 frames. If nil, no
	   padding is applied. */
	PaddingStrategy PaddingStrategy
}

/*
Creates a new configuration with defaults optimized to emulate the behavior of a
modern web browser. Includes a pre-configured cookie jar, sensible timeouts, a
default retry policy, and standard HTTP/2 and HTTP/3 settings. *
*/
func NewBrowserClientConfig() *ClientConfig {
	// Create a default cookie jar
	jar, _ := cookiejar.New(nil) // Error is only if PublicSuffixList is provided and invalid.

	return &ClientConfig{
		DialerConfig:        network.NewDialerConfig(),
		DialContext:         nil, // Default to nil; can be set by user
		CookieJar:           jar,
		RequestTimeout:      30 * time.Second,
		IdleConnTimeout:     90 * time.Second, // Standard browser idle timeout
		InsecureSkipVerify:  false,
		CheckRedirect:       nil,
		RetryPolicy:         NewDefaultRetryPolicy(),
		CredentialsProvider: nil,
		H2Config:            DefaultH2Settings(),
		H3Config:            DefaultH3Settings(),
		PaddingStrategy:     nil,
	}
}

/*
A convenience method to configure an HTTP/HTTPS proxy. Sets the `ProxyURL` field
in the underlying `DialerConfig`. *
*/
func (c *ClientConfig) SetProxy(proxyURL *url.URL) {
	if c.DialerConfig == nil {
		c.DialerConfig = network.NewDialerConfig()
	}
	c.DialerConfig.ProxyURL = proxyURL
}
