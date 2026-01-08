package customhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors" // Added import
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/observability" // Added import
	"go.uber.org/zap"
	"golang.org/x/net/http2" // Added import
)

// Define a reasonable limit for buffering request bodies in memory for replayability.
// This prevents excessive memory usage when handling large uploads that might need retries/redirects.
const MaxReplayableBodyBytes = 2 * 1024 * 1024 // 2 MB

// ConnectionPool defines a minimal interface for a connection pool, used by the
// CustomClient's connection evictor to manage and close idle connections.
type ConnectionPool interface {
	// Close immediately closes all connections in the pool.
	Close() error
	// IsIdle returns true if the pool has been idle for at least the specified duration.
	IsIdle(timeout time.Duration) bool
}

// CustomClient is a sophisticated, low level HTTP client designed for fine grained
// control over HTTP/1.1, HTTP/2 and HTTP/3 connections. It is the core of the browser's
// networking stack, managing persistent connections on a per-host basis and handling
// the full request lifecycle, including cookies, redirects, retries, and authentication.
//
// It maintains separate pools of `H1Client`, `H2Client`, and `H3Client` instances, allowing it
// to transparently handle different protocol versions. A background goroutine
// periodically evicts idle connections to conserve resources.
type CustomClient struct {
	Config *ClientConfig
	Logger *zap.Logger

	// mu protects the client maps (h1Clients, h2Clients, h3Clients).
	// Changed from sync.Mutex to sync.RWMutex to allow concurrent reads (e.g., getting connection count)
	// and optimize connection lookup.
	mu        sync.RWMutex
	h1Clients map[string]*H1Client // key: "host:port"
	h2Clients map[string]*H2Client // key: "host:port"
	h3Clients map[string]*H3Client // key: "host:port"

	// Unsupported maps track hosts known not to support specific protocols (e.g., due to negotiation failure).
	// Protected by mu.
	h2Unsupported map[string]bool // key: "host:port"
	h3Unsupported map[string]bool // key: "host:port"

	// MaxRedirects specifies the maximum number of redirects to follow for a single request.
	MaxRedirects int

	closeChan chan struct{}
	evictorWG sync.WaitGroup
}

// NewCustomClient creates and initializes a new CustomClient with the given
// configuration. It also starts a background goroutine to periodically close
// idle connections from its pools.
func NewCustomClient(config *ClientConfig, logger *zap.Logger) *CustomClient {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	// If no logger is provided, fetch the global logger.
	if logger == nil {
		logger = observability.GetLogger()
	}

	client := &CustomClient{
		Config:        config,
		Logger:        logger.Named("customhttp_client"),
		h1Clients:     make(map[string]*H1Client),
		h2Clients:     make(map[string]*H2Client),
		h3Clients:     make(map[string]*H3Client),
		h2Unsupported: make(map[string]bool),
		h3Unsupported: make(map[string]bool),
		MaxRedirects:  10, // Default maximum redirects
		closeChan:     make(chan struct{}),
	}

	// Start the background connection evictor.
	client.evictorWG.Add(1)
	go client.connectionEvictor()

	return client
}

// ConnectionCount returns the total number of active connections (H1 + H2 + H3).
// This method is thread-safe and primarily intended for testing purposes.
func (c *CustomClient) ConnectionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.h1Clients) + len(c.h2Clients) + len(c.h3Clients)
}

// GetH1Connection returns the underlying net.Conn for an H1 connection to the specified host.
// The host should be in "host:port" format (e.g., "example.com:443").
// Returns nil if no H1 connection exists for the host or if the client is not connected.
// This method is thread-safe.
func (c *CustomClient) GetH1Connection(host string) net.Conn {
	c.mu.RLock()
	client, exists := c.h1Clients[host]
	c.mu.RUnlock()

	if !exists || client == nil {
		return nil
	}
	return client.Conn
}

// GetH2Connection returns the underlying net.Conn for an H2 connection to the specified host.
// The host should be in "host:port" format (e.g., "example.com:443").
// Returns nil if no H2 connection exists for the host or if the client is not connected.
// This method is thread-safe.
func (c *CustomClient) GetH2Connection(host string) net.Conn {
	c.mu.RLock()
	client, exists := c.h2Clients[host]
	c.mu.RUnlock()

	if !exists || client == nil {
		return nil
	}
	return client.Conn
}

// GetH3Connection returns the underlying net.Conn for an H3 connection to the specified host.
// Note: HTTP/3 uses QUIC which manages connections differently. The underlying QUIC
// connection is managed by the http3.Transport and is not directly exposed as a net.Conn.
// This method always returns nil for H3 connections.
// This method is thread-safe.
func (c *CustomClient) GetH3Connection(host string) net.Conn {
	// H3 uses QUIC which doesn't expose a traditional net.Conn.
	// The connection is managed internally by quic-go's http3.Transport.
	return nil
}

// GetConnection returns the underlying net.Conn for any active connection to the specified host.
// It checks H2 and H1 connections in that order and returns the first one found.
// The host should be in "host:port" format (e.g., "example.com:443").
// Returns nil if no connection exists for the host.
// Note: H3/QUIC connections are not included as they don't expose a traditional net.Conn.
// This method is thread-safe.
func (c *CustomClient) GetConnection(host string) net.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check H2 first (most common for modern HTTPS)
	if client, exists := c.h2Clients[host]; exists && client != nil && client.Conn != nil {
		return client.Conn
	}
	// Check H1
	if client, exists := c.h1Clients[host]; exists && client != nil && client.Conn != nil {
		return client.Conn
	}
	// H3/QUIC connections don't expose a traditional net.Conn
	return nil
}

// Do executes a single HTTP request and returns the response. This is the main
// entry point for the client. It orchestrates the entire request lifecycle,
// including:
//
// 1. Making the request body replayable for retries and redirects.
// 2. Adding cookies from the client's cookie jar.
// 3. Executing the request with a configurable retry policy for transient errors.
// 4. Storing cookies from the response.
// 5. Handling authentication challenges (e.g., HTTP Basic Auth).
// 6. Following HTTP redirects up to a configured limit.
//
// Parameters:
//   - ctx: The context for the entire request operation, including all retries and redirects.
//   - req: The HTTP request to send.
//
// Returns the final HTTP response or an error if the request could not be completed.
func (c *CustomClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Ensure the request body is replayable from the start, as it might be needed for retries or redirects.
	if err := ensureBodyReplayable(req); err != nil {
		return nil, fmt.Errorf("failed to make request body replayable: %w", err)
	}

	// Initialize the request history for redirect tracking. authAttempted starts as false.
	return c.doInternal(ctx, req, 0, nil, false)
}

// doInternal handles the request execution loop, managing redirects and authentication attempts.
func (c *CustomClient) doInternal(ctx context.Context, req *http.Request, redirectCount int, via []*http.Request, authAttempted bool) (*http.Response, error) {
	if req.URL == nil {
		return nil, fmt.Errorf("request URL is nil")
	}

	// 1. Handle Cookies
	c.addCookies(req)

	// 2. Execute Request with Retries
	resp, err := c.executeWithRetries(ctx, req)
	if err != nil {
		return nil, err
	}

	// 3. Store Cookies
	c.storeCookies(req.URL, resp)

	// 4. Handle Authentication Challenges (Basic Auth)
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired) && !authAttempted && c.Config.CredentialsProvider != nil {
		if handled, nextReq, err := c.handleAuthentication(ctx, req, resp); handled {
			if err != nil {
				// Error occurred while trying to handle auth (e.g., getting credentials).
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return nil, err
			}
			// Close the unauthorized response body.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			// Retry the request with authentication, marking authAttempted=true to prevent loops.
			return c.doInternal(ctx, nextReq, redirectCount, via, true)
		}
	}

	// 5. Handle Redirects
	if isRedirect(resp.StatusCode) {
		return c.handleRedirect(ctx, req, resp, redirectCount, via)
	}

	return resp, nil
}

// executeWithRetries handles the retry logic for a single request attempt (before redirects).
func (c *CustomClient) executeWithRetries(ctx context.Context, req *http.Request) (*http.Response, error) {
	policy := c.Config.RetryPolicy
	if policy == nil {
		policy = NewDefaultRetryPolicy()
	}

	var resp *http.Response
	var err error
	attempt := 0

	for {
		// Immediately check for cancellation before proceeding with the attempt.
		select {
		case <-ctx.Done():
			if err != nil {
				return resp, err
			}
			return nil, ctx.Err()
		default:
		}

		// Clear the response from the previous attempt if this is a retry.
		if attempt > 0 {
			resp = nil
		}

		// Clone the request context for this attempt.
		reqAttempt := req.Clone(ctx)

		// Reset body for replayability
		if req.Body != nil && req.GetBody != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, fmt.Errorf("failed to reset request body for attempt %d: %w", attempt+1, bodyErr)
			}
			reqAttempt.Body = body
		}

		// -- Execute the request (single attempt) --
		attemptErr := error(nil)
		h3Attempted := false

		// 1. Try HTTP/3 First
		if c.shouldAttemptH3(reqAttempt.URL) {
			resp, attemptErr = c.executeH3(ctx, reqAttempt)
			if attemptErr == nil {
				// H3 Success
				h3Attempted = true
			} else {
				// H3 Failed: Fallback logic
				// Log the failure but don't stop; allow fallback to H2/H1
				c.Logger.Debug("H3 attempt failed, falling back to H2/H1", zap.String("host", req.URL.Host), zap.Error(attemptErr))

				// Mark H3 as unsupported for this host to skip overhead on future requests
				c.mu.Lock()
				c.h3Unsupported[req.URL.Host] = true
				c.mu.Unlock()

				// Clean up the failed H3 client
				c.closeClient(req.URL.Host, "h3")

				// Reset state for fallback
				attemptErr = nil
				resp = nil
				h3Attempted = false
			}
		}

		// 2. Try HTTP/2 (if H3 didn't succeed)
		useH2 := !h3Attempted && c.shouldAttemptH2(reqAttempt.URL)

		if useH2 {
			resp, attemptErr = c.executeH2(ctx, reqAttempt)
			if attemptErr != nil {
				// If H2 fails, determine if fallback to H1 is appropriate.
				isNegotiationFailure := strings.Contains(attemptErr.Error(), "did not negotiate HTTP/2") ||
					strings.Contains(attemptErr.Error(), "tls: no application protocol")

				if isNegotiationFailure {
					c.mu.Lock()
					c.h2Unsupported[req.URL.Host] = true
					c.mu.Unlock()

					c.Logger.Info("H2 negotiation failed, falling back to H1", zap.String("host", req.URL.Host), zap.Error(attemptErr))
					useH2 = false
					attemptErr = nil
				} else {
					// Other H2 errors (connection closed, stream error).
					c.closeClient(req.URL.Host, "h2")
				}
			}
		}

		// 3. Fallback or primary H1 execution
		if !h3Attempted && !useH2 {
			// Only execute H1 if H2/H3 didn't succeed.
			if resp == nil {
				resp, attemptErr = c.executeH1(ctx, reqAttempt)
				if attemptErr != nil {
					c.closeClient(req.URL.Host, "h1")
				}
			}
		}

		err = attemptErr // Update the overall error state

		// -- Check if we should retry --
		shouldRetry, retryAfter := c.shouldRetry(ctx, req, resp, err, policy, attempt)
		if !shouldRetry {
			break
		}

		attempt++
		retryCount := attempt
		c.Logger.Warn("Retrying request", zap.Int("attempt", retryCount), zap.Error(err), zap.String("url", req.URL.String()))

		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		backoff := retryAfter
		if backoff == 0 {
			backoff = calculateBackoff(policy, retryCount)
		}

		select {
		case <-time.After(backoff):
			continue
		case <-ctx.Done():
			if err != nil {
				return resp, err
			}
			if resp != nil {
				return resp, nil
			}
			return nil, ctx.Err()
		}
	}

	return resp, err
}

// shouldRetry determines if the request should be retried based on the response, error, and policy.
func (c *CustomClient) shouldRetry(ctx context.Context, req *http.Request, resp *http.Response, err error, policy *RetryPolicy, attempt int) (bool, time.Duration) {
	if attempt >= policy.MaxRetries {
		return false, 0
	}

	if ctx.Err() != nil {
		return false, 0
	}

	if err != nil {
		// Check for H2 REFUSED_STREAM
		var h2ResetErr H2StreamResetError
		if errors.As(err, &h2ResetErr) {
			if h2ResetErr.ErrCode == http2.ErrCodeRefusedStream {
				return true, 0
			}
			return false, 0
		}

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true, 0
		}
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Op == "dial" || opErr.Op == "read" || opErr.Op == "write" {
				return true, 0
			}
		}
		if err == io.EOF || strings.Contains(err.Error(), "unexpected EOF") ||
			strings.Contains(err.Error(), "connection closed unexpectedly") || strings.Contains(err.Error(), "connection closed") {
			return true, 0
		}
		return false, 0
	}

	isIdempotent := req.Method == http.MethodGet || req.Method == http.MethodHead ||
		req.Method == http.MethodOptions || req.Method == http.MethodTrace ||
		req.Method == http.MethodPut || req.Method == http.MethodDelete

	canRetryStatus := isIdempotent

	if canRetryStatus && policy.RetryableStatusCodes[resp.StatusCode] {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
					return true, time.Duration(seconds) * time.Second
				}
				if date, err := http.ParseTime(retryAfter); err == nil {
					duration := time.Until(date)
					if duration > 0 {
						return true, duration
					}
				}
			}
		}
		return true, 0
	}

	return false, 0
}

func calculateBackoff(policy *RetryPolicy, attemptNum int) time.Duration {
	backoff := float64(policy.InitialBackoff) * math.Pow(policy.BackoffFactor, float64(attemptNum-1))

	if backoff > float64(policy.MaxBackoff) || backoff <= 0 {
		if policy.MaxBackoff > 0 {
			backoff = float64(policy.MaxBackoff)
		} else {
			return policy.InitialBackoff
		}
	}

	duration := time.Duration(backoff)

	if policy.Jitter {
		if duration > 0 {
			jitterFactor := 0.5 + rand.Float64()*0.5
			duration = time.Duration(float64(duration) * jitterFactor)
		}
	}

	return duration
}

// -- Protocol Execution --

// shouldAttemptH3 determines if we should try HTTP/3.
func (c *CustomClient) shouldAttemptH3(targetURL *url.URL) bool {
	// H3Client requires HTTPS.
	if targetURL.Scheme != "https" {
		return false
	}
	// Check if the host is known not to support H3.
	c.mu.RLock()
	isUnsupported := c.h3Unsupported[targetURL.Host]
	c.mu.RUnlock()

	if isUnsupported {
		return false
	}
	return true
}

// shouldAttemptH2 determines the protocol preference for H2.
func (c *CustomClient) shouldAttemptH2(targetURL *url.URL) bool {
	if targetURL.Scheme != "https" {
		return false
	}
	c.mu.RLock()
	isUnsupported := c.h2Unsupported[targetURL.Host]
	c.mu.RUnlock()

	if isUnsupported {
		return false
	}
	return true
}

func (c *CustomClient) executeH1(ctx context.Context, req *http.Request) (*http.Response, error) {
	client, err := c.getH1Client(req.URL)
	if err != nil {
		return nil, err
	}
	return client.Do(ctx, req)
}

func (c *CustomClient) executeH2(ctx context.Context, req *http.Request) (*http.Response, error) {
	client, err := c.getH2Client(req.URL)
	if err != nil {
		return nil, err
	}
	return client.Do(ctx, req)
}

func (c *CustomClient) executeH3(ctx context.Context, req *http.Request) (*http.Response, error) {
	client, err := c.getH3Client(req.URL)
	if err != nil {
		return nil, err
	}
	return client.Do(ctx, req)
}

// -- Connection Management --

// getH1Client retrieves or creates a persistent H1Client.
func (c *CustomClient) getH1Client(targetURL *url.URL) (*H1Client, error) {
	c.mu.RLock()
	key := targetURL.Host
	client, exists := c.h1Clients[key]
	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if client, exists := c.h1Clients[key]; exists {
		return client, nil
	}

	var err error
	client, err = NewH1Client(targetURL, c.Config, c.Logger)
	if err != nil {
		return nil, err
	}
	c.h1Clients[key] = client
	return client, nil
}

// getH2Client retrieves or creates a persistent H2Client.
func (c *CustomClient) getH2Client(targetURL *url.URL) (*H2Client, error) {
	c.mu.RLock()
	key := targetURL.Host
	client, exists := c.h2Clients[key]
	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if client, exists := c.h2Clients[key]; exists {
		return client, nil
	}

	var err error
	client, err = NewH2Client(targetURL, c.Config, c.Logger)
	if err != nil {
		return nil, err
	}
	c.h2Clients[key] = client
	return client, nil
}

// getH3Client retrieves or creates a persistent H3Client.
func (c *CustomClient) getH3Client(targetURL *url.URL) (*H3Client, error) {
	c.mu.RLock()
	key := targetURL.Host
	client, exists := c.h3Clients[key]
	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if client, exists := c.h3Clients[key]; exists {
		return client, nil
	}

	var err error
	client, err = NewH3Client(targetURL, c.Config, c.Logger)
	if err != nil {
		return nil, err
	}
	c.h3Clients[key] = client
	return client, nil
}

// closeClient closes a specific client instance.
// proto should be "h1", "h2", or "h3".
func (c *CustomClient) closeClient(key string, proto string) {
	c.mu.Lock()
	var client ConnectionPool
	var exists bool

	switch proto {
	case "h3":
		client, exists = c.h3Clients[key]
		if exists {
			delete(c.h3Clients, key)
		}
	case "h2":
		client, exists = c.h2Clients[key]
		if exists {
			delete(c.h2Clients, key)
		}
	case "h1":
		client, exists = c.h1Clients[key]
		if exists {
			delete(c.h1Clients, key)
		}
	}
	c.mu.Unlock()

	if exists && client != nil {
		c.Logger.Debug("Closing client connection due to error/fallback", zap.String("host", key), zap.String("proto", proto))
		client.Close()
	}
}

// connectionEvictor runs in the background and periodically closes idle connections.
func (c *CustomClient) connectionEvictor() {
	defer c.evictorWG.Done()

	idleTimeout := c.Config.IdleConnTimeout
	if idleTimeout <= 0 {
		return // Eviction disabled.
	}

	checkInterval := idleTimeout / 2
	if checkInterval < 1*time.Second {
		checkInterval = 1 * time.Second
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closeChan:
			return
		case <-ticker.C:
			c.evictIdleConnections(idleTimeout)
		}
	}
}

// evictIdleConnections iterates over all clients and closes those that are idle.
func (c *CustomClient) evictIdleConnections(timeout time.Duration) {

	// 1. Collect all client references under RLock.
	c.mu.RLock()
	type clientRef struct {
		key    string
		client ConnectionPool
		proto  string
	}
	var allClients []clientRef
	for key, client := range c.h1Clients {
		if client != nil {
			allClients = append(allClients, clientRef{key, client, "h1"})
		}
	}
	for key, client := range c.h2Clients {
		if client != nil {
			allClients = append(allClients, clientRef{key, client, "h2"})
		}
	}
	for key, client := range c.h3Clients {
		if client != nil {
			allClients = append(allClients, clientRef{key, client, "h3"})
		}
	}
	c.mu.RUnlock()

	// 2. Check for idleness outside the global lock.
	var idleClients []clientRef
	for _, ref := range allClients {
		if ref.client.IsIdle(timeout) {
			idleClients = append(idleClients, ref)
		}
	}

	if len(idleClients) == 0 {
		return
	}

	// 3. Acquire Lock to remove idle clients.
	c.mu.Lock()
	var toClose []ConnectionPool
	for _, ref := range idleClients {
		var currentClient ConnectionPool
		var exists bool

		switch ref.proto {
		case "h3":
			currentClient, exists = c.h3Clients[ref.key]
		case "h2":
			currentClient, exists = c.h2Clients[ref.key]
		case "h1":
			currentClient, exists = c.h1Clients[ref.key]
		}

		if exists && currentClient == ref.client {
			switch ref.proto {
			case "h3":
				delete(c.h3Clients, ref.key)
			case "h2":
				delete(c.h2Clients, ref.key)
			case "h1":
				delete(c.h1Clients, ref.key)
			}
			toClose = append(toClose, ref.client)
		}
	}
	c.mu.Unlock()

	// 4. Close the connections outside the global lock.
	if len(toClose) > 0 {
		c.Logger.Debug("Evicting idle connections", zap.Int("count", len(toClose)))
		for _, client := range toClose {
			client.Close()
		}
	}
}

// CloseAll shuts down the client, closing all active and idle connections.
func (c *CustomClient) CloseAll() {
	select {
	case <-c.closeChan:
	default:
		close(c.closeChan)
	}
	c.evictorWG.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, client := range c.h1Clients {
		client.Close()
		delete(c.h1Clients, key)
	}
	for key, client := range c.h2Clients {
		client.Close()
		delete(c.h2Clients, key)
	}
	for key, client := range c.h3Clients {
		client.Close()
		delete(c.h3Clients, key)
	}
}

// -- Cookie Handling --

func (c *CustomClient) addCookies(req *http.Request) {
	if c.Config.CookieJar != nil {
		cookies := c.Config.CookieJar.Cookies(req.URL)
		if len(cookies) > 0 {
			existingCookies := req.Header.Get("Cookie")
			var cookiePairs []string
			if existingCookies != "" {
				cookiePairs = append(cookiePairs, existingCookies)
			}
			for _, cookie := range cookies {
				cookiePairs = append(cookiePairs, cookie.Name+"="+cookie.Value)
			}
			req.Header.Set("Cookie", strings.Join(cookiePairs, "; "))
		}
	}
}

func (c *CustomClient) storeCookies(u *url.URL, resp *http.Response) {
	if c.Config.CookieJar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			c.Config.CookieJar.SetCookies(u, cookies)
		}
	}
}

// -- Authentication Handling --

func (c *CustomClient) handleAuthentication(ctx context.Context, req *http.Request, resp *http.Response) (bool, *http.Request, error) {
	isProxy := resp.StatusCode == http.StatusProxyAuthRequired
	headerKey := "WWW-Authenticate"
	authHeaderKey := "Authorization"
	if isProxy {
		headerKey = "Proxy-Authenticate"
		authHeaderKey = "Proxy-Authorization"
	}

	challenges := resp.Header.Values(headerKey)
	if len(challenges) == 0 {
		return false, nil, nil
	}

	var basicRealm string
	for _, challenge := range challenges {
		if strings.HasPrefix(strings.ToLower(challenge), "basic") {
			parts := strings.SplitN(challenge, "realm=", 2)
			if len(parts) == 2 {
				realm := strings.Trim(parts[1], `" `)
				if idx := strings.Index(realm, ","); idx != -1 {
					realm = strings.Trim(realm[:idx], `" `)
				}
				basicRealm = realm
				break
			}
		}
	}

	if basicRealm == "" {
		c.Logger.Debug("No supported authentication scheme found", zap.Strings("challenges", challenges))
		return false, nil, nil
	}

	host := req.URL.Host
	if isProxy && c.Config.DialerConfig != nil && c.Config.DialerConfig.ProxyURL != nil {
		host = c.Config.DialerConfig.ProxyURL.Host
	}

	username, password, err := c.Config.CredentialsProvider.GetCredentials(host, basicRealm)
	if err != nil {
		if err == ErrCredentialsNotFound {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	auth := username + ":" + password
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	nextReq := req.Clone(ctx)
	nextReq.Header.Set(authHeaderKey, basicAuth)
	return true, nextReq, nil
}

// -- Redirect Handling --

func isRedirect(statusCode int) bool {
	switch statusCode {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func (c *CustomClient) handleRedirect(ctx context.Context, req *http.Request, resp *http.Response, redirectCount int, via []*http.Request) (*http.Response, error) {

	currentVia := append(via, req)
	location := resp.Header.Get("Location")

	if location == "" {
		return resp, fmt.Errorf("redirect response missing Location header (Status %d)", resp.StatusCode)
	}

	nextURL, err := req.URL.Parse(location)
	if err != nil {
		return resp, fmt.Errorf("invalid redirect Location '%s': %w", location, err)
	}

	nextReq, err := c.prepareNextRequest(ctx, req, nextURL, resp.StatusCode)
	if err != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, err
	}

	if c.Config.CheckRedirect != nil {
		if err := c.Config.CheckRedirect(nextReq, currentVia); err != nil {
			if err == http.ErrUseLastResponse {
				return resp, nil
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, err
		}
	}

	if redirectCount >= c.MaxRedirects {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("maximum redirects (%d) followed", c.MaxRedirects)
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return c.doInternal(ctx, nextReq, redirectCount+1, currentVia, false)
}

func isSameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	p1 := u1.Port()
	if p1 == "" {
		switch u1.Scheme {
		case "https":
			p1 = "443"
		case "http":
			p1 = "80"
		}
	}
	p2 := u2.Port()
	if p2 == "" {
		switch u2.Scheme {
		case "https":
			p2 = "443"
		case "http":
			p2 = "80"
		}
	}

	return u1.Scheme == u2.Scheme && u1.Hostname() == u2.Hostname() && p1 == p2
}

func (c *CustomClient) prepareNextRequest(ctx context.Context, originalReq *http.Request, nextURL *url.URL, statusCode int) (*http.Request, error) {
	method := originalReq.Method
	var getBody func() (io.ReadCloser, error)
	contentLength := originalReq.ContentLength

	switch statusCode {
	case http.StatusSeeOther: // 303
		if method != http.MethodHead {
			method = http.MethodGet
		}
		getBody = nil
		contentLength = 0
	case http.StatusFound, http.StatusMovedPermanently: // 302, 301
		if method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
			getBody = nil
			contentLength = 0
		}
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect: // 307, 308
		if originalReq.GetBody != nil {
			getBody = originalReq.GetBody
		} else if originalReq.Body != nil && originalReq.ContentLength != 0 {
			return nil, fmt.Errorf("cannot follow 307/308 redirect with non-replayable body for method %s", method)
		}
	}

	nextReq, err := http.NewRequestWithContext(ctx, method, nextURL.String(), nil)
	if err != nil {
		return nil, err
	}
	nextReq.ContentLength = contentLength
	nextReq.GetBody = getBody
	nextReq.Host = nextURL.Host

	crossOrigin := !isSameOrigin(originalReq.URL, nextURL)

	for k, vv := range originalReq.Header {
		kLower := strings.ToLower(k)
		if kLower == "host" || kLower == "content-length" || kLower == "cookie" {
			continue
		}
		if kLower == "content-type" && (method == http.MethodGet && getBody == nil) {
			continue
		}
		if crossOrigin && (kLower == "authorization" || kLower == "proxy-authorization") {
			continue
		}
		nextReq.Header[k] = vv
	}

	if !(originalReq.URL.Scheme == "https" && nextURL.Scheme == "http") {
		refererURL := *originalReq.URL
		refererURL.User = nil
		refererURL.Fragment = ""
		nextReq.Header.Set("Referer", refererURL.String())
	}

	return nextReq, nil
}

func ensureBodyReplayable(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody != nil {
		return nil
	}

	if MaxReplayableBodyBytes > 0 && req.ContentLength > MaxReplayableBodyBytes {
		return fmt.Errorf("request body too large (%d bytes) to make replayable (limit %d bytes)", req.ContentLength, MaxReplayableBodyBytes)
	}

	var limitedReader io.Reader = req.Body
	if MaxReplayableBodyBytes > 0 {
		limitedReader = io.LimitReader(req.Body, MaxReplayableBodyBytes+1)
	}

	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}
	req.Body.Close()

	if MaxReplayableBodyBytes > 0 && int64(len(bodyBytes)) > MaxReplayableBodyBytes {
		return fmt.Errorf("request body exceeded limit (%d bytes) while trying to make replayable", MaxReplayableBodyBytes)
	}

	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	req.ContentLength = int64(len(bodyBytes))
	return nil
}
