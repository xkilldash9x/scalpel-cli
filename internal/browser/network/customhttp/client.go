package customhttp

import (
	"bytes"
	"context"
	"encoding/base64"
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

	"github.com/xkilldash9x/scalpel-cli/internal/observability" // Added import
	"go.uber.org/zap"
)

// ConnectionPool defines a minimal interface for a connection pool, used by the
// CustomClient's connection evictor to manage and close idle connections.
type ConnectionPool interface {
	// Close immediately closes all connections in the pool.
	Close() error
	// IsIdle returns true if the pool has been idle for at least the specified duration.
	IsIdle(timeout time.Duration) bool
}

// CustomClient is a sophisticated, low level HTTP client designed for fine grained
// control over HTTP/1.1 and HTTP/2 connections. It is the core of the browser's
// networking stack, managing persistent connections on a per-host basis and handling
// the full request lifecycle, including cookies, redirects, retries, and authentication.
//
// It maintains separate pools of `H1Client` and `H2Client` instances, allowing it
// to transparently handle different protocol versions. A background goroutine
// periodically evicts idle connections to conserve resources.
type CustomClient struct {
	Config *ClientConfig
	Logger *zap.Logger

	// mu protects the client maps (h1Clients, h2Clients).
	// Changed from sync.Mutex to sync.RWMutex to allow concurrent reads (e.g., getting connection count)
	// and optimize connection lookup.
	mu        sync.RWMutex
	h1Clients map[string]*H1Client // key: "host:port"
	h2Clients map[string]*H2Client // key: "host:port"

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
		Config:       config,
		Logger:       logger.Named("customhttp_client"),
		h1Clients:    make(map[string]*H1Client),
		h2Clients:    make(map[string]*H2Client),
		MaxRedirects: 10, // Default maximum redirects
		closeChan:    make(chan struct{}),
	}

	// Start the background connection evictor.
	client.evictorWG.Add(1)
	go client.connectionEvictor()

	return client
}

// ConnectionCount returns the total number of active connections (H1 + H2).
// This method is thread-safe and primarily intended for testing purposes.
func (c *CustomClient) ConnectionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.h1Clients) + len(c.h2Clients)
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
		// This prevents new requests from being initiated if the context has been cancelled
		// during the backoff period of the previous attempt, or if the loop is spinning.
		select {
		case <-ctx.Done():
			// Return the last known error, or the context error if none exists.
			if err != nil {
				return resp, err
			}
			return nil, ctx.Err()
		default:
		}

		// CRITICAL FIX: Clear the response from the previous attempt if this is a retry.
		// If the previous attempt returned a retryable status code (e.g., 503), 'resp' is non-nil.
		// The execution logic (like H1 fallback check `if resp == nil`) requires resp to be nil
		// to correctly execute the request again.
		if attempt > 0 {
			resp = nil
		}

		// Clone the request context for this attempt.
		reqAttempt := req.Clone(ctx)

		// If the body exists, we must ensure it's reset using GetBody before each attempt.
		// GetBody is guaranteed to be set by ensureBodyReplayable in Do().
		if req.Body != nil && req.GetBody != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, fmt.Errorf("failed to reset request body for attempt %d: %w", attempt+1, bodyErr)
			}
			reqAttempt.Body = body
		}

		// -- Execute the request (single attempt) --
		useH2 := c.shouldAttemptH2(reqAttempt.URL)
		attemptErr := error(nil)

		if useH2 {
			resp, attemptErr = c.executeH2(ctx, reqAttempt)
			if attemptErr != nil {
				// If H2 fails, determine if fallback to H1 is appropriate for this attempt.

				// Check for ALPN negotiation failures both during the TLS handshake (e.g. "tls: no application protocol")
				// and after the handshake if the server didn't select "h2" (e.g. "did not negotiate HTTP/2").
				isNegotiationFailure := strings.Contains(attemptErr.Error(), "did not negotiate HTTP/2") ||
					strings.Contains(attemptErr.Error(), "tls: no application protocol")

				if isNegotiationFailure {
					c.Logger.Info("H2 negotiation failed, falling back to H1", zap.String("url", req.URL.String()), zap.Error(attemptErr))
					useH2 = false
					// Crucial: Clear the attempt error. We successfully detected the need to fallback,
					// so this attempt shouldn't count as a failure unless the H1 execution also fails.
					attemptErr = nil
					// No need to explicitly close H2 client as connection failed.
				} else {
					// Other H2 errors (connection closed, stream error).
					// Close the specific client instance to force reconnection on the next attempt if retried.
					c.closeClient(req.URL.Host, true)
				}
			}
		}

		// Fallback or primary H1 execution
		if !useH2 {
			// Only execute H1 if H2 was not attempted or if H2 failed negotiation (and didn't already succeed).
			// We check if resp is nil to ensure we don't overwrite a potential response from a failed H2 attempt (e.g. protocol error response).
			if resp == nil {
				resp, attemptErr = c.executeH1(ctx, reqAttempt)
				if attemptErr != nil {
					// Close the H1 client instance on error to force reconnection.
					c.closeClient(req.URL.Host, false)
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
		retryCount := attempt // 1-based count of the upcoming retry
		c.Logger.Warn("Retrying request", zap.Int("attempt", retryCount), zap.Error(err), zap.String("url", req.URL.String()))

		// If retrying, consume and close the response body (if present).
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		// Calculate backoff duration.
		backoff := retryAfter
		if backoff == 0 {
			// Pass the 1-based retry count to calculateBackoff.
			backoff = calculateBackoff(policy, retryCount)
		}

		// Wait for backoff or context cancellation.
		select {
		case <-time.After(backoff):
			continue
		case <-ctx.Done():
			// Return the last response/error if available, otherwise context error.
			if err != nil {
				return resp, err
			}
			// If we have a response but context was cancelled during backoff, return the response.
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
	// attempt is the 0-based index of the attempt that just completed.
	if attempt >= policy.MaxRetries {
		return false, 0
	}

	// 1. Check context cancellation.
	if ctx.Err() != nil {
		return false, 0
	}

	// 2. Check network errors and connection issues.
	if err != nil {
		// Retry transient network errors (timeouts).
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true, 0
		}
		// Retry connection errors (refused, reset by peer).
		if opErr, ok := err.(*net.OpError); ok {
			// Common transient errors during dial, read, or write.
			if opErr.Op == "dial" || opErr.Op == "read" || opErr.Op == "write" {
				return true, 0
			}
		}
		// Specific errors indicating connection closure (EOF, "connection closed"). Often happens with keep-alive race conditions.
		if err == io.EOF || strings.Contains(err.Error(), "unexpected EOF") ||
			strings.Contains(err.Error(), "connection closed unexpectedly") || strings.Contains(err.Error(), "connection closed") {
			return true, 0
		}

		// Do not retry non-transient errors (e.g., TLS handshake failures, invalid request serialization, definitive protocol errors).
		return false, 0
	}

	// 3. Check HTTP status codes
	isIdempotent := req.Method == http.MethodGet || req.Method == http.MethodHead ||
		req.Method == http.MethodOptions || req.Method == http.MethodTrace ||
		req.Method == http.MethodPut || req.Method == http.MethodDelete

	// Allow retry on status code if method is idempotent
	// OR if it's not (like POST) but has a replayable body.
	canRetryStatus := isIdempotent
	if !canRetryStatus && req.GetBody != nil {
		canRetryStatus = true
	}

	if canRetryStatus && policy.RetryableStatusCodes[resp.StatusCode] {
		// Handle 429 Too Many Requests or 503 Service Unavailable with Retry-After header.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
				// Attempt to parse as seconds.
				if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
					return true, time.Duration(seconds) * time.Second
				}
				// Attempt to parse as HTTP-date (RFC 7231 Section 7.1.3).
				if date, err := http.ParseTime(retryAfter); err == nil {
					duration := time.Until(date)
					if duration > 0 {
						return true, duration
					}
				}
			}
		}
		// Retry if status code matches policy and no specific Retry-After guidance prevents it.
		return true, 0
	}

	return false, 0
}

// calculateBackoff determines the backoff duration based on the policy and attempt number.
// attemptNum is the 1-based index of the upcoming retry attempt.
func calculateBackoff(policy *RetryPolicy, attemptNum int) time.Duration {
	// Exponential backoff: initial * (factor ^ (attemptNum-1))
	backoff := float64(policy.InitialBackoff) * math.Pow(policy.BackoffFactor, float64(attemptNum-1))

	if backoff > float64(policy.MaxBackoff) || backoff <= 0 {
		// Handle overflow or zero/negative max backoff.
		if policy.MaxBackoff > 0 {
			backoff = float64(policy.MaxBackoff)
		} else {
			// Fallback if MaxBackoff is invalid, though default policy validation prevents this.
			return policy.InitialBackoff
		}
	}

	duration := time.Duration(backoff)

	// Apply jitter (randomize between duration/2 and duration).
	if policy.Jitter {
		// Ensure duration is positive before calculating jitter.
		if duration > 0 {
			// Generate a random float between 0.5 and 1.0
			// Note: Ensure rand is seeded (e.g., in main() using rand.Seed(time.Now().UnixNano()) if Go < 1.20)
			jitterFactor := 0.5 + rand.Float64()*0.5
			duration = time.Duration(float64(duration) * jitterFactor)
		}
	}

	return duration
}

// -- Protocol Execution --

// shouldAttemptH2 determines the protocol preference.
func (c *CustomClient) shouldAttemptH2(targetURL *url.URL) bool {
	// H2Client currently requires HTTPS.
	if targetURL.Scheme != "https" {
		return false
	}
	// TODO: Implement protocol prediction or caching based on previous successful connections (e.g., Alt-Svc).
	// For now, default behavior: always attempt H2 for HTTPS.
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

// -- Connection Management --

// getH1Client retrieves or creates a persistent H1Client.
func (c *CustomClient) getH1Client(targetURL *url.URL) (*H1Client, error) {
	// Optimization: Use RLock for lookup first.
	c.mu.RLock()
	key := targetURL.Host
	client, exists := c.h1Clients[key]
	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	// If not found, acquire Write Lock to create and insert.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check existence after acquiring Write Lock, as another goroutine might have created it.
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
	// Optimization: Use RLock for lookup first.
	c.mu.RLock()
	key := targetURL.Host
	client, exists := c.h2Clients[key]
	c.mu.RUnlock()

	if exists {
		return client, nil
	}

	// If not found, acquire Write Lock to create and insert.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check existence after acquiring Write Lock.
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

// closeClient closes a specific client instance (used during error handling/retries).
func (c *CustomClient) closeClient(key string, isH2 bool) {
	c.mu.Lock()
	var client ConnectionPool
	var exists bool

	if isH2 {
		client, exists = c.h2Clients[key]
		if exists {
			delete(c.h2Clients, key)
		}
	} else {
		client, exists = c.h1Clients[key]
		if exists {
			delete(c.h1Clients, key)
		}
	}
	c.mu.Unlock()

	if exists && client != nil {
		c.Logger.Debug("Closing client connection due to error/fallback", zap.String("host", key), zap.Bool("isH2", isH2))
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

	// Check interval (e.g., half the idle timeout, but not excessively frequent).
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
	c.mu.Lock()
	// Identify idle clients while holding the lock and remove them from the map.
	var toClose []ConnectionPool

	for key, client := range c.h1Clients {
		// IsIdle acquires its own internal lock to check the state safely.
		if client.IsIdle(timeout) {
			toClose = append(toClose, client)
			delete(c.h1Clients, key)
		}
	}

	for key, client := range c.h2Clients {
		if client.IsIdle(timeout) {
			toClose = append(toClose, client)
			delete(c.h2Clients, key)
		}
	}
	c.mu.Unlock()

	// Close the connections outside the main lock to allow other operations to proceed.
	if len(toClose) > 0 {
		c.Logger.Debug("Evicting idle connections", zap.Int("count", len(toClose)))
		for _, client := range toClose {
			client.Close()
		}
	}
}

// CloseAll shuts down the client, closing all active and idle connections and
// stopping the background connection evictor goroutine. It waits for the evictor
// to terminate cleanly before returning.
func (c *CustomClient) CloseAll() {
	// Stop the evictor first.
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
}

// -- Cookie Handling --

func (c *CustomClient) addCookies(req *http.Request) {
	if c.Config.CookieJar != nil {
		cookies := c.Config.CookieJar.Cookies(req.URL)
		// Add cookies manually to ensure they are serialized correctly, especially for H2 compatibility.
		if len(cookies) > 0 {
			// If the Cookie header is already set (e.g., manually by the user), we append to it.
			existingCookies := req.Header.Get("Cookie")
			var cookiePairs []string
			if existingCookies != "" {
				cookiePairs = append(cookiePairs, existingCookies)
			}
			for _, cookie := range cookies {
				// Basic validation/sanitization of cookie value might be needed here.
				cookiePairs = append(cookiePairs, cookie.Name+"="+cookie.Value)
			}
			// RFC 6265 Section 5.4: Cookies are concatenated with "; ".
			req.Header.Set("Cookie", strings.Join(cookiePairs, "; "))
		}
	}
}

func (c *CustomClient) storeCookies(u *url.URL, resp *http.Response) {
	if c.Config.CookieJar != nil {
		// resp.Cookies() parses the Set-Cookie headers.
		if cookies := resp.Cookies(); len(cookies) > 0 {
			c.Config.CookieJar.SetCookies(u, cookies)
		}
	}
}

// -- Authentication Handling --

// handleAuthentication processes a 401 Unauthorized or 407 Proxy Auth Required response and attempts to retrieve credentials.
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

	// Parse the challenges (simplified parsing focusing on the first Basic auth challenge found).
	// A robust implementation must handle multiple challenges, scheme prioritization (e.g., Digest over Basic), and parameter parsing.
	var basicRealm string
	for _, challenge := range challenges {
		if strings.HasPrefix(strings.ToLower(challenge), "basic") {
			// Simplified extraction of the realm parameter.
			parts := strings.SplitN(challenge, "realm=", 2)
			if len(parts) == 2 {
				realm := strings.Trim(parts[1], `" `)
				// Handle potential trailing attributes (e.g., charset="UTF-8").
				if idx := strings.Index(realm, ","); idx != -1 {
					realm = strings.Trim(realm[:idx], `" `)
				}
				basicRealm = realm
				break
			}
		}
	}

	if basicRealm == "" {
		// No supported authentication scheme found.
		c.Logger.Debug("No supported authentication scheme found", zap.Strings("challenges", challenges))
		return false, nil, nil
	}

	// Get credentials using the provider callback.
	host := req.URL.Host
	// Ensure DialerConfig exists before accessing ProxyURL
	if isProxy && c.Config.DialerConfig != nil && c.Config.DialerConfig.ProxyURL != nil {
		host = c.Config.DialerConfig.ProxyURL.Host
	}

	username, password, err := c.Config.CredentialsProvider.GetCredentials(host, basicRealm)
	if err != nil {
		if err == ErrCredentialsNotFound {
			// Credentials unavailable, cannot handle auth.
			return false, nil, nil
		}
		// Error occurred during credential retrieval.
		return false, nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Create the Authorization header (Basic Auth).
	auth := username + ":" + password
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	// Clone the request and add the header.
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

	// Update the request history
	currentVia := append(via, req)
	location := resp.Header.Get("Location")

	if location == "" {
		return resp, fmt.Errorf("redirect response missing Location header (Status %d)", resp.StatusCode)
	}

	nextURL, err := req.URL.Parse(location)
	if err != nil {
		return resp, fmt.Errorf("invalid redirect Location '%s': %w", location, err)
	}

	// Prepare the next request based on RFC rules before checking the policy.
	nextReq, err := c.prepareNextRequest(ctx, req, nextURL, resp.StatusCode)
	if err != nil {
		// Error preparing the request (e.g., non-replayable body for 307/308).
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, err
	}

	// Check custom redirect policy if defined.
	if c.Config.CheckRedirect != nil {
		if err := c.Config.CheckRedirect(nextReq, currentVia); err != nil {
			if err == http.ErrUseLastResponse {
				// Policy requests using the current response.
				return resp, nil
			}
			// Policy denied the redirect. Close body and return error.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil, err
		}
	}

	// Check maximum redirects (default policy check if CheckRedirect is nil or allows it).
	if redirectCount >= c.MaxRedirects {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("maximum redirects (%d) followed", c.MaxRedirects)
	}

	// Consume and close the body of the redirect response before proceeding.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Recurse into doInternal. Reset authAttempted=false for the new request/location.
	return c.doInternal(ctx, nextReq, redirectCount+1, currentVia, false)
}

// prepareNextRequest constructs the subsequent request, handling method changes and body replayability robustly.
func (c *CustomClient) prepareNextRequest(ctx context.Context, originalReq *http.Request, nextURL *url.URL, statusCode int) (*http.Request, error) {
	method := originalReq.Method
	var getBody func() (io.ReadCloser, error)
	contentLength := originalReq.ContentLength

	// Handle method changes and body preservation (RFC 7231/7538)
	switch statusCode {
	case http.StatusSeeOther: // 303
		// Always change to GET (or HEAD). Body is discarded.
		if method != http.MethodHead {
			method = http.MethodGet
		}
		getBody = nil
		contentLength = 0
	case http.StatusFound, http.StatusMovedPermanently: // 302, 301
		// Historical browser behavior (and common practice): change POST/PUT/DELETE to GET.
		if method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
			getBody = nil
			contentLength = 0
		}
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect: // 307, 308
		// Must preserve the method. Check if the body is replayable.
		// ensureBodyReplayable (called in Do) ensures GetBody is available if Body existed.
		if originalReq.GetBody != nil {
			getBody = originalReq.GetBody
		} else if originalReq.Body != nil && originalReq.ContentLength != 0 {
			// This case should ideally not happen if ensureBodyReplayable was called correctly.
			return nil, fmt.Errorf("cannot follow 307/308 redirect with non-replayable body for method %s", method)
		}
		// If body is nil or empty, GetBody might be nil, which is fine.
	}

	// Create the new request. The actual body reader will be instantiated from GetBody during execution.
	nextReq, err := http.NewRequestWithContext(ctx, method, nextURL.String(), nil)
	if err != nil {
		return nil, err
	}
	nextReq.ContentLength = contentLength
	nextReq.GetBody = getBody
	nextReq.Host = nextURL.Host

	// Copy headers, skipping those that should be reset or managed elsewhere.
	for k, vv := range originalReq.Header {
		kLower := strings.ToLower(k)
		// Host, Content-Length are handled above. Cookie is handled by addCookies in doInternal.
		if kLower == "host" || kLower == "content-length" || kLower == "cookie" {
			continue
		}
		// Content-Type should be preserved if the body is preserved.
		if kLower == "content-type" && (method == http.MethodGet && getBody == nil) {
			continue
		}
		// Authorization headers are removed. They will be re-added by handleAuthentication if needed on the new origin.
		if kLower == "authorization" || kLower == "proxy-authorization" {
			continue
		}

		// Preserve other headers (User-Agent, Accept, etc.)
		nextReq.Header[k] = vv
	}

	// Add Referer header (RFC 7231 Section 5.5.2).
	// Policy: Don't send Referer if moving from HTTPS to HTTP.
	if !(originalReq.URL.Scheme == "https" && nextURL.Scheme == "http") {
		refererURL := *originalReq.URL
		refererURL.User = nil    // Ensure userinfo (credentials) is stripped from Referer.
		refererURL.Fragment = "" // Fragments are not sent in Referer.
		nextReq.Header.Set("Referer", refererURL.String())
	}

	return nextReq, nil
}

// ensureBodyReplayable ensures that the request body can be read multiple times (for retries/redirects).
func ensureBodyReplayable(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody != nil {
		// Body is already replayable.
		return nil
	}

	// Body is not replayable (e.g., a one-time reader like a stream). We must read it entirely into memory.
	// WARNING: This can consume significant memory for large uploads. A production client might use disk buffering or limit upload size.
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body.Close()

	// Replace the body with an in-memory reader and set GetBody.
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	// Update ContentLength if it was not set or was incorrect (e.g., -1 for chunked).
	req.ContentLength = int64(len(bodyBytes))
	return nil
}
