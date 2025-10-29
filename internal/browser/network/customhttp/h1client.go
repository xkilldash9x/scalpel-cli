// internal/browser/network/customhttp/h1client.go
package customhttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"go.uber.org/zap"
)

// H1Client manages a single, persistent HTTP/1.1 connection.
// It supports sequential requests (Keep-Alive) and manual pipelining.
type H1Client struct {
	Conn        net.Conn
	Config      *ClientConfig
	TargetURL   *url.URL
	Address     string
	Logger      *zap.Logger
	parser      *network.HTTPParser
	bufReader   *bufio.Reader
	mu          sync.Mutex // Protects connection state (isConnected), ensures sequential writes/reads, and protects lastUsed.
	isConnected bool
	lastUsed    time.Time // Tracks the last time the connection completed an operation.
}

// NewH1Client creates a new H1Client. Connection is established lazily.
func NewH1Client(targetURL *url.URL, config *ClientConfig, logger *zap.Logger) (*H1Client, error) {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	address, err := determineAddress(targetURL)
	if err != nil {
		return nil, err
	}

	return &H1Client{
		Config:    config,
		TargetURL: targetURL,
		Address:   address,
		Logger:    logger.Named("h1client").With(zap.String("host", targetURL.Host)),
		parser:    network.NewHTTPParser(logger),
		lastUsed:  time.Now(), // Initialize lastUsed upon creation
	}, nil
}

// Connect establishes the TCP/TLS connection, forcing HTTP/1.1 negotiation if applicable.
func (c *H1Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return nil
	}

	// Clone the dialer config to modify it safely.
	dialerConfig := c.Config.DialerConfig.Clone()
	// Ensure NoDelay is set for responsiveness, crucial for H1.
	dialerConfig.NoDelay = true

	// Configure TLS based on the scheme
	if c.TargetURL.Scheme == "https" {
		if dialerConfig.TLSConfig == nil {
			dialerConfig.TLSConfig = network.NewDialerConfig().TLSConfig.Clone()
		}
		dialerConfig.TLSConfig.InsecureSkipVerify = c.Config.InsecureSkipVerify

		// CRITICAL: Force HTTP/1.1 via ALPN.
		// We explicitly ensure "http/1.1" is prioritized and "h2" is excluded for this client.
		dialerConfig.TLSConfig.NextProtos = []string{"http/1.1"}

	} else {
		// If scheme is http, ensure TLSConfig is nil for the final connection.
		// The network.DialContext handles the complexity: if an HTTPS proxy is used (configured in DialerConfig),
		// it establishes the tunnel (potentially over TLS) and then returns the raw connection for HTTP traffic.
		dialerConfig.TLSConfig = nil
	}

	// Use the robust network dialer (handles TCP, Proxy Tunneling, and TLS upgrade if configured).
	conn, err := network.DialContext(ctx, "tcp", c.Address, dialerConfig)
	if err != nil {
		return fmt.Errorf("failed to dial target: %w", err)
	}

	c.Conn = conn
	c.bufReader = bufio.NewReader(conn)
	c.isConnected = true
	c.lastUsed = time.Now() // Update lastUsed upon successful connection
	c.Logger.Debug("H1 connection established")
	return nil
}

// Close closes the underlying connection.
func (c *H1Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeInternal()
}

// closeInternal handles the connection closure logic without acquiring the lock.
func (c *H1Client) closeInternal() error {
	if c.isConnected && c.Conn != nil {
		c.Logger.Debug("Closing H1 connection")
		c.isConnected = false
		return c.Conn.Close()
	}
	return nil
}

// IsIdle checks if the connection is idle based on the configured timeout.
// Used by the connection evictor (implements ConnectionPool interface).
func (c *H1Client) IsIdle(timeout time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// If not connected (or already closed by previous error/eviction), it's effectively idle for removal purposes.
	if !c.isConnected {
		return true
	}
	// In H1, we rely on the time since the last completed operation. If the client is currently locked
	// (processing a request), it is technically not idle, but the eviction logic in CustomClient
	// runs independently. If the time exceeds the timeout, we consider it idle.
	return time.Since(c.lastUsed) > timeout
}

// Do sends a single HTTP/1.1 request and reads the response.
// It ensures sequential access to the connection (HTTP Keep-Alive behavior).
func (c *H1Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	// Lock the connection for the entire request/response cycle to ensure atomicity and sequential access.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update lastUsed at the start of the operation.
	c.lastUsed = time.Now()

	if !c.isConnected {
		// If connection was closed between Connect() and acquiring the lock (e.g., by server sending "Connection: close" on previous response,
		// or closed by the connection evictor just before we acquired the lock).
		// We rely on the CustomClient's retry logic to handle reconnection.
		return nil, fmt.Errorf("connection closed unexpectedly (likely due to server closure or idle eviction)")
	}

	// Apply timeout for the entire cycle.
	deadline := time.Now().Add(c.Config.RequestTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := c.Conn.SetDeadline(deadline); err != nil {
		// If setting the deadline fails, the connection is likely broken.
		c.closeInternal()
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Serialize request
	reqBytes, err := SerializeRequest(req)
	if err != nil {
		// Serialization errors are non-transient.
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Send request
	if _, err := c.Conn.Write(reqBytes); err != nil {
		c.closeInternal() // Connection is likely broken
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read response
	// The parser reads sequentially from the bufReader associated with the connection.
	responses, err := c.parser.ParsePipelinedResponses(c.bufReader, 1)
	if err != nil {
		c.closeInternal() // Connection state is uncertain after parse failure
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(responses) == 0 {
		c.closeInternal()
		return nil, fmt.Errorf("no response received (connection closed by server)")
	}

	resp := responses[0]
	// Check if the server requested the connection to be closed (resp.Close is set by the parser).
	if resp.Close {
		c.closeInternal()
	}

	// Update lastUsed after successful completion.
	c.lastUsed = time.Now()

	return resp, nil
}

// SendRaw sends raw bytes over the connection. Useful for manual pipelining or specific testing strategies.
// The caller must ensure appropriate synchronization if sending multiple chunks sequentially.
func (c *H1Client) SendRaw(ctx context.Context, data []byte) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastUsed = time.Now()

	if !c.isConnected {
		return fmt.Errorf("connection closed before raw write")
	}

	// Set write deadline
	writeDeadline := time.Now().Add(c.Config.RequestTimeout)
	if err := c.Conn.SetWriteDeadline(writeDeadline); err != nil {
		c.closeInternal()
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := c.Conn.Write(data); err != nil {
		c.closeInternal()
		return fmt.Errorf("failed to write raw data: %w", err)
	}
	// Update lastUsed after successful write.
	c.lastUsed = time.Now()
	return nil
}

// ReadPipelinedResponses reads a specified number of responses from the connection.
// This should be called after manually sending pipelined requests using SendRaw.
func (c *H1Client) ReadPipelinedResponses(ctx context.Context, expectedCount int) ([]*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastUsed = time.Now()

	if !c.isConnected {
		return nil, fmt.Errorf("not connected")
	}

	// Set read deadline for the entire operation
	readDeadline := time.Now().Add(c.Config.RequestTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(readDeadline) {
		readDeadline = ctxDeadline
	}
	if err := c.Conn.SetReadDeadline(readDeadline); err != nil {
		c.closeInternal()
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// The parser reads sequentially from the connection's bufReader.
	responses, err := c.parser.ParsePipelinedResponses(c.bufReader, expectedCount)

	if err != nil {
		// If parsing fails, the connection state is unreliable.
		c.closeInternal()
		return responses, fmt.Errorf("failed to parse pipelined responses: %w", err)
	}

	// Check if the last response indicated connection closure
	if len(responses) > 0 && responses[len(responses)-1].Close {
		c.closeInternal()
	}

	c.lastUsed = time.Now()
	return responses, nil
}

// SerializeRequest converts an *http.Request into its raw HTTP/1.1 wire format.
func SerializeRequest(req *http.Request) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	if req.URL == nil {
		return nil, fmt.Errorf("request URL is nil")
	}

	// Create a clone of the request to modify headers safely without affecting the original request object,
	// which is crucial for retries and redirects managed by CustomClient.
	reqClone := req.Clone(req.Context())

	if reqClone.Host == "" {
		reqClone.Host = reqClone.URL.Host
	}

	// Handle body and Content-Length.
	// CustomClient ensures that GetBody is available if the body exists.
	var bodyBytes []byte
	if reqClone.Body != nil {
		if reqClone.GetBody != nil {
			var err error
			// Get a fresh reader for serialization.
			reqClone.Body, err = reqClone.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to get request body: %w", err)
			}
		}

		var err error
		// Read the body to determine length and prepare for serialization by http.Request.Write.
		bodyBytes, err = io.ReadAll(reqClone.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		reqClone.Body.Close()
		// Restore the body in the cloned request object so http.Request.Write can read it.
		reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		reqClone.ContentLength = int64(len(bodyBytes))
	}

	// Header modifications specific to H1 serialization.
	if reqClone.Header == nil {
		reqClone.Header = make(http.Header)
	}

	// CRITICAL: Explicitly handle 'Expect: 100-continue'.
	// When manually serializing and sending, we typically don't want the complexity of handling intermediate '100 Continue' responses.
	if strings.EqualFold(reqClone.Header.Get("Expect"), "100-continue") {
		reqClone.Header.Del("Expect")
	}

	// Ensure Connection header is set appropriately for Keep-Alive.
	// If the user hasn't specified "close", default to "keep-alive".
	if reqClone.Header.Get("Connection") == "" {
		reqClone.Header.Set("Connection", "keep-alive")
	}

	// Serialize the request using a buffer.
	buf := new(bytes.Buffer)
	// http.Request.Write handles the serialization of the start line, headers, and body according to HTTP/1.1 spec.
	if err := reqClone.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to serialize request using http.Request.Write: %w", err)
	}

	if buf.Len() == 0 {
		return nil, fmt.Errorf("serialized request is empty")
	}

	return buf.Bytes(), nil
}

// determineAddress resolves the host:port string from a URL.
func determineAddress(targetURL *url.URL) (string, error) {
	port := targetURL.Port()
	scheme := targetURL.Scheme

	// Default ports if not specified
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			// If scheme is missing or unsupported, we cannot determine the address reliably.
			return "", fmt.Errorf("unsupported or missing scheme: %q", scheme)
		}
	}

	return net.JoinHostPort(targetURL.Hostname(), port), nil
}
