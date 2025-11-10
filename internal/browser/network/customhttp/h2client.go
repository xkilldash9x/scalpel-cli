package customhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/observability" // Added import
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// MaxResponseBodyBytes defines a reasonable limit for response bodies.
	MaxResponseBodyBytes = 32 * 1024 * 1024 // 32 MB

	// H2 specific constants (RFC 7540)
	DefaultH2InitialWindowSize = 65535
	DefaultH2MaxFrameSize      = 16384

	// Define target receive window sizes for better throughput.
	// These values are advertised to the server during connection setup.
	TargetH2ConnWindowSize   = 8 * 1024 * 1024 // 8 MB
	TargetH2StreamWindowSize = 4 * 1024 * 1024 // 4 MB
)

// H2Client manages a single, persistent HTTP/2 connection to a specific host.
// It is a low level client that provides full control over the HTTP/2 framing layer,
// including concurrent request multiplexing, stream management, and manual flow control.
//
// A background goroutine reads and processes incoming frames, dispatching them
// to the appropriate streams. Another optional goroutine handles keep-alive PINGs
// to maintain connection liveness. The client is thread-safe and designed for
// high concurrency scenarios.
type H2Client struct {
	Conn      net.Conn
	Config    *ClientConfig
	TargetURL *url.URL
	Address   string
	Logger    *zap.Logger

	Framer    *http2.Framer
	HPEncoder *hpack.Encoder
	HPDecoder *hpack.Decoder
	hpackBuf  *bytes.Buffer

	mu           sync.Mutex
	isConnected  bool
	nextStreamID uint32
	streams      map[uint32]*h2StreamState
	lastUsed     time.Time

	// Flow control for sending data to the server.
	connSendWindow          int64
	maxFrameSize            uint32
	initialStreamSendWindow int32

	// Flow control for receiving data from the server.
	connRecvWindow    int64
	connRecvWindowMax int64

	pingAcks map[uint64]chan struct{}

	doneChan   chan struct{}
	loopWG     sync.WaitGroup
	fatalError error
}

// h2StreamState represents the state of a single HTTP/2 stream within a connection.
// It holds the request, tracks the construction of the response, manages flow
// control windows, and signals completion.
type h2StreamState struct {
	ID         uint32
	Request    *http.Request
	Response   *http.Response
	BodyBuffer *bytes.Buffer
	Headers    http.Header
	StatusCode int
	// DoneChan is closed or receives an error when the stream is complete.
	DoneChan chan error

	// Stream-level send window.
	sendWindow int64
	// sendCond is used to block and wake up the request-sending goroutine when
	// the send window is updated.
	sendCond *sync.Cond

	// Stream-level receive window.
	recvWindow    int32
	recvWindowMax int32
}

// NewH2Client creates a new, un-connected H2Client for a given target URL and
// configuration. The actual network connection and H2 preface exchange happen
// lazily on the first request.
func NewH2Client(targetURL *url.URL, config *ClientConfig, logger *zap.Logger) (*H2Client, error) {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	// If no logger is provided, fetch the global logger.
	if logger == nil {
		logger = observability.GetLogger()
	}

	// H2 over TLS (h2) is the primary focus. H2C (cleartext) is not implemented here.
	if targetURL.Scheme != "https" {
		return nil, fmt.Errorf("HTTP/2 client currently only supports https scheme")
	}

	address, err := determineAddress(targetURL)
	if err != nil {
		return nil, err
	}

	hbuf := new(bytes.Buffer)
	const defaultDynamicTableSize = 4096

	client := &H2Client{
		Config:       config,
		TargetURL:    targetURL,
		Address:      address,
		Logger:       logger.Named("h2client").With(zap.String("host", targetURL.Host)),
		hpackBuf:     hbuf,
		HPEncoder:    hpack.NewEncoder(hbuf),
		HPDecoder:    hpack.NewDecoder(defaultDynamicTableSize, nil),
		nextStreamID: 1, // Client-initiated streams must be odd
		streams:      make(map[uint32]*h2StreamState),
		doneChan:     make(chan struct{}),
		lastUsed:     time.Now(),
		// Initialize flow control windows.
		// Send windows start at default until server SETTINGS received.
		connSendWindow:          DefaultH2InitialWindowSize,
		initialStreamSendWindow: DefaultH2InitialWindowSize,
		maxFrameSize:            DefaultH2MaxFrameSize,

		// Receive windows start at target sizes.
		connRecvWindow:    TargetH2ConnWindowSize,
		connRecvWindowMax: TargetH2ConnWindowSize,

		pingAcks: make(map[uint64]chan struct{}),
	}

	return client, nil
}

// IsIdle determines if the connection has been idle for a duration longer than
// the specified timeout. A connection is considered idle only if it is active and
// has no streams in progress. This method is used by the `CustomClient`'s connection
// evictor and implements the `ConnectionPool` interface.
func (c *H2Client) IsIdle(timeout time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// If not connected or failed, it's effectively idle.
	if !c.isConnected || c.fatalError != nil {
		return true
	}
	// If there are active streams, the connection is not idle, regardless of lastUsed time.
	if len(c.streams) > 0 {
		return false
	}
	return time.Since(c.lastUsed) > timeout
}

// Connect establishes the full H2 connection if it is not already active. This
// is the primary setup method and is called lazily by `Do`. It is idempotent.
//
// The connection process involves:
//  1. Establishing a TCP connection and performing a TLS handshake with ALPN to negotiate "h2".
//  2. Sending the client preface string.
//  3. Sending initial SETTINGS and WINDOW_UPDATE frames to configure the connection.
//  4. Starting background goroutines to read incoming frames (`readLoop`) and
//     handle keep-alive PINGs (`pingLoop`).
func (c *H2Client) Connect(ctx context.Context) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isConnected {
		return nil
	}
	if c.fatalError != nil {
		return fmt.Errorf("H2 connection previously failed: %w", c.fatalError)
	}

	// 1. Dial TCP/TLS
	conn, err := c.dialH2Connection(ctx)
	if err != nil {
		return err
	}
	c.Conn = conn
	// Configure Framer to automatically handle CONTINUATION frames by linking HPDecoder.
	c.Framer = http2.NewFramer(conn, conn)
	c.Framer.ReadMetaHeaders = c.HPDecoder

	// 2. Send H2 preface (RFC 7540 Section 3.5).
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write H2 preface: %w", err)
	}

	// 3. Send initial SETTINGS frame.
	settings := []http2.Setting{
		// Disable PUSH (SettingID 2).
		{ID: http2.SettingEnablePush, Val: 0},
		// Advertise our initial stream window size.
		{ID: http2.SettingInitialWindowSize, Val: TargetH2StreamWindowSize},
	}

	if err := c.Framer.WriteSettings(settings...); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write initial SETTINGS: %w", err)
	}

	// 4. Send initial connection WINDOW_UPDATE if we increased the window size significantly beyond the default.
	if c.connRecvWindow > DefaultH2InitialWindowSize {
		increment := uint32(c.connRecvWindow - DefaultH2InitialWindowSize)
		if err := c.Framer.WriteWindowUpdate(0, increment); err != nil {
			conn.Close()
			return fmt.Errorf("failed to write initial connection WINDOW_UPDATE: %w", err)
		}
	}

	// 5. Start the background loops.
	c.isConnected = true
	c.lastUsed = time.Now()

	loopsToStart := 1 // readLoop
	if c.Config.H2Config.PingInterval > 0 {
		loopsToStart++ // pingLoop
	}
	c.loopWG.Add(loopsToStart)
	go c.readLoop()
	if c.Config.H2Config.PingInterval > 0 {
		go c.pingLoop()
	}

	c.Logger.Debug("H2 connection established and initialized")
	return nil
}

// dialH2Connection handles the specific dialing requirements for H2 (ALPN negotiation).
func (c *H2Client) dialH2Connection(ctx context.Context) (net.Conn, error) {
	// Clone the dialer config to modify it safely.
	dialerConfig := c.Config.DialerConfig.Clone()

	if dialerConfig.TLSConfig == nil {
		dialerConfig.TLSConfig = network.NewDialerConfig().TLSConfig.Clone()
	}

	// Ensure H2 is prioritized in ALPN.
	// We include "http/1.1" as a fallback indicator, but we strictly check for "h2" success below.
	// FIX: Changed "http/1.live" (which caused the failures) to the standard "http/1.1".
	dialerConfig.TLSConfig.NextProtos = []string{"h2", "http/1.1"}

	dialerConfig.TLSConfig.InsecureSkipVerify = c.Config.InsecureSkipVerify
	if dialerConfig.TLSConfig.ServerName == "" {
		dialerConfig.TLSConfig.ServerName = c.TargetURL.Hostname()
	}

	// Use the robust network dialer (handles TCP, Proxy Tunneling, and TLS handshake).
	conn, err := network.DialContext(ctx, "tcp", c.Address, dialerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial H2 connection: %w", err)
	}

	// Verify H2 negotiation success.
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol != "h2" {
			conn.Close()
			// This specific error allows CustomClient to detect negotiation failure and attempt fallback to H1.
			return nil, fmt.Errorf("server did not negotiate HTTP/2 (ALPN: %s)", state.NegotiatedProtocol)
		}
	} else {
		// If the scheme is https, the connection must be TLS.
		conn.Close()
		return nil, fmt.Errorf("internal error: dialed connection for https scheme is not a TLS connection")
	}

	return conn, nil
}

// Close gracefully shuts down the H2 connection. It sends a GOAWAY frame with
// no error code, signals the background loops to terminate, closes the underlying
// network connection, and waits for the loops to exit. It implements the
// `ConnectionPool` interface.
func (c *H2Client) Close() error {
	return c.closeWithError(http2.ErrCodeNo, nil)
}

// closeWithError shuts down the connection, optionally sending a GOAWAY frame with a specific error code.
func (c *H2Client) closeWithError(code http2.ErrCode, err error) error {
	c.mu.Lock()
	if !c.isConnected {
		c.mu.Unlock()
		return nil
	}
	c.isConnected = false
	if c.fatalError == nil {
		c.fatalError = err // Store the reason for closure.
	}

	// Send GOAWAY frame (best effort) while holding the lock.
	if c.Framer != nil {
		// Last successful stream ID. For a client closing, this is typically the highest stream ID we initiated.
		lastStreamID := c.nextStreamID - 2
		if lastStreamID < 1 {
			lastStreamID = 0
		}
		// We ignore the write error here as the connection might already be broken if we are closing due to an error.
		c.Framer.WriteGoAway(uint32(lastStreamID), code, nil)
	}

	// Wake up any goroutines blocked on flow control windows.
	for _, stream := range c.streams {
		stream.sendCond.Broadcast()
	}

	c.mu.Unlock()

	// Signal background loops to stop
	select {
	case <-c.doneChan:
	default:
		close(c.doneChan)
	}

	// Close the underlying TCP connection
	var closeErr error
	if c.Conn != nil {
		closeErr = c.Conn.Close()
	}

	// Wait for background loops to finish
	c.loopWG.Wait()

	// Terminate any pending streams with an error.
	c.mu.Lock()
	if err == nil {
		// If closed cleanly but streams are still pending, use EOF to signal completion.
		err = io.EOF
	}
	for _, stream := range c.streams {
		select {
		case stream.DoneChan <- err: // Signal connection closed
		default:
		}
	}
	c.streams = nil
	c.mu.Unlock()

	c.Logger.Debug("H2 connection closed", zap.Error(err))
	return closeErr
}

// Do executes a single HTTP request over the multiplexed H2 connection. It is the
// primary method for interacting with the client and is safe for concurrent use.
//
// The process involves:
//  1. Lazily establishing the H2 connection if needed.
//  2. Initializing a new stream for the request.
//  3. Starting a new goroutine to serialize and send the request headers and body,
//     respecting H2 flow control.
//  4. Waiting for the response to be received by the background `readLoop`, or
//     for the request context to be cancelled.
//
// This concurrent design allows multiple `Do` calls to be in flight simultaneously
// over the single TCP connection.
func (c *H2Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	// CustomClient ensures the body is replayable (GetBody is set). We verify this assumption.
	if req.Body != nil && req.ContentLength != 0 && req.GetBody == nil {
		// If somehow a non-replayable body reaches here, it's an internal error in the client logic.
		return nil, fmt.Errorf("internal error: H2Client requires a replayable request body (GetBody must be set)")
	}

	stream, err := c.initializeStream(req)
	if err != nil {
		return nil, err
	}

	// Send the request in a separate goroutine. This allows concurrent processing, flow control blocking, and cancellation handling.
	sendErrChan := make(chan error, 1)
	go func() {
		sendErrChan <- c.sendRequest(stream)
	}()

	// Wait for response, context cancellation, or send completion.
	select {
	case err := <-sendErrChan:
		// Send process completed (successfully or with error).
		if err != nil {
			c.cleanupStream(stream.ID, err)
			return nil, fmt.Errorf("failed to send H2 request: %w", err)
		}
		// Send succeeded, now wait for the response from the server.
		select {
		case err := <-stream.DoneChan:
			if err != nil {
				return nil, err
			}
			// Response is ready. Handle automatic decompression.
			if err := network.DecompressResponse(stream.Response); err != nil {
				c.Logger.Warn("Failed to initialize decompression", zap.Error(err), zap.Uint32("streamID", stream.ID))
				// Proceed with potentially compressed body if initialization fails.
			}
			return stream.Response, nil

		case <-ctx.Done():
			// Context cancelled after send completed but before response received.
			// Send RST_STREAM (best effort) to notify the server.
			c.mu.Lock()
			if c.isConnected {
				c.Framer.WriteRSTStream(stream.ID, http2.ErrCodeCancel)
			}
			c.mu.Unlock()
			c.cleanupStream(stream.ID, ctx.Err())
			return nil, ctx.Err()
		}

	case err := <-stream.DoneChan:
		// Response completed (or stream reset by server) before the send process finished (or even started).
		// This can happen if the server sends an immediate error response (e.g., 400 Bad Request).
		if err != nil {
			return nil, err
		}
		return stream.Response, nil

	case <-ctx.Done():
		// Context cancelled while still sending (e.g., blocked on flow control or writing headers).
		// We signal the stream cleanup immediately. The sendRequest goroutine will eventually unblock
		// when the connection closes or flow control updates (and check if the stream still exists).
		c.cleanupStream(stream.ID, ctx.Err())
		// We might also send RST_STREAM if we knew headers were sent, but determining that state robustly is complex.
		return nil, ctx.Err()
	}
}

func (c *H2Client) initializeStream(req *http.Request) (*h2StreamState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isConnected {
		if c.fatalError != nil {
			return nil, fmt.Errorf("H2 connection closed due to error: %w", c.fatalError)
		}
		return nil, fmt.Errorf("H2 connection closed")
	}

	streamID := c.nextStreamID
	c.nextStreamID += 2

	stream := &h2StreamState{
		ID:         streamID,
		Request:    req,
		BodyBuffer: new(bytes.Buffer),
		Headers:    make(http.Header),
		DoneChan:   make(chan error, 1), // Buffered to prevent blocking the read loop.
		// Initialize stream windows based on current connection settings.
		sendWindow:    int64(c.initialStreamSendWindow),
		recvWindow:    TargetH2StreamWindowSize,
		recvWindowMax: TargetH2StreamWindowSize,
	}
	stream.sendCond = sync.NewCond(&c.mu) // Use the connection's lock for the stream condition variable.
	c.streams[streamID] = stream

	c.lastUsed = time.Now() // Update activity tracker
	return stream, nil
}

// cleanupStream removes a stream from the active list and signals completion with an error.
func (c *H2Client) cleanupStream(streamID uint32, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, exists := c.streams[streamID]; exists {
		// Signal completion if not already done.
		select {
		case stream.DoneChan <- err:
		default:
		}
		delete(c.streams, streamID)
		// Wake up any waiters blocked on this stream's flow control, as the stream is terminating.
		stream.sendCond.Broadcast()
	}
	c.lastUsed = time.Now()
}

// sendRequest handles the serialization and sending of HEADERS and DATA frames, respecting flow control.
func (c *H2Client) sendRequest(stream *h2StreamState) error {
	req := stream.Request

	// Prepare the body for sending. Use GetBody to ensure a fresh reader.
	var bodyBytes []byte
	if req.Body != nil && req.GetBody != nil {
		bodyReader, err := req.GetBody()
		if err != nil {
			return fmt.Errorf("failed to get request body: %w", err)
		}
		defer bodyReader.Close()

		// Read the body entirely. This simplifies H2 implementation (calculating Content-Length for headers)
		// and ensures we can handle flow control correctly.
		bodyBytes, err = io.ReadAll(bodyReader)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
	}

	// -- Send HEADERS --
	c.mu.Lock()

	if !c.isConnected {
		c.mu.Unlock()
		return fmt.Errorf("connection closed before writing HEADERS")
	}

	// Encode headers (uses shared HPEncoder and hpackBuf).
	headerBlock, err := c.encodeHeaders(req, bodyBytes)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to encode headers: %w", err)
	}

	// Write HEADERS frame.
	endStream := len(bodyBytes) == 0
	// Assuming headers fit in one frame (EndHeaders=true). A robust implementation must handle CONTINUATION frames for large headers.
	if err := c.Framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      stream.ID,
		BlockFragment: headerBlock,
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		c.mu.Unlock()
		// Treat write failures as fatal connection errors.
		c.closeWithError(http2.ErrCodeInternal, fmt.Errorf("failed to write HEADERS frame: %w", err))
		return err
	}
	c.mu.Unlock()

	if endStream {
		return nil
	}

	// -- Send DATA (with Flow Control) --
	return c.sendData(stream, bodyBytes)
}

// sendData handles sending DATA frames, respecting stream and connection flow control windows.
func (c *H2Client) sendData(stream *h2StreamState, data []byte) error {

	for len(data) > 0 {
		c.mu.Lock()

		// 1. Wait for available window capacity.
		// We must wait if either the connection window OR the stream window is exhausted.
		for c.connSendWindow <= 0 || stream.sendWindow <= 0 {
			if !c.isConnected {
				c.mu.Unlock()
				return fmt.Errorf("connection closed while waiting for flow control window")
			}
			// Check if the stream still exists (might have been cancelled or reset by server).
			if _, exists := c.streams[stream.ID]; !exists {
				c.mu.Unlock()
				return fmt.Errorf("stream closed or cancelled while sending data")
			}

			// Block until a WINDOW_UPDATE arrives. We use the stream's condition variable.
			// processWindowUpdateFrame ensures this is broadcasted for both stream and connection updates.
			// Wait() atomically unlocks c.mu and suspends the goroutine, then relocks c.mu when awakened.
			stream.sendCond.Wait()
		}

		// 2. Determine chunk size.
		// Constrained by remaining data, max frame size, connection window, and stream window.
		chunkSize := len(data)
		if uint32(chunkSize) > c.maxFrameSize {
			chunkSize = int(c.maxFrameSize)
		}
		if int64(chunkSize) > c.connSendWindow {
			chunkSize = int(c.connSendWindow)
		}
		if int64(chunkSize) > stream.sendWindow {
			chunkSize = int(stream.sendWindow)
		}

		chunk := data[:chunkSize]
		data = data[chunkSize:]
		isLastChunk := len(data) == 0

		// 3. Decrement windows.
		c.connSendWindow -= int64(chunkSize)
		stream.sendWindow -= int64(chunkSize)

		// 4. Write DATA frame.
		if err := c.Framer.WriteData(stream.ID, isLastChunk, chunk); err != nil {
			c.mu.Unlock()
			// Treat write failures as fatal connection errors.
			c.closeWithError(http2.ErrCodeInternal, fmt.Errorf("failed to write DATA frame: %w", err))
			return err
		}

		c.mu.Unlock()
	}
	return nil
}

// encodeHeaders serializes HTTP headers into HPACK format. Must be called with c.mu locked.
func (c *H2Client) encodeHeaders(req *http.Request, body []byte) ([]byte, error) {
	c.hpackBuf.Reset()

	// Pseudo-headers (RFC 7540 Section 8.1.2.3). Must be first and in order.
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":method", Value: req.Method})
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: c.TargetURL.Scheme})

	// :authority (Host header)
	authority := req.Host
	if authority == "" {
		authority = c.TargetURL.Host
	}
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

	// :path
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})

	// Content-Length. Required for requests with bodies.
	if len(body) > 0 {
		c.HPEncoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
	} else if req.ContentLength > 0 {
		// Handle cases where body might be empty but ContentLength was explicitly set (e.g., POST with empty body).
		c.HPEncoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
	}

	// Regular headers.
	for k, vv := range req.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		// Skip prohibited headers (RFC 7540 Section 8.1.2.2) and those covered by pseudo-headers.
		if canonicalKey == "Host" || canonicalKey == "Content-Length" ||
			canonicalKey == "Connection" || canonicalKey == "Keep-Alive" || canonicalKey == "Proxy-Connection" ||
			canonicalKey == "Transfer-Encoding" || canonicalKey == "Upgrade" {
			continue
		}

		// H2 mandates lower-case header names.
		name := strings.ToLower(k)
		for _, v := range vv {
			// Handle Cookie headers specifically (RFC 7540 Section 8.1.2.5).
			// They might be split into multiple fields for better compression.
			if name == "cookie" {
				// Split concatenated cookies ("; ") back into individual key-value pairs.
				cookies := strings.Split(v, "; ")
				for _, cookie := range cookies {
					if cookie != "" {
						c.HPEncoder.WriteField(hpack.HeaderField{Name: name, Value: cookie})
					}
				}
			} else {
				c.HPEncoder.WriteField(hpack.HeaderField{Name: name, Value: v})
			}
		}
	}

	// Return a copy of the buffer contents.
	result := make([]byte, c.hpackBuf.Len())
	copy(result, c.hpackBuf.Bytes())
	return result, nil
}

// -- Background Loops --

// pingLoop periodically sends PING frames to keep the connection alive and detect failures (NAT timeouts, half-open connections).
func (c *H2Client) pingLoop() {
	defer c.loopWG.Done()

	interval := c.Config.H2Config.PingInterval
	timeout := c.Config.H2Config.PingTimeout

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.doneChan:
			return
		case <-ticker.C:
			// Send PING
			ackChan, err := c.sendPing()
			if err != nil {
				c.Logger.Warn("Failed to send H2 PING", zap.Error(err))
				// If sending fails, the connection is likely broken. closeWithError is called by sendPing.
				return
			}

			// Wait for ACK
			select {
			case <-ackChan:
				// ACK received successfully.
				c.Logger.Debug("H2 PING ACK received")
			case <-time.After(timeout):
				// Timeout waiting for ACK.
				c.Logger.Error("H2 PING timeout, closing connection")
				c.closeWithError(http2.ErrCodeNo, fmt.Errorf("PING timeout"))
				return
			case <-c.doneChan:
				return
			}
		}
	}
}

// sendPing generates a unique PING payload and sends the frame.
func (c *H2Client) sendPing() (<-chan struct{}, error) {
	// Generate a unique 8-byte payload.
	var payload [8]byte
	if _, err := rand.Read(payload[:]); err != nil {
		// Fallback to time-based payload if rand fails.
		binary.BigEndian.PutUint64(payload[:], uint64(time.Now().UnixNano()))
	}

	payloadInt := binary.BigEndian.Uint64(payload[:])
	ackChan := make(chan struct{})

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isConnected {
		return nil, fmt.Errorf("connection closed")
	}

	// Register the channel to wait for the ACK.
	c.pingAcks[payloadInt] = ackChan

	if err := c.Framer.WritePing(false, payload); err != nil {
		delete(c.pingAcks, payloadInt)
		// Treat write failures as fatal connection errors.
		c.closeWithError(http2.ErrCodeInternal, fmt.Errorf("failed to write PING frame: %w", err))
		return nil, err
	}

	return ackChan, nil
}

// readLoop runs in the background and processes all incoming frames sequentially.
func (c *H2Client) readLoop() {
	defer c.loopWG.Done()
	// Ensure connection is closed if the loop exits unexpectedly.
	defer func() {
		// Check if the connection is still considered active.
		c.mu.Lock()
		isConn := c.isConnected
		c.mu.Unlock()

		if isConn {
			// If the loop exits but the connection wasn't
			// cleanly shut down (e.g., by c.Close()),
			// we must trigger the close to clean up resources.
			c.Close()
		}
	}()

	// Use a long read timeout if PINGs are enabled, as PINGs verify connectivity.
	// If PINGs are disabled, use the IdleConnTimeout to detect inactive connections.
	var readTimeout time.Duration
	if c.Config.H2Config.PingInterval > 0 {
		readTimeout = 5 * time.Minute
	} else {
		readTimeout = c.Config.IdleConnTimeout
		if readTimeout == 0 {
			readTimeout = 90 * time.Second
		}
	}

	for {
		// Check if the loop should terminate.
		select {
		case <-c.doneChan:
			return
		default:
		}

		// Set a read deadline.
		c.Conn.SetReadDeadline(time.Now().Add(readTimeout))

		// Read the next frame.
		frame, err := c.Framer.ReadFrame()
		if err != nil {
			if err == io.EOF {
				// Server closed the connection cleanly.
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Read timeout occurred.
				c.Logger.Info("H2 connection read timeout reached, closing.")
				c.closeWithError(http2.ErrCodeNo, fmt.Errorf("read timeout"))
				return
			}
			// Treat other read errors as fatal.
			c.Logger.Error("Error reading frame, closing connection", zap.Error(err))
			// Determine the appropriate error code based on the type of error returned by the Framer.
			errCode := http2.ErrCodeInternal
			var se http2.StreamError
			var ce http2.ConnectionError
			if errors.As(err, &se) {
				errCode = se.Code
			} else if errors.As(err, &ce) {
				errCode = http2.ErrCode(ce)
			}

			c.closeWithError(errCode, fmt.Errorf("frame read error: %w", err))
			return
		}

		// Process the frame.
		if err := c.processFrame(frame); err != nil {
			// processFrame returns an error if the connection should be terminated (Protocol Error, etc.).
			c.Logger.Error("Error processing frame, closing connection", zap.Error(err))
			errCode := http2.ErrCodeProtocol
			var se http2.StreamError
			var ce http2.ConnectionError
			if errors.As(err, &se) {
				errCode = se.Code
			} else if errors.As(err, &ce) {
				errCode = http2.ErrCode(ce)
			}
			c.closeWithError(errCode, err)
			return
		}
	}
}

// processFrame handles a single incoming frame. Returns a fatal connection error if processing fails.
func (c *H2Client) processFrame(frame http2.Frame) error {
	streamID := frame.Header().StreamID

	if streamID == 0 {
		return c.processControlFrame(frame)
	}

	c.mu.Lock()
	stream, exists := c.streams[streamID]
	c.mu.Unlock()

	// Handle frames for unknown or closed streams (RFC 7540 Section 5.1).
	if !exists {
		// PUSH_PROMISE is not allowed from server if we disabled it.
		if frame.Header().Type == http2.FramePushPromise {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		// If DATA is received for a closed stream, we must return the flow control credit.
		if f, ok := frame.(*http2.DataFrame); ok && len(f.Data()) > 0 {
			c.mu.Lock()
			if c.isConnected {
				// Return credit to connection window.
				c.Framer.WriteWindowUpdate(0, uint32(len(f.Data())))
			}
			c.mu.Unlock()
		}
		// Ignore other frames on closed streams.
		return nil
	}

	var streamErr error
	streamEnded := false

	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		// MetaHeadersFrame is generated when Framer.ReadMetaHeaders is set (handles HEADERS+CONTINUATION).
		streamEnded, streamErr = c.processHeadersFrame(stream, f)
	case *http2.DataFrame:
		streamEnded, streamErr = c.processDataFrame(stream, f)
	case *http2.RSTStreamFrame:
		streamErr = fmt.Errorf("stream reset by server (Error Code: %v)", f.ErrCode)
		streamEnded = true
	case *http2.WindowUpdateFrame:
		streamErr = c.processWindowUpdateFrame(stream, f)
	case *http2.PriorityFrame:
		// Priority hints are advisory and ignored in this implementation.
	default:
		// Unknown frame types must be ignored.
	}

	if streamErr != nil {
		// Check if it's a fatal connection error first. If so, return it to readLoop.
		var ce http2.ConnectionError
		if errors.As(streamErr, &ce) {
			return ce // Pass connection error up
		}

		// Handle stream-level errors.
		c.Logger.Error("Stream error", zap.Uint32("streamID", streamID), zap.Error(streamErr))

		// Determine the appropriate error code for RST_STREAM.
		errCode := http2.ErrCodeInternal
		var se http2.StreamError
		if errors.As(streamErr, &se) {
			errCode = se.Code
		}

		// Send RST_STREAM if the error is recoverable at the connection level and the stream hasn't ended yet.
		if !streamEnded {
			c.mu.Lock()
			if c.isConnected {
				c.Framer.WriteRSTStream(streamID, errCode)
			}
			c.mu.Unlock()
		}
		c.cleanupStream(streamID, streamErr)
	} else if streamEnded {
		c.finalizeStream(stream)
	}
	return nil
}

// processControlFrame handles frames on Stream 0 (connection control). Returns a fatal connection error if processing fails.
func (c *H2Client) processControlFrame(frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		return c.processSettingsFrame(f)
	case *http2.PingFrame:
		return c.processPingFrame(f)
	case *http2.GoAwayFrame:
		// Server is shutting down the connection.
		c.closeWithError(f.ErrCode, fmt.Errorf("received GOAWAY from server (Error Code: %v)", f.ErrCode))
		return nil // Connection closure is handled by closeWithError.
	case *http2.WindowUpdateFrame:
		return c.processWindowUpdateFrame(nil, f)
	default:
		// Validate frame types allowed on stream 0.
		switch f.Header().Type {
		case http2.FrameData, http2.FrameHeaders, http2.FramePriority, http2.FrameRSTStream, http2.FramePushPromise, http2.FrameContinuation:
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		// Ignore unknown control frames.
		return nil
	}
}

// processSettingsFrame handles SETTINGS frames from the server.
func (c *H2Client) processSettingsFrame(f *http2.SettingsFrame) error {
	if f.IsAck() {
		// Acknowledgment of our settings, nothing to do.
		return nil
	}

	// Apply server settings.
	c.mu.Lock()
	defer c.mu.Unlock()

	err := f.ForeachSetting(func(setting http2.Setting) error {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			newWindowSize := int32(setting.Val)
			// Check for invalid window size (http2 library handles > MaxInt32 during parsing).
			if newWindowSize < 0 {
				return http2.ConnectionError(http2.ErrCodeFlowControl)
			}
			// Update existing streams' send windows (RFC 7540 Section 6.9.2).
			delta := int64(newWindowSize) - int64(c.initialStreamSendWindow)
			c.initialStreamSendWindow = newWindowSize

			for _, stream := range c.streams {
				stream.sendWindow += delta
				// Broadcast if the window changed, potentially unblocking senders.
				stream.sendCond.Broadcast()
			}
		case http2.SettingMaxFrameSize:
			if setting.Val < DefaultH2MaxFrameSize || setting.Val > (1<<24-1) {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
			c.maxFrameSize = setting.Val
		case http2.SettingHeaderTableSize:
			// Update the HPACK encoder's dynamic table size limit.
			c.HPEncoder.SetMaxDynamicTableSize(setting.Val)
		}
		return nil
	})

	if err != nil {
		return err
	}

	// Acknowledge the server's settings (RFC 7540 Section 6.5.3).
	if c.isConnected {
		if err := c.Framer.WriteSettingsAck(); err != nil {
			// Failure to write ACK is treated as a connection error.
			return fmt.Errorf("failed to write SETTINGS ACK: %w", err)
		}
	}
	return nil
}

// processPingFrame handles PING frames.
func (c *H2Client) processPingFrame(f *http2.PingFrame) error {
	if f.IsAck() {
		// PING ACK received. Notify the corresponding waiter in pingLoop.
		payloadInt := binary.BigEndian.Uint64(f.Data[:])
		c.mu.Lock()
		if ackChan, exists := c.pingAcks[payloadInt]; exists {
			close(ackChan)
			delete(c.pingAcks, payloadInt)
		}
		c.mu.Unlock()
	} else {
		// PING received, must send ACK (PONG).
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.isConnected {
			if err := c.Framer.WritePing(true, f.Data); err != nil {
				// Failure to write PING ACK is usually not fatal immediately, but log it.
				c.Logger.Warn("Failed to write PING ACK", zap.Error(err))
			}
		}
	}
	return nil
}

// processWindowUpdateFrame handles WINDOW_UPDATE frames for both connection (stream=nil) and streams.
func (c *H2Client) processWindowUpdateFrame(stream *h2StreamState, f *http2.WindowUpdateFrame) error {
	increment := f.Increment
	if increment == 0 {
		// WINDOW_UPDATE with 0 increment is an error (RFC 7540 Section 6.9).
		if stream == nil {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		// Stream error.
		return http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if stream == nil {
		// Connection window update.
		// Check for overflow.
		if c.connSendWindow > math.MaxInt64-int64(increment) {
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
		c.connSendWindow += int64(increment)

		// Signal all blocked stream writers as the connection window increased.
		for _, s := range c.streams {
			s.sendCond.Broadcast()
		}

	} else {
		// Stream window update.
		// Check if the stream still exists (might have been cleaned up concurrently).
		if _, exists := c.streams[stream.ID]; !exists {
			return nil
		}

		if stream.sendWindow > math.MaxInt64-int64(increment) {
			// This is a stream error.
			return http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeFlowControl}
		}
		stream.sendWindow += int64(increment)
		stream.sendCond.Broadcast()
	}
	return nil
}

// processHeadersFrame processes decoded headers from a MetaHeadersFrame.
func (c *H2Client) processHeadersFrame(stream *h2StreamState, f *http2.MetaHeadersFrame) (bool, error) {
	// f.HeadersEnded() is always true for MetaHeadersFrame.

	isTrailer := stream.StatusCode != 0

	if isTrailer && !f.StreamEnded() {
		// Received intermediate HEADERS (e.g., 1xx responses). We ignore them in this implementation.
		return false, nil
	}

	// Process header fields.
	for _, hf := range f.Fields {
		if strings.HasPrefix(hf.Name, ":") {
			// Pseudo-headers.
			if isTrailer {
				// Trailers must not include pseudo-headers.
				return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
			}
			if hf.Name == ":status" {
				status, err := strconv.Atoi(hf.Value)
				if err != nil {
					return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
				}
				stream.StatusCode = status
			}
			// Other response pseudo-headers are ignored.
		} else {
			// Regular headers (and trailers).
			stream.Headers.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
		}
	}

	if !isTrailer && stream.StatusCode == 0 {
		// Final response headers must include :status.
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	return f.StreamEnded(), nil
}

// processDataFrame handles DATA frames, respecting receive flow control.
func (c *H2Client) processDataFrame(stream *h2StreamState, f *http2.DataFrame) (bool, error) {
	if stream.StatusCode == 0 {
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	data := f.Data()
	dataLen := len(data)

	if dataLen == 0 {
		// Empty DATA frame is valid (often used to signal END_STREAM).
		return f.StreamEnded(), nil
	}

	// Check flow control limits (RFC 7540 Section 6.9).
	c.mu.Lock()
	if c.connRecvWindow < int64(dataLen) {
		c.mu.Unlock()
		// Connection flow control violation is a connection error.
		return false, http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	if stream.recvWindow < int32(dataLen) {
		c.mu.Unlock()
		// Stream flow control violation is a stream error.
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeFlowControl}
	}

	// Decrement windows.
	c.connRecvWindow -= int64(dataLen)
	stream.recvWindow -= int32(dataLen)

	// Check if we need to send WINDOW_UPDATE to replenish the windows.
	// Strategy: Send update if the window drops below half the max size.
	connUpdate := c.maybeSendWindowUpdate(0, c.connRecvWindow, c.connRecvWindowMax)
	streamUpdate := c.maybeSendWindowUpdate(stream.ID, int64(stream.recvWindow), int64(stream.recvWindowMax))

	// Update windows if updates were sent.
	if connUpdate > 0 {
		c.connRecvWindow += int64(connUpdate)
	}
	if streamUpdate > 0 {
		stream.recvWindow += int32(streamUpdate)
	}
	c.mu.Unlock()

	// Enforce response body size limit.
	if stream.BodyBuffer.Len()+dataLen > MaxResponseBodyBytes {
		// This is a stream error (cancel the stream).
		return true, fmt.Errorf("response body exceeded limit (%d bytes)", MaxResponseBodyBytes)
	}

	// Write data to the stream buffer.
	stream.BodyBuffer.Write(data)
	return f.StreamEnded(), nil
}

// maybeSendWindowUpdate checks the window against the threshold (half the max window) and sends WINDOW_UPDATE if needed.
// Must be called with c.mu locked.
func (c *H2Client) maybeSendWindowUpdate(streamID uint32, currentWindow, maxWindow int64) uint32 {
	threshold := maxWindow / 2
	if currentWindow <= threshold {
		increment := uint32(maxWindow - currentWindow)
		if increment > 0 && c.isConnected {
			if err := c.Framer.WriteWindowUpdate(streamID, increment); err != nil {
				// Failure to write WINDOW_UPDATE is usually not fatal immediately, but log it.
				c.Logger.Warn("Failed to write WINDOW_UPDATE", zap.Uint32("streamID", streamID), zap.Error(err))
				return 0
			}
			return increment
		}
	}
	return 0
}

// finalizeStream converts the stream state into an *http.Response and signals completion.
func (c *H2Client) finalizeStream(stream *h2StreamState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.streams[stream.ID]; !exists {
		return
	}

	resp := &http.Response{
		Status:        fmt.Sprintf("%d %s", stream.StatusCode, http.StatusText(stream.StatusCode)),
		StatusCode:    stream.StatusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        stream.Headers,
		Body:          io.NopCloser(stream.BodyBuffer),
		Request:       stream.Request,
		ContentLength: int64(stream.BodyBuffer.Len()),
		// Trailers would be populated here if processed.
	}

	// Optional: Check Content-Length header consistency.
	if clHeader := resp.Header.Get("Content-Length"); clHeader != "" {
		cl, err := strconv.ParseInt(clHeader, 10, 64)
		if err == nil && cl != resp.ContentLength {
			c.Logger.Warn("Content-Length mismatch", zap.Int64("header", cl), zap.Int64("actual", resp.ContentLength))
			// While technically a violation, browsers often tolerate this.
		}
	}

	stream.Response = resp

	// Signal completion successfully
	select {
	case stream.DoneChan <- nil:
	default:
	}
	delete(c.streams, stream.ID)
	c.lastUsed = time.Now() // Update activity tracker
}
