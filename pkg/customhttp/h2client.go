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

	"github.com/xkilldash9x/scalpel-cli/pkg/network"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// PaddingStrategy defines how to calculate padding for specific frames.
// It accepts the http.Request object, allowing the strategy to make decisions
// based on headers, context values, or other request-specific metadata.
type PaddingStrategy interface {
	// CalculatePadding returns the number of padding bytes to add for a given frame type and payload length.
	// req: The specific request associated with this frame.
	// frameType: http2.FrameHeaders or http2.FrameData.
	// payloadLen: The size of the data/header block being sent.
	CalculatePadding(req *http.Request, frameType http2.FrameType, payloadLen int) uint8
}

// ClientConfig holds configuration for the H2Client.
// Ensure your ClientConfig struct includes:
// PaddingStrategy PaddingStrategy

// H2StreamResetError is returned when an H2 stream is reset by the server.
type H2StreamResetError struct {
	ErrCode http2.ErrCode
}

func (e H2StreamResetError) Error() string {
	return fmt.Sprintf("stream reset by server (Error Code: %v)", e.ErrCode)
}

// H2StreamHandle is an opaque reference required to trigger the second phase of an SPA attack.
type H2StreamHandle struct {
	streamID uint32
	req      *http.Request
	body     []byte
}

const (
	// MaxResponseBodyBytes defines a reasonable limit for response bodies.
	MaxResponseBodyBytes = 32 * 1024 * 1024 // 32 MB

	// H2 specific constants (RFC 9113)
	DefaultH2InitialWindowSize = 65535
	DefaultH2MaxFrameSize      = 16384

	// Define target receive window sizes for better throughput.
	TargetH2ConnWindowSize   = 8 * 1024 * 1024 // 8 MB
	TargetH2StreamWindowSize = 4 * 1024 * 1024 // 4 MB
)

// h2WriteRequest is an interface for items that can be sent to the writeLoop.
type h2WriteRequest interface {
	writeFrame(f *http2.Framer) error
	handleError(err error)
}

// H2Client manages a single, persistent HTTP/2 connection to a specific host.
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

	writeChan chan h2WriteRequest

	doneChan   chan struct{}
	loopWG     sync.WaitGroup
	fatalError error
}

// h2StreamState represents the state of a single HTTP/2 stream within a connection.
type h2StreamState struct {
	ID         uint32
	Request    *http.Request
	Response   *http.Response
	BodyBuffer *bytes.Buffer
	Headers    http.Header
	StatusCode int
	DoneChan   chan error

	sendWindow    int64
	sendCond      *sync.Cond
	recvWindow    int32
	recvWindowMax int32
}

// NewH2Client creates a new, un-connected H2Client.
func NewH2Client(targetURL *url.URL, config *ClientConfig, logger *zap.Logger) (*H2Client, error) {
	if config == nil {
		config = NewBrowserClientConfig()
	}
	if logger == nil {
		logger = observability.GetLogger()
	}

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
		Config:                  config,
		TargetURL:               targetURL,
		Address:                 address,
		Logger:                  logger.Named("h2client").With(zap.String("host", targetURL.Host)),
		hpackBuf:                hbuf,
		HPEncoder:               hpack.NewEncoder(hbuf),
		HPDecoder:               hpack.NewDecoder(defaultDynamicTableSize, nil),
		nextStreamID:            1, // Client-initiated streams must be odd
		streams:                 make(map[uint32]*h2StreamState),
		doneChan:                make(chan struct{}),
		lastUsed:                time.Now(),
		connSendWindow:          DefaultH2InitialWindowSize,
		initialStreamSendWindow: DefaultH2InitialWindowSize,
		maxFrameSize:            DefaultH2MaxFrameSize,
		connRecvWindow:          TargetH2ConnWindowSize,
		connRecvWindowMax:       TargetH2ConnWindowSize,
		pingAcks:                make(map[uint64]chan struct{}),
	}

	client.writeChan = make(chan h2WriteRequest, 64)

	return client, nil
}

// IsIdle determines if the connection has been idle.
func (c *H2Client) IsIdle(timeout time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isConnected || c.fatalError != nil {
		return true
	}
	if len(c.streams) > 0 {
		return false
	}
	return time.Since(c.lastUsed) > timeout
}

// Connect establishes the full H2 connection if it is not already active.
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
	c.Framer = http2.NewFramer(conn, conn)
	c.Framer.ReadMetaHeaders = c.HPDecoder

	// 2. Send H2 preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write H2 preface: %w", err)
	}

	// 3. Send initial SETTINGS frame.
	settings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: TargetH2StreamWindowSize},
	}

	if err := c.Framer.WriteSettings(settings...); err != nil {
		conn.Close()
		return fmt.Errorf("failed to write initial SETTINGS: %w", err)
	}

	// 4. Send initial connection WINDOW_UPDATE
	if c.connRecvWindow > DefaultH2InitialWindowSize {
		increment := uint32(c.connRecvWindow - DefaultH2InitialWindowSize)
		if err := c.Framer.WriteWindowUpdate(0, increment); err != nil {
			conn.Close()
			return fmt.Errorf("failed to write initial connection WINDOW_UPDATE: %w", err)
		}
	}

	// 5. Start background loops
	c.isConnected = true
	c.lastUsed = time.Now()

	loopsToStart := 2
	if c.Config.H2Config.PingInterval > 0 {
		loopsToStart++
	}
	c.loopWG.Add(loopsToStart)
	go c.readLoop()
	go c.writeLoop()
	if c.Config.H2Config.PingInterval > 0 {
		go c.pingLoop()
	}

	c.Logger.Debug("H2 connection established and initialized")
	return nil
}

// dialH2Connection handles ALPN negotiation.
func (c *H2Client) dialH2Connection(ctx context.Context) (net.Conn, error) {
	dialerConfig := c.Config.DialerConfig.Clone()

	if dialerConfig.TLSConfig == nil {
		dialerConfig.TLSConfig = network.NewDialerConfig().TLSConfig.Clone()
	}

	dialerConfig.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
	dialerConfig.TLSConfig.InsecureSkipVerify = c.Config.InsecureSkipVerify
	if dialerConfig.TLSConfig.ServerName == "" {
		dialerConfig.TLSConfig.ServerName = c.TargetURL.Hostname()
	}

	conn, err := network.DialContext(ctx, "tcp", c.Address, dialerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial H2 connection: %w", err)
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol != "h2" {
			conn.Close()
			return nil, fmt.Errorf("server did not negotiate HTTP/2 (ALPN: %s)", state.NegotiatedProtocol)
		}
	} else {
		conn.Close()
		return nil, fmt.Errorf("internal error: dialed connection for https scheme is not a TLS connection")
	}

	return conn, nil
}

// Close gracefully shuts down the H2 connection.
func (c *H2Client) Close() error {
	err := c.shutdown(http2.ErrCodeNo, nil)
	c.loopWG.Wait()
	c.Logger.Debug("H2 connection closed fully.")
	return err
}

func (c *H2Client) shutdown(_ http2.ErrCode, err error) error {
	c.mu.Lock()
	if !c.isConnected {
		c.mu.Unlock()
		return nil
	}
	c.isConnected = false
	if c.fatalError == nil {
		c.fatalError = err
	}
	for _, stream := range c.streams {
		stream.sendCond.Broadcast()
	}

	c.mu.Unlock()

	select {
	case <-c.doneChan:
	default:
		close(c.doneChan)
	}

	var closeErr error
	if c.Conn != nil {
		closeErr = c.Conn.Close()
	}

	c.mu.Lock()
	if err == nil {
		err = io.EOF
	}
	for _, stream := range c.streams {
		select {
		case stream.DoneChan <- err:
		default:
		}
	}
	c.streams = nil
	c.mu.Unlock()

	c.Logger.Debug("H2 connection shutdown initiated", zap.Error(err))
	return closeErr
}

// Do executes a single HTTP request.
func (c *H2Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	if req.Body != nil && req.ContentLength != 0 && req.GetBody == nil {
		return nil, fmt.Errorf("internal error: H2Client requires a replayable request body (GetBody must be set)")
	}

	stream, err := c.initializeStream(req)
	if err != nil {
		return nil, err
	}

	sendErrChan := make(chan error, 1)
	go func() {
		sendErrChan <- c.sendRequest(stream)
	}()

	select {
	case err := <-sendErrChan:
		if err != nil {
			c.cleanupStream(stream.ID, err)
			return nil, fmt.Errorf("failed to send H2 request: %w", err)
		}
		select {
		case err := <-stream.DoneChan:
			if err != nil {
				return nil, err
			}
			if err := network.DecompressResponse(stream.Response); err != nil {
				c.Logger.Warn("Failed to initialize decompression", zap.Error(err), zap.Uint32("streamID", stream.ID))
			}
			return stream.Response, nil

		case <-ctx.Done():
			c.mu.Lock()
			if c.isConnected {
				wrst := &writeRSTStream{streamID: stream.ID, errCode: http2.ErrCodeCancel}
				wrst.init()
				select {
				case c.writeChan <- wrst:
				default:
					c.Logger.Warn("Failed to queue RST_STREAM on cancel (write buffer full)", zap.Uint32("streamID", stream.ID))
				}
			}
			c.mu.Unlock()
			c.cleanupStream(stream.ID, ctx.Err())
			return nil, ctx.Err()
		}

	case err := <-stream.DoneChan:
		if err != nil {
			return nil, err
		}
		return stream.Response, nil

	case <-ctx.Done():
		c.cleanupStream(stream.ID, ctx.Err())
		return nil, ctx.Err()
	}
}

// PrepareRequest sends the HEADERS frame immediately but strictly holds the DATA frame.
func (c *H2Client) PrepareRequest(ctx context.Context, req *http.Request) (*H2StreamHandle, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	var bodyBytes []byte
	if req.Body != nil {
		if req.GetBody == nil {
			return nil, fmt.Errorf("request body must be replayable (GetBody is nil)")
		}
		r, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		bodyBytes, _ = io.ReadAll(r)
		r.Close()
	}

	stream, err := c.initializeStream(req)
	if err != nil {
		return nil, err
	}

	endStream := len(bodyBytes) == 0

	c.mu.Lock()
	headerBlock, err := c.encodeHeaders(req, bodyBytes)
	c.mu.Unlock()

	if err != nil {
		c.cleanupStream(stream.ID, err)
		return nil, err
	}

	// Calculate padding for HEADERS frame with Request Context
	var padLen uint8
	if c.Config.PaddingStrategy != nil {
		padLen = c.Config.PaddingStrategy.CalculatePadding(req, http2.FrameHeaders, len(headerBlock))
	}

	wh := &writeHeaders{
		streamID:     stream.ID,
		headerBlock:  headerBlock,
		endStream:    endStream,
		maxFrameSize: c.maxFrameSize,
		padLength:    padLen,
	}
	wh.init()
	if wh.maxFrameSize == 0 {
		wh.maxFrameSize = DefaultH2MaxFrameSize
	}

	select {
	case c.writeChan <- wh:
	case <-c.doneChan:
		c.cleanupStream(stream.ID, fmt.Errorf("connection closed"))
		return nil, fmt.Errorf("connection closed")
	}

	if err := wh.wait(); err != nil {
		c.cleanupStream(stream.ID, err)
		return nil, err
	}

	return &H2StreamHandle{
		streamID: stream.ID,
		req:      req,
		body:     bodyBytes,
	}, nil
}

// ReleaseBody sends the DATA frame for a prepared stream.
func (c *H2Client) ReleaseBody(handle *H2StreamHandle) error {
	if len(handle.body) == 0 {
		return nil
	}

	c.mu.Lock()
	stream, exists := c.streams[handle.streamID]
	c.mu.Unlock()

	if !exists {
		return fmt.Errorf("stream %d closed prematurely", handle.streamID)
	}

	return c.sendData(stream, handle.body)
}

// WaitResponse allows the caller to wait for the result of a specific stream handle.
func (c *H2Client) WaitResponse(ctx context.Context, handle *H2StreamHandle) (*http.Response, error) {
	c.mu.Lock()
	stream, exists := c.streams[handle.streamID]
	c.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("stream %d result lost or closed", handle.streamID)
	}

	select {
	case err := <-stream.DoneChan:
		if err != nil {
			return nil, err
		}
		return stream.Response, nil
	case <-ctx.Done():
		c.cleanupStream(handle.streamID, ctx.Err())
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
		ID:            streamID,
		Request:       req,
		BodyBuffer:    new(bytes.Buffer),
		Headers:       make(http.Header),
		DoneChan:      make(chan error, 1),
		sendWindow:    int64(c.initialStreamSendWindow),
		recvWindow:    TargetH2StreamWindowSize,
		recvWindowMax: TargetH2StreamWindowSize,
	}
	stream.sendCond = sync.NewCond(&c.mu)
	c.streams[streamID] = stream

	c.lastUsed = time.Now()
	return stream, nil
}

func (c *H2Client) cleanupStream(streamID uint32, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, exists := c.streams[streamID]; exists {
		select {
		case stream.DoneChan <- err:
		default:
		}
		delete(c.streams, streamID)
		stream.sendCond.Broadcast()
	}
	c.lastUsed = time.Now()
}

func (c *H2Client) sendRequest(stream *h2StreamState) error {
	req := stream.Request

	var bodyBytes []byte
	if req.Body != nil && req.GetBody != nil {
		bodyReader, err := req.GetBody()
		if err != nil {
			return fmt.Errorf("failed to get request body: %w", err)
		}
		defer bodyReader.Close()

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

	headerBlock, err := c.encodeHeaders(req, bodyBytes)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to encode headers: %w", err)
	}

	endStream := len(bodyBytes) == 0

	// Calculate padding for HEADERS frame with Request Context
	var padLen uint8
	if c.Config.PaddingStrategy != nil {
		padLen = c.Config.PaddingStrategy.CalculatePadding(req, http2.FrameHeaders, len(headerBlock))
	}

	wh := &writeHeaders{
		streamID:     stream.ID,
		headerBlock:  headerBlock,
		endStream:    endStream,
		maxFrameSize: c.maxFrameSize,
		padLength:    padLen,
	}
	wh.init()
	if wh.maxFrameSize == 0 {
		wh.maxFrameSize = DefaultH2MaxFrameSize
	}

	select {
	case c.writeChan <- wh:
	case <-c.doneChan:
		c.mu.Unlock()
		return fmt.Errorf("connection closed while queuing HEADERS")
	}
	c.mu.Unlock()

	if err := wh.wait(); err != nil {
		return fmt.Errorf("failed to write HEADERS frame: %w", err)
	}

	if endStream {
		return nil
	}

	// -- Send DATA --
	return c.sendData(stream, bodyBytes)
}

func (c *H2Client) sendData(stream *h2StreamState, data []byte) error {

	for len(data) > 0 {
		c.mu.Lock()

		for c.connSendWindow <= 0 || stream.sendWindow <= 0 {
			if !c.isConnected {
				c.mu.Unlock()
				return fmt.Errorf("connection closed while waiting for flow control window")
			}
			if _, exists := c.streams[stream.ID]; !exists {
				c.mu.Unlock()
				return fmt.Errorf("stream closed or cancelled while sending data")
			}
			stream.sendCond.Wait()
		}

		chunkSize := len(data)
		if uint32(chunkSize) > c.maxFrameSize {
			chunkSize = int(c.maxFrameSize)
		}

		// Calculate padding for this DATA frame chunk with Request Context
		var padLen uint8
		if c.Config.PaddingStrategy != nil {
			padLen = c.Config.PaddingStrategy.CalculatePadding(stream.Request, http2.FrameData, chunkSize)
		}

		// RFC 9113: Padding consumes flow control window.
		totalRequired := int64(chunkSize) + int64(padLen)

		availableConn := c.connSendWindow
		availableStream := stream.sendWindow
		availableMaxFrame := int64(c.maxFrameSize)

		limit := availableConn
		if availableStream < limit {
			limit = availableStream
		}
		if availableMaxFrame < limit {
			limit = availableMaxFrame
		}

		if totalRequired > limit {
			// Reduce data payload to fit the padding + data within the window
			reducedDataSize := limit - int64(padLen)

			if reducedDataSize <= 0 {
				// Window is too small to fit even 1 byte + required padding. Wait.
				stream.sendCond.Wait()
				c.mu.Unlock()
				continue
			}
			chunkSize = int(reducedDataSize)
		}

		chunk := data[:chunkSize]
		data = data[chunkSize:]
		isLastChunk := len(data) == 0

		consumed := int64(chunkSize) + int64(padLen)
		c.connSendWindow -= consumed
		stream.sendWindow -= consumed

		wd := &writeData{
			streamID:  stream.ID,
			data:      chunk,
			endStream: isLastChunk,
			padLength: padLen,
		}
		wd.init()

		select {
		case c.writeChan <- wd:
		case <-c.doneChan:
			c.mu.Unlock()
			return fmt.Errorf("connection closed while queuing DATA")
		}
		c.mu.Unlock()

		if err := wd.wait(); err != nil {
			return fmt.Errorf("failed to write DATA frame: %w", err)
		}
	}
	return nil
}

func (c *H2Client) encodeHeaders(req *http.Request, body []byte) ([]byte, error) {
	c.hpackBuf.Reset()

	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":method", Value: req.Method})
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: c.TargetURL.Scheme})

	authority := req.Host
	if authority == "" {
		authority = c.TargetURL.Host
	}
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	c.HPEncoder.WriteField(hpack.HeaderField{Name: ":path", Value: path})

	if len(body) > 0 {
		c.HPEncoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
	} else if req.ContentLength > 0 {
		c.HPEncoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.FormatInt(req.ContentLength, 10)})
	}

	for k, vv := range req.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if canonicalKey == "Host" || canonicalKey == "Content-Length" ||
			canonicalKey == "Connection" || canonicalKey == "Keep-Alive" || canonicalKey == "Proxy-Connection" ||
			canonicalKey == "Transfer-Encoding" || canonicalKey == "Upgrade" {
			continue
		}

		name := strings.ToLower(k)
		for _, v := range vv {
			if name == "cookie" {
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

	result := make([]byte, c.hpackBuf.Len())
	copy(result, c.hpackBuf.Bytes())
	return result, nil
}

// -- Background Loops --

func (c *H2Client) writeLoop() {
	defer c.loopWG.Done()
	const writeTimeout = 15 * time.Second

	for {
		select {
		case <-c.doneChan:
			c.drainWriteQueue(fmt.Errorf("connection closed"))
			return
		case req := <-c.writeChan:
			if c.Conn != nil {
				c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			}

			err := req.writeFrame(c.Framer)

			if c.Conn != nil {
				c.Conn.SetWriteDeadline(time.Time{})
			}

			if err != nil {
				c.Logger.Error("Error writing frame, closing connection", zap.Error(err))
				c.shutdown(http2.ErrCodeInternal, fmt.Errorf("frame write error: %w", err))
				req.handleError(err)
				c.drainWriteQueue(err)
				return
			}
			req.handleError(nil)
		}
	}
}

func (c *H2Client) drainWriteQueue(err error) {
	for {
		select {
		case req := <-c.writeChan:
			req.handleError(err)
		default:
			return
		}
	}
}

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
			ackChan, err := c.sendPing()
			if err != nil {
				c.Logger.Warn("Failed to send H2 PING", zap.Error(err))
				return
			}

			select {
			case <-ackChan:
				c.Logger.Debug("H2 PING ACK received")
			case <-time.After(timeout):
				c.Logger.Error("H2 PING timeout, closing connection")
				c.shutdown(http2.ErrCodeNo, fmt.Errorf("PING timeout"))
				return
			case <-c.doneChan:
				return
			}
		}
	}
}

func (c *H2Client) sendPing() (<-chan struct{}, error) {
	var payload [8]byte
	if _, err := rand.Read(payload[:]); err != nil {
		binary.BigEndian.PutUint64(payload[:], uint64(time.Now().UnixNano()))
	}

	payloadInt := binary.BigEndian.Uint64(payload[:])
	ackChan := make(chan struct{})

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isConnected {
		return nil, fmt.Errorf("connection closed")
	}

	c.pingAcks[payloadInt] = ackChan
	wp := &writePing{data: payload, ack: false}
	wp.init()

	select {
	case c.writeChan <- wp:
	case <-c.doneChan:
		delete(c.pingAcks, payloadInt)
		return nil, fmt.Errorf("connection closed while queuing PING")
	}

	return ackChan, nil
}

func (c *H2Client) readLoop() {
	defer func() {
		c.mu.Lock()
		isConn := c.isConnected
		c.mu.Unlock()

		if isConn {
			c.shutdown(http2.ErrCodeInternal, fmt.Errorf("readLoop exited unexpectedly"))
		}
	}()

	defer c.loopWG.Done()

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
		select {
		case <-c.doneChan:
			return
		default:
		}

		c.Conn.SetReadDeadline(time.Now().Add(readTimeout))
		frame, err := c.Framer.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.Logger.Info("H2 connection read timeout reached, closing.")
				c.shutdown(http2.ErrCodeNo, fmt.Errorf("read timeout"))
				return
			}
			c.Logger.Error("Error reading frame, closing connection", zap.Error(err))
			errCode := http2.ErrCodeInternal
			var se http2.StreamError
			var ce http2.ConnectionError
			if errors.As(err, &se) {
				errCode = se.Code
			} else if errors.As(err, &ce) {
				errCode = http2.ErrCode(ce)
			}

			c.shutdown(errCode, fmt.Errorf("frame read error: %w", err))
			return
		}

		if err := c.processFrame(frame); err != nil {
			c.Logger.Error("Error processing frame, closing connection", zap.Error(err))
			errCode := http2.ErrCodeProtocol
			var se http2.StreamError
			var ce http2.ConnectionError
			if errors.As(err, &se) {
				errCode = se.Code
			} else if errors.As(err, &ce) {
				errCode = http2.ErrCode(ce)
			}
			c.shutdown(errCode, err)
			return
		}
	}
}

func (c *H2Client) processFrame(frame http2.Frame) error {
	streamID := frame.Header().StreamID

	if streamID == 0 {
		return c.processControlFrame(frame)
	}

	c.mu.Lock()
	stream, exists := c.streams[streamID]
	c.mu.Unlock()

	if !exists {
		if frame.Header().Type == http2.FramePushPromise {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		if f, ok := frame.(*http2.DataFrame); ok && len(f.Data()) > 0 {
			c.mu.Lock()
			if c.isConnected {
				c.Framer.WriteWindowUpdate(0, uint32(len(f.Data())))
			}
			c.mu.Unlock()
		}
		return nil
	}

	var streamErr error
	streamEnded := false

	switch f := frame.(type) {
	case *http2.MetaHeadersFrame:
		streamEnded, streamErr = c.processHeadersFrame(stream, f)
	case *http2.DataFrame:
		streamEnded, streamErr = c.processDataFrame(stream, f)
	case *http2.RSTStreamFrame:
		streamErr = H2StreamResetError{ErrCode: f.ErrCode}
		streamEnded = true
	case *http2.WindowUpdateFrame:
		streamErr = c.processWindowUpdateFrame(stream, f)
	case *http2.PriorityFrame:
		// RFC 9113 Section 5.3.2: Priority scheme deprecated.
	default:
	}

	if streamErr != nil {
		var ce http2.ConnectionError
		if errors.As(streamErr, &ce) {
			return ce
		}

		c.Logger.Error("Stream error", zap.Uint32("streamID", streamID), zap.Error(streamErr))

		errCode := http2.ErrCodeInternal
		var se http2.StreamError
		if errors.As(streamErr, &se) {
			errCode = se.Code
		}

		if !streamEnded {
			c.mu.Lock()
			if c.isConnected {
				wrst := &writeRSTStream{streamID: streamID, errCode: errCode}
				wrst.init()
				select {
				case c.writeChan <- wrst:
				default:
					c.Logger.Warn("Failed to queue RST_STREAM (write buffer full)", zap.Uint32("streamID", streamID), zap.Error(streamErr))
				}
			}
			c.mu.Unlock()
		}
		c.cleanupStream(streamID, streamErr)
	} else if streamEnded {
		c.finalizeStream(stream)
	}
	return nil
}

func (c *H2Client) processControlFrame(frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		return c.processSettingsFrame(f)
	case *http2.PingFrame:
		return c.processPingFrame(f)
	case *http2.GoAwayFrame:
		c.shutdown(f.ErrCode, fmt.Errorf("received GOAWAY from server (Error Code: %v)", f.ErrCode))
		return nil
	case *http2.WindowUpdateFrame:
		return c.processWindowUpdateFrame(nil, f)
	default:
		switch f.Header().Type {
		case http2.FrameData, http2.FrameHeaders, http2.FramePriority, http2.FrameRSTStream, http2.FramePushPromise, http2.FrameContinuation:
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return nil
	}
}

func (c *H2Client) processSettingsFrame(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	err := f.ForeachSetting(func(setting http2.Setting) error {
		switch setting.ID {
		case http2.SettingInitialWindowSize:
			newWindowSize := int32(setting.Val)
			if newWindowSize < 0 {
				return http2.ConnectionError(http2.ErrCodeFlowControl)
			}
			delta := int64(newWindowSize) - int64(c.initialStreamSendWindow)
			c.initialStreamSendWindow = newWindowSize

			for _, stream := range c.streams {
				stream.sendWindow += delta
				stream.sendCond.Broadcast()
			}
		case http2.SettingMaxFrameSize:
			if setting.Val < DefaultH2MaxFrameSize || setting.Val > (1<<24-1) {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
			c.maxFrameSize = setting.Val
		case http2.SettingHeaderTableSize:
			c.HPEncoder.SetMaxDynamicTableSize(setting.Val)
		}
		return nil
	})

	if err != nil {
		return err
	}

	if c.isConnected {
		ws := &writeSettings{isAck: true}
		ws.init()
		select {
		case c.writeChan <- ws:
		default:
			c.Logger.Warn("Failed to queue SETTINGS ACK (write buffer full)")
		}
	}
	return nil
}

func (c *H2Client) processPingFrame(f *http2.PingFrame) error {
	if f.IsAck() {
		payloadInt := binary.BigEndian.Uint64(f.Data[:])
		c.mu.Lock()
		if ackChan, exists := c.pingAcks[payloadInt]; exists {
			close(ackChan)
			delete(c.pingAcks, payloadInt)
		}
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.isConnected {
			wp := &writePing{data: f.Data, ack: true}
			wp.init()
			select {
			case c.writeChan <- wp:
			default:
				c.Logger.Warn("Failed to queue PING ACK (write buffer full)")
			}
		}
	}
	return nil
}

func (c *H2Client) processWindowUpdateFrame(stream *h2StreamState, f *http2.WindowUpdateFrame) error {
	increment := f.Increment
	if increment == 0 {
		if stream == nil {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if stream == nil {
		if c.connSendWindow > math.MaxInt64-int64(increment) {
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
		c.connSendWindow += int64(increment)
		for _, s := range c.streams {
			s.sendCond.Broadcast()
		}

	} else {
		if _, exists := c.streams[stream.ID]; !exists {
			return nil
		}

		if stream.sendWindow > math.MaxInt64-int64(increment) {
			return http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeFlowControl}
		}
		stream.sendWindow += int64(increment)
		stream.sendCond.Broadcast()
	}
	return nil
}

func (c *H2Client) processHeadersFrame(stream *h2StreamState, f *http2.MetaHeadersFrame) (bool, error) {
	isTrailer := stream.StatusCode != 0

	if isTrailer && !f.StreamEnded() {
		return false, nil
	}

	for _, hf := range f.Fields {
		if strings.HasPrefix(hf.Name, ":") {
			if isTrailer {
				return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
			}
			if hf.Name == ":status" {
				status, err := strconv.Atoi(hf.Value)
				if err != nil {
					return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
				}
				stream.StatusCode = status
			}
		} else {
			stream.Headers.Add(hf.Name, hf.Value)
		}
	}

	if !isTrailer && stream.StatusCode == 0 {
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	return f.StreamEnded(), nil
}

func (c *H2Client) processDataFrame(stream *h2StreamState, f *http2.DataFrame) (bool, error) {
	if stream.StatusCode == 0 {
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeProtocol}
	}

	data := f.Data()
	dataLen := len(data)

	if dataLen == 0 {
		return f.StreamEnded(), nil
	}

	c.mu.Lock()
	if c.connRecvWindow < int64(dataLen) {
		c.mu.Unlock()
		return false, http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	if stream.recvWindow < int32(dataLen) {
		c.mu.Unlock()
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeFlowControl}
	}

	c.connRecvWindow -= int64(dataLen)
	stream.recvWindow -= int32(dataLen)

	connUpdate := c.maybeSendWindowUpdate(0, c.connRecvWindow, c.connRecvWindowMax)
	streamUpdate := c.maybeSendWindowUpdate(stream.ID, int64(stream.recvWindow), int64(stream.recvWindowMax))

	if connUpdate > 0 {
		c.connRecvWindow += int64(connUpdate)
	}
	if streamUpdate > 0 {
		stream.recvWindow += int32(streamUpdate)
	}
	c.mu.Unlock()

	if stream.BodyBuffer.Len()+dataLen > MaxResponseBodyBytes {
		return false, http2.StreamError{StreamID: stream.ID, Code: http2.ErrCodeCancel, Cause: fmt.Errorf("response body exceeded limit (%d bytes)", MaxResponseBodyBytes)}
	}

	stream.BodyBuffer.Write(data)
	return f.StreamEnded(), nil
}

func (c *H2Client) maybeSendWindowUpdate(streamID uint32, currentWindow, maxWindow int64) uint32 {
	threshold := maxWindow / 2
	if currentWindow <= threshold {
		increment := uint32(maxWindow - currentWindow)
		if increment > 0 && c.isConnected {
			wwu := &writeWindowUpdate{streamID: streamID, increment: increment}
			wwu.init()
			select {
			case c.writeChan <- wwu:
				return increment
			default:
				c.Logger.Warn("Failed to queue WINDOW_UPDATE (write buffer full)", zap.Uint32("streamID", streamID))
				return 0
			}
		}
	}
	return 0
}

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
	}

	if clHeader := resp.Header.Get("Content-Length"); clHeader != "" {
		cl, err := strconv.ParseInt(clHeader, 10, 64)
		if err == nil && cl != resp.ContentLength {
			c.Logger.Warn("Content-Length mismatch", zap.Int64("header", cl), zap.Int64("actual", resp.ContentLength))
		}
	}

	stream.Response = resp

	select {
	case stream.DoneChan <- nil:
	default:
	}
	delete(c.streams, stream.ID)
	c.lastUsed = time.Now()
}

// -- Write Request Implementations --

type baseWriteRequest struct {
	doneChan chan error
}

func (b *baseWriteRequest) init() {
	b.doneChan = make(chan error, 1)
}

func (b *baseWriteRequest) handleError(err error) {
	select {
	case b.doneChan <- err:
	default:
	}
}

func (b *baseWriteRequest) wait() error {
	return <-b.doneChan
}

type writeSettings struct {
	baseWriteRequest
	settings []http2.Setting
	isAck    bool
}

func (w *writeSettings) writeFrame(f *http2.Framer) error {
	if w.isAck {
		return f.WriteSettingsAck()
	}
	return f.WriteSettings(w.settings...)
}

type writeWindowUpdate struct {
	baseWriteRequest
	streamID  uint32
	increment uint32
}

func (w *writeWindowUpdate) writeFrame(f *http2.Framer) error {
	return f.WriteWindowUpdate(w.streamID, w.increment)
}

type writePing struct {
	baseWriteRequest
	data [8]byte
	ack  bool
}

func (w *writePing) writeFrame(f *http2.Framer) error {
	return f.WritePing(w.ack, w.data)
}

type writeRSTStream struct {
	baseWriteRequest
	streamID uint32
	errCode  http2.ErrCode
}

func (w *writeRSTStream) writeFrame(f *http2.Framer) error {
	return f.WriteRSTStream(w.streamID, w.errCode)
}

type writeHeaders struct {
	baseWriteRequest
	streamID     uint32
	headerBlock  []byte
	endStream    bool
	maxFrameSize uint32
	padLength    uint8
}

func (w *writeHeaders) writeFrame(f *http2.Framer) error {
	// Handle fragmentation (CONTINUATION frames).

	// Check if we can fit everything (header block + padding) in one frame
	// RFC 9113: Padding only on HEADERS frame, NOT on CONTINUATION.
	if uint32(len(w.headerBlock)) <= w.maxFrameSize {
		return f.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      w.streamID,
			BlockFragment: w.headerBlock,
			EndStream:     w.endStream,
			EndHeaders:    true,
			PadLength:     w.padLength,
		})
	}

	// Needs CONTINUATION frames.
	// 1. Send initial HEADERS frame (with padding if specified).
	chunk := w.headerBlock[:w.maxFrameSize]
	w.headerBlock = w.headerBlock[w.maxFrameSize:]

	err := f.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      w.streamID,
		BlockFragment: chunk,
		EndStream:     w.endStream,
		EndHeaders:    false,
		PadLength:     w.padLength, // Padding only on initial HEADERS
	})
	if err != nil {
		return err
	}

	// 2. Send CONTINUATION frames (No Padding).
	for len(w.headerBlock) > 0 {
		chunkSize := uint32(len(w.headerBlock))
		endHeaders := false
		if chunkSize > w.maxFrameSize {
			chunkSize = w.maxFrameSize
		} else {
			endHeaders = true
		}

		chunk := w.headerBlock[:chunkSize]
		w.headerBlock = w.headerBlock[chunkSize:]

		err := f.WriteContinuation(w.streamID, endHeaders, chunk)
		if err != nil {
			return err
		}
	}

	return nil
}

type writeData struct {
	baseWriteRequest
	streamID  uint32
	data      []byte
	endStream bool
	padLength uint8
}

func (w *writeData) writeFrame(f *http2.Framer) error {
	if w.padLength > 0 {
		// RFC 9113 allow padding on DATA frames.
		// WriteDataPadded helper handles structure.
		// Note: The data slice is the payload, the padding bytes are appended as zeros by the framer.
		return f.WriteDataPadded(w.streamID, w.endStream, w.data, []byte(strings.Repeat("\x00", int(w.padLength))))
	}
	return f.WriteData(w.streamID, w.endStream, w.data)
}

type writeGoAway struct {
	baseWriteRequest
	maxStreamID uint32
	code        http2.ErrCode
	debugData   []byte
}

func (w *writeGoAway) writeFrame(f *http2.Framer) error {
	return f.WriteGoAway(w.maxStreamID, w.code, w.debugData)
}
