// internal/browser/network/customhttp/h2client_test.go
package customhttp

import (
	"bytes" // Added import
	"context"
	"io"
	"net" // Added import
	"net/http"
	"net/url"
	"strings" // Added import
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// setupH2Client initializes an H2Client with a mocked connection for unit testing.
// It bypasses the actual network dialing and TLS handshake.
// Uses default config.
func setupH2Client(t *testing.T, conn net.Conn) (*H2Client, error) {
	return setupH2ClientWithConfig(t, conn, NewBrowserClientConfig())
}

// setupH2ClientWithConfig initializes an H2Client with a mocked connection and custom config.
func setupH2ClientWithConfig(t *testing.T, conn net.Conn, config *ClientConfig) (*H2Client, error) {
	logger := zaptest.NewLogger(t)
	// This just needs *a* valid URL for setup, mockConn bypasses actual connection.
	targetURL, _ := url.Parse("https://example.com")

	client, err := NewH2Client(targetURL, config, logger)

	if err != nil {
		return nil, err
	}

	client.Conn = conn
	client.Framer = http2.NewFramer(conn, conn)
	client.Framer.ReadMetaHeaders = client.HPDecoder // Crucial for MetaHeadersFrame processing
	client.isConnected = true

	// Start background loops as Connect() is bypassed.
	loopsToStart := 2 // readLoop and writeLoop
	if config.H2Config.PingInterval > 0 {
		loopsToStart++ // pingLoop
	}
	client.loopWG.Add(loopsToStart)

	go client.readLoop()
	go client.writeLoop()

	if config.H2Config.PingInterval > 0 {
		go client.pingLoop()
	}

	return client, nil
}

func TestH2Client_Do_Success(t *testing.T) {
	// Use net.Pipe for a concrete, working example simulating network I/O.
	clientConn, serverConn := net.Pipe()

	client, err := setupH2Client(t, clientConn)
	require.NoError(t, err)
	defer client.Close()

	// --- Server-side simulation ---
	go func() {
		defer serverConn.Close()
		framer := http2.NewFramer(serverConn, serverConn)

		// Since isConnected=true, Do() will not call Connect(). It proceeds directly to initializeStream and sendRequest.

		// Read client's first request (HEADERS).
		// Set a timeout for reading frames to prevent tests from hanging.
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Logf("Server error reading frame: %v", err)
			return
		}

		headersFrame, ok := frame.(*http2.HeadersFrame)
		if !ok {
			t.Logf("Server expected HEADERS frame, got %T", frame)
			return
		}
		assert.True(t, headersFrame.StreamEnded())

		// Send response
		var hpackBuf bytes.Buffer
		encoder := hpack.NewEncoder(&hpackBuf)
		encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})

		framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      headersFrame.StreamID,
			BlockFragment: hpackBuf.Bytes(),
			EndHeaders:    true,
		})
		framer.WriteData(headersFrame.StreamID, true, []byte("hello h2"))
	}()
	// --- End server simulation ---

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// Patch the TargetURL and Address as Do() uses them.
	client.TargetURL, _ = url.Parse("https://example.com")
	client.Address = "example.com:443"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Do(ctx, req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "hello h2", string(body))
}

func TestH2Client_FlowControl(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	client, err := setupH2Client(t, clientConn)
	require.NoError(t, err)
	defer client.Close()

	// Patch URL and Address
	client.TargetURL, _ = url.Parse("https://example.com")
	client.Address = "example.com:443"

	// Reduce window size for testing
	client.connSendWindow = 10
	client.initialStreamSendWindow = 10

	go func() {
		defer serverConn.Close()
		// Mock server behavior
		framer := http2.NewFramer(serverConn, serverConn)

		// Set timeout for reading frames
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Read headers
		_, err := framer.ReadFrame() // Headers
		if err != nil {
			t.Logf("Server error reading Headers frame: %v", err)
			return
		}

		// Read initial data (10 bytes)
		dataFrame1, err := framer.ReadFrame() // First data chunk
		if err != nil {
			t.Logf("Server error reading Data frame 1: %v", err)
			return
		}
		assert.Equal(t, 10, len(dataFrame1.(*http2.DataFrame).Data()))

		// At this point, client is blocked. Send window update.
		framer.WriteWindowUpdate(0, 100) // Connection window
		framer.WriteWindowUpdate(1, 100) // Stream window

		// Read remaining data
		for {
			frame, err := framer.ReadFrame()
			if err != nil {
				t.Logf("Server error reading subsequent Data frames: %v", err)
				return
			}
			if df, ok := frame.(*http2.DataFrame); ok && df.StreamEnded() {
				break
			}
		}

		// Send response
		var hpackBuf bytes.Buffer
		encoder := hpack.NewEncoder(&hpackBuf)
		encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
		framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: hpackBuf.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		})
	}()

	body := "this is a long body that will exceed the flow control window"
	req, _ := http.NewRequest("POST", "https://example.com", strings.NewReader(body))
	// Need to set GetBody for H2Client
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Do(ctx, req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 204, resp.StatusCode)
}

// TestH2Client_WriteLoop_Concurrency verifies that writes do not block the main lock (c.mu).
func TestH2Client_WriteLoop_Concurrency(t *testing.T) {
	// Use net.Pipe. The key here is that if the reader (server) stops reading, the writer (client) will block.
	clientConn, serverConn := net.Pipe()

	// Disable PINGs to simplify the test.
	config := NewBrowserClientConfig()
	config.H2Config.PingInterval = 0

	client, err := setupH2ClientWithConfig(t, clientConn, config)
	require.NoError(t, err)
	defer client.Close()

	// --- Server-side simulation (Minimal) ---
	go func() {
		// Read HEADERS, then stop reading to cause the client's DATA write to block.
		defer serverConn.Close()
		framer := http2.NewFramer(serverConn, serverConn)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := framer.ReadFrame() // Read Headers
		if err != nil {
			t.Logf("Server error reading Headers: %v", err)
			return
		}
		// Intentionally stop reading here.
		time.Sleep(5 * time.Second)
	}()
	// --- End server simulation ---

	// Start a large POST request.
	// The body size needs to be large enough to fill the TCP buffer and block the writeLoop.
	postBody := strings.Repeat("A", 1*1024*1024) // 1MB body
	postReq, _ := http.NewRequest("POST", "https://example.com/upload", strings.NewReader(postBody))
	postReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(postBody)), nil
	}

	writeStarted := make(chan struct{})
	go func() {
		close(writeStarted)
		// This will eventually block in the writeLoop.
		client.Do(context.Background(), postReq)
	}()

	<-writeStarted
	// Give the writeLoop time to start processing and potentially block.
	time.Sleep(100 * time.Millisecond)

	// Try to acquire the lock. If the write operation held the lock (pre-fix behavior), this would block.
	lockAcquired := make(chan bool)
	go func() {
		client.mu.Lock()
		lockAcquired <- true
		client.mu.Unlock()
	}()

	select {
	case <-lockAcquired:
		// Success: Lock acquired quickly, meaning writeLoop is not holding it while blocked.
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out acquiring client lock. writeLoop is likely blocking while holding the lock.")
	}
}

func TestH2Client_Do_LargeHeaders_Continuation(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	client, err := setupH2Client(t, clientConn)
	require.NoError(t, err)
	defer client.Close()

	// Generate a large header value (e.g., 64KB). Default max frame size is 16KB.
	// We use a larger value to ensure HPACK compression doesn't reduce it below 16KB.
	// 'a' repeats compress well, so we need a significant multiplier.
	largeValue := strings.Repeat("a", 64*1024)

	// --- Server-side simulation ---
	serverReceivedContinuation := false
	go func() {
		defer serverConn.Close()
		framer := http2.NewFramer(serverConn, serverConn)

		// Expect HEADERS frame followed by CONTINUATION frame(s).

		// Read first frame (HEADERS).
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Logf("Server error reading HEADERS frame: %v", err)
			return
		}

		headersFrame, ok := frame.(*http2.HeadersFrame)
		if !ok {
			t.Logf("Server expected HEADERS frame, got %T", frame)
			return
		}

		// Check if EndHeaders is false (indicating CONTINUATION follows)
		if !headersFrame.Header().Flags.Has(http2.FlagHeadersEndHeaders) {
			// Expect CONTINUATION frame.
			frame, err = framer.ReadFrame()
			if err != nil {
				t.Logf("Server error reading CONTINUATION frame: %v", err)
				return
			}
			_, ok := frame.(*http2.ContinuationFrame)
			if ok {
				serverReceivedContinuation = true
			}
		}

		// Send response (simplified)
		var hpackBuf bytes.Buffer
		encoder := hpack.NewEncoder(&hpackBuf)
		encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      1,
			BlockFragment: hpackBuf.Bytes(),
			EndHeaders:    true,
			EndStream:     true,
		})
	}()
	// --- End server simulation ---

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("X-Large-Header", largeValue)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Do(ctx, req)

	// Before the fix, this would fail with "frame too large" or similar errors.
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	// Verify that the server actually saw a CONTINUATION frame.
	assert.True(t, serverReceivedContinuation, "Server should have received a CONTINUATION frame for large headers")
}

// TestH2Client_Shutdown_NoDeadlock verifies that the client does not deadlock
// if a background loop (e.g., pingLoop or readLoop) initiates connection closure.
func TestH2Client_Shutdown_NoDeadlock(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Configure client with very short PING timeout to trigger shutdown via pingLoop.
	config := NewBrowserClientConfig()
	config.H2Config.PingInterval = 10 * time.Millisecond
	config.H2Config.PingTimeout = 10 * time.Millisecond

	client, err := setupH2ClientWithConfig(t, clientConn, config)
	require.NoError(t, err)

	// --- Server-side simulation ---
	go func() {
		defer serverConn.Close()
		framer := http2.NewFramer(serverConn, serverConn)

		// Read PING frames but never respond (do not send ACK).
		for {
			serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			frame, err := framer.ReadFrame()
			if err != nil {
				// Expected when client closes connection due to timeout.
				return
			}
			if pingFrame, ok := frame.(*http2.PingFrame); ok && !pingFrame.IsAck() {
				// Received PING, intentionally ignore it.
			}
		}
	}()
	// --- End server simulation ---

	// Wait for the client to detect the PING timeout and close itself.
	// If the deadlock exists (pre-fix), this wait will hang because the pingLoop
	// calls Close/closeWithError which waits for loopWG, but pingLoop hasn't called loopWG.Done() yet.

	done := make(chan struct{})
	go func() {
		// Wait for the loops to finish. This is what loopWG.Wait() inside Close() does.
		// After the fix, pingLoop calls shutdown() (which doesn't wait) and then exits, calling Done().
		client.loopWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: loops finished, no deadlock.
		client.mu.Lock()
		assert.False(t, client.isConnected)
		assert.Error(t, client.fatalError)
		if client.fatalError != nil {
			assert.Contains(t, client.fatalError.Error(), "PING timeout")
		}
		client.mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out waiting for H2Client loops to stop. Potential deadlock detected.")
	}
}
