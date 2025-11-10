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
// Signature updated to accept t *testing.T
func setupH2Client(t *testing.T, conn net.Conn) (*H2Client, error) {
	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
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

	// Start the readLoop as Connect() is bypassed.
	client.loopWG.Add(1)
	go client.readLoop()

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
