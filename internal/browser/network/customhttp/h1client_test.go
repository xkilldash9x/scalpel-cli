// internal/browser/network/customhttp/h1client_test.go
package customhttp

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// Switched from custom mockConn based on bytes.Buffer to net.Pipe() for reliable simulation of network I/O and deadlines.

func TestH1Client_Do_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	targetURL, _ := url.Parse("http://example.com")

	client, err := NewH1Client(targetURL, config, logger)
	require.NoError(t, err)

	// Use net.Pipe to simulate a connection
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	client.Conn = clientConn
	client.bufReader = bufio.NewReader(clientConn)
	client.isConnected = true

	// Simulate server side
	go func() {
		// Read the request sent by the client
		r := bufio.NewReader(serverConn)
		reqRead, err := http.ReadRequest(r)
		if err != nil {
			// Handle potential closed pipe error if client closes first
			// t.Logf("Server failed to read request: %v", err)
			return
		}

		// Basic validation of the received request
		if reqRead.Method != "GET" || reqRead.Host != "example.com" {
			t.Logf("Server received unexpected request: %v %v", reqRead.Method, reqRead.Host)
		}

		// Send response
		response := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Length: 12\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n" +
			"hello world!"
		serverConn.Write([]byte(response))
	}()

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp, err := client.Do(context.Background(), req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello world!", string(body))
}

func TestH1Client_ConnectionClose(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	targetURL, _ := url.Parse("http://example.com")

	client, err := NewH1Client(targetURL, config, logger)
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	client.Conn = clientConn
	client.bufReader = bufio.NewReader(clientConn)
	client.isConnected = true

	go func() {
		r := bufio.NewReader(serverConn)
		http.ReadRequest(r) // Read request

		response := "HTTP/1.1 204 No Content\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		serverConn.Write([]byte(response))
	}()

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	_, err = client.Do(context.Background(), req)
	require.NoError(t, err)

	// The client should detect "Connection: close" and update its state.
	assert.False(t, client.isConnected)
}

// TestH1Client_RequestTimeout verifies the client respects the RequestTimeout configuration.
func TestH1Client_RequestTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := NewBrowserClientConfig()
	// Set a short timeout
	config.RequestTimeout = 50 * time.Millisecond
	targetURL, _ := url.Parse("http://example.com")

	client, err := NewH1Client(targetURL, config, logger)
	require.NoError(t, err)

	// Use net.Pipe() which correctly simulates blocking I/O and respects SetDeadline.
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	client.Conn = clientConn
	client.bufReader = bufio.NewReader(clientConn)
	client.isConnected = true

	// Server side: Read the request but never respond
	go func() {
		reader := bufio.NewReader(serverConn)
		// Read the request to ensure the client finishes sending the request.
		_, err := http.ReadRequest(reader)
		if err != nil {
			// Expected if connection closes due to timeout on client side (e.g., EOF or reset).
			return
		}
		// Intentionally do not respond to trigger the client timeout.
		time.Sleep(200 * time.Millisecond)
	}()

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	startTime := time.Now()
	_, err = client.Do(context.Background(), req)
	duration := time.Since(startTime)

	require.Error(t, err)

	// Check that the duration is approximately the timeout value.
	assert.GreaterOrEqual(t, duration, 50*time.Millisecond)

	// Check the error type. When using net.Pipe and SetDeadline, the error returned
	// on timeout typically contains "i/o timeout".
	assert.Contains(t, err.Error(), "i/o timeout")
}

func TestSerializeRequest(t *testing.T) {
	t.Run("GET request", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/path", nil)
		req.Header.Set("User-Agent", "Test")

		// Ensure GetBody is initialized, mimicking CustomClient behavior.
		ensureBodyReplayable(req)

		serialized, err := SerializeRequest(req)
		require.NoError(t, err)

		s := string(serialized)
		assert.True(t, strings.HasPrefix(s, "GET /path HTTP/1.1\r\n"))
		assert.Contains(t, s, "Host: example.com\r\n")
		assert.Contains(t, s, "User-Agent: Test\r\n")
		assert.Contains(t, s, "Connection: keep-alive\r\n")
	})

	t.Run("POST request with body", func(t *testing.T) {
		body := "field=value"
		req, _ := http.NewRequest("POST", "https://example.com/submit", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Ensure body is replayable as SerializeRequest reads the body to calculate length and serialize.
		ensureBodyReplayable(req)

		serialized, err := SerializeRequest(req)
		require.NoError(t, err)

		s := string(serialized)
		assert.Contains(t, s, "POST /submit HTTP/1.1\r\n")
		assert.Contains(t, s, "Host: example.com\r\n")
		assert.Contains(t, s, "Content-Type: application/x-www-form-urlencoded\r\n")
		assert.Contains(t, s, "Content-Length: 11\r\n")
		assert.True(t, strings.HasSuffix(s, "\r\n\r\nfield=value"))
	})
}
