package network_test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/pkg/network"
)

const testBody = "Hello, world! This is a compressible string."

// Helper to create a compressed buffer
func compressData(t *testing.T, data string, encoding string) *bytes.Buffer {
	buf := new(bytes.Buffer)
	var writer io.WriteCloser

	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(buf)
	case "deflate":
		writer = zlib.NewWriter(buf)
	case "br":
		// Brotli writer needs to be closed to flush the buffer.
		brWriter := brotli.NewWriter(buf)
		writer = struct {
			io.Writer
			io.Closer
		}{brWriter, brWriter}
	default:
		t.Fatalf("Unsupported encoding: %s", encoding)
	}

	_, err := writer.Write([]byte(data))
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)
	return buf
}

func TestCompressionMiddleware_Integration(t *testing.T) {
	testCases := []struct {
		name     string
		encoding string
	}{
		{"Gzip", "gzip"},
		{"Deflate", "deflate"},
		{"Brotli", "br"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Setup a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the middleware added the Accept-Encoding header
				assert.Contains(t, r.Header.Get("Accept-Encoding"), tc.encoding)

				// Send compressed response
				compressedBody := compressData(t, testBody, tc.encoding)

				w.Header().Set("Content-Encoding", tc.encoding)
				w.Write(compressedBody.Bytes())
			}))
			defer server.Close()

			// 2. Setup client with middleware
			transport := network.NewCompressionMiddleware(http.DefaultTransport)
			client := &http.Client{Transport: transport}

			// 3. Execute request
			resp, err := client.Get(server.URL)
			require.NoError(t, err)
			defer resp.Body.Close()

			// 4. Verify results
			// The middleware should have removed the Content-Encoding header
			assert.Empty(t, resp.Header.Get("Content-Encoding"), "Content-Encoding header should have been removed")
			assert.True(t, resp.Uncompressed, "Response Uncompressed field should be true")

			// The body should be transparently decompressed
			bodyBytes, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, testBody, string(bodyBytes))
		})
	}
}

func TestCompressionMiddleware_HeaderHandling(t *testing.T) {
    // Test that the middleware does not override an explicitly set Accept-Encoding header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Verify the header was NOT overridden
        assert.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
		w.Write([]byte(testBody))
	}))
	defer server.Close()

	transport := network.NewCompressionMiddleware(http.DefaultTransport)
	client := &http.Client{Transport: transport}

    req, _ := http.NewRequest("GET", server.URL, nil)
    req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	require.NoError(t, err)
    defer resp.Body.Close()

    assert.False(t, resp.Uncompressed)
}
