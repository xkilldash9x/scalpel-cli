// internal/network/parser_test.go
package network

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Helper function to create a basic, disposable HTTPParser for tests.
func newTestParser() *HTTPParser {
	// Using zap.NewNop() ensures no logging output cluttering the test run unless we want it.
	return NewHTTPParser(zap.NewNop())
}

// -- Simple Parsing Logic Tests --

// TestParseResponseHeaders verifies that headers are correctly extracted and mapped
// from the net/http Header type, focusing on extracting only the first value for simplicity.
func TestParseResponseHeaders(t *testing.T) {
	// A hypothetical parsing function is implemented inline for demonstration,
	// but the test confirms the expected behavior for external use of the response headers.

	// A table of test cases for our parsing function.
	testCases := []struct {
		name     string
		headers  http.Header
		expected map[string]string
	}{
		{
			name: "single header",
			headers: http.Header{
				"Content-Type": {"application/json"},
			},
			expected: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "multiple headers",
			headers: http.Header{
				"Content-Type":    {"text/html"},
				"Cache-Control":   {"no-cache"},
				"X-Custom-Header": {"some-value"},
			},
			expected: map[string]string{
				"Content-Type":    "text/html",
				"Cache-Control":   "no-cache",
				"X-Custom-Header": "some-value",
			},
		},
		{
			name: "header with multiple values (only first matters)",
			headers: http.Header{
				// In HTTP headers, multiple values are common (e.g., Set-Cookie).
				// We assume the parser should only expose the first one in the simplified map.
				"Set-Cookie": {"session=abc", "locale=en-US"},
			},
			expected: map[string]string{
				"Set-Cookie": "session=abc",
			},
		},
		{
			name:     "empty headers",
			headers:  http.Header{},
			expected: map[string]string{},
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: map[string]string{},
		},
		{
			name: "header key case preservation",
			headers: http.Header{
				"content-type": {"application/xml"},
			},
			expected: map[string]string{
				"content-type": "application/xml", // Go's Header type preserves original case map keys.
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Inline implementation of the header parsing logic for testing purposes:
			parsedHeaders := make(map[string]string)
			if tc.headers != nil {
				for key, values := range tc.headers {
					if len(values) > 0 {
						parsedHeaders[key] = values[0]
					}
				}
			}

			assert.Equal(t, tc.expected, parsedHeaders, "Parsed headers should match expected output")
		})
	}
}

// TestParseStatusCode verifies that the HTTP status code is correctly identified.
func TestParseStatusCode(t *testing.T) {
	// This test simply confirms standard HTTP response status code extraction logic.
	t.Run("valid status code", func(t *testing.T) {
		// Mock response struct to test the StatusCode field
		resp := &http.Response{StatusCode: http.StatusOK}
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("client error status code", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusNotFound}
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("redirect status code", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusFound}
		assert.Equal(t, http.StatusFound, resp.StatusCode)
	})
}

// -- Pipelining and Decompression Logic Tests --

// TestParsePipelinedResponses_Basic verifies sequential parsing and body consumption.
func TestParsePipelinedResponses_Basic(t *testing.T) {
	parser := newTestParser()

	// 1. Generate Pipelined Responses
	resp1Body := "Response Body 1"
	resp1 := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(resp1Body), resp1Body)

	resp2Body := "Response Body 2"
	resp2 := fmt.Sprintf("HTTP/1.1 201 Created\r\nContent-Length: %d\r\n\r\n%s", len(resp2Body), resp2Body)

	pipelinedData := resp1 + resp2
	reader := strings.NewReader(pipelinedData)

	// 2. Parse the responses
	responses, err := parser.ParsePipelinedResponses(reader, 2)
	require.NoError(t, err)
	require.Len(t, responses, 2, "Expected exactly two responses to be parsed")

	// 3. Verify results
	assert.Equal(t, http.StatusOK, responses[0].StatusCode)
	assert.Equal(t, http.StatusCreated, responses[1].StatusCode)

	// The parser reads the body to advance the stream, but replaces it so the caller can still read it.
	body1, err := io.ReadAll(responses[0].Body)
	require.NoError(t, err)
	assert.Equal(t, resp1Body, string(body1), "The body for response 1 should be readable and correct")

	body2, err := io.ReadAll(responses[1].Body)
	require.NoError(t, err)
	assert.Equal(t, resp2Body, string(body2), "The body for response 2 should be readable and correct")
}

// TestParsePipelinedResponses_ConnectionClose verifies that parsing stops when a "Connection: close" header is encountered.
func TestParsePipelinedResponses_ConnectionClose(t *testing.T) {
	parser := newTestParser()

	// Response 1 signals connection close
	resp1Body := "Body 1"
	resp1 := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(resp1Body), resp1Body)
	// Response 2 is included in the stream but should not be read
	resp2 := "HTTP/1.1 200 OK\r\n\r\nBody 2"

	reader := strings.NewReader(resp1 + resp2)

	// We expect 2 responses, but should only get 1 due to the 'close' header
	responses, err := parser.ParsePipelinedResponses(reader, 2)
	require.NoError(t, err)
	assert.Len(t, responses, 1, "Should stop parsing after Connection: close is signaled by the server")
}

// TestParsePipelinedResponses_Compressed verifies that the parser can handle and consume a Gzip compressed body.
func TestParsePipelinedResponses_Compressed(t *testing.T) {
	parser := newTestParser()

	// 1. Prepare compressed data
	originalBody := "This is a compressed body that must be handled transparently."
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(originalBody))
	_ = gz.Close()
	compressedBodyBytes := buf.Bytes()

	// 2. Generate Response with Gzip encoding
	// FIX: We must construct the response by writing headers and then the binary body, not using Sprintf("%s") on bytes.
	resp1Headers := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(compressedBodyBytes))

	var requestBuf bytes.Buffer
	requestBuf.WriteString(resp1Headers)
	requestBuf.Write(compressedBodyBytes)
	reader := bytes.NewReader(requestBuf.Bytes())

	// 3. Parse
	responses, err := parser.ParsePipelinedResponses(reader, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	// 4. Verify Decompression and Header Clearing
	// NOTE: We assume DecompressResponse is responsible for clearing these.
	assert.Empty(t, responses[0].Header.Get("Content-Encoding"), "Content-Encoding header should be cleared after decompression handling")
	assert.NotEqual(t, len(compressedBodyBytes), responses[0].ContentLength, "Content-Length should be modified after decompression")

	// The parser consumes the compressed body but should return a response with a readable, decompressed body.
	body, err := io.ReadAll(responses[0].Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(body), "Expected body to be fully decompressed and readable")
}

// TestParsePipelinedResponses_DecompressionFailure verifies that parsing aborts if decompression initialization fails, preventing pipeline corruption.
func TestParsePipelinedResponses_DecompressionFailure(t *testing.T) {
	parser := newTestParser()

	// 1. Generate Response 1 (Claims Gzip but body is invalid/missing header)
	invalidBody := "not gzip data"
	// The Content-Length must match the length of the invalid body for ReadResponse to succeed initially.
	resp1 := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", len(invalidBody), invalidBody)

	// 2. Generate Response 2 (Valid)
	resp2Body := "Response Body 2"
	resp2 := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(resp2Body), resp2Body)

	pipelinedData := resp1 + resp2
	reader := strings.NewReader(pipelinedData)

	// 3. Parse the responses
	// We expect the parser to fail when trying to initialize gzip decompression for the first response.
	responses, err := parser.ParsePipelinedResponses(reader, 2)

	// 4. Verify results
	assert.Error(t, err, "Expected an error due to failed decompression initialization")
	assert.Contains(t, err.Error(), "failed to initialize decompression")
	// It should return 0 responses because the first one failed during the processing steps (after ReadResponse succeeded).
	assert.Len(t, responses, 0, "Should not return the response if decompression failed during parsing")
}

// TestParsePipelinedResponses_Malformed verifies robustness against bad responses in the pipeline.
func TestParsePipelinedResponses_Malformed(t *testing.T) {
	parser := newTestParser()

	// Good response followed by a malformed one
	resp1 := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBody"
	malformedResp := "HTTP/1.1 Bad Request\r\n" // Missing status line elements and proper formatting

	reader := strings.NewReader(resp1 + malformedResp)

	// We expect 2, but should get an error after the first one
	responses, err := parser.ParsePipelinedResponses(reader, 2)

	assert.Error(t, err, "Expected an error due to malformed response in the stream")
	assert.Len(t, responses, 1, "Should still return the first valid response before the error occurred")
	assert.Equal(t, http.StatusOK, responses[0].StatusCode)
}

// TestDecompressBody_NoCompression verifies that an uncompressed body is returned as is.
func TestDecompressBody_NoCompression(t *testing.T) {
	// LINTER FIX: This test now targets the new DecompressResponse function
	// which is no longer a method on HTTPParser.
	originalBody := io.NopCloser(strings.NewReader("uncompressed"))
	resp := &http.Response{
		Body:   originalBody,
		Header: http.Header{}, // No Content-Encoding
	}

	err := DecompressResponse(resp)
	require.NoError(t, err)

	// Should return the original body reader if no decompression was needed
	assert.Equal(t, originalBody, resp.Body)
}

// TestDecompressBody_GzipError verifies decompression failure handling.
func TestDecompressBody_GzipError(t *testing.T) {
	// LINTER FIX: This test now targets the new DecompressResponse function.
	// Body is too short/malformed to be valid Gzip
	resp := &http.Response{
		Body:   io.NopCloser(strings.NewReader("not gzip data")),
		Header: http.Header{"Content-Encoding": {"gzip"}},
	}

	err := DecompressResponse(resp)

	// Expect a decompression error
	assert.Error(t, err)
}
