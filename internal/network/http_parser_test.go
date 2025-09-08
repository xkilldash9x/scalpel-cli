package network

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Test Setup Helpers --

// Generates a raw byte stream containing multiple HTTP responses.
func createPipelinedResponseStream(responses []string) io.Reader {
	// Use strings.Join with an empty separator as the responses already contain necessary CRLF.
	return bytes.NewBufferString(strings.Join(responses, ""))
}

// Define standard response formats for testing. Adherence to CRLF is critical.
const (
	responseTemplateCL      = "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s"
	responseTemplateChunked = "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%s"
)

func formatResponseCL(status int, body string) string {
	return fmt.Sprintf(responseTemplateCL, status, http.StatusText(status), len(body), body)
}

func formatResponseChunked(status int, chunks []string) string {
	var chunkedBody string
	for _, chunk := range chunks {
		// Format: <length in hex>\r\n<data>\r\n
		chunkedBody += fmt.Sprintf("%x\r\n%s\r\n", len(chunk), chunk)
	}
	chunkedBody += "0\r\n\r\n" // End chunk
	return fmt.Sprintf(responseTemplateChunked, status, http.StatusText(status), chunkedBody)
}

// -- Test Cases: Pipelined Response Parsing (Success Scenarios) --

// Verifies parsing of standard responses defined by Content-Length.
func TestParsePipelinedResponses_Success_ContentLength(t *testing.T) {
	SetupObservability(t)
	response1 := formatResponseCL(200, "Response Body 1")
	response2 := formatResponseCL(404, "Not Found")
	response3 := formatResponseCL(201, "Created Resource XYZ")

	stream := createPipelinedResponseStream([]string{response1, response2, response3})
	expectedCount := 3

	// Execute
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, expectedCount)

	// Verify
	require.NoError(t, err)
	require.Len(t, parsedResponses, expectedCount)

	// Verify Response 1 details
	assert.Equal(t, 200, parsedResponses[0].StatusCode)
	assert.Equal(t, "Response Body 1", string(parsedResponses[0].Body))
	assert.Equal(t, "text/plain", parsedResponses[0].Headers.Get("Content-Type"))
	assert.Greater(t, parsedResponses[0].Duration, time.Duration(0), "Duration should be recorded")
	assert.NotNil(t, parsedResponses[0].Raw)

	// Verify Response 2
	assert.Equal(t, 404, parsedResponses[1].StatusCode)
	assert.Equal(t, "Not Found", string(parsedResponses[1].Body))

	// Verify Response 3
	assert.Equal(t, 201, parsedResponses[2].StatusCode)
}

// Verifies parsing of responses that use Transfer-Encoding: chunked.
func TestParsePipelinedResponses_Success_ChunkedEncoding(t *testing.T) {
	SetupObservability(t)
	response1 := formatResponseChunked(200, []string{"Chunk1", "Part2", "FinalPart"})
	response2 := formatResponseCL(500, "Internal Error") // Mixed encodings are valid

	stream := createPipelinedResponseStream([]string{response1, response2})
	expectedCount := 2

	// Execute
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, expectedCount)

	// Verify
	require.NoError(t, err)
	require.Len(t, parsedResponses, expectedCount)

	// Verify Response 1 (Chunked). The parser should automatically de-chunk the body.
	assert.Equal(t, 200, parsedResponses[0].StatusCode)
	assert.Equal(t, "Chunk1Part2FinalPart", string(parsedResponses[0].Body))
	// Verify raw response details
	require.NotNil(t, parsedResponses[0].Raw)
	assert.Equal(t, "chunked", parsedResponses[0].Raw.TransferEncoding[0])
}

// Verifies correct handling of HEAD requests, where no body is expected.
func TestParsePipelinedResponses_HEADMethod(t *testing.T) {
	SetupObservability(t)
	// Server sends Content-Length but the parser must know not to read the body for HEAD.
	response1 := formatResponseCL(200, "This body should not be read")
	// Manually strip the body to simulate a correct HEAD response stream
	response1 = response1[:strings.Index(response1, "\r\n\r\n")+4]

	response2 := formatResponseCL(200, "Another body")
	response2 = response2[:strings.Index(response2, "\r\n\r\n")+4]

	stream := createPipelinedResponseStream([]string{response1, response2})
	expectedCount := 2

	// Execute using http.MethodHead
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodHead, expectedCount)

	// Verify
	require.NoError(t, err)
	require.Len(t, parsedResponses, expectedCount)

	// Verify Response 1
	assert.Empty(t, parsedResponses[0].Body, "Body must be empty for HEAD requests")
	// Verify headers are still present and correct
	assert.Equal(t, strconv.Itoa(len("This body should not be read")), parsedResponses[0].Headers.Get("Content-Length"))

	// Verify Response 2
	assert.Empty(t, parsedResponses[1].Body)
}

// Verifies efficient handling of responses that are larger than the internal buffer.
func TestParsePipelinedResponses_LargeResponse(t *testing.T) {
	SetupObservability(t)
	// Generate a body larger than parserBufferSize (32KB), e.g., 100KB.
	largeBodySize := 100 * 1024
	largeBody := strings.Repeat("A", largeBodySize)

	response1 := formatResponseCL(200, largeBody)
	stream := createPipelinedResponseStream([]string{response1})

	// Execute
	startTime := time.Now()
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, 1)
	duration := time.Since(startTime)

	// Verify
	require.NoError(t, err)
	require.Len(t, parsedResponses, 1)
	assert.Equal(t, largeBodySize, len(parsedResponses[0].Body))
	assert.Equal(t, largeBody, string(parsedResponses[0].Body))
	assert.Less(t, duration, 500*time.Millisecond, "Parsing large response should be efficient")
}

// -- Test Cases: Error Handling and Robustness --

// Verifies behavior when the stream contains invalid HTTP data.
func TestParsePipelinedResponses_MalformedResponse(t *testing.T) {
	SetupObservability(t)
	response1 := formatResponseCL(200, "Valid Response")
	// Invalid status line (HTP instead of HTTP)
	response2_Malformed := "HTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBody"

	stream := createPipelinedResponseStream([]string{response1, response2_Malformed})

	// Execute
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, 2)

	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response 2/2")
	// Verify that the successfully parsed response (Response 1) is still returned.
	require.Len(t, parsedResponses, 1)
	assert.Equal(t, 200, parsedResponses[0].StatusCode)
}

// Verifies detection of a premature connection closure signaled by the server.
func TestParsePipelinedResponses_ConnectionCloseHeader(t *testing.T) {
	SetupObservability(t)
	response1 := formatResponseCL(200, "Response 1")
	// Modify Response 2 to include Connection: close
	response2_Close := strings.Replace(formatResponseCL(200, "Response 2"), "Connection: keep-alive", "Connection: close", 1)
	// Response 3 might still be in the buffer, but the parser should stop after Response 2.
	response3 := formatResponseCL(200, "Response 3")

	stream := createPipelinedResponseStream([]string{response1, response2_Close, response3})

	// Execute expecting 3 responses
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, 3)

	// Verify specific error indicating premature closure
	assert.Error(t, err)
	assert.Equal(t, "connection closed by server after 2 of 3 expected responses", err.Error())
	assert.Len(t, parsedResponses, 2, "Should have parsed until the closure signal")
}

// Verifies behavior when the stream ends before headers are completely read.
func TestParsePipelinedResponses_IncompleteRead_Headers(t *testing.T) {
	SetupObservability(t)
	response1 := formatResponseCL(200, "Response 1")
	// Incomplete Response 2 (truncated mid-header)
	response2_Incomplete := "HTTP/1.1 200 OK\r\nContent-Len"

	stream := createPipelinedResponseStream([]string{response1, response2_Incomplete})

	// Execute
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, 2)

	// Verify error (should be EOF or unexpected EOF)
	assert.Error(t, err)
	assert.Len(t, parsedResponses, 1)
	assert.Contains(t, err.Error(), "failed to parse response 2/2")
	// Check if the underlying error is EOF related
	assert.True(t, strings.Contains(err.Error(), io.EOF.Error()) || strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()))
}

// Verifies behavior when the stream ends in the middle of a response body.
func TestParsePipelinedResponses_IncompleteRead_Body(t *testing.T) {
	SetupObservability(t)
	// Response 1 advertises length 20, but only provides less data before EOF.
	response1_IncompleteBody := fmt.Sprintf(responseTemplateCL, 200, "OK", 20, "Incomplete")

	stream := createPipelinedResponseStream([]string{response1_IncompleteBody})

	// Execute
	parsedResponses, err := ParsePipelinedResponses(stream, http.MethodGet, 1)

	// Verify: Parsing the headers (http.ReadResponse) succeeds, but reading the body (io.ReadAll) encounters EOF.
	// The implementation handles this gracefully by returning the partial data and logging a warning.
	require.NoError(t, err, "Parsing should not fail on incomplete body read, only warn internally")
	require.Len(t, parsedResponses, 1)

	// Verify the partial data is captured
	assert.Equal(t, 200, parsedResponses[0].StatusCode)
	assert.Equal(t, "Incomplete", string(parsedResponses[0].Body))
}

// -- Test Cases: Advanced Scenarios --

// Verifies correct handling of compressed content.
func TestParsePipelinedResponses_CompressedBody(t *testing.T) {
	SetupObservability(t)
	// 1. Compress the body
	originalBody := "This is a compressed response body."
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(originalBody))
	require.NoError(t, err)
	gz.Close()
	compressedBody := buf.Bytes()

	// 2. Create the response manually to set Content-Encoding
	// We must use bytes.Buffer for the stream to handle the binary compressed data correctly.
	var stream bytes.Buffer
	header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(compressedBody))
	stream.WriteString(header)
	stream.Write(compressedBody)

	// Execute
	parsedResponses, err := ParsePipelinedResponses(&stream, http.MethodGet, 1)

	// Verify
	require.NoError(t, err)
	require.Len(t, parsedResponses, 1)

	// CRITICAL: The parser (http.ReadResponse) does NOT automatically decompress.
	// It reads the raw bytes from the stream.
	assert.Equal(t, compressedBody, parsedResponses[0].Body)
	assert.Equal(t, "gzip", parsedResponses[0].Headers.Get("Content-Encoding"))

	// Verify the consumer can decompress it
	gzReader, err := gzip.NewReader(bytes.NewReader(parsedResponses[0].Body))
	require.NoError(t, err)
	decompressedBody, err := io.ReadAll(gzReader)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(decompressedBody))
}
