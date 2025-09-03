// File:         pkg/network/http_parser.go
// Description:  This file contains a specialized parser for HTTP/1.1 pipelined responses,
//               which is a critical component for the TimeSlip race condition analyzer.
//
package network

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
)

// Optimization: Define a larger buffer size for parsing potentially large pipelined responses.
// A 32KB buffer reduces the number of syscalls compared to the default 4KB buffer, improving throughput.
const parserBufferSize = 32 * 1024

// ParsedResponse represents a single HTTP response parsed from a raw stream or client execution.
type ParsedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
	Raw        *http.Response // Useful for detailed inspection.
}

// ParsePipelinedResponses parses multiple HTTP/1.1 responses from a raw stream.
// This specialized function is crucial for analyzing race conditions (TimeSlip) where
// multiple responses arrive on a single TCP connection.
func ParsePipelinedResponses(r io.Reader, requestMethod string, expectedCount int) ([]*ParsedResponse, error) {
	logger := observability.GetLogger().Named("network.http_parser")

	// Use an optimized buffered reader.
	reader := bufio.NewReaderSize(r, parserBufferSize)
	responses := make([]*ParsedResponse, 0, expectedCount)

	// Architectural Note: http.ReadResponse requires a request context to correctly interpret
	// headers and response bodies, especially for HEAD requests where no body is expected.
	// We create a "dummy" request to provide this necessary context to the parser.
	dummyReq, err := http.NewRequest(requestMethod, "http://placeholder.scalpel/", nil)
	if err != nil {
		// This is a setup error, so we fail fast.
		return nil, fmt.Errorf("failed to create dummy request for parser: %w", err)
	}

	for i := 0; i < expectedCount; i++ {
		startTime := time.Now()

		// http.ReadResponse correctly handles parsing response boundaries based on
		// Content-Length or chunked transfer encoding.
		resp, err := http.ReadResponse(reader, dummyReq)

		if err != nil {
			// A parsing error often means the stream was malformed or the connection
			// was closed prematurely by the server (e.g., rejecting pipelining).
			logger.Error("Failed to parse pipelined response",
				zap.Int("response_index", i),
				zap.Int("expected_total", expectedCount),
				zap.Error(err))
			// Return what we successfully parsed so far, along with the error that stopped us.
			return responses, fmt.Errorf("failed to parse response %d/%d: %w", i+1, expectedCount, err)
		}

		// CRITICAL: We must fully read and then close the response body to advance the
		// underlying buffered reader to the start of the next response in the stream.
		// Failure to do this would cause subsequent calls to http.ReadResponse to fail.
		body, readErr := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log the close error, as it might indicate a problem, but it's less critical than the read error.
			logger.Warn("Error closing response body", zap.Error(closeErr))
		}
		duration := time.Since(startTime) // Duration includes parsing and reading time.

		if readErr != nil {
			// This is not a fatal parsing error. The connection might have dropped mid-stream.
			// We can still process the partial response data we have.
			logger.Warn("Failed reading response body (incomplete content)",
				zap.Int("status", resp.StatusCode),
				zap.Int("response_index", i),
				zap.Error(readErr))
		}

		responses = append(responses, &ParsedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       body,
			Duration:   duration,
			Raw:        resp,
		})

		// Check if the server signaled connection closure via the "Connection: close" header.
		if resp.Close && i+1 < expectedCount {
			logger.Warn("Connection closed prematurely by server",
				zap.Int("received", i+1),
				zap.Int("expected", expectedCount))
			// Return a specific error indicating the server does not support keep-alive for this many requests.
			return responses, fmt.Errorf("connection closed by server after %d of %d expected responses", i+1, expectedCount)
		}
	}

	return responses, nil
}
