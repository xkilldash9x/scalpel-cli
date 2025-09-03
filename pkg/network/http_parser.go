// pkg/network/http_parser.go
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
// 32KB reduces the number of syscalls compared to the default 4KB buffer.
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
// This specialized function is crucial for analyzing race conditions (TimeSlip).
func ParsePipelinedResponses(r io.Reader, requestMethod string, expectedCount int) ([]*ParsedResponse, error) {
	// Unification. Using the standardized logger.
	logger := observability.GetLogger().Named("network.http_parser")

	// Use an optimized buffered reader.
	reader := bufio.NewReaderSize(r, parserBufferSize)
	var responses []*ParsedResponse

	// http.ReadResponse requires a request context to interpret headers (e.g., HEAD response behavior).
	dummyReq, err := http.NewRequest(requestMethod, "http://placeholder.scalpel/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create dummy request for parser: %w", err)
	}

	for i := 0; i < expectedCount; i++ {
		startTime := time.Now()

		// http.ReadResponse handles parsing boundaries (Content-Length/Chunked).
		resp, err := http.ReadResponse(reader, dummyReq)

		if err != nil {
			// Stream might be malformed or truncated (e.g., connection closed).
			logger.Error("Failed to parse pipelined response",
				zap.Int("response_index", i),
				zap.Int("expected_total", expectedCount),
				zap.Error(err))
			// Return what we successfully parsed so far.
			return responses, fmt.Errorf("failed to parse response %d/%d: %w", i+1, expectedCount, err)
		}

		// We must read the body fully to advance the reader to the start of the next response.
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		duration := time.Since(startTime) // Duration includes parsing and reading time.

		if readErr != nil {
			// Non-fatal: Body reading might fail if the connection drops mid-stream.
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

		// Check if the server signaled connection close.
		if resp.Close && i+1 < expectedCount {
			logger.Warn("Connection closed prematurely by server",
				zap.Int("received", i+1),
				zap.Int("expected", expectedCount))
			return responses, fmt.Errorf("connection closed prematurely by server after %d responses", i+1)
		}
	}

	return responses, nil
}
