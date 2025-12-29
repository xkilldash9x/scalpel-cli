// internal/network/http_parser.go
package network

import (
	"bufio"
	// Removed compression imports as decompression is centralized in DecompressResponse.
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

// HTTPParser provides functionality for parsing raw HTTP messages from a stream,
// with a specific focus on handling sequences of responses from HTTP pipelining.
type HTTPParser struct {
	logger *zap.Logger
}

// NewHTTPParser creates and returns a new HTTPParser.
func NewHTTPParser(logger *zap.Logger) *HTTPParser {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &HTTPParser{
		logger: logger.Named("http_parser"),
	}
}

// ParsePipelinedResponses reads a sequence of HTTP responses from a single
// `io.Reader` (e.g., a TCP connection) and parses them. This is essential for
// handling HTTP/1.1 pipelining, where multiple requests are sent without waiting
// for each response.
//
// The function iteratively reads and parses each response from the buffered reader.
// For each response, it:
// 1. Initializes the appropriate decompression stream based on `Content-Encoding`.
// 2. Reads the entire response body to advance the reader to the start of the next response.
// 3. Replaces the consumed body with a new, readable `io.NopCloser` containing the
//    fully read and decompressed body content.
//
// This ensures that the caller receives a slice of complete, decompressed `http.Response`
// objects, ready for immediate use.
//
// Parameters:
//   - conn: The `io.Reader` from which to read the response stream.
//   - expectedTotal: The number of responses to attempt to parse.
//
// Returns a slice of parsed `http.Response` objects or an error if a non-EOF
// parsing or decompression error occurs.
func (p *HTTPParser) ParsePipelinedResponses(conn io.Reader, expectedTotal int) ([]*http.Response, error) {
	if expectedTotal <= 0 {
		return nil, nil
	}

	var responses []*http.Response
	// Wrap the connection reader in a bufio.Reader for efficient parsing.
	bufReader := bufio.NewReader(conn)

	for i := 0; i < expectedTotal; i++ {
		// Parse the headers and initialize the body reader for the next response.
		resp, err := http.ReadResponse(bufReader, nil)
		if err != nil {
			// If we hit EOF after successfully parsing some responses, it's acceptable.
			if errors.Is(err, io.EOF) && len(responses) > 0 {
				break
			}
			// Other errors (e.g., malformed HTTP) are fatal for the sequence.
			p.logger.Error("Failed to parse pipelined response headers", zap.Int("response_index", i), zap.Error(err))
			return responses, err
		}

		// CRITICAL STEP 1: Initialize decompression BEFORE reading the body (Wrap-then-Read strategy).
		if err := DecompressResponse(resp); err != nil {
			// FIX: If DecompressResponse fails, resp.Body might be partially consumed during initialization attempts (e.g., reading headers).
			// We cannot continue reading the pipeline, as the stream position is lost. We must abort.

			// Log the error and abort the pipeline processing.
			p.logger.Error("Failed to initialize decompression for pipelined response. Aborting pipeline.",
				zap.Int("response_index", i),
				zap.Error(err))

			// Ensure the (potentially partially initialized/wrapped) body is closed.
			if resp.Body != nil {
				_ = resp.Body.Close()
			}

			return responses, fmt.Errorf("failed to initialize decompression for response %d: %w", i, err)
		}

		// CRITICAL STEP 2: The body MUST be fully read here to advance the bufReader to the start of the next response.
		// Reading from the (potentially wrapped) resp.Body consumes the correct amount of data from the wire.
		var bodyBytes []byte
		if resp.Body != nil {
			// Read the body (decompressed).
			bodyBytes, err = io.ReadAll(resp.Body)
			// Ensure the body is closed. This closes the wrapper(s) and returns pooled readers.
			resp.Body.Close()

			if err != nil {
				// Error during reading or decompression (e.g., truncated stream, corrupted data).
				p.logger.Error("Failed to consume/decompress pipelined response body", zap.Error(err))
				return responses, fmt.Errorf("failed to consume body for response %d: %w", i, err)
			}
		}

		// CRITICAL STEP 3: Replace the now-consumed body with a new, readable one containing the final data.
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		responses = append(responses, resp)

		// If the response indicated connection closure, stop parsing.
		if resp.Close {
			break
		}
	}

	return responses, nil
}
