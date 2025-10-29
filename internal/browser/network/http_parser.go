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

// HTTPParser handles the parsing of raw HTTP messages, specifically for pipelined connections.
type HTTPParser struct {
	logger *zap.Logger
}

// NewHTTPParser creates a new HTTPParser instance.
func NewHTTPParser(logger *zap.Logger) *HTTPParser {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &HTTPParser{
		logger: logger.Named("http_parser"),
	}
}

// ParsePipelinedResponses reads from a connection reader and attempts to parse a specified
// number of HTTP responses. It ensures bodies are consumed and decompressed efficiently.
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
		// This wraps the underlying reader (which respects HTTP boundaries like Content-Length/Chunking)
		// with the decompression stream (e.g., gzip.Reader), utilizing pooling and multi-layer support.
		if err := DecompressResponse(resp); err != nil {
			// Log the error but continue. The body will be read as compressed data if initialization fails.
			// DecompressResponse ensures cleanup internally upon failure.
			p.logger.Warn("Failed to initialize decompression for pipelined response. Body remains compressed.",
				zap.Int("response_index", i),
				zap.Error(err))
		}

		// CRITICAL STEP 2: The body MUST be fully read here to advance the bufReader to the start of the next response.
		// Reading from the (potentially wrapped) resp.Body consumes the correct amount of data from the wire.
		var bodyBytes []byte
		if resp.Body != nil {
			// Read the body (decompressed or compressed).
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
