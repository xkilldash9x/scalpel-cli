package network

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// ParsePipelinedResponses reads from a reader and attempts to parse a specified
// number of HTTP responses. This is crucial for handling HTTP pipelining, where
// multiple responses are sent over the same connection in sequence.
func ParsePipelinedResponses(conn io.Reader, expectedTotal int) ([]*http.Response, error) {
	if expectedTotal <= 0 {
		return nil, nil
	}

	var responses []*http.Response
	bufReader := bufio.NewReader(conn)

	for i := 0; i < expectedTotal; i++ {
		// ReadResponse will parse the status line, headers, and prepare the body for reading.
		// We pass nil for the request because in a client context, we only care about parsing the response.
		resp, err := http.ReadResponse(bufReader, nil)
		if err != nil {
			// -- Correction for TestParsePipelinedResponses_IncompleteRead_Headers --
			// This is the critical fix. If reading a response fails at any point (e.g., a malformed
			// header), we must stop processing and propagate the error. The original code might have
			// swallowed this error, causing the test to fail on an incorrect assertion later.
			logger.Error("Failed to parse pipelined response", "response_index", i, "expected_total", expectedTotal, "error", err)
			return responses, err
		}

		// After successfully parsing the response, we need to handle the body.
		// The body must be fully read or discarded to allow the next response in the pipeline
		// to be parsed from the buffered reader.
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			// This case handles situations where the body is shorter than Content-Length.
			logger.Warn("Failed reading response body (incomplete content)", "status", resp.StatusCode, "response_index", i, "error", err)
			// We still append the response with its partially read body, as it's a server-side issue.
		}
		resp.Body.Close() // Close the original body reader.

		// Check for content encoding (e.g., gzip, deflate) and decompress if necessary.
		var reader io.ReadCloser
		switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
		case "gzip":
			reader, err = gzip.NewReader(bytes.NewReader(bodyBytes))
			if err != nil {
				logger.Error("Failed to create gzip reader", "error", err)
			}
		case "deflate":
			reader, err = zlib.NewReader(bytes.NewReader(bodyBytes))
			if err != nil {
				logger.Error("Failed to create zlib reader", "error", err)
			}
		default:
			reader = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		if err != nil {
			// If decompression setup failed, we'll just use the raw body.
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else {
			// Replace the response body with the new, decompressed reader.
			resp.Body = reader
		}

		// Recalculate Content-Length to reflect the decompressed size.
		// This is important for downstream consumers of the response.
		finalBody, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(finalBody))
		resp.ContentLength = int64(len(finalBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(finalBody)))

		responses = append(responses, resp)

		// A "Connection: close" header indicates this is the last response the server intends to send.
		if strings.EqualFold(resp.Header.Get("Connection"), "close") {
			if i < expectedTotal-1 {
				logger.Warn("Connection closed prematurely by server", "received", len(responses), "expected", expectedTotal)
			}
			break // Stop parsing further responses.
		}
	}

	return responses, nil
}

