// File: internal/analysis/active/timeslip/h1_singlebyte.go
package timeslip

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"go.uber.org/zap"
)

// ExecuteH1SingleByteSend implements the "single-byte send" strategy using HTTP Pipelining.
// It constructs the entire pipelined stream (R1+R2+...RN) and sends everything except the very last byte.
// The last byte is then sent, aiming for the server to process the entire batch nearly simultaneously.
func ExecuteH1SingleByteSend(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle, logger *zap.Logger) (*RaceResult, error) {
	startTime := time.Now()

	// 1. Establish a raw TCP/TLS connection.
	targetURL, err := url.Parse(candidate.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrConfigurationError, err)
	}

	// Configure dialer.
	dialerConfig := network.NewDialerConfig()
	dialerConfig.Timeout = config.Timeout
	dialerConfig.NoDelay = true // Disable Nagle's algorithm for immediate transmission of the last byte.

	address, err := setupConnectionDetails(targetURL, dialerConfig, config.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	conn, err := network.DialContext(ctx, "tcp", address, dialerConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to dial target: %v", ErrTargetUnreachable, err)
	}
	defer conn.Close()

	// Set deadline for the entire operation (send + receive).
	deadline := time.Now().Add(config.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// 2. Build the raw HTTP request strings (includes mutation).
	requests, err := preparePipelinedRequests(candidate, config.Concurrency, targetURL.Host)
	if err != nil {
		return nil, err
	}

	// 3. Construct the full pipelined stream.
	// Use a pooled buffer for efficiency.
	fullStreamBuf := getBuffer()
	defer putBuffer(fullStreamBuf)

	for _, req := range requests {
		if len(req) == 0 {
			// Safety check, though preparePipelinedRequests should prevent this.
			return nil, fmt.Errorf("%w: encountered an empty request during stream construction", ErrConfigurationError)
		}
		fullStreamBuf.Write(req)
	}

	// We must copy the bytes from the buffer as the buffer will be returned to the pool.
	pipelinedBytes := make([]byte, fullStreamBuf.Len())
	copy(pipelinedBytes, fullStreamBuf.Bytes())

	if len(pipelinedBytes) == 0 {
		return nil, fmt.Errorf("%w: generated pipelined stream is empty", ErrConfigurationError)
	}

	// 4. Apply the single-byte send technique.
	// Send everything except the last byte.
	prefix := pipelinedBytes[:len(pipelinedBytes)-1]
	lastByte := pipelinedBytes[len(pipelinedBytes)-1:]

	// Write the prefix.
	if _, err := conn.Write(prefix); err != nil {
		// If the server closes the connection during the write, it likely rejects pipelining or large requests.
		return nil, fmt.Errorf("%w: error writing pipelined prefix: %v", ErrPipeliningRejected, err)
	}

	// 5. The gate. Fire the last byte.
	if _, err := conn.Write(lastByte); err != nil {
		return nil, fmt.Errorf("%w: failed to write final byte: %v", ErrPipeliningRejected, err)
	}

	// 6. Read and parse all the responses.
	parser := network.NewHTTPParser(logger)
	// The parser must read exactly N responses from the connection.
	httpResponses, err := parser.ParsePipelinedResponses(conn, config.Concurrency)
	duration := time.Since(startTime)

	if err != nil {
		// It's expected that we might not get all responses if the server doesn't fully support pipelining
		// or if timeouts occur during reading.
		logger.Warn("Warning: failed to parse all pipelined responses (potential partial results)",
			zap.Int("expected", config.Concurrency),
			zap.Int("parsed", len(httpResponses)),
			zap.Error(err))
	}

	if len(httpResponses) == 0 {
		if err != nil {
			// If we got 0 responses and an error occurred, report the underlying error.
			return nil, fmt.Errorf("%w: failed to parse any responses: %v", ErrTargetUnreachable, err)
		}
		return nil, fmt.Errorf("%w: no responses received", ErrTargetUnreachable)
	}

	// Get the exclusion map for fingerprinting.
	excludeMap := config.GetExcludedHeaders()

	// 7. Package the results.
	result := &RaceResult{
		Strategy:  H1SingleByteSend,
		Responses: make([]*RaceResponse, 0, len(httpResponses)),
		Duration:  duration,
	}

	for _, httpResp := range httpResponses {
		// Convert the standard *http.Response from the parser into our local *ParsedResponse type.

		// Read body. The parser is expected to handle Content-Length/chunking and provide the body reader.
		bodyBytes, readErr := io.ReadAll(httpResp.Body)
		httpResp.Body.Close() // Close body reader immediately after reading.

		if readErr != nil {
			logger.Error("failed to read body from parsed pipelined response", zap.Error(readErr))
			// Append a response indicating the read error instead of skipping.
			result.Responses = append(result.Responses, &RaceResponse{Error: readErr})
			continue
		}

		// Create the local ParsedResponse.
		localParsedResp := &ParsedResponse{
			StatusCode: httpResp.StatusCode,
			Headers:    httpResp.Header,
			Body:       bodyBytes,
			Duration:   0, // Individual request duration is not meaningful in pipelining.
			Raw:        httpResp,
		}

		// Generate the composite fingerprint.
		fingerprint := GenerateFingerprint(localParsedResp.StatusCode, localParsedResp.Headers, localParsedResp.Body, excludeMap)

		raceResp := &RaceResponse{
			ParsedResponse: localParsedResp,
			Fingerprint:    fingerprint,
			SpecificBody:   localParsedResp.Body,
		}

		// Determine success using the SuccessOracle.
		raceResp.IsSuccess = oracle.IsSuccess(raceResp)

		result.Responses = append(result.Responses, raceResp)
	}

	return result, nil
}

// setupConnectionDetails configures TLS settings specifically for HTTP/1.1 pipelining.
// It ensures that ALPN negotiation forces HTTP/1.1 if TLS is used.
func setupConnectionDetails(targetURL *url.URL, dialerConfig *network.DialerConfig, ignoreTLS bool) (string, error) {
	scheme := targetURL.Scheme
	port := targetURL.Port()

	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
		// Ensure TLSConfig is initialized or cloned if it exists.
		if dialerConfig.TLSConfig == nil {
			dialerConfig.TLSConfig = &tls.Config{}
		} else {
			dialerConfig.TLSConfig = dialerConfig.TLSConfig.Clone()
		}

		dialerConfig.TLSConfig.InsecureSkipVerify = ignoreTLS
		// CRITICAL: Force HTTP/1.1 for pipelining via ALPN. If H2 is negotiated, pipelining semantics don't apply.
		dialerConfig.TLSConfig.NextProtos = []string{"http/1.1"}

	case "http":
		if port == "" {
			port = "80"
		}
		// Ensure TLSConfig is nil for plain HTTP.
		dialerConfig.TLSConfig = nil
	default:
		// Use ErrConfigurationError for unsupported schemes in this context.
		return "", fmt.Errorf("%w: unsupported scheme for pipelining: %s", ErrConfigurationError, scheme)
	}

	return net.JoinHostPort(targetURL.Hostname(), port), nil
}

// preparePipelinedRequests crafts the raw HTTP request strings, including mutation.
func preparePipelinedRequests(candidate *RaceCandidate, count int, host string) ([][]byte, error) {
	var preparedRequests [][]byte

	for i := 0; i < count; i++ {
		// 1. Apply mutations.
		// Create a copy of the candidate for mutation to ensure thread safety and independence.
		candidateCopy := *candidate
		// Ensure Headers map is initialized before cloning if it's nil.
		if candidateCopy.Headers == nil {
			candidateCopy.Headers = make(http.Header)
		}
		candidateCopy.Headers = candidateCopy.Headers.Clone()

		mutatedBody, mutatedHeaders, mutatedURL, err := MutateRequest(&candidateCopy)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to mutate request %d: %v", ErrPayloadMutationFail, i, err)
		}

		// 2. Create request object.
		// We use bytes.NewReader for the body.
		req, err := http.NewRequest(candidate.Method, mutatedURL, bytes.NewReader(mutatedBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request object %d: %w", i, err)
		}
		req.Header = mutatedHeaders
		req.Host = host
		// Ensure Connection: keep-alive is set, which is essential for pipelining.
		req.Header.Set("Connection", "keep-alive")

		// Explicitly disable 'Expect: 100-continue'.
		// If the server honors this header, it will pause and send a 100 Continue response
		// before reading the body. This ruins the synchronization of the single-byte strategy
		// by causing the server to process the stream prematurely or introducing delays.
		if len(mutatedBody) > 0 {
			// Setting the Expect header to empty string prevents the Go client (used here for serialization) from adding it.
			req.Header.Set("Expect", "")
		}

		// Ensure Content-Length is correct for the mutated body.
		if len(mutatedBody) > 0 {
			req.ContentLength = int64(len(mutatedBody))
			// Note: req.Write() handles setting the Content-Length header based on req.ContentLength.
		}

		// 3. Serialize the request using a pooled buffer.
		buf := getBuffer()
		// We must return the buffer to the pool even if serialization fails.
		// Ensure buffer is returned before returning from the function or continuing the loop.

		if err := req.Write(buf); err != nil {
			putBuffer(buf) // Return buffer on error
			return nil, fmt.Errorf("failed to serialize request %d: %w", i, err)
		}

		if buf.Len() == 0 {
			putBuffer(buf) // Return buffer on error
			return nil, fmt.Errorf("%w: serialized request %d is empty", ErrConfigurationError, i)
		}

		// Copy bytes from the buffer, as the buffer will be reused in the next iteration.
		reqBytes := make([]byte, buf.Len())
		copy(reqBytes, buf.Bytes())

		preparedRequests = append(preparedRequests, reqBytes)

		// Return the buffer to the pool at the end of the iteration.
		putBuffer(buf)
	}
	return preparedRequests, nil
}
