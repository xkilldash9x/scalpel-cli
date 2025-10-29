// File: internal/analysis/active/timeslip/h1_singlebyte.go
package timeslip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// ExecuteH1SingleByteSend implements the "single-byte send" strategy using HTTP Pipelining.
func ExecuteH1SingleByteSend(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle) (*RaceResult, error) {
	startTime := time.Now()
	logger := observability.GetLogger().Named("timeslip.h1_singlebyte")

	// 1. Establish a raw TCP/TLS connection.
	targetURL, err := url.Parse(candidate.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid URL: %v", ErrConfigurationError, err)
	}

	// Configure dialer.
	dialerConfig := network.NewDialerConfig()
	dialerConfig.Timeout = config.Timeout
	dialerConfig.NoDelay = true // Disable Nagle's algorithm.

	address, err := setupConnectionDetails(targetURL, dialerConfig, config.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	conn, err := network.DialContext(ctx, "tcp", address, dialerConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to dial target: %v", ErrTargetUnreachable, err)
	}
	defer conn.Close()

	// Set deadline.
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

	// 3. Send prefixes and prepare the final burst.
	finalBurst := make([]byte, 0, config.Concurrency)

	for i, req := range requests {
		if len(req) < 1 {
			return nil, fmt.Errorf("%w: generated request %d is empty", ErrConfigurationError, i)
		}
		prefix := req[:len(req)-1]
		lastByte := req[len(req)-1]

		// Write the prefix.
		if _, err := conn.Write(prefix); err != nil {
			return nil, fmt.Errorf("%w: error writing prefix %d: %v", ErrPipeliningRejected, i, err)
		}

		finalBurst = append(finalBurst, lastByte)
	}

	// 4. The gate. Fire all the last bytes at once.
	if _, err := conn.Write(finalBurst); err != nil {
		return nil, fmt.Errorf("%w: failed to write final byte burst: %v", ErrPipeliningRejected, err)
	}

	// 5. Read and parse all the responses.
	parser := network.NewHTTPParser(logger)
	httpResponses, err := parser.ParsePipelinedResponses(conn, config.Concurrency)
	duration := time.Since(startTime)

	if err != nil {
		logger.Warn("Warning: failed to parse all pipelined responses",
			zap.Int("parsed", len(httpResponses)),
			zap.Error(err))
	}

	if len(httpResponses) == 0 {
		if err != nil {
			return nil, fmt.Errorf("failed to parse any responses: %w", err)
		}
		return nil, fmt.Errorf("no responses received")
	}

	// Get the exclusion map for fingerprinting.
	excludeMap := config.GetExcludedHeaders()

	// 6. Package the results.
	result := &RaceResult{
		Strategy:  H1SingleByteSend,
		Responses: make([]*RaceResponse, 0, len(httpResponses)),
		Duration:  duration,
	}

	for _, httpResp := range httpResponses {
		// FIX: Convert the standard *http.Response from the parser into our
		// local *ParsedResponse type for analysis.

		bodyBytes, readErr := io.ReadAll(httpResp.Body)
		if readErr != nil {
			logger.Error("failed to read body from parsed pipelined response", zap.Error(readErr))
			result.Responses = append(result.Responses, &RaceResponse{Error: readErr})
			continue
		}
		httpResp.Body.Close()

		// Create the local ParsedResponse. Individual duration isn't available here.
		localParsedResp := &ParsedResponse{
			StatusCode: httpResp.StatusCode,
			Headers:    httpResp.Header,
			Body:       bodyBytes,
			Duration:   0, // Individual duration is not meaningful in pipelining.
			Raw:        httpResp,
		}

		// Generate the composite fingerprint using the now-correct types.
		// Use the excludeMap.
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
func setupConnectionDetails(targetURL *url.URL, dialerConfig *network.DialerConfig, ignoreTLS bool) (string, error) {
	scheme := targetURL.Scheme
	port := targetURL.Port()

	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
		if dialerConfig.TLSConfig != nil {
			dialerConfig.TLSConfig = dialerConfig.TLSConfig.Clone()
			dialerConfig.TLSConfig.InsecureSkipVerify = ignoreTLS
			// Force HTTP/1.1 for pipelining via ALPN.
			dialerConfig.TLSConfig.NextProtos = []string{"http/1.1"}
		}
	case "http":
		if port == "" {
			port = "80"
		}
		dialerConfig.TLSConfig = nil
	default:
		return "", fmt.Errorf("%w: unsupported scheme: %s", ErrConfigurationError, scheme)
	}

	return net.JoinHostPort(targetURL.Hostname(), port), nil
}

// preparePipelinedRequests crafts the raw HTTP request strings, including mutation.
func preparePipelinedRequests(candidate *RaceCandidate, count int, host string) ([][]byte, error) {
	var preparedRequests [][]byte

	for i := 0; i < count; i++ {
		// 1. Apply mutations.
		mutatedBody, mutatedHeaders, err := MutateRequest(candidate.Body, candidate.Headers)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to mutate request %d: %v", ErrPayloadMutationFail, i, err)
		}

		// 2. Create request object.
		req, err := http.NewRequest(candidate.Method, candidate.URL, bytes.NewReader(mutatedBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request object %d: %w", i, err)
		}
		req.Header = mutatedHeaders
		req.Host = host
		// Ensure Connection: keep-alive is set for pipelining.
		req.Header.Set("Connection", "keep-alive")

		// IMPROVEMENT: Explicitly disable 'Expect: 100-continue'.
		// If a request has a body, the Go client might automatically add this header,
		// or the server might expect it by default.
		// If the server honors it, it will pause and send a 100 Continue response
		// before reading the body. This ruins the synchronization of the single-byte strategy
		// by causing the server to process the stream prematurely.
		if len(mutatedBody) > 0 {
			req.Header.Set("Expect", "")
		}

		// Ensure Content-Length is correct for the mutated body.
		if len(mutatedBody) > 0 {
			req.ContentLength = int64(len(mutatedBody))
			// Note: req.Write() handles setting the Content-Length header if req.ContentLength is set.
		}

		// 3. Serialize the request using a pooled buffer.
		buf := getBuffer()
		defer putBuffer(buf)

		if err := req.Write(buf); err != nil {
			return nil, fmt.Errorf("failed to serialize request %d: %w", i, err)
		}

		if buf.Len() == 0 {
			return nil, fmt.Errorf("%w: serialized request %d is empty", ErrConfigurationError, i)
		}

		// Copy bytes from the buffer, as the buffer will be reused.
		reqBytes := make([]byte, buf.Len())
		copy(reqBytes, buf.Bytes())

		preparedRequests = append(preparedRequests, reqBytes)
	}
	return preparedRequests, nil
}
