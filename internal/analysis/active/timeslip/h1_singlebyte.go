// pkg/analysis/active/timeslip/h1_singlebyte.go
package timeslip

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/network"
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
	dialerConfig.ForceNoDelay = true // Disable Nagle's algorithm.

	address, err := setupConnectionDetails(targetURL, dialerConfig, config.IgnoreTLSErrors)
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

		// Note: Jitter is generally less effective/desirable for single-byte send, as the goal is maximum synchronization of the final burst.

		// Write the prefix.
		if _, err := conn.Write(prefix); err != nil {
			// Server closed the connection, likely rejecting pipelining.
			return nil, fmt.Errorf("%w: error writing prefix %d: %v", ErrPipeliningRejected, i, err)
		}

		finalBurst = append(finalBurst, lastByte)
	}

	// 4. The gate. Fire all the last bytes at once.
	if _, err := conn.Write(finalBurst); err != nil {
		return nil, fmt.Errorf("%w: failed to write final byte burst: %v", ErrPipeliningRejected, err)
	}

	// 5. Read and parse all the responses.
	parsedResponses, err := network.ParsePipelinedResponses(conn, candidate.Method, config.Concurrency)
	duration := time.Since(startTime)

	if err != nil {
		logger.Warn("Warning: failed to parse all pipelined responses",
			zap.Int("parsed", len(parsedResponses)),
			zap.Error(err))
	}

	if len(parsedResponses) == 0 {
		if err != nil {
			return nil, fmt.Errorf("failed to parse any responses: %w", err)
		}
		return nil, fmt.Errorf("no responses received")
	}

	// 6. Package the results.
	result := &RaceResult{
		Strategy:  H1SingleByteSend,
		Responses: make([]*RaceResponse, 0, len(parsedResponses)),
		Duration:  duration,
	}

	for _, pResp := range parsedResponses {
		// Generate the composite fingerprint.
		fingerprint := GenerateFingerprint(pResp.StatusCode, pResp.Headers, pResp.Body)

		raceResp := &RaceResponse{
			ParsedResponse: pResp,
			Fingerprint:    fingerprint,
			SpecificBody:   pResp.Body,
		}

		// Determine success using the SuccessOracle.
		raceResp.IsSuccess = oracle.IsSuccess(raceResp)

		result.Responses = append(result.Responses, raceResp)
	}

	return result, nil
}

// setupConnectionDetails configures TLS settings specifically for HTTP/1.1 pipelining.
func setupConnectionDetails(targetURL *url.URL, dialerConfig *network.DialerConfig, ignoreTLS bool) (string, error) {
	// (Implementation remains the same as the original, ensuring HTTP/1.1 ALPN)
	scheme := targetURL.Scheme
	port := targetURL.Port()

	if scheme == "https" {
		if port == "" {
			port = "443"
		}
		if dialerConfig.TLSConfig == nil {
			// This should ideally be handled by the network package initialization, but we check defensively.
			return "", fmt.Errorf("internal error: TLS configuration is missing")
		}
		dialerConfig.TLSConfig = dialerConfig.TLSConfig.Clone()
		dialerConfig.TLSConfig.InsecureSkipVerify = ignoreTLS
		// Force HTTP/1.1 for pipelining.
		dialerConfig.TLSConfig.NextProtos = []string{"http/1.1"}

	} else if scheme == "http" {
		if port == "" {
			port = "80"
		}
		dialerConfig.TLSConfig = nil
	} else {
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
		req.Header.Set("Connection", "keep-alive")

		// Ensure Content-Length is correct for the mutated body.
		if len(mutatedBody) > 0 {
			req.ContentLength = int64(len(mutatedBody))
			req.Header.Set("Content-Length", fmt.Sprintf("%d", req.ContentLength))
		}

		// 3. Serialize the request using a pooled buffer.
		buf := getBuffer()

		if err := req.Write(buf); err != nil {
			putBuffer(buf)
			return nil, fmt.Errorf("failed to serialize request %d: %w", i, err)
		}

		if buf.Len() == 0 {
			putBuffer(buf)
			return nil, fmt.Errorf("%w: serialized request %d is empty", ErrConfigurationError, i)
		}

		// Copy bytes from the buffer, as the buffer will be reused.
		reqBytes := make([]byte, buf.Len())
		copy(reqBytes, buf.Bytes())
		putBuffer(buf)

		preparedRequests = append(preparedRequests, reqBytes)
	}
	return preparedRequests, nil
}