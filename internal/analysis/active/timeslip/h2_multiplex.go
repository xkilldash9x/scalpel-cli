// internal/analysis/active/timeslip/h2_multiplex.go
package timeslip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// ExecuteH2Multiplexing leverages HTTP/2 stream multiplexing.
func ExecuteH2Multiplexing(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle) (*RaceResult, error) {
	startTime := time.Now()

	// H2 practically requires HTTPS.
	if !strings.HasPrefix(candidate.URL, "https://") {
		return nil, fmt.Errorf("%w: H2 Multiplexing generally requires HTTPS", ErrConfigurationError)
	}

	// 1. Configure the client for H2.
	// FIX: Renamed function and updated field names for consistency with network package refactor.
	clientConfig := network.NewBrowserClientConfig()
	clientConfig.RequestTimeout = config.Timeout
	clientConfig.InsecureSkipVerify = config.InsecureSkipVerify
	// The new transport automatically attempts H2, so ForceHTTP2 is no longer needed.
	// Optimize for single connection reuse.
	clientConfig.MaxIdleConnsPerHost = 1
	clientConfig.MaxConnsPerHost = 1

	client := network.NewClient(clientConfig)

	// 2. Prepare for concurrent execution.
	resultsChan := make(chan *RaceResponse, config.Concurrency)
	var wg sync.WaitGroup
	initWg := sync.WaitGroup{}
	startGate := make(chan struct{})

	// Get the exclusion map once for use in all goroutines.
	excludeMap := config.GetExcludedHeaders()

	// 3. Initialize the request goroutines.
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		initWg.Add(1)
		go func(streamIndex int) {
			defer wg.Done()

			// -- Mutation Phase --
			mutatedBody, mutatedHeaders, err := MutateRequest(candidate.Body, candidate.Headers)
			if err != nil {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("%w: %v", ErrPayloadMutationFail, err)}
				initWg.Done()
				return
			}

			// Signal readiness.
			initWg.Done()

			// -- Synchronization Phase --
			select {
			case <-startGate:
			// Proceed
			case <-ctx.Done():
				resultsChan <- &RaceResponse{Error: ctx.Err()}
				return
			}

			// Apply Request Jitter.
			if config.RequestJitter > 0 {
				rng := getRNG() // Use pooled RNG
				jitter := time.Duration(rng.Int63n(int64(config.RequestJitter)))
				putRNG(rng) // Return RNG immediately after use
				time.Sleep(jitter)
			}

			// -- Execution Phase --
			reqStart := time.Now()

			req, err := http.NewRequestWithContext(ctx, candidate.Method, candidate.URL, bytes.NewReader(mutatedBody))
			if err != nil {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}
			req.Header = mutatedHeaders

			resp, err := client.Do(req)
			reqDuration := time.Since(reqStart)

			if err != nil {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("request failed: %w", err)}
				return
			}
			defer resp.Body.Close()

			// Verification: Ensure the server actually used HTTP/2.
			if resp.ProtoMajor != 2 {
				resultsChan <- &RaceResponse{Error: ErrH2Unsupported}
				return
			}

			// -- Response Processing Phase --
			// Use pooled buffer for reading the response body.
			buf := getBuffer()
			defer putBuffer(buf)

			n, err := io.CopyN(buf, resp.Body, maxResponseBodyBytes+1)
			if err != nil && err != io.EOF {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("failed to read response body: %w", err)}
				return
			}
			if n > maxResponseBodyBytes {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("response body exceeded limit of %d bytes", maxResponseBodyBytes)}
				return
			}

			// Copy the bytes from the buffer.
			body := make([]byte, n)
			copy(body, buf.Bytes()[:n])

			// Generate the composite fingerprint.
			// Use the excludeMap.
			fingerprint := GenerateFingerprint(resp.StatusCode, resp.Header, body, excludeMap)

			parsedResponse := &ParsedResponse{
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
				Body:       body,
				Duration:   reqDuration,
				Raw:        resp,
			}

			raceResp := &RaceResponse{
				ParsedResponse: parsedResponse,
				Fingerprint:    fingerprint,
				SpecificBody:   body,
				StreamID:       uint32(streamIndex),
			}

			// Determine success using the SuccessOracle.
			raceResp.IsSuccess = oracle.IsSuccess(raceResp)

			resultsChan <- raceResp
		}(i)
	}

	// 4. Wait for initialization and start the race!
	initWg.Wait()
	close(startGate)

	// 5. Collect results and verify strategy validity.
	wg.Wait()
	close(resultsChan)
	duration := time.Since(startTime)

	result := &RaceResult{
		Strategy:  H2Multiplexing,
		Responses: make([]*RaceResponse, 0, config.Concurrency),
		Duration:  duration,
	}

	h2Used := false
	protocolErrorOccurred := false
	var firstError error

	for resp := range resultsChan {
		result.Responses = append(result.Responses, resp)
		if resp.Error == nil {
			h2Used = true
		} else {
			if firstError == nil {
				firstError = resp.Error
			}
			if resp.Error == ErrH2Unsupported {
				protocolErrorOccurred = true
			}
		}
	}

	if protocolErrorOccurred {
		return nil, ErrH2Unsupported
	}

	if !h2Used && len(result.Responses) > 0 {
		if firstError != nil {
			return nil, fmt.Errorf("%w: %v", ErrTargetUnreachable, firstError)
		}
		return nil, fmt.Errorf("%w: no successful responses received", ErrTargetUnreachable)
	}

	return result, nil
}
