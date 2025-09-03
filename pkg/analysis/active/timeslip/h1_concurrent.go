// pkg/analysis/active/timeslip/h1_concurrent.go
package timeslip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/network"
)

// ExecuteH1Concurrent implements the "dogpile" strategy.
func ExecuteH1Concurrent(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle) (*RaceResult, error) {
	startTime := time.Now()

	// 1. Configure the client.
	clientConfig := network.NewDefaultClientConfig()
	clientConfig.ForceHTTP2 = false
	clientConfig.RequestTimeout = config.Timeout
	clientConfig.IgnoreTLSErrors = config.IgnoreTLSErrors
	clientConfig.DisableKeepAlives = true
	clientConfig.IdleConnTimeout = 0

	client := network.NewClient(clientConfig)

	resultsChan := make(chan *RaceResponse, config.Concurrency)
	var wg sync.WaitGroup

	// 2. Set up the Start Gate and Initialization WaitGroup.
	startGate := make(chan struct{})
	// initWg ensures all goroutines are initialized (mutated, primed) before the gate opens.
	initWg := sync.WaitGroup{}

	// 3. Initialize the request goroutines.
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		initWg.Add(1)
		go func() {
			defer wg.Done()

			// --- Mutation Phase ---
			mutatedBody, mutatedHeaders, err := MutateRequest(candidate.Body, candidate.Headers)
			if err != nil {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("%w: %v", ErrPayloadMutationFail, err)}
				initWg.Done()
				return
			}

			// --- Initialization Phase (Connection Priming Simulation) ---
			// If ConnectionDelay is specified, wait here before signaling readiness.
			if config.ConnectionDelay > 0 {
				select {
				case <-time.After(config.ConnectionDelay):
					// Delay complete
				case <-ctx.Done():
					// Interrupted during initialization
					resultsChan <- &RaceResponse{Error: ctx.Err()}
					initWg.Done()
					return
				}
			}

			// Signal that this goroutine is initialized and ready to fire.
			initWg.Done()

			// --- Synchronization Phase ---
			select {
			case <-startGate:
			// Proceed
			case <-ctx.Done():
				resultsChan <- &RaceResponse{Error: ctx.Err()}
				return
			}

			// Apply Request Jitter just before sending.
			if config.RequestJitter > 0 {
				rng := getRNG() // Use pooled RNG
				jitter := time.Duration(rng.Int63n(int64(config.RequestJitter)))
				putRNG(rng) // Return RNG immediately after use
				time.Sleep(jitter)
			}

			// --- Execution Phase ---
			reqStart := time.Now()

			req, err := http.NewRequestWithContext(ctx, candidate.Method, candidate.URL, bytes.NewReader(mutatedBody))
			if err != nil {
				resultsChan <- &RaceResponse{Error: fmt.Errorf("failed to create request: %w", err)}
				return
			}
			req.Header = mutatedHeaders
			req.Close = true

			resp, err := client.Do(req)
			reqDuration := time.Since(reqStart)

			if err != nil {
				// Transport errors.
				resultsChan <- &RaceResponse{Error: fmt.Errorf("request failed: %w", err)}
				return
			}
			defer resp.Body.Close()

			// --- Response Processing Phase ---

			// Use pooled buffer for reading the response body to reduce GC pressure.
			buf := getBuffer()

			// Read body with limit to prevent OOM. Read +1 to detect overflow.
			n, err := io.CopyN(buf, resp.Body, maxResponseBodyBytes+1)

			if err != nil && err != io.EOF {
				putBuffer(buf)
				resultsChan <- &RaceResponse{Error: fmt.Errorf("failed to read response body: %w", err)}
				return
			}

			if n > maxResponseBodyBytes {
				putBuffer(buf)
				resultsChan <- &RaceResponse{Error: fmt.Errorf("response body exceeded limit of %d bytes", maxResponseBodyBytes)}
				return
			}

			// CRITICAL: Copy the bytes from the buffer into a new slice.
			// Use the actual number of bytes read (n).
			body := make([]byte, n)
			copy(body, buf.Bytes()[:n])
			putBuffer(buf)

			// Generate the composite fingerprint.
			fingerprint := GenerateFingerprint(resp.StatusCode, resp.Header, body)

			parsedResponse := &network.ParsedResponse{
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
			}

			// Determine success using the SuccessOracle.
			raceResp.IsSuccess = oracle.IsSuccess(raceResp)

			resultsChan <- raceResp
		}()
	}

	// 4. Wait for all goroutines to initialize (mutate and prime).
	initWg.Wait()

	// 5. Release the hounds!
	close(startGate)

	// 6. Wait for completion and collect results.
	wg.Wait()
	close(resultsChan)
	duration := time.Since(startTime)

	result := &RaceResult{
		Strategy:  H1Concurrent,
		Responses: make([]*RaceResponse, 0, config.Concurrency),
		Duration:  duration,
	}

	for resp := range resultsChan {
		result.Responses = append(result.Responses, resp)
	}

	// Error classification: If all requests failed, treat as unreachable/error.
	if len(result.Responses) > 0 {
		allFailed := true
		var firstError error
		for _, r := range result.Responses {
			if r.Error == nil {
				allFailed = false
				break
			}
			if firstError == nil && r.Error != context.Canceled && r.Error != context.DeadlineExceeded {
				firstError = r.Error
			}
		}
		if allFailed && firstError != nil {
			// If we can identify a root cause error, use it, otherwise default to ErrTargetUnreachable.
			return nil, fmt.Errorf("%w: %v", ErrTargetUnreachable, firstError)
		}
	}

	return result, nil
}
