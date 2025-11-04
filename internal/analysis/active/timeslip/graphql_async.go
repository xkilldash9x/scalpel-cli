// -- internal/analysis/active/timeslip/graphql_async.go --
package timeslip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"go.uber.org/zap"
)

// ExecuteGraphQLAsync implements the GraphQL Batching race strategy.
func ExecuteGraphQLAsync(ctx context.Context, candidate *RaceCandidate, config *Config, oracle *SuccessOracle, logger *zap.Logger) (*RaceResult, error) {
	startTime := time.Now()

	// 1. Construct the batched request body (includes mutation).
	batchedBody, err := constructBatchedGraphQL(candidate, config.Concurrency)
	if err != nil {
		return nil, fmt.Errorf("failed to construct batched GraphQL request: %w", err)
	}

	// 2. Send the single batched request.
	// FIX: Renamed function and updated field names.
	clientConfig := network.NewBrowserClientConfig()
	clientConfig.RequestTimeout = config.Timeout
	clientConfig.InsecureSkipVerify = config.InsecureSkipVerify
	client := network.NewClient(clientConfig)

	reqStart := time.Now()
	req, err := http.NewRequestWithContext(ctx, candidate.Method, candidate.URL, bytes.NewReader(batchedBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	// Use original headers for the container request, ensuring req.Header is not overwritten with a nil map.
	// http.NewRequestWithContext already initializes req.Header to a non-nil map.
	if candidate.Headers != nil {
		req.Header = candidate.Headers.Clone()
	}

	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Note: Jitter is less relevant for a single request.
	resp, err := client.Do(req)
	reqDuration := time.Since(reqStart)
	duration := time.Since(startTime)

	if err != nil {
		return nil, fmt.Errorf("%w: failed to execute batched request: %v", ErrTargetUnreachable, err)
	}
	defer resp.Body.Close()

	// Enforce read limit on the response body.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if len(body) >= int(maxResponseBodyBytes) {
		return nil, fmt.Errorf("response body exceeded limit of %d bytes", maxResponseBodyBytes)
	}

	// Create the shared ParsedResponse.
	parsedHTTPResp := &ParsedResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   reqDuration,
		Raw:        resp,
	}

	// Get the exclusion map for fingerprinting.
	excludeMap := config.GetExcludedHeaders()

	// 3. Parse the batched response.
	var batchedResponse []json.RawMessage
	// Check if it looks like a batched response (JSON array), accounting for whitespace.
	trimmedBody := bytes.TrimSpace(body)
	isBatched := len(trimmedBody) > 0 && trimmedBody[0] == '['

	if !isBatched || json.Unmarshal(body, &batchedResponse) != nil {
		// Pass the excludeMap to the non-batched handler.
		return handleNonBatchedGraphQLResponse(parsedHTTPResp, duration, oracle, excludeMap), nil
	}

	// 4. Transform individual operation results into RaceResponses.
	result := &RaceResult{
		Strategy:  AsyncGraphQL,
		Responses: make([]*RaceResponse, 0, len(batchedResponse)),
		Duration:  duration,
	}

	for _, opResultRaw := range batchedResponse {
		opBody := []byte(opResultRaw)

		// Generate the composite fingerprint.
		// Use the excludeMap.
		fingerprint := GenerateFingerprint(resp.StatusCode, resp.Header, opBody, excludeMap)

		raceResp := &RaceResponse{
			ParsedResponse: parsedHTTPResp,
			Fingerprint:    fingerprint,
			SpecificBody:   opBody,
		}

		// Determine success using the centralized oracle.
		raceResp.IsSuccess = oracle.IsSuccess(raceResp)

		result.Responses = append(result.Responses, raceResp)
	}

	return result, nil
}

// constructBatchedGraphQL creates a JSON array containing the operation repeated N times, with mutations applied.
func constructBatchedGraphQL(candidate *RaceCandidate, count int) ([]byte, error) {
	operationBody := candidate.Body
	// Basic validation of the template.
	trimmedBody := bytes.TrimSpace(operationBody)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' {
		return nil, fmt.Errorf("%w: input GraphQL operation body must be a JSON object", ErrConfigurationError)
	}

	// Use buffer pool for construction.
	buf := getBuffer()
	defer putBuffer(buf)

	buf.WriteByte('[')
	for i := 0; i < count; i++ {
		// Apply mutation for each operation instance.
		// We pass empty headers as we only care about the body mutation here.
		// FIX: The call to MutateRequest was not updated after its signature changed.
		// Create a temporary candidate for mutation.
		tempCandidate := &RaceCandidate{Body: trimmedBody}
		mutatedBody, _, _, err := MutateRequest(tempCandidate)

		if err != nil {
			return nil, fmt.Errorf("%w: failed to mutate GraphQL operation %d: %v", ErrPayloadMutationFail, i, err)
		}

		// Validation: ensure the mutated input is still valid JSON.
		if !json.Valid(mutatedBody) {
			return nil, fmt.Errorf("%w: mutated GraphQL operation body %d resulted in invalid JSON", ErrPayloadMutationFail, i)
		}

		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(mutatedBody)
	}
	buf.WriteByte(']')

	// Copy result from buffer before returning it to the pool.
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())

	return result, nil
}

// handleNonBatchedGraphQLResponse handles cases where the server returns a single response.
// FIX: Updated to accept excludeMap as map[string]bool.
func handleNonBatchedGraphQLResponse(parsedResp *ParsedResponse, duration time.Duration, oracle *SuccessOracle, excludeMap map[string]bool) *RaceResult {
	// Use the excludeMap for fingerprinting.
	fingerprint := GenerateFingerprint(parsedResp.StatusCode, parsedResp.Headers, parsedResp.Body, excludeMap)

	raceResp := &RaceResponse{
		ParsedResponse: parsedResp,
		Fingerprint:    fingerprint,
		SpecificBody:   parsedResp.Body,
	}

	// Determine success using the Oracle.
	raceResp.IsSuccess = oracle.IsSuccess(raceResp)

	return &RaceResult{
		Strategy:  AsyncGraphQL,
		Responses: []*RaceResponse{raceResp},
		Duration:  duration,
	}
}
