// idor.go
package idor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// ErrUnauthenticated is returned when required sessions are missing or unauthenticated.
type ErrUnauthenticated struct {
	Message string
}

func (e *ErrUnauthenticated) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "IDOR analysis requires authenticated sessions"
}

// analysisTask represents a unit of work for the worker pool.
type analysisTask struct {
	Pair     RequestResponsePair
	Config   Config
	TestType string // "Horizontal" or "Manipulation"
	// Fields specific to the Manipulation strategy
	Identifier *ObservedIdentifier
	TestValue  string
}

const (
	TestTypeHorizontal   = "Horizontal"
	TestTypeManipulation = "Manipulation"
)

// Detect performs the IDOR analysis concurrently using errgroup for robust management.
func Detect(ctx context.Context, traffic []RequestResponsePair, config Config, logger *log.Logger) ([]Finding, error) {
	// Use errgroup for robust concurrency management, synchronization, and context propagation.
	g, groupCtx := errgroup.WithContext(ctx)
	// Set the concurrency limit. This effectively manages the worker pool size.
	g.SetLimit(config.ConcurrencyLevel)

	// Channel to collect findings safely from concurrent workers.
	findingsChan := make(chan Finding, config.ConcurrencyLevel)

	logger.Printf("Starting IDOR analysis with concurrency level %d...", config.ConcurrencyLevel)

	// Use a WaitGroup to track the producer goroutine.
	var producerWG sync.WaitGroup
	producerWG.Add(1)

	// Producer loop: Generate tasks in a separate goroutine to prevent deadlocks
	// when the findings channel buffer or worker pool is full.
	go func() {
		defer producerWG.Done()

		for _, pair := range traffic {
			// Check for cancellation before proceeding.
			if groupCtx.Err() != nil {
				return
			}

			// Capture loop variable
			currentPair := pair

			if shouldSkipRequest(currentPair.Request) {
				continue
			}

			// Strategy 1: Horizontal IDOR Check
			// This might block if the worker pool (g.SetLimit) is full. This is desired behavior.
			g.Go(func() error {
				// The groupCtx ensures that if any goroutine fails, the context is cancelled for others.
				return analyzeTask(groupCtx, config.HttpClient, analysisTask{
					Pair:     currentPair,
					Config:   config,
					TestType: TestTypeHorizontal,
				}, findingsChan, logger)
			})

			// Strategy 2: Resource Manipulation Check
			identifiers := ExtractIdentifiers(currentPair.Request, currentPair.RequestBody)
			for _, ident := range identifiers {
				// Check for cancellation inside the inner loop as well.
				if groupCtx.Err() != nil {
					return
				}

				// Capture loop variable
				currentIdent := ident
				testValue, err := GenerateTestValue(currentIdent)
				if err != nil {
					logger.Printf("Skipping manipulation test for %s: %v", currentIdent.Value, err)
					continue
				}

				g.Go(func() error {
					return analyzeTask(groupCtx, config.HttpClient, analysisTask{
						Pair:       currentPair,
						Config:     config,
						TestType:   TestTypeManipulation,
						Identifier: &currentIdent,
						TestValue:  testValue,
					}, findingsChan, logger)
				})
			}
		}
	}()

	// Waiter Goroutine: Waits for producer to finish scheduling, then waits for workers, then closes channel.
	go func() {
		producerWG.Wait() // Wait for all g.Go() calls to be made.
		g.Wait()          // Wait for all workers to complete.
		close(findingsChan)
	}()

	// Collect results (Main Goroutine)
	// This now runs concurrently with the producer and workers, preventing deadlock.
	var findings []Finding
	// Range over the channel until it's closed by the waiter goroutine.
	for finding := range findingsChan {
		findings = append(findings, finding)
	}

	// MODIFICATION: Replaced flawed error handling with a correct, simpler version.
	// First, wait for all goroutines managed by the errgroup to finish.
	// The 'err' will be the first non-nil error returned by a worker.
	err := g.Wait()

	// Now, check the original context that was passed into Detect.
	// If it was cancelled, that is the root cause and its error should be returned.
	// This correctly returns context.DeadlineExceeded when appropriate.
	if ctx.Err() != nil {
		return findings, ctx.Err()
	}

	// Otherwise, if the original context is fine, we return the error
	// that the errgroup captured from one of its workers (which could be nil).
	return findings, err
}

// analyzeTask performs the actual HTTP request replay and comparison based on the task type.
func analyzeTask(ctx context.Context, client *http.Client, task analysisTask, findingsChan chan<- Finding, logger *log.Logger) error {
	// Check context before starting work (Idiomatic Context usage)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var replayReq *http.Request
	var err error
	var session Session
	finding := &Finding{
		TestType: task.TestType,
	}

	// 1. Prepare the request based on the strategy
	switch task.TestType {
	case TestTypeHorizontal:
		// Use User B's session, keep the original request structure.
		session = task.Config.SecondSession
		replayReq, err = cloneRequest(ctx, task.Pair.Request, task.Pair.RequestBody)
		if err != nil {
			logger.Printf("Error cloning request: %v", err)
			return nil // Non-fatal error for this task
		}
		finding.Severity = SeverityHigh
		finding.Evidence = "User B successfully accessed User A's resource (Horizontal)."
	case TestTypeManipulation:
		// Use User A's session, modify the identifier in the request.
		session = task.Config.Session
		// Pass the worker context (ctx) to ApplyTestValue for correct context propagation.
		replayReq, _, err = ApplyTestValue(ctx, task.Pair.Request, task.Pair.RequestBody, *task.Identifier, task.TestValue)
		if err != nil {
			logger.Printf("Error applying test value: %v", err)
			return nil // Non-fatal error for this task
		}
		finding.Severity = SeverityMedium // Default to Medium, can be adjusted based on sensitivity.
		finding.Evidence = fmt.Sprintf("Successfully accessed resource with manipulated ID '%s' (Manipulation).", task.TestValue)
		finding.Identifier = task.Identifier
		finding.TestedValue = task.TestValue

	default:
		return fmt.Errorf("unknown task type: %s", task.TestType)
	}

	// 2. Apply session and execute
	session.ApplyToRequest(replayReq)
	// URL and Method might be modified in Manipulation strategy.
	finding.URL = replayReq.URL.String()
	finding.Method = replayReq.Method

	resp, respBody, err := executeRequest(client, replayReq)
	if err != nil {
		// Network errors (timeouts, connection issues) or context cancellation during request.
		if ctx.Err() != nil {
			return ctx.Err() // Propagate cancellation error
		}
		// Ignore other network errors in the context of IDOR findings.
		return nil
	}
	finding.StatusCode = resp.StatusCode

	// 3. Evaluate the response
	// Pass the test type and identifier details to allow specialized comparison logic.
	vulnerable, comparisonResult, err := evaluateResponse(task.Pair, resp, respBody, task.Config.ComparisonRules, task.TestType, task.Identifier, task.TestValue)
	if err != nil {
		logger.Printf("Error evaluating response for %s: %v", replayReq.URL, err)
		return nil
	}

	if vulnerable {
		finding.ComparisonDetails = comparisonResult

		// Send finding back to the collector
		select {
		case findingsChan <- *finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// evaluateResponse determines if the replay response indicates a vulnerability by comparing it to the original.
func evaluateResponse(originalPair RequestResponsePair, replayResp *http.Response, replayBody []byte, rules HeuristicRules, testType string, identifier *ObservedIdentifier, testValue string) (bool, *ResponseComparisonResult, error) {
	originalResp := originalPair.Response

	// Heuristic 1: Status Code Analysis
	isOriginalSuccess := originalResp.StatusCode >= 200 && originalResp.StatusCode < 400
	isReplaySuccess := replayResp.StatusCode >= 200 && replayResp.StatusCode < 400

	// If the replay resulted in an authorization error (401/403), the authorization check works.
	if replayResp.StatusCode == http.StatusUnauthorized || replayResp.StatusCode == http.StatusForbidden {
		return false, nil, nil
	}

	// If the original was successful but the replay was not (e.g., 404, 500), it's likely not vulnerable
	// (or in the case of Manipulation, the manipulated resource ID doesn't exist).
	if isOriginalSuccess && !isReplaySuccess {
		return false, nil, nil
	}

	// If both are successful (or both failed similarly), we must compare the content.
	// Heuristic 2: Semantic Body Comparison (The core check)

	comparisonRules := rules

	// Enhance normalization specifically for Manipulation tests.
	// When User A accesses Resource B (manipulation), the response content will differ from Resource A.
	// To verify structural equivalence, we enable structural comparison.
	if testType == TestTypeManipulation && identifier != nil {
		// Create a deep copy of the rules to avoid modifying the shared config (concurrency safety).
		comparisonRules = rules.DeepCopy()

		// FIX: Enable structural comparison mode.
		comparisonRules.NormalizeAllValuesForStructure = true

		// Add the original value and the test value to the ignore list for this specific comparison.
		// (This is technically redundant with NormalizeAllValuesForStructure, but provides defense in depth).
		comparisonRules.SpecificValuesToIgnore[identifier.Value] = struct{}{}
		comparisonRules.SpecificValuesToIgnore[testValue] = struct{}{}
	}

	// We compare the replayed response body against the original response body.
	comparisonResult, err := CompareResponses(originalPair.ResponseBody, replayBody, comparisonRules)
	if err != nil {
		return false, nil, err
	}

	// If the responses are semantically equivalent after normalization, it indicates IDOR.
	return comparisonResult.AreEquivalent, comparisonResult, nil
}

// cloneRequest creates a deep copy of an http.Request, ensuring the body is readable.
func cloneRequest(ctx context.Context, original *http.Request, body []byte) (*http.Request, error) {
	cloned := original.Clone(ctx)
	// Idiomatic optimization: len(nil slice) is 0, so the explicit nil check is redundant.
	if len(body) > 0 {
		cloned.Body = io.NopCloser(bytes.NewReader(body))
		cloned.ContentLength = int64(len(body))
	} else {
		cloned.Body = http.NoBody
		cloned.ContentLength = 0
	}
	return cloned, nil
}

// executeRequest sends the HTTP request and reads the response body.
func executeRequest(client *http.Client, req *http.Request) (*http.Response, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read the body (limit size to prevent excessive memory usage in high-throughput scenarios)
	const maxBodySize = 5 * 1024 * 1024 // 5MB limit
	bodyReader := io.LimitReader(resp.Body, maxBodySize)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		// Ignore errors if the context was cancelled while reading the body
		if req.Context().Err() != nil {
			return resp, nil, req.Context().Err()
		}
		return resp, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp, body, nil
}

// shouldSkipRequest filters out requests that are generally not relevant for IDOR testing.
func shouldSkipRequest(req *http.Request) bool {
	// Skip methods that typically don't access resources directly
	if req.Method == http.MethodOptions || req.Method == http.MethodHead || req.Method == http.MethodTrace {
		return true
	}

	// Skip common static file extensions
	path := strings.ToLower(req.URL.Path)
	extensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".svg", ".ico", ".ttf"}
	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}
