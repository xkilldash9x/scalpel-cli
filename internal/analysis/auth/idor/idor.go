// File: internal/analysis/auth/idor/idor.go
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

	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"golang.org/x/sync/errgroup"
)

// ErrUnauthenticated is a custom error type.
type ErrUnauthenticated struct {
	Message string
}

func (e *ErrUnauthenticated) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "IDOR analysis requires authenticated sessions"
}

// analysisTask represents a single unit of work for a concurrent worker.
type analysisTask struct {
	Pair       RequestResponsePair
	Config     Config
	TestType   string // "Horizontal", "Manipulation", or "Unauthenticated"
	Identifier *ObservedIdentifier
	TestValue  string
}

const (
	TestTypeHorizontal      = "Horizontal"
	TestTypeManipulation    = "Manipulation"
	TestTypeUnauthenticated = "Unauthenticated"
)

// Detect is the core logic engine for the IDOR analysis. It generates and executes
// test cases based on the enabled strategies.
func Detect(ctx context.Context, traffic []RequestResponsePair, config Config, logger *log.Logger, comparer jsoncompare.JSONComparison) ([]Finding, error) {
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(config.ConcurrencyLevel)

	findingsChan := make(chan Finding, config.ConcurrencyLevel)

	logger.Printf("Starting IDOR analysis with concurrency level %d...", config.ConcurrencyLevel)

	var producerWG sync.WaitGroup
	producerWG.Add(1)

	// Producer loop: Generate tasks.
	go func() {
		defer producerWG.Done()

		for _, pair := range traffic {
			if groupCtx.Err() != nil {
				return
			}

			currentPair := pair

			if shouldSkipRequest(currentPair.Request) {
				continue
			}

			// Strategy 0: Unauthenticated Check
			if !config.SkipUnauthenticated {
				g.Go(func() error {
					return analyzeTask(groupCtx, config.HttpClient, analysisTask{
						Pair:     currentPair,
						Config:   config,
						TestType: TestTypeUnauthenticated,
					}, findingsChan, logger, comparer)
				})
			}

			// Strategy 1: Horizontal IDOR Check
			if !config.SkipHorizontal {
				g.Go(func() error {
					return analyzeTask(groupCtx, config.HttpClient, analysisTask{
						Pair:     currentPair,
						Config:   config,
						TestType: TestTypeHorizontal,
					}, findingsChan, logger, comparer)
				})
			}

			// Strategy 2: Resource Manipulation Check
			if !config.SkipManipulation {
				// Identifiers are extracted and deduplicated in ExtractIdentifiers
				identifiers := ExtractIdentifiers(currentPair.Request, currentPair.RequestBody)
				for _, ident := range identifiers {
					if groupCtx.Err() != nil {
						return
					}

					currentIdent := ident
					// Generate multiple test values
					testValues, err := GenerateTestValues(currentIdent)
					if err != nil {
						logger.Printf("Skipping manipulation test for %s: %v", currentIdent.Value, err)
						continue
					}

					for _, testValue := range testValues {
						// Capture loop variable
						currentTestValue := testValue
						g.Go(func() error {
							return analyzeTask(groupCtx, config.HttpClient, analysisTask{
								Pair:       currentPair,
								Config:     config,
								TestType:   TestTypeManipulation,
								Identifier: &currentIdent,
								TestValue:  currentTestValue,
							}, findingsChan, logger, comparer)
						})
					}
				}
			}
		}
	}()

	// Waiter Goroutine
	go func() {
		producerWG.Wait()
		g.Wait()
		close(findingsChan)
	}()

	// Collect results and deduplicate
	// We deduplicate because multiple test values might succeed for the same identifier.
	findingMap := make(map[string]Finding)
	for finding := range findingsChan {
		// Create a unique key for the finding
		key := fmt.Sprintf("%s|%s|%s", finding.Method, finding.URL, finding.TestType)
		if finding.Identifier != nil {
			// Append identifier location details (Location and Key/PathIndex) to the key for manipulation tests.
			key = fmt.Sprintf("%s|%s", key, finding.Identifier.String())
		}

		// Only add if it doesn't exist, or if the new finding has higher severity (unlikely in this logic, but safe).
		if existing, ok := findingMap[key]; !ok || finding.Severity > existing.Severity {
			findingMap[key] = finding
		}
	}

	var findings []Finding
	for _, finding := range findingMap {
		findings = append(findings, finding)
	}

	err := g.Wait()

	if ctx.Err() != nil {
		return findings, ctx.Err()
	}

	return findings, err
}

// analyzeTask performs the actual HTTP request replay and comparison.
func analyzeTask(ctx context.Context, client *http.Client, task analysisTask, findingsChan chan<- Finding, logger *log.Logger, comparer jsoncompare.JSONComparison) error {
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
		session = task.Config.SecondSession
		replayReq, err = cloneRequest(ctx, task.Pair.Request, task.Pair.RequestBody)
		if err != nil {
			logger.Printf("Error cloning request: %v", err)
			return nil
		}
		finding.Severity = SeverityHigh
		finding.Evidence = "User B successfully accessed User A's resource (Horizontal)."

	case TestTypeManipulation:
		session = task.Config.Session
		replayReq, _, err = ApplyTestValue(ctx, task.Pair.Request, task.Pair.RequestBody, *task.Identifier, task.TestValue)
		if err != nil {
			// Log detailed error but allow other tasks to continue.
			logger.Printf("Error applying test value (%s) with value '%s': %v", task.Identifier.String(), task.TestValue, err)
			return nil
		}
		finding.Severity = SeverityMedium
		finding.Evidence = fmt.Sprintf("Successfully accessed resource with manipulated ID '%s' (Manipulation).", task.TestValue)
		finding.Identifier = task.Identifier
		finding.TestedValue = task.TestValue

	case TestTypeUnauthenticated:
		// Use the NilSession to represent the unauthenticated state.
		session = &NilSession{}
		replayReq, err = cloneRequest(ctx, task.Pair.Request, task.Pair.RequestBody)
		if err != nil {
			logger.Printf("Error cloning request: %v", err)
			return nil
		}
		// Crucial: Explicitly remove authorization headers/cookies from the cloned request.
		sanitizeRequest(replayReq)
		finding.Severity = SeverityCritical
		finding.Evidence = "Resource successfully accessed without any authentication."

	default:
		return fmt.Errorf("unknown task type: %s", task.TestType)
	}

	// 2. Apply session and execute
	// For authenticated sessions, this applies credentials. For NilSession, it does nothing.
	session.ApplyToRequest(replayReq)

	finding.URL = replayReq.URL.String()
	finding.Method = replayReq.Method

	resp, respBody, err := executeRequest(client, replayReq)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Ignore other network errors.
		return nil
	}
	finding.StatusCode = resp.StatusCode

	// 3. Evaluate the response using the injected comparer service.
	vulnerable, comparisonResult, err := evaluateResponse(task.Pair, resp, respBody, task.Config.ComparisonOptions, task.TestType, task.Identifier, task.TestValue, comparer)
	if err != nil {
		logger.Printf("Error evaluating response for %s: %v", replayReq.URL, err)
		return nil
	}

	if vulnerable {
		finding.ComparisonDetails = comparisonResult

		select {
		case findingsChan <- *finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// sanitizeRequest removes common authentication headers and cookies from a request.
func sanitizeRequest(req *http.Request) {
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	req.Header.Del("X-Api-Key")
	req.Header.Del("X-Auth-Token")
	req.Header.Del("X-CSRF-Token")
	req.Header.Del("X-XSRF-Token")
}

// evaluateResponse determines if the replay response indicates a vulnerability.
func evaluateResponse(originalPair RequestResponsePair, replayResp *http.Response, replayBody []byte, baseOpts jsoncompare.Options, testType string, identifier *ObservedIdentifier, testValue string, comparer jsoncompare.JSONComparison) (bool, *jsoncompare.ComparisonResult, error) {
	originalResp := originalPair.Response

	// Heuristic 1: Status Code Analysis
	isOriginalSuccess := originalResp.StatusCode >= 200 && originalResp.StatusCode < 400

	if replayResp.StatusCode == http.StatusUnauthorized || replayResp.StatusCode == http.StatusForbidden {
		return false, nil, nil
	}

	// Handle Redirects (3xx)
	if replayResp.StatusCode >= 300 && replayResp.StatusCode < 400 {
		// If Unauthenticated, a redirect likely means redirection to a login page (secure).
		if testType == TestTypeUnauthenticated {
			return false, nil, nil
		}

		// For other types, if both original and replay redirect to the same location, it might be IDOR.
		originalLocation := originalResp.Header.Get("Location")
		replayLocation := replayResp.Header.Get("Location")
		// Check if the original was also a redirect
		isOriginalRedirect := originalResp.StatusCode >= 300 && originalResp.StatusCode < 400

		if isOriginalRedirect && originalLocation != "" && originalLocation == replayLocation {
			return true, &jsoncompare.ComparisonResult{
				AreEquivalent: true,
				Diff:          fmt.Sprintf("Both requests redirected to the same location: %s", replayLocation),
			}, nil
		}
		return false, nil, nil
	}

	isReplaySuccess := replayResp.StatusCode >= 200 && replayResp.StatusCode < 400

	if isOriginalSuccess && !isReplaySuccess {
		return false, nil, nil
	}

	// Heuristic 2: Semantic Body Comparison (The core check)

	// Start with a concurrency-safe copy of the base options provided in the config.
	comparisonOpts := baseOpts.DeepCopy()

	// Enhance normalization specifically for Manipulation tests.
	// We need structural comparison because User A accessing Resource B will have different data than Resource A.
	if testType == TestTypeManipulation && identifier != nil {
		// Enable structural comparison mode.
		comparisonOpts.NormalizeAllValuesForStructure = true

		// Explicitly ignore the tested identifiers (defense in depth).
		if comparisonOpts.SpecificValuesToIgnore == nil {
			comparisonOpts.SpecificValuesToIgnore = make(map[string]struct{})
		}
		comparisonOpts.SpecificValuesToIgnore[identifier.Value] = struct{}{}
		comparisonOpts.SpecificValuesToIgnore[testValue] = struct{}{}
	}
	// For Horizontal and Unauthenticated tests, we expect nearly identical responses.

	// We compare the replayed response body against the original response body using the injected service.
	// The comparison service handles JSON and XML robustly.
	comparisonResult, err := comparer.CompareWithOptions(originalPair.ResponseBody, replayBody, comparisonOpts)
	if err != nil {
		// The service handles non-structured data gracefully, so this error indicates an unexpected processing issue.
		return false, nil, fmt.Errorf("error during response comparison processing: %w", err)
	}

	// If the responses are semantically equivalent after normalization, it indicates IDOR.
	return comparisonResult.AreEquivalent, comparisonResult, nil
}

// cloneRequest creates a deep copy of an http.Request, ensuring the body is readable and cookies are preserved.
func cloneRequest(ctx context.Context, original *http.Request, body []byte) (*http.Request, error) {
	cloned := original.Clone(ctx)
	if len(body) > 0 {
		cloned.Body = io.NopCloser(bytes.NewReader(body))
		cloned.ContentLength = int64(len(body))
	} else {
		cloned.Body = http.NoBody
		cloned.ContentLength = 0
	}

	// Ensure cookies are explicitly copied, as http.Request.Clone() might not handle the internal cookie slice correctly.
	if len(original.Cookies()) > 0 {
		cloned.Header.Del("Cookie") // Clear any potentially shallow-copied header
		for _, cookie := range original.Cookies() {
			cloned.AddCookie(cookie)
		}
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

	// Read the body (limit size)
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
