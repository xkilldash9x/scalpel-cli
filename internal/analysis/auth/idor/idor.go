// File: internal/analysis/auth/idor/idor.go
package idor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime" // Added for improved content type handling
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
	TestType   string
	Identifier *ObservedIdentifier
	TestValue  string
}

const (
	TestTypeHorizontal             = "Horizontal"
	TestTypeManipulation           = "Manipulation"
	TestTypeUnauthenticated        = "Unauthenticated"
	TestTypeHorizontalManipulation = "HorizontalManipulation" // (Strategic 5.1)
	TestTypeResourceEnumeration    = "ResourceEnumeration"    // (Strategic 5.6)
)

// Detect is the core logic engine for the IDOR analysis.
// Added identifierPool parameter (Strategic 5.2).
func Detect(ctx context.Context, traffic []RequestResponsePair, config Config, logger *log.Logger, comparer jsoncompare.JSONComparison, identifierPool *IdentifierPool) ([]Finding, error) {
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(config.ConcurrencyLevel)

	findingsChan := make(chan Finding, config.ConcurrencyLevel)

	logger.Printf("Starting IDOR detection phase...")

	// (Fix 3.1: Pre-fetch auth artifacts for dynamic sanitization)
	var authArtifacts AuthArtifacts
	if config.Session != nil && config.Session.IsAuthenticated() {
		authArtifacts = config.Session.GetAuthArtifacts()
	} else {
		// Initialize empty artifacts if no primary session exists.
		authArtifacts = AuthArtifacts{
			HeaderNames: make(map[string]struct{}),
			CookieNames: make(map[string]struct{}),
		}
	}

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

			// (Fix 3.2) Check if the request method is safe or allowed.
			if shouldSkipRequest(currentPair.Request, config.AllowUnsafeMethods) {
				continue
			}

			// (Fix 3.4) Ensure the original request was successful.
			if !isSuccessful(currentPair.Response) {
				continue
			}

			// Strategy 0: Unauthenticated Check
			if !config.SkipUnauthenticated {
				g.Go(func() error {
					// Pass authArtifacts for sanitization
					return analyzeTask(groupCtx, config.HttpClient, analysisTask{
						Pair:     currentPair,
						Config:   config,
						TestType: TestTypeUnauthenticated,
					}, findingsChan, logger, comparer, authArtifacts)
				})
			}

			// Strategy 1: Horizontal IDOR Check (Implicit IDs)
			if !config.SkipHorizontal {
				g.Go(func() error {
					return analyzeTask(groupCtx, config.HttpClient, analysisTask{
						Pair:     currentPair,
						Config:   config,
						TestType: TestTypeHorizontal,
					}, findingsChan, logger, comparer, AuthArtifacts{})
				})
			}

			// Strategies involving manipulation (2 and 3)
			runManipulation := !config.SkipManipulation
			runHorizontalManipulation := !config.SkipHorizontalManipulation

			if runManipulation || runHorizontalManipulation {
				identifiers := ExtractIdentifiers(currentPair.Request, currentPair.RequestBody)
				for _, ident := range identifiers {
					if groupCtx.Err() != nil {
						return
					}

					currentIdent := ident
					// (Strategic 5.2) Generate test values using the pool.
					testValues, err := GenerateTestValues(currentIdent, identifierPool)
					if err != nil {
						logger.Printf("Could not generate test values for identifier %s: %v", currentIdent.Value, err)
						continue
					}
					if len(testValues) == 0 {
						continue
					}

					for _, testValue := range testValues {
						currentTestValue := testValue

						// Strategy 2: Resource Manipulation Check (User A -> Modified ID)
						if runManipulation {
							g.Go(func() error {
								return analyzeTask(groupCtx, config.HttpClient, analysisTask{
									Pair:       currentPair,
									Config:     config,
									TestType:   TestTypeManipulation,
									Identifier: &currentIdent,
									TestValue:  currentTestValue,
								}, findingsChan, logger, comparer, AuthArtifacts{})
							})
						}

						// (Strategic 5.1) Strategy 3: Horizontal Manipulation Check (User B -> Modified ID)
						if runHorizontalManipulation {
							g.Go(func() error {
								return analyzeTask(groupCtx, config.HttpClient, analysisTask{
									Pair:       currentPair,
									Config:     config,
									TestType:   TestTypeHorizontalManipulation,
									Identifier: &currentIdent,
									TestValue:  currentTestValue,
								}, findingsChan, logger, comparer, AuthArtifacts{})
							})
						}
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
	findingMap := make(map[string]Finding)
	for finding := range findingsChan {
		// Create a unique key for the finding
		key := fmt.Sprintf("%s|%s|%s", finding.Method, finding.URL, finding.TestType)
		if finding.Identifier != nil {
			// Use the detailed String() representation for the key.
			key = fmt.Sprintf("%s|%s", key, finding.Identifier.String())
		}

		// Deduplication logic: Prioritize stronger findings (higher severity).
		// If a Manipulation test results in both IDOR and ResourceEnumeration for the same endpoint/ID, the IDOR finding takes precedence.
		if existing, ok := findingMap[key]; ok {
			if finding.Severity > existing.Severity {
				findingMap[key] = finding
			}
		} else {
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
// (Fix 3.1: Added authArtifacts parameter)
func analyzeTask(ctx context.Context, client *http.Client, task analysisTask, findingsChan chan<- Finding, logger *log.Logger, comparer jsoncompare.JSONComparison, authArtifacts AuthArtifacts) error {
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
		// Severity/Evidence determined during evaluation (Strategic 5.4)

	case TestTypeManipulation:
		session = task.Config.Session
		// ApplyTestValue handles encoded payloads (Strategic 5.3)
		replayReq, _, err = ApplyTestValue(ctx, task.Pair.Request, task.Pair.RequestBody, *task.Identifier, task.TestValue)
		if err != nil {
			logger.Printf("Error applying test value (%s) with value '%s': %v", task.Identifier.String(), task.TestValue, err)
			return nil
		}
		finding.Severity = SeverityMedium
		finding.Evidence = fmt.Sprintf("Successfully accessed resource with manipulated ID '%s' (Manipulation).", task.TestValue)
		finding.Identifier = task.Identifier
		finding.TestedValue = task.TestValue

	// (Strategic 5.1) Horizontal Manipulation
	case TestTypeHorizontalManipulation:
		session = task.Config.SecondSession // User B's session
		replayReq, _, err = ApplyTestValue(ctx, task.Pair.Request, task.Pair.RequestBody, *task.Identifier, task.TestValue)
		if err != nil {
			logger.Printf("Error applying test value (%s) with value '%s': %v", task.Identifier.String(), task.TestValue, err)
			return nil
		}
		finding.Severity = SeverityHigh // High severity for accessing arbitrary data as another user.
		finding.Evidence = fmt.Sprintf("User B successfully accessed resource with manipulated ID '%s' (Horizontal Manipulation).", task.TestValue)
		finding.Identifier = task.Identifier
		finding.TestedValue = task.TestValue

	case TestTypeUnauthenticated:
		session = &NilSession{}
		replayReq, err = cloneRequest(ctx, task.Pair.Request, task.Pair.RequestBody)
		if err != nil {
			logger.Printf("Error cloning request: %v", err)
			return nil
		}
		// (Fix 3.1) Dynamically sanitize the request.
		sanitizeRequest(replayReq, authArtifacts)
		finding.Severity = SeverityCritical
		finding.Evidence = "Resource successfully accessed without any authentication."

	default:
		return fmt.Errorf("unknown task type: %s", task.TestType)
	}

	// 2. Apply session and execute
	// (Fix 3.3 CSRF Note): Authenticated replays might fail here if single-use CSRF tokens are used.
	session.ApplyToRequest(replayReq)

	finding.URL = replayReq.URL.String()
	finding.Method = replayReq.Method

	resp, respBody, err := executeRequest(client, replayReq)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	finding.StatusCode = resp.StatusCode

	// 3. Evaluate the response.
	evaluationResult, err := evaluateResponse(task.Pair, resp, respBody, task.Config, task.TestType, task.Identifier, task.TestValue, comparer, logger)
	if err != nil {
		logger.Printf("Error evaluating response for %s: %v", replayReq.URL, err)
		return nil
	}

	if evaluationResult.Vulnerable {
		finding.ComparisonDetails = evaluationResult.ComparisonResult

		// Apply overrides from evaluation (e.g., for Resource Enumeration or context-aware Horizontal)
		if evaluationResult.SeverityOverride != "" {
			finding.Severity = evaluationResult.SeverityOverride
		}
		if evaluationResult.TestTypeOverride != "" {
			finding.TestType = evaluationResult.TestTypeOverride
		}
		if evaluationResult.EvidenceOverride != "" {
			finding.Evidence = evaluationResult.EvidenceOverride
		}

		select {
		case findingsChan <- *finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// (Fix 3.1) sanitizeRequest removes authentication headers and cookies dynamically.
func sanitizeRequest(req *http.Request, artifacts AuthArtifacts) {
	// 1. Remove headers identified by the session.
	for headerName := range artifacts.HeaderNames {
		req.Header.Del(headerName)
	}

	// 2. Handle cookies.
	if len(artifacts.CookieNames) > 0 {
		// Rebuild the cookie header, excluding the specific session cookies.
		existingCookies := req.Cookies()
		req.Header.Del("Cookie") // Clear the header

		// Re-add cookies that are NOT authentication artifacts.
		for _, cookie := range existingCookies {
			if _, exists := artifacts.CookieNames[cookie.Name]; !exists {
				req.AddCookie(cookie)
			}
		}
	} else {
		// Fallback: If the session didn't specify cookies, assume all cookies might be auth-related for a strict unauthenticated test.
		req.Header.Del("Cookie")
	}

	// 3. Defense-in-depth: Ensure standard headers are removed if not already covered.
	req.Header.Del("Authorization")
	req.Header.Del("X-Api-Key")
	req.Header.Del("X-Auth-Token")
	// Remove CSRF tokens as they might interfere with the replay.
	req.Header.Del("X-CSRF-Token")
	req.Header.Del("X-XSRF-Token")
}

// EvaluationResult holds the outcome of the response analysis.
type EvaluationResult struct {
	Vulnerable       bool
	ComparisonResult *jsoncompare.ComparisonResult
	SeverityOverride Severity
	TestTypeOverride string
	EvidenceOverride string
}

// evaluateResponse determines if the replay response indicates a vulnerability.
func evaluateResponse(
	originalPair RequestResponsePair,
	replayResp *http.Response,
	replayBody []byte,
	config Config,
	testType string,
	identifier *ObservedIdentifier,
	testValue string,
	comparer jsoncompare.JSONComparison,
	logger *log.Logger,
) (EvaluationResult, error) {

	originalResp := originalPair.Response
	baseOpts := config.ComparisonOptions

	// Heuristic 1: Status Code Analysis and Authorization Oracle (Strategic 5.6)

	if replayResp.StatusCode == http.StatusUnauthorized || replayResp.StatusCode == http.StatusForbidden {
		// (Strategic 5.6) Authorization Oracle Detection
		// If the test involved manipulation, and the result is 403/401, it implies the resource exists.
		if testType == TestTypeManipulation || testType == TestTypeHorizontalManipulation {
			// (Fix 3.3) Check for potential CSRF interference on unsafe methods before declaring an oracle.
			if replayResp.StatusCode == http.StatusForbidden && !isSafeMethod(originalPair.Request.Method) {
				logger.Printf("Ambiguous 403 Forbidden on unsafe method %s for URL %s. Could be Authorization Oracle or CSRF token failure.", originalPair.Request.Method, originalPair.Request.URL.String())
				// We do not report this as an oracle due to ambiguity.
				return EvaluationResult{Vulnerable: false}, nil
			}

			return EvaluationResult{
				Vulnerable:       true,
				SeverityOverride: SeverityLow,
				TestTypeOverride: TestTypeResourceEnumeration,
				EvidenceOverride: fmt.Sprintf("Request for ID '%s' resulted in %d, indicating the resource exists but access is denied (Authorization Oracle).", testValue, replayResp.StatusCode),
				ComparisonResult: &jsoncompare.ComparisonResult{
					AreEquivalent: false,
					Diff:          fmt.Sprintf("Status code indicates authorization check performed: %d", replayResp.StatusCode),
				},
			}, nil
		}
		return EvaluationResult{Vulnerable: false}, nil
	}

	// Handle Redirects (3xx)
	if replayResp.StatusCode >= 300 && replayResp.StatusCode < 400 {
		// If Unauthenticated, a redirect likely means redirection to a login page (secure).
		if testType == TestTypeUnauthenticated {
			return EvaluationResult{Vulnerable: false}, nil
		}

		// For other types, if both original and replay redirect to the same location, it might be IDOR.
		originalLocation := originalResp.Header.Get("Location")
		replayLocation := replayResp.Header.Get("Location")
		isOriginalRedirect := originalResp.StatusCode >= 300 && originalResp.StatusCode < 400

		if isOriginalRedirect && originalLocation != "" && originalLocation == replayLocation {
			return EvaluationResult{
				Vulnerable: true,
				ComparisonResult: &jsoncompare.ComparisonResult{
					AreEquivalent: true,
					Diff:          fmt.Sprintf("Both requests redirected to the same location: %s", replayLocation),
				},
			}, nil
		}
		return EvaluationResult{Vulnerable: false}, nil
	}

	// If the replay failed (e.g., 404 Not Found, 500 Error), it's not IDOR.
	if !isSuccessful(replayResp) {
		return EvaluationResult{Vulnerable: false}, nil
	}

	// Heuristic 2: Semantic Body Comparison (The core check)

	// Start with a concurrency-safe copy of the base options.
	comparisonOpts := baseOpts.DeepCopy()

	// (Strategic 5.4) Strategy: Horizontal (Implicit ID) - Requires Context-Aware Comparison
	if testType == TestTypeHorizontal {
		// 1. Compare Replay (User B) vs Original (User A) using content comparison.
		comparisonResultA, err := comparer.CompareWithOptions(originalPair.ResponseBody, replayBody, comparisonOpts)
		if err != nil {
			return EvaluationResult{Vulnerable: false}, fmt.Errorf("error during response comparison (Horizontal A vs B): %w", err)
		}

		// If Replay(B) is equivalent to Original(A), User B accessed User A's data.
		if comparisonResultA.AreEquivalent {
			return EvaluationResult{
				Vulnerable:       true,
				SeverityOverride: SeverityHigh,
				EvidenceOverride: "User B successfully accessed User A's resource (Horizontal). Response identical to User A's response.",
				ComparisonResult: comparisonResultA,
			}, nil
		}

		// 2. If they differ, check if the structure is the same (indicating a successful context switch to User B's data).
		structuralOpts := comparisonOpts.DeepCopy()
		structuralOpts.NormalizeAllValuesForStructure = true
		structuralComparison, err := comparer.CompareWithOptions(originalPair.ResponseBody, replayBody, structuralOpts)
		if err != nil {
			return EvaluationResult{Vulnerable: false}, fmt.Errorf("error during structural comparison (Horizontal): %w", err)
		}

		if structuralComparison.AreEquivalent {
			// Outcome 2: Secure (Structures match, content differs -> Context switch occurred).
			return EvaluationResult{Vulnerable: false}, nil
		}

		// Outcome 3: Secure (Content differs AND structure differs).
		return EvaluationResult{Vulnerable: false}, nil
	}

	// Strategy: Manipulation (Vertical/Horizontal) - Requires Structural Comparison
	isManipulationTest := (testType == TestTypeManipulation || testType == TestTypeHorizontalManipulation) && identifier != nil

	if isManipulationTest {
		// Enable structural comparison mode.
		comparisonOpts.NormalizeAllValuesForStructure = true

		// Explicitly ignore the tested identifiers.
		if comparisonOpts.SpecificValuesToIgnore == nil {
			comparisonOpts.SpecificValuesToIgnore = make(map[string]struct{})
		}
		comparisonOpts.SpecificValuesToIgnore[identifier.Value] = struct{}{}
		comparisonOpts.SpecificValuesToIgnore[testValue] = struct{}{}
	}
	// Strategy: Unauthenticated - Requires Content Comparison (default opts).

	// (Strategic 5.5) Handle Non-Structured Responses (HTML/Text)
	contentType := originalResp.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)

	// Use the robust comparison service for structured data (JSON, XML).
	isStructured := strings.Contains(mediaType, "json") || strings.Contains(mediaType, "xml")

	if isStructured {
		comparisonResult, err := comparer.CompareWithOptions(originalPair.ResponseBody, replayBody, comparisonOpts)
		if err != nil {
			return EvaluationResult{Vulnerable: false}, fmt.Errorf("error during response comparison processing: %w", err)
		}

		return EvaluationResult{
			Vulnerable:       comparisonResult.AreEquivalent,
			ComparisonResult: comparisonResult,
		}, nil
	}

	// Heuristics for non-structured data (HTML/Text)
	// Basic heuristic: Compare content length similarity.
	originalLen := len(originalPair.ResponseBody)
	replayLen := len(replayBody)

	if originalLen == 0 && replayLen == 0 {
		return EvaluationResult{Vulnerable: true, ComparisonResult: &jsoncompare.ComparisonResult{AreEquivalent: true, Diff: "Both response bodies were empty."}}, nil
	}

	// Check length similarity (e.g., within 15% tolerance)
	diff := float64(abs(originalLen - replayLen))
	tolerance := 0.15

	if originalLen > 0 && (diff/float64(originalLen)) > tolerance {
		return EvaluationResult{Vulnerable: false, ComparisonResult: &jsoncompare.ComparisonResult{
			AreEquivalent: false,
			Diff:          fmt.Sprintf("Response lengths differ significantly (Original: %d, Replay: %d)", originalLen, replayLen),
		}}, nil
	}

	// If lengths are similar, we assume equivalence for non-structured data.
	return EvaluationResult{Vulnerable: true, ComparisonResult: &jsoncompare.ComparisonResult{
		AreEquivalent: true,
		Diff:          fmt.Sprintf("Non-structured data (%s) with similar lengths (Original: %d, Replay: %d)", mediaType, originalLen, replayLen),
	}}, nil
}

// Helper for absolute difference
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// cloneRequest creates a deep copy of an http.Request.
func cloneRequest(ctx context.Context, original *http.Request, body []byte) (*http.Request, error) {
	cloned := original.Clone(ctx)
	if len(body) > 0 {
		cloned.Body = io.NopCloser(bytes.NewReader(body))
		cloned.ContentLength = int64(len(body))
	} else {
		cloned.Body = http.NoBody
		cloned.ContentLength = 0
	}

	// Ensure cookies are explicitly copied if the Clone didn't populate the Header map correctly.
	if len(original.Cookies()) > 0 && cloned.Header.Get("Cookie") == "" {
		cloned.Header.Del("Cookie")
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

// (Fix 3.2) shouldSkipRequest filters requests based on relevance and safety.
func shouldSkipRequest(req *http.Request, allowUnsafe bool) bool {
	// 1. Check HTTP Method Safety
	if !allowUnsafe && !isSafeMethod(req.Method) {
		return true
	}

	// 2. Skip methods that typically don't access resources directly
	if req.Method == http.MethodOptions || req.Method == http.MethodHead || req.Method == http.MethodTrace {
		return true
	}

	// 3. Skip common static file extensions
	path := strings.ToLower(req.URL.Path)
	extensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".svg", ".ico", ".ttf", ".map"}
	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// isSafeMethod checks if the HTTP method is generally considered safe (idempotent and read-only).
func isSafeMethod(method string) bool {
	// GET is the primary safe method for automated IDOR testing.
	return method == http.MethodGet
}

// isSuccessful checks if the HTTP response indicates a successful operation (2xx or 3xx).
func isSuccessful(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
