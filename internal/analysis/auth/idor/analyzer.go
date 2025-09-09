// internal/analysis/auth/idor/analyzer.go
package idor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// Note: Core data structures for this package, such as SessionContext
// and ObservedRequest, are defined in the types.go file.

// Analyzer orchestrates the IDOR testing process (User A vs User B).
type Analyzer struct {
	ScanID      uuid.UUID
	logger      *zap.Logger
	sessions    map[string]*SessionContext
	reporter    core.Reporter
	mu          sync.RWMutex // Mutex for protecting the sessions map
	concurrency int
}

// NewAnalyzer initializes the IDOR analyzer.
// Concurrency level determines the number of parallel test requests.
func NewAnalyzer(scanID uuid.UUID, logger *zap.Logger, reporter core.Reporter, concurrency int) *Analyzer {
	if concurrency <= 0 {
		concurrency = 10 // Default concurrency
	}
	return &Analyzer{
		ScanID:      scanID,
		logger:      logger.Named("idor_analyzer"),
		sessions:    make(map[string]*SessionContext),
		reporter:    reporter,
		concurrency: concurrency,
	}
}

// InitializeSession creates a new user persona for testing, with its own cookie jar.
func (a *Analyzer) InitializeSession(role string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar for role %s: %w", role, err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		// Crucial: Disable redirects to observe authorization responses (e.g., 302 vs 403).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Lock the Analyzer before modifying the sessions map
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.sessions[role]; exists {
		return fmt.Errorf("session role %s already initialized", role)
	}

	a.sessions[role] = &SessionContext{
		Role:             role,
		Client:           client,
		ObservedRequests: make(map[string]ObservedRequest),
	}
	return nil
}

// ObserveAndExecute is called during the crawl phase. It executes requests within a session and saves interesting ones.
func (a *Analyzer) ObserveAndExecute(ctx context.Context, role string, req *http.Request, body []byte) (*http.Response, error) {
	// RLock Analyzer to safely access the session
	a.mu.RLock()
	session, exists := a.sessions[role]
	a.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session role %s not initialized", role)
	}

	// Prepare request body
	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Execute the request
	resp, err := session.Client.Do(req.WithContext(ctx))
	if err != nil {
		return resp, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Warn("Failed to read response body during observation, skipping", zap.Error(err), zap.String("url", req.URL.String()))
		// Do not return the error, but also do not process the observation.
		// We still need to give back the response object with a reset body.
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		return resp, nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody)) // Reset body

	// Analyze the request for identifiers
	identifiers := ExtractIdentifiers(req, body)

	if len(identifiers) > 0 {
		requestKey := fmt.Sprintf("%s %s", req.Method, req.URL.Path)

		// Clone the request before acquiring the lock to reduce contention
		clonedReq := req.Clone(ctx)

		// Lock the SessionContext for safe concurrent writes during observation
		session.mu.Lock()
		defer session.mu.Unlock()

		session.ObservedRequests[requestKey] = ObservedRequest{
			Request:        clonedReq,
			Body:           body,
			Identifiers:    identifiers,
			BaselineStatus: resp.StatusCode,
			BaselineLength: int64(len(respBody)),
		}
	}

	return resp, nil
}

// RunAnalysis is the main testing phase. Optimized for concurrent execution.
func (a *Analyzer) RunAnalysis(ctx context.Context, primaryRole, secondaryRole string) error {
	// RLock Analyzer to safely access sessions
	a.mu.RLock()
	primarySession, okP := a.sessions[primaryRole]
	secondarySession, okS := a.sessions[secondaryRole]
	a.mu.RUnlock()

	if !okP || !okS {
		return fmt.Errorf("both primary (%s) and secondary (%s) roles must be initialized", primaryRole, secondaryRole)
	}

	// Safely access the count of observed requests
	primarySession.mu.RLock()
	observedCount := len(primarySession.ObservedRequests)
	primarySession.mu.RUnlock()

	a.logger.Info("Starting IDOR analysis",
		zap.String("Victim", primaryRole),
		zap.String("Attacker", secondaryRole),
		zap.Int("ObservedRequests", observedCount))

	var wg sync.WaitGroup

	// Strategy 1: Horizontal IDOR (Attacker accesses Victim's resources)
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.testHorizontal(ctx, primarySession, secondarySession)
	}()

	// Strategy 2: Predictive IDOR (Can we guess IDs of other resources?)
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.testPredictive(ctx, primarySession)
	}()

	wg.Wait()
	a.logger.Info("IDOR analysis completed")

	return nil
}

// testHorizontal replays User A's requests using User B's session.
// Optimized using a worker pool pattern.
func (a *Analyzer) testHorizontal(ctx context.Context, primarySession *SessionContext, secondarySession *SessionContext) {
	jobs := make(chan ObservedRequest, len(primarySession.ObservedRequests))

	// Fill the job channel (safe read access)
	primarySession.mu.RLock()
	for _, observed := range primarySession.ObservedRequests {
		jobs <- observed
	}
	primarySession.mu.RUnlock()
	close(jobs)

	var wg sync.WaitGroup

	// Start worker Goroutines
	for i := 0; i < a.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.horizontalWorker(ctx, primarySession, secondarySession, jobs)
		}()
	}

	wg.Wait()
}

// horizontalWorker processes jobs from the channel for horizontal IDOR testing.
func (a *Analyzer) horizontalWorker(ctx context.Context, primarySession *SessionContext, secondarySession *SessionContext, jobs <-chan ObservedRequest) {
	for observed := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Prepare the request clone
		req := observed.Request.Clone(ctx)
		var reqBody []byte
		if len(observed.Body) > 0 {
			reqBody = observed.Body
			req.Body = io.NopCloser(bytes.NewReader(observed.Body))
		}

		// Replay the request using the secondary session (Attacker's context)
		resp, err := secondarySession.Client.Do(req)
		if err != nil {
			a.logger.Debug("Network error during IDOR replay", zap.Error(err), zap.String("url", req.URL.String()))
			continue
		}
		// Crucial: Guarantee the body is closed to prevent connection leaks
		defer resp.Body.Close()

		// Analyze the response
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			a.logger.Warn("Failed to read response body during IDOR analysis", zap.Error(err), zap.String("url", req.URL.String()))
			continue // Cannot analyze without the full body
		}

		currentLength := int64(len(respBody))

		// Detection Logic: Same status code and similar content length.
		if resp.StatusCode == observed.BaselineStatus {
			lengthDiff := abs(currentLength - observed.BaselineLength)
			tolerance := int64(float64(observed.BaselineLength) * 0.1) // 10% tolerance for dynamic content

			if lengthDiff <= tolerance {
				// Vulnerability found
				key := fmt.Sprintf("%s %s", req.Method, req.URL.Path)
				description := fmt.Sprintf("A resource belonging to %s (Victim) was successfully accessed by %s (Attacker). The status code (%d) and content length (%d vs baseline %d) match the original request, indicating an access control failure (BOLA).",
					primarySession.Role, secondarySession.Role, resp.StatusCode, currentLength, observed.BaselineLength)

				evidence := &core.Evidence{
					Summary: fmt.Sprintf("Horizontal access to %s", key),
					Request: &core.SerializedRequest{
						Method:  req.Method,
						URL:     req.URL.String(),
						Headers: req.Header,
						Body:    string(reqBody),
					},
					Response: &core.SerializedResponse{
						StatusCode: resp.StatusCode,
						Headers:    resp.Header,
						Body:       string(respBody),
					},
				}

				a.reportFinding(
					"Horizontal Insecure Direct Object Reference (IDOR)",
					description,
					core.SeverityHigh,
					req.URL.String(),
					evidence,
					"CWE-284", // Improper Access Control
				)
			}
		}
	}
}

//  checks if modifying identifiers leads to accessing other valid resources.
// Optimized using a worker pool pattern.
func (a *Analyzer) testPredictive(ctx context.Context, session *SessionContext) {
	// PredictiveJob is defined in types.go
	jobs := make(chan PredictiveJob, 100) // Buffer the channel

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Prepare job list (safe read access)
		session.mu.RLock()
		for _, observed := range session.ObservedRequests {
			for _, identifier := range observed.Identifiers {
				job := PredictiveJob{Observed: observed, Identifier: identifier}
				select {
				case jobs <- job:
				case <-ctx.Done():
					session.mu.RUnlock()
					close(jobs)
					return
				}
			}
		}
		session.mu.RUnlock()
		close(jobs)
	}()

	// Start worker Goroutines
	for i := 0; i < a.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.predictiveWorker(ctx, session, jobs)
		}()
	}

	wg.Wait()
}

//  processes jobs from the channel for predictive IDOR testing.
func (a *Analyzer) predictiveWorker(ctx context.Context, session *SessionContext, jobs <-chan PredictiveJob) {
	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		observed := job.Observed
		identifier := job.Identifier

		// Generate the test value
		testValue, err := GenerateTestValue(identifier)
		if err != nil {
			// Skip if we cannot generate a predictable value (e.g., UUIDs)
			continue
		}

		// Create the modified request
		testReq, testBody, err := ApplyTestValue(observed.Request, observed.Body, identifier, testValue)
		if err != nil {
			a.logger.Debug("Failed to apply test value", zap.Error(err))
			continue
		}

		if len(testBody) > 0 {
			testReq.Body = io.NopCloser(bytes.NewReader(testBody))
		}

		// Send the modified request using the original user's session
		resp, err := session.Client.Do(testReq.WithContext(ctx))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			a.logger.Warn("Failed to read response body during predictive IDOR analysis", zap.Error(err), zap.String("url", testReq.URL.String()))
			continue
		}

		// Detection Logic: A successful response (2xx).
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Vulnerability found
			key := fmt.Sprintf("%s %s", observed.Request.Method, observed.Request.URL.Path)
			description := fmt.Sprintf("The application granted access to a resource by predicting an identifier. The original identifier '%s' (Type: %s) at location '%s' (Key: %s) was modified to '%s', and the request succeeded (Status: %d).",
				identifier.Value, identifier.Type, identifier.Location, identifier.Key, testValue, resp.StatusCode)

			evidence := &core.Evidence{
				Summary: fmt.Sprintf("Predictive access to %s using modified ID %s", key, testValue),
				Request: &core.SerializedRequest{
					Method:  testReq.Method,
					URL:     testReq.URL.String(),
					Headers: testReq.Header,
					Body:    string(testBody),
				},
				Response: &core.SerializedResponse{
					StatusCode: resp.StatusCode,
					Headers:    resp.Header,
					Body:       string(respBody),
				},
			}

			a.reportFinding(
				"Predictive Insecure Direct Object Reference (IDOR)",
				description,
				core.SeverityMedium,
				testReq.URL.String(),
				evidence,
				"CWE-639", // Authorization Bypass Through User-Controlled Key
			)
		}
	}
}

//  publishes the vulnerability details via the core reporter interface.
func (a *Analyzer) reportFinding(title, description string, severity core.SeverityLevel, targetURL string, evidence *core.Evidence, cwe string) {
	finding := core.AnalysisResult{
		ScanID:            a.ScanID,
		AnalyzerName:      "IDORAnalyzer",
		Timestamp:         time.Now().UTC(),
		VulnerabilityType: "BrokenObjectLevelAuthorization",
		Title:             title,
		Description:       description,
		Severity:          severity,
		Status:            core.StatusOpen,
		Confidence:        0.95, // High confidence for active tests.
		TargetURL:         targetURL,
		Evidence:          evidence,
		CWE:               cwe,
	}
	if err := a.reporter.Publish(finding); err != nil {
		a.logger.Error("Failed to publish finding", zap.Error(err), zap.String("title", title))
	}
}

// Helper function for absolute value of int64
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
