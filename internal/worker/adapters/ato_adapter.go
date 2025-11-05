// File: internal/worker/adapters/ato_adapter.go
// File: internal/worker/adapters/ato_adapter.go
package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/ato"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// jsonMarshal is a variable that holds the json.Marshal function.
// This allows it to be replaced during testing to simulate marshaling errors.
var jsonMarshal = json.Marshal

// Default settings for the ATO adapter.
const (
	defaultHTTPTimeout      = 15 * time.Second
	requestThrottleDuration = 200 * time.Millisecond
	maxResponseBodyReadSize = 1024 * 1024 // 1MB
	atoScannerUserAgent     = "evolution-scalpel-ATO-Scanner/1.1"
)

// ATOAdapter is responsible for performing password spraying attacks to find weak credentials.
// It iterates through a list of usernames and a predefined wordlist of common passwords,
// reporting successful logins or potential user enumeration vulnerabilities.
//
// The adapter includes throttling to avoid overwhelming the target system and handles
// context cancellation gracefully to allow for clean shutdown of scans.
type ATOAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

// NewATOAdapter creates a new ATOAdapter with a default HTTP client.
func NewATOAdapter() *ATOAdapter {
	// Configure the default client to not follow redirects automatically.
	defaultClient := &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &ATOAdapter{
		// Do not fetch the global logger here. The logger will be retrieved from the
		// AnalysisContext during the Analyze method. This prevents race conditions
		// during initialization where the global logger may not have been configured yet.
		// The BaseAnalyzer safely handles a nil logger.
		BaseAnalyzer: *core.NewBaseAnalyzer("ATO Adapter (Password Spraying)", "Tests for weak credentials via password spraying", core.TypeActive, nil),
		httpClient:   defaultClient,
	}
}

// SetHttpClient allows overriding the default HTTP client, primarily for testing.
func (a *ATOAdapter) SetHttpClient(client *http.Client) {
	if client != nil {
		a.httpClient = client
	}
}

// GetHttpClient returns the current HTTP client (used for testing).
func (a *ATOAdapter) GetHttpClient() *http.Client {
	return a.httpClient
}

func (a *ATOAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Ensure the HTTP client is initialized (defense in depth).
	if a.httpClient == nil {
		return fmt.Errorf("critical error: HTTP client not initialized in ATOAdapter")
	}

	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Starting active password spraying attack.")

	// 1. Parameter Validation and Extraction
	params, err := a.extractParams(analysisCtx)
	if err != nil {
		return err
	}

	// 2. Payload Generation
	payloads := ato.GenerateSprayingPayloads(params.Usernames)
	logger.Info("Generated login payloads for spraying attack", zap.Int("payload_count", len(payloads)))

	// 3. Execution with Throttling
	throttle := time.NewTicker(requestThrottleDuration)
	defer throttle.Stop()

	for _, attempt := range payloads {
		// Check for cancellation signal before each attempt.
		select {
		case <-ctx.Done():
			logger.Warn("ATO analysis cancelled by context.", zap.Error(ctx.Err()))
			return ctx.Err()
		case <-throttle.C:
			// Proceed with the login attempt.
			a.performLoginAttempt(ctx, analysisCtx, attempt)
		}
	}

	logger.Info("Password spraying attack completed.")
	return nil
}

// extractParams handles the type assertion and validation of the task parameters.
func (a *ATOAdapter) extractParams(analysisCtx *core.AnalysisContext) (schemas.ATOTaskParams, error) {
	var params schemas.ATOTaskParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.ATOTaskParams:
		params = p
	case *schemas.ATOTaskParams:
		if p == nil {
			return schemas.ATOTaskParams{}, fmt.Errorf("invalid parameters: nil pointer for ATO task")
		}
		params = *p
	default:
		actualType := fmt.Sprintf("%T", p)
		analysisCtx.Logger.Error("Invalid parameter type assertion",
			zap.String("expected", "schemas.ATOTaskParams or pointer"),
			zap.String("actual", actualType))
		return schemas.ATOTaskParams{}, fmt.Errorf("invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got %T", p)
	}

	if len(params.Usernames) == 0 {
		return schemas.ATOTaskParams{}, fmt.Errorf("'usernames' parameter must be a non-empty array of strings")
	}

	return params, nil
}

func (a *ATOAdapter) performLoginAttempt(ctx context.Context, analysisCtx *core.AnalysisContext, attempt ato.LoginAttempt) {
	logger := analysisCtx.Logger.With(zap.String("username", attempt.Username), zap.String("password", "REDACTED"))
	logger.Debug("Performing login attempt")

	// Ensure TargetURL is valid before use.
	if analysisCtx.TargetURL == nil {
		logger.Error("TargetURL is nil in AnalysisContext, cannot perform login attempt.")
		return
	}

	// Prepare the request (Assuming JSON POST).
	payloadBytes, err := json.Marshal(map[string]string{
		"username": attempt.Username, // Redacted in logs
		"password": attempt.Password, // Redacted in logs
	})
	if err != nil {
		logger.Error("Failed to marshal login payload for ATO attempt", zap.Error(err))
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", analysisCtx.TargetURL.String(), bytes.NewReader(payloadBytes))
	if err != nil {
		logger.Error("Failed to create HTTP request for ATO attempt", zap.Error(err), zap.String("target_url", analysisCtx.TargetURL.String()))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", atoScannerUserAgent)

	// Execute the request
	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	if err != nil {
		// Check for cancellation before logging network errors, as cancellation often manifests as a network error.
		if ctx.Err() != nil {
			return
		}
		logger.Warn("HTTP request failed during login attempt", zap.Error(err), zap.String("target_url", analysisCtx.TargetURL.String()))
		return
	}
	defer resp.Body.Close()
	responseTimeMs := time.Since(startTime).Milliseconds()

	// Read the body, limiting the size.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyReadSize))
	if err != nil {
		logger.Warn("Failed to read response body during ATO attempt", zap.Error(err), zap.Int("status_code", resp.StatusCode))
		// We can still proceed with analysis based on the status code.
	}

	// Analyze the response using the dedicated ATO logic package.
	result := ato.AnalyzeResponse(attempt, resp.StatusCode, string(bodyBytes), responseTimeMs)

	// Report findings based on the analysis result.
	if result.Success {
		a.createAtoFinding(analysisCtx, "Successful Login with Weak Credentials", schemas.SeverityHigh, "CWE-521",
			fmt.Sprintf("Successfully authenticated as user '%s' using a common weak password ('%s').", result.Attempt.Username, result.Attempt.Password),
			result)
	}
	if result.IsUserEnumeration {
		a.createAtoFinding(analysisCtx, "User Enumeration on Login Form", schemas.SeverityMedium, "CWE-200",
			fmt.Sprintf("The login endpoint response for user '%s' allows for user enumeration. Detail: %s", result.Attempt.Username, result.EnumerationDetail),
			result)
	}
}

// createAtoFinding generates and reports a finding based on the ATO analysis result.
func (a *ATOAdapter) createAtoFinding(analysisCtx *core.AnalysisContext, vulnName string, severity schemas.Severity, cwe, desc string, result ato.LoginResponse) {
	// Truncate evidence if it exceeds a reasonable limit for storage.
	responseBodyEvidence := result.ResponseBody
	if len(responseBodyEvidence) > 2048 {
		responseBodyEvidence = responseBodyEvidence[:2048] + "... [TRUNCATED]"
	}

	evidenceMap := map[string]interface{}{
		"username": result.Attempt.Username,
		// IMPORTANT: Password intentionally omitted from evidence logs for security.
		"statusCode":     result.StatusCode,
		"responseBody":   responseBodyEvidence,
		"detail":         result.EnumerationDetail,
		"responseTimeMs": result.ResponseTimeMs,
	}
	evidence, err := json.Marshal(evidenceMap)
	if err != nil {
		analysisCtx.Logger.Error("Failed to marshal ATO evidence", zap.Error(err), zap.String("vuln_name", vulnName))
		// Fallback evidence in case of marshaling error.
		evidence = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %s"}`, err.Error()))
	}

	// Ensure Target URL is available for the finding.
	target := ""
	if analysisCtx.TargetURL != nil {
		target = analysisCtx.TargetURL.String()
	}

	finding := schemas.Finding{
		ID:        uuid.New().String(),
		TaskID:    analysisCtx.Task.TaskID,
		Timestamp: time.Now().UTC(),
		Target:    target,
		Module:    a.Name(),
		Vulnerability: schemas.Vulnerability{
			Name: vulnName,
		},
		Severity:       severity,
		Description:    desc,
		Evidence:       string(evidence),
		Recommendation: "Implement rate limiting, account lockouts, and CAPTCHA. Ensure login responses are generic (e.g., 'Invalid username or password') and do not disclose whether a username or password was correct. Implement Multi-Factor Authentication (MFA).",
		CWE:            []string{cwe},
	}
	analysisCtx.AddFinding(finding)
	analysisCtx.Logger.Info("ATO finding generated",
		zap.String("vulnerability", vulnName),
		zap.String("severity", string(severity)),
		zap.String("username", result.Attempt.Username),
		zap.String("target", target),
	)
}

// -- Test Helpers --

// GetJSONMarshalForTest returns the current json.Marshal function used by the adapter.
func GetJSONMarshalForTest() func(v interface{}) ([]byte, error) {
	return jsonMarshal
}

// SetJSONMarshalForTest overrides the json.Marshal function for testing purposes.
func SetJSONMarshalForTest(fn func(v interface{}) ([]byte, error)) {
	jsonMarshal = fn
}
