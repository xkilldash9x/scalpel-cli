// internal/worker/adapters/ato_adapter.go
package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/go-homedir"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/ato"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// Constants for default behavior if not specified in task parameters (assuming future schema updates).
const (
	defaultUserField   = "username"
	defaultPassField   = "password"
	defaultContentType = "application/json"
)

type ATOAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

// NewATOAdapter creates a new ATOAdapter with a default HTTP client.
func NewATOAdapter() *ATOAdapter {
	defaultClient := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	return &ATOAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer("ATO Adapter (Password Spraying)", "Tests for weak credentials via password spraying", core.TypeActive, zap.NewNop()),
		httpClient:   defaultClient,
	}
}

// SetHttpClient allows overriding the default HTTP client, primarily for testing.
func (a *ATOAdapter) SetHttpClient(client *http.Client) {
	if client != nil {
		a.httpClient = client
	}
}

func (a *ATOAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if a.httpClient == nil {
		return fmt.Errorf("critical error: HTTP client not initialized in ATOAdapter")
	}
	analysisCtx.Logger.Info("Starting active password spraying attack.")

	// Use the specific parameter struct for type safety.
	// Use robust type assertion.
	var params schemas.ATOTaskParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.ATOTaskParams:
		params = p
	case *schemas.ATOTaskParams:
		if p == nil {
			return fmt.Errorf("invalid parameters: nil pointer for ATO task")
		}
		params = *p
	default:
		actualType := fmt.Sprintf("%T", analysisCtx.Task.Parameters)
		analysisCtx.Logger.Error("Invalid parameter type assertion", zap.String("expected", "schemas.ATOTaskParams or pointer"), zap.String("actual", actualType))
		return fmt.Errorf("invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got %s", actualType)
	}

	// Load usernames from SecLists if not provided in task parameters
	usernames, err := a.loadUsernames(analysisCtx.Global.Config, params)
	if err != nil {
		analysisCtx.Logger.Error("Failed to load usernames for ATO attack", zap.Error(err))
		return err
	}

	if len(usernames) == 0 {
		analysisCtx.Logger.Warn("No usernames loaded for ATO attack, skipping.")
		return nil
	}

	payloads := ato.GenerateSprayingPayloads(usernames)
	analysisCtx.Logger.Info("Generated login payloads for spraying attack", zap.Int("payload_count", len(payloads)))

	// Throttle requests to avoid overwhelming the target.
	throttle := time.NewTicker(200 * time.Millisecond)
	defer throttle.Stop()

	// Determine request structure (Fields and Content-Type).
	// NOTE: We assume these fields might be added to schemas.ATOTaskParams in the future.
	// For now, we use defaults, making the adapter less flexible.
	userField := defaultUserField
	passField := defaultPassField
	contentType := defaultContentType

	/*
		// Example of how to integrate if schema is updated:
		if params.UserField != "" {
			userField = params.UserField
		}
		// ... similar for PassField and ContentType
	*/

	for _, attempt := range payloads {
		// Check for cancellation signal before each attempt.
		select {
		case <-ctx.Done():
			analysisCtx.Logger.Warn("ATO analysis cancelled by context.", zap.Error(ctx.Err()))
			return ctx.Err()
		case <-throttle.C: // Receive from the ticker's channel 'C'.
			a.performLoginAttempt(ctx, analysisCtx, attempt, userField, passField, contentType)
		}
	}
	analysisCtx.Logger.Info("ATO analysis finished.")
	return nil
}

// prepareRequestBody handles JSON and Form URL Encoded content types dynamically.
func (a *ATOAdapter) prepareRequestBody(attempt ato.LoginAttempt, userField, passField, contentType string) (io.Reader, error) {

	if strings.Contains(contentType, "application/json") {
		payload := map[string]string{
			userField: attempt.Username,
			passField: attempt.Password,
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
		}
		return bytes.NewReader(payloadBytes), nil
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		values := url.Values{}
		values.Add(userField, attempt.Username)
		values.Add(passField, attempt.Password)
		return strings.NewReader(values.Encode()), nil
	}

	return nil, fmt.Errorf("unsupported content type: %s", contentType)
}

func (a *ATOAdapter) performLoginAttempt(ctx context.Context, analysisCtx *core.AnalysisContext, attempt ato.LoginAttempt, userField, passField, contentType string) {
	logger := analysisCtx.Logger.With(zap.String("username", attempt.Username))

	// ENHANCEMENT: Handle different request body formats.
	requestBody, err := a.prepareRequestBody(attempt, userField, passField, contentType)
	if err != nil {
		logger.Error("Failed to prepare login payload", zap.Error(err))
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", analysisCtx.TargetURL.String(), requestBody)
	if err != nil {
		logger.Error("Failed to create HTTP request", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "evolution-scalpel-ATO-Scanner/1.2")

	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	if err != nil {
		// Check for cancellation before logging network errors.
		if ctx.Err() != nil {
			return
		}
		logger.Warn("HTTP request failed during login attempt", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	responseTimeMs := time.Since(startTime).Milliseconds()

	// Read the body, limiting the size (e.g., 1MB) to prevent memory exhaustion.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		logger.Warn("Failed to read response body", zap.Error(err))
		// Proceed with analysis based on status code even if body reading failed.
	}

	result := ato.AnalyzeResponse(attempt, resp.StatusCode, string(bodyBytes), responseTimeMs)

	// Handle Success or MFA (which implies valid primary credentials)
	if result.Success {
		vulnName := "Successful Login with Weak Credentials"
		severity := schemas.SeverityHigh
		cwe := "CWE-521"

		// VULN FIX: CWE-312 - Redact the password from the description.
		desc := fmt.Sprintf("Successfully authenticated primary credentials as user '%s' using a common weak password (redacted).", result.Attempt.Username)

		if result.IsMFAChallenge {
			vulnName = "Weak Credentials Accepted (MFA Present)"
			// Severity adjusted in createAtoFinding based on MFA presence.
			desc += " An MFA challenge was detected."
		}

		a.createAtoFinding(analysisCtx, vulnName, severity, cwe, desc, result)
	}

	if result.IsUserEnumeration {
		// Only report enumeration if success hasn't already confirmed the user exists.
		if !result.Success {
			a.createAtoFinding(analysisCtx, "User Enumeration on Login Form", schemas.SeverityMedium, "CWE-203",
				fmt.Sprintf("The login endpoint response for user '%s' allows for user enumeration. Detail: %s", result.Attempt.Username, result.EnumerationDetail),
				result)
		}
	}
}

func (a *ATOAdapter) createAtoFinding(analysisCtx *core.AnalysisContext, vulnName string, severity schemas.Severity, cwe, desc string, result ato.LoginResponse) {
	// Truncate evidence if necessary.
	responseBodyEvidence := result.ResponseBody
	if len(responseBodyEvidence) > 2048 {
		responseBodyEvidence = responseBodyEvidence[:2048] + "... [TRUNCATED]"
	}

	// Adjust severity if MFA is detected, specifically for High severity findings (downgrade to Medium).
	if result.IsMFAChallenge && severity == schemas.SeverityHigh {
		severity = schemas.SeverityMedium
	}

	evidenceMap := map[string]interface{}{
		"username": result.Attempt.Username,
		// Password intentionally omitted from evidence logs.
		"statusCode":     result.StatusCode,
		"responseBody":   responseBodyEvidence,
		"detail":         result.EnumerationDetail,
		"responseTimeMs": result.ResponseTimeMs,
		"mfaDetected":    result.IsMFAChallenge,
	}
	evidence, err := json.Marshal(evidenceMap)
	if err != nil {
		analysisCtx.Logger.Error("Failed to marshal ATO evidence", zap.Error(err))
		evidence = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %s"}`, err.Error()))
	}

	finding := schemas.Finding{
		ID:                uuid.New().String(),
		TaskID:            analysisCtx.Task.TaskID,
		ObservedAt:        time.Now().UTC(),
		Target:            analysisCtx.TargetURL.String(),
		Module:            a.Name(),
		VulnerabilityName: vulnName,
		Severity:          severity,
		Description:       desc,
		Evidence:          evidence,
		Recommendation:    "Implement rate limiting, account lockouts, and CAPTCHA. Ensure login responses are generic and do not disclose whether a username or password was correct. Implement and enforce MFA.",
		CWE:               []string{cwe},
	}
	analysisCtx.AddFinding(finding)
}

// loadUsernames determines the list of usernames to use for the ATO attack.
// It prioritizes usernames provided directly in the task parameters. If none are
// provided, it attempts to load a default list from the SecLists repository,
// using the path specified in the application configuration.
func (a *ATOAdapter) loadUsernames(cfg config.Interface, params schemas.ATOTaskParams) ([]string, error) {
	// If usernames are explicitly provided in the task, use them.
	if len(params.Usernames) > 0 {
		return params.Usernames, nil
	}

	// Otherwise, load from the configured SecLists path.
	atoCfg := cfg.Scanners().Active.Auth.ATO
	if atoCfg.SecListsPath == "" {
		// Provide a helpful error message if SecLists is required but not configured.
		return nil, fmt.Errorf("no usernames provided in task parameters and SecLists path is not configured in config.yaml")
	}

	// Expand tilde for home directory support.
	secListsDir, err := homedir.Expand(atoCfg.SecListsPath)
	if err != nil {
		return nil, fmt.Errorf("could not expand SecLists path '%s': %w", atoCfg.SecListsPath, err)
	}

	// Check if the directory exists.
	if _, err := os.Stat(secListsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("SecLists directory not found at '%s'. Please install SecLists or configure the correct path.", secListsDir)
	}

	// Construct the path to the default username list.
	usernameFile := filepath.Join(secListsDir, "Usernames", "top-usernames-shortlist.txt")
	if _, err := os.Stat(usernameFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("default username list not found at '%s'. Please ensure SecLists is installed correctly.", usernameFile)
	}

	// Read the usernames from the file.
	file, err := os.Open(usernameFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open username file '%s': %w", usernameFile, err)
	}
	defer file.Close()

	var usernames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Trim space and ignore empty lines or comments (often starting with #)
		if username := strings.TrimSpace(scanner.Text()); username != "" && !strings.HasPrefix(username, "#") {
			usernames = append(usernames, username)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading username file '%s': %w", usernameFile, err)
	}

	return usernames, nil
}
