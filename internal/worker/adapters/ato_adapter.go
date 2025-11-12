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
		// FIX: Instead of calling Fatal, which exits the program, return an error.
		// This allows tests to assert the error condition correctly.
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

	for _, attempt := range payloads {
		// Check for cancellation signal before each attempt.
		select {
		case <-ctx.Done():
			analysisCtx.Logger.Warn("ATO analysis cancelled by context.", zap.Error(ctx.Err()))
			return ctx.Err()
		case <-throttle.C: // Receive from the ticker's channel 'C'.
			a.performLoginAttempt(ctx, analysisCtx, attempt)
		}
	}
	analysisCtx.Logger.Info("ATO analysis finished.")
	return nil
}

func (a *ATOAdapter) performLoginAttempt(ctx context.Context, analysisCtx *core.AnalysisContext, attempt ato.LoginAttempt) {
	logger := analysisCtx.Logger.With(zap.String("username", attempt.Username))
	payloadBytes, err := json.Marshal(map[string]string{"username": attempt.Username, "password": attempt.Password})
	if err != nil {
		logger.Error("Failed to marshal login payload", zap.Error(err))
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", analysisCtx.TargetURL.String(), bytes.NewReader(payloadBytes))
	if err != nil {
		logger.Error("Failed to create HTTP request", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "evolution-scalpel-ATO-Scanner/1.1")

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

func (a *ATOAdapter) createAtoFinding(analysisCtx *core.AnalysisContext, vulnName string, severity schemas.Severity, cwe, desc string, result ato.LoginResponse) {
	// Truncate evidence if necessary.
	responseBodyEvidence := result.ResponseBody
	if len(responseBodyEvidence) > 2048 {
		responseBodyEvidence = responseBodyEvidence[:2048] + "... [TRUNCATED]"
	}

	evidenceMap := map[string]interface{}{
		"username": result.Attempt.Username,
		// Password intentionally omitted from evidence logs.
		"statusCode":     result.StatusCode,
		"responseBody":   responseBodyEvidence,
		"detail":         result.EnumerationDetail,
		"responseTimeMs": result.ResponseTimeMs,
	}
	evidence, err := json.Marshal(evidenceMap)
	if err != nil {
		analysisCtx.Logger.Error("Failed to marshal ATO evidence", zap.Error(err))
		evidence = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %s"}`, err.Error()))
	}

	finding := schemas.Finding{
		ID:     uuid.New().String(),
		TaskID: analysisCtx.Task.TaskID,
		// Refactored: Renamed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     analysisCtx.TargetURL.String(),
		Module:     a.Name(),
		// Refactored: Flattened Vulnerability struct to VulnerabilityName
		VulnerabilityName: vulnName,
		Severity:          severity,
		Description:       desc,
		// Refactored: Assign []byte directly to json.RawMessage
		Evidence:       evidence,
		Recommendation: "Implement rate limiting, account lockouts, and CAPTCHA. Ensure login responses are generic and do not disclose whether a username or password was correct. Implement MFA.",
		CWE:            []string{cwe},
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
		return nil, fmt.Errorf("ATO scanner is enabled, but no SecLists path is configured in config.yaml")
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
		if username := strings.TrimSpace(scanner.Text()); username != "" {
			usernames = append(usernames, username)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading username file '%s': %w", usernameFile, err)
	}

	return usernames, nil
}
