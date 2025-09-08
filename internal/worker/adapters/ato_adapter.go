// internal/worker/adapters/ato_adapter.go --
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
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/ato"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

type ATOAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

func NewATOAdapter() *ATOAdapter {
	return &ATOAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("ATO Adapter (Password Spraying)", core.TypeActive),
		httpClient: &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (a *ATOAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting active password spraying attack.")

	// Use the specific parameter struct for type safety.
	params, ok := analysisCtx.Task.Parameters.(schemas.ATOTaskParams)
	if !ok {
		return fmt.Errorf("invalid parameters type for ATO task; expected schemas.ATOTaskParams")
	}

	if len(params.Usernames) == 0 {
		return fmt.Errorf("'usernames' parameter must be a non-empty array of strings")
	}

	payloads := ato.GenerateSprayingPayloads(params.Usernames)
	analysisCtx.Logger.Info("Generated login payloads for spraying attack", zap.Int("payload_count", len(payloads)))

	for _, attempt := range payloads {
		select {
		case <-ctx.Done():
			analysisCtx.Logger.Warn("ATO analysis cancelled by context.", zap.Error(ctx.Err()))
			return ctx.Err()
		default:
		}
		a.performLoginAttempt(ctx, analysisCtx, attempt)
		time.Sleep(200 * time.Millisecond)
	}
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
	req.Header.Set("User-Agent", "evolution-scalpel-ATO-Scanner/1.0")

	startTime := time.Now()
	resp, err := a.httpClient.Do(req)
	if err != nil {
		logger.Warn("HTTP request failed during login attempt", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	responseTimeMs := time.Since(startTime).Milliseconds()
	bodyBytes, _ := io.ReadAll(resp.Body)

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

func (a *ATOAdapter) createAtoFinding(analysisCtx *core.AnalysisContext, vuln string, severity schemas.Severity, cwe, desc string, result ato.LoginResponse) {
	evidence, _ := json.Marshal(map[string]interface{}{
		"attempt":      result.Attempt,
		"statusCode":   result.StatusCode,
		"responseBody": result.ResponseBody,
		"detail":       result.EnumerationDetail,
	})

	finding := schemas.Finding{
		ID:             uuid.New().String(),
		TaskID:         analysisCtx.Task.TaskID,
		Timestamp:      time.Now().UTC(),
		Target:         analysisCtx.TargetURL.String(),
		Module:         a.Name(),
		Vulnerability:  vuln,
		Severity:       severity,
		Description:    desc,
		Evidence:       evidence,
		Recommendation: "Implement rate limiting, account lockouts, and CAPTCHA. Ensure login responses are generic and do not disclose whether a username or password was correct.",
		CWE:            cwe,
	}
	analysisCtx.AddFinding(finding)
}
