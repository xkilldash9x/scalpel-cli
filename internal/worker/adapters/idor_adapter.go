// internal/worker/adapters/idor_adapter.go --
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
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/idor"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

type IDORAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

func NewIDORAdapter() *IDORAdapter {
	return &IDORAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("IDOR Adapter", core.TypeActive),
		httpClient: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (a *IDORAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting active IDOR analysis.")

	// Use the specific parameter struct.
	params, ok := analysisCtx.Task.Parameters.(schemas.IDORTaskParams)
	if !ok {
		return fmt.Errorf("invalid parameters type for IDOR task; expected schemas.IDORTaskParams")
	}

	baseReq, err := http.NewRequestWithContext(ctx, params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
	if err != nil {
		return fmt.Errorf("failed to create baseline request: %w", err)
	}
	for k, v := range params.HTTPHeaders {
		baseReq.Header.Set(k, v)
	}

	baseResp, err := a.httpClient.Do(baseReq)
	if err != nil {
		return fmt.Errorf("baseline request failed: %w", err)
	}
	defer baseResp.Body.Close()
	io.Copy(io.Discard, baseResp.Body)

	if baseResp.StatusCode < 200 || baseResp.StatusCode >= 400 {
		analysisCtx.Logger.Info("Baseline request was not successful, skipping IDOR scan.", zap.Int("status_code", baseResp.StatusCode))
		return nil
	}
	analysisCtx.Logger.Info("Baseline request successful.", zap.Int("status_code", baseResp.StatusCode))

	reqForExtraction, _ := http.NewRequest(params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
	for k, v := range params.HTTPHeaders {
		reqForExtraction.Header.Set(k, v)
	}
	identifiers := idor.ExtractIdentifiers(reqForExtraction, []byte(params.HTTPBody))
	if len(identifiers) == 0 {
		analysisCtx.Logger.Info("No potential identifiers found to test for IDOR.")
		return nil
	}
	analysisCtx.Logger.Info("Found potential identifiers to test.", zap.Int("count", len(identifiers)))

	for _, ident := range identifiers {
		logger := analysisCtx.Logger.With(zap.String("identifier_value", ident.Value), zap.String("location", string(ident.Location)))
		testValue, err := idor.GenerateTestValue(ident)
		if err != nil {
			logger.Debug("Cannot generate predictable test value for identifier.", zap.Error(err))
			continue
		}
		logger.Info("Generated test value", zap.String("test_value", testValue))

		originalReq, _ := http.NewRequestWithContext(ctx, params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
		for k, v := range params.HTTPHeaders {
			originalReq.Header.Set(k, v)
		}
		modifiedReq, newBody, err := idor.ApplyTestValue(originalReq, []byte(params.HTTPBody), ident, testValue)
		if err != nil {
			logger.Error("Failed to apply test value to request", zap.Error(err))
			continue
		}
		modifiedReq.Body = io.NopCloser(bytes.NewReader(newBody))

		testResp, err := a.httpClient.Do(modifiedReq)
		if err != nil {
			logger.Warn("Modified IDOR test request failed", zap.Error(err))
			continue
		}
		defer testResp.Body.Close()
		io.Copy(io.Discard, testResp.Body)

		if testResp.StatusCode == baseResp.StatusCode {
			logger.Warn("Potential IDOR detected!", zap.Int("status_code", testResp.StatusCode))
			a.createIdorFinding(analysisCtx, ident, testValue, baseResp.StatusCode, testResp.StatusCode)
		}
	}
	return nil
}

func (a *IDORAdapter) createIdorFinding(analysisCtx *core.AnalysisContext, ident idor.ObservedIdentifier, testValue string, originalStatus, testStatus int) {
	desc := fmt.Sprintf("A potential IDOR vulnerability was found. An identifier ('%s') in the %s was changed to a predictable value ('%s'). The server responded with the same status code (%d) as the original authorized request, suggesting access controls may be missing.",
		ident.Value, ident.Location, testValue, testStatus)
	evidence, _ := json.Marshal(map[string]interface{}{"originalIdentifier": ident, "testedValue": testValue, "originalStatusCode": originalStatus, "testStatusCode": testStatus, "targetUrl": analysisCtx.TargetURL.String()})

	finding := schemas.Finding{
		ID:             uuid.New().String(),
		TaskID:         analysisCtx.Task.TaskID,
		Timestamp:      time.Now().UTC(),
		Target:         analysisCtx.TargetURL.String(),
		Module:         a.Name(),
		Vulnerability:  "Insecure Direct Object Reference (IDOR)",
		Severity:       schemas.SeverityHigh,
		Description:    desc,
		Evidence:       evidence,
		Recommendation: "Verify that the current authenticated user is authorized to access or modify the requested resource ID on the server-side before performing any action.",
		CWE:            "CWE-639",
	}
	analysisCtx.AddFinding(finding)
}
