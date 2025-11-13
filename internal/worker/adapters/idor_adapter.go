// internal/worker/adapters/idor_adapter.go
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
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/idor"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"go.uber.org/zap"
)

type IDORAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

func NewIDORAdapter() *IDORAdapter {
	return &IDORAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer("IDOR Adapter", "Finds Insecure Direct Object Reference vulnerabilities", core.TypeActive, zap.NewNop()),
		httpClient: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (a *IDORAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting active IDOR analysis.")

	// -- Use the specific parameter struct.
	var params schemas.IDORTaskParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.IDORTaskParams:
		params = p
	case *schemas.IDORTaskParams:
		if p == nil {
			return fmt.Errorf("invalid parameters: nil pointer for IDOR task")
		}
		params = *p
	default:
		return fmt.Errorf("invalid parameters type for IDOR task; expected schemas.IDORTaskParams or *schemas.IDORTaskParams, got %T", analysisCtx.Task.Parameters)
	}

	// -- Make a baseline request to ensure it's valid and to get a response to compare against.
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

	// -- Read the baseline body now, as we need it for later comparisons.
	baseRespBody, err := io.ReadAll(baseResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read baseline response body: %w", err)
	}

	if baseResp.StatusCode < 200 || baseResp.StatusCode >= 400 {
		analysisCtx.Logger.Info("Baseline request was not successful, skipping IDOR scan.", zap.Int("status_code", baseResp.StatusCode))
		return nil
	}
	analysisCtx.Logger.Info("Baseline request successful.", zap.Int("status_code", baseResp.StatusCode))

	// -- Extract identifiers from the original request parameters.
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

	// -- Instantiate the new comparison service.
	comparer := jsoncompare.NewService()

	// -- Loop through each identifier and test for IDOR by manipulating it.
	for _, ident := range identifiers {
		logger := analysisCtx.Logger.With(zap.String("identifier_value", ident.Value), zap.String("location", string(ident.Location)))
		testValues, err := idor.GenerateTestValues(ident)
		if err != nil {
			logger.Debug("Cannot generate predictable test values for identifier.", zap.Error(err))
			continue
		}
		if len(testValues) == 0 {
			logger.Debug("No test values generated for identifier.")
			continue
		}
		testValue := testValues[0]
		logger.Info("Generated test value", zap.String("test_value", testValue))

		// -- Create a new request with the manipulated identifier.
		originalReq, _ := http.NewRequestWithContext(ctx, params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
		for k, v := range params.HTTPHeaders {
			originalReq.Header.Set(k, v)
		}

		modifiedReq, _, err := idor.ApplyTestValue(ctx, originalReq, []byte(params.HTTPBody), ident, testValue)
		if err != nil {
			logger.Error("Failed to apply test value to request", zap.Error(err))
			continue
		}

		// -- Execute the manipulated request.
		testResp, err := a.httpClient.Do(modifiedReq)
		if err != nil {
			logger.Warn("Modified IDOR test request failed", zap.Error(err))
			continue
		}
		defer testResp.Body.Close()
		testRespBody, err := io.ReadAll(testResp.Body)
		if err != nil {
			logger.Warn("Failed to read test response body", zap.Error(err))
			continue
		}

		// -- If the manipulated request failed, it's likely not vulnerable in this way.
		if testResp.StatusCode >= 400 {
			logger.Info("Modified request was not successful.", zap.Int("status_code", testResp.StatusCode))
			continue
		}

		// -- The core upgrade: Use semantic comparison instead of a simple status code check.
		opts := jsoncompare.DefaultOptions()
		opts.SpecificValuesToIgnore = make(map[string]struct{})
		opts.SpecificValuesToIgnore[ident.Value] = struct{}{}
		opts.SpecificValuesToIgnore[testValue] = struct{}{}

		comparisonResult, err := comparer.CompareWithOptions(baseRespBody, testRespBody, opts)
		if err != nil {
			logger.Error("Failed to compare responses", zap.Error(err))
			continue
		}

		if comparisonResult.AreEquivalent {
			logger.Warn("Potential IDOR detected based on semantic equivalence!", zap.Int("base_status", baseResp.StatusCode), zap.Int("test_status", testResp.StatusCode))
			a.createIdorFinding(analysisCtx, ident, testValue, baseResp.StatusCode, testResp.StatusCode)
		} else {
			logger.Info("Responses are not semantically equivalent.", zap.String("diff", comparisonResult.Diff))
		}
	}
	analysisCtx.Logger.Info("IDOR analysis finished.")
	return nil
}

// Updated to use the idor.ObservedIdentifier type from the new package.
func (a *IDORAdapter) createIdorFinding(analysisCtx *core.AnalysisContext, ident idor.ObservedIdentifier, testValue string, originalStatus, testStatus int) {
	desc := fmt.Sprintf("A potential IDOR vulnerability was found. An identifier ('%s') in the %s was changed to a predictable value ('%s'). The server responded with a semantically equivalent response to the original authorized request, suggesting access controls may be missing.",
		ident.Value, ident.Location, testValue)
	evidence, _ := json.Marshal(map[string]interface{}{
		"originalIdentifier": ident,
		"testedValue":        testValue,
		"originalStatusCode": originalStatus,
		"testStatusCode":     testStatus,
		"targetUrl":          analysisCtx.TargetURL.String(),
		"comparisonResult":   "Responses were semantically equivalent, indicating a likely IDOR.",
	})

	finding := schemas.Finding{
		ID:     uuid.New().String(),
		TaskID: analysisCtx.Task.TaskID,
		// Refactored: Renamed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     analysisCtx.TargetURL.String(),
		Module:     a.Name(),
		// Refactored: Flattened Vulnerability struct to VulnerabilityName
		VulnerabilityName: "Insecure Direct Object Reference (IDOR)",
		Severity:          schemas.SeverityHigh,
		Description:       desc,
		// Refactored: Assign []byte directly to json.RawMessage
		Evidence:       evidence,
		Recommendation: "Verify that the current authenticated user is authorized to access or modify the requested resource ID on the server-side before performing any action.",
		CWE:            []string{"CWE-639"},
	}
	analysisCtx.AddFinding(finding)
}
