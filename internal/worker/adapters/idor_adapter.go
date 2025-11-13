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

	// (Fix 4.1: Import centralized networking package)
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"go.uber.org/zap"
)

type IDORAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
}

func NewIDORAdapter() *IDORAdapter {
	// (Fix 4.1: Initialize a secure, production-ready HTTP client (SSRF Mitigation)).
	clientConfig := network.NewBrowserClientConfig()
	secureClient := network.NewClient(clientConfig)

	// Configure specific timeout and redirect policy required for the adapter.
	secureClient.Timeout = 10 * time.Second
	// Ensure redirects are not followed automatically.
	secureClient.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	return &IDORAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer("IDOR Adapter", "Finds Insecure Direct Object Reference vulnerabilities (Active Manipulation)", core.TypeActive, zap.NewNop()),
		httpClient:   secureClient,
	}
}

func (a *IDORAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting active IDOR analysis.")

	// -- Parameter validation
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

	// -- Baseline request
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

	// -- Read the baseline body and close immediately.
	baseRespBody, err := io.ReadAll(baseResp.Body)
	baseResp.Body.Close() // Close baseline response body.

	if err != nil {
		return fmt.Errorf("failed to read baseline response body: %w", err)
	}

	// (Fix 3.4: Ensure baseline success)
	if baseResp.StatusCode < 200 || baseResp.StatusCode >= 400 {
		analysisCtx.Logger.Info("Baseline request was not successful, skipping IDOR scan.", zap.Int("status_code", baseResp.StatusCode))
		return nil
	}
	analysisCtx.Logger.Info("Baseline request successful.", zap.Int("status_code", baseResp.StatusCode))

	// -- Identifier Extraction
	reqForExtraction, _ := http.NewRequest(params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
	for k, v := range params.HTTPHeaders {
		reqForExtraction.Header.Set(k, v)
	}
	// Uses the enhanced ExtractIdentifiers
	identifiers := idor.ExtractIdentifiers(reqForExtraction, []byte(params.HTTPBody))
	if len(identifiers) == 0 {
		analysisCtx.Logger.Info("No potential identifiers found to test for IDOR.")
		return nil
	}
	analysisCtx.Logger.Info("Found potential identifiers to test.", zap.Int("count", len(identifiers)))

	// -- Analysis Loop
	comparer := jsoncompare.NewService()

	for _, ident := range identifiers {
		// Use ident.String() for detailed location logging
		logger := analysisCtx.Logger.With(zap.String("identifier_value", ident.Value), zap.String("location", ident.String()))

		// Note: We use synthetic generation here as the adapter doesn't have the full traffic context (Pool).
		testValues, err := idor.GenerateTestValues(ident, nil)
		if err != nil {
			logger.Debug("Cannot generate predictable test values for identifier.", zap.Error(err))
			continue
		}

		// (Fix 2.3: Iterate through all generated test values)
		for _, testValue := range testValues {
			logger.Info("Testing value", zap.String("test_value", testValue))

			// -- Create a new request with the manipulated identifier.
			originalReq, _ := http.NewRequestWithContext(ctx, params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
			for k, v := range params.HTTPHeaders {
				originalReq.Header.Set(k, v)
			}

			// Uses the enhanced ApplyTestValue (handles encoded payloads)
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

			// (Fix 2.2: Read the body and close immediately within the loop iteration.)
			testRespBody, readErr := io.ReadAll(testResp.Body)
			testResp.Body.Close() // Explicitly close the body here.

			if readErr != nil {
				logger.Warn("Failed to read test response body", zap.Error(readErr))
				continue
			}

			// -- Response Evaluation
			if testResp.StatusCode >= 400 {
				logger.Info("Modified request was not successful.", zap.Int("status_code", testResp.StatusCode))
				continue
			}

			// -- Semantic Comparison
			opts := jsoncompare.DefaultOptions()

			// (Fix 2.1: Enable structural comparison for manipulation tests.)
			opts.NormalizeAllValuesForStructure = true

			opts.SpecificValuesToIgnore = make(map[string]struct{})
			opts.SpecificValuesToIgnore[ident.Value] = struct{}{}
			opts.SpecificValuesToIgnore[testValue] = struct{}{}

			comparisonResult, err := comparer.CompareWithOptions(baseRespBody, testRespBody, opts)
			if err != nil {
				logger.Error("Failed to compare responses", zap.Error(err))
				continue
			}

			if comparisonResult.AreEquivalent {
				logger.Warn("Potential IDOR detected based on structural equivalence!", zap.Int("base_status", baseResp.StatusCode), zap.Int("test_status", testResp.StatusCode))
				a.createIdorFinding(analysisCtx, ident, testValue, baseResp.StatusCode, testResp.StatusCode)
				// Stop testing other values for this identifier once a vulnerability is found.
				break
			} else {
				logger.Info("Responses are not structurally equivalent.", zap.String("diff", comparisonResult.Diff))
			}
		}
	}
	analysisCtx.Logger.Info("IDOR analysis finished.")
	return nil
}

func (a *IDORAdapter) createIdorFinding(analysisCtx *core.AnalysisContext, ident idor.ObservedIdentifier, testValue string, originalStatus, testStatus int) {
	// Updated description to reflect structural comparison and detailed location.
	desc := fmt.Sprintf("A potential IDOR vulnerability (Manipulation) was found. An identifier ('%s') located at [%s] was changed to a predictable value ('%s'). The server responded with a structurally equivalent response to the original authorized request, suggesting access controls may be missing.",
		ident.Value, ident.String(), testValue) // Use ident.String() for detailed location
	evidence, _ := json.Marshal(map[string]interface{}{
		"originalIdentifier": ident,
		"testedValue":        testValue,
		"originalStatusCode": originalStatus,
		"testStatusCode":     testStatus,
		"targetUrl":          analysisCtx.TargetURL.String(),
		"comparisonResult":   "Responses were structurally equivalent, indicating a likely IDOR (Manipulation).",
	})

	finding := schemas.Finding{
		ID:                uuid.New().String(),
		TaskID:            analysisCtx.Task.TaskID,
		ObservedAt:        time.Now().UTC(),
		Target:            analysisCtx.TargetURL.String(),
		Module:            a.Name(),
		VulnerabilityName: "Insecure Direct Object Reference (IDOR)",
		Severity:          schemas.SeverityHigh,
		Description:       desc,
		Evidence:          evidence,
		Recommendation:    "Verify that the current authenticated user is authorized to access or modify the requested resource ID on the server-side before performing any action.",
		CWE:               []string{"CWE-639"},
	}
	analysisCtx.AddFinding(finding)
}
