// File: internal/worker/adapters/idor_adapter.go
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
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare" // This is a comment to force a change
	"go.uber.org/zap"
)

const (
	idorHTTPTimeout         = 10 * time.Second
	maxIDORResponseBodyRead = 2 * 1024 * 1024 // 2MB
)

type IDORAdapter struct {
	core.BaseAnalyzer
	httpClient *http.Client
	comparer   jsoncompare.JSONComparison
}

// NewIDORAdapter creates a new IDORAdapter.
func NewIDORAdapter(logger *zap.Logger) *IDORAdapter {
	// Configure the client to not follow redirects.
	client := &http.Client{
		Timeout: idorHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &IDORAdapter{
		// Pass the provided logger to the BaseAnalyzer.
		BaseAnalyzer: *core.NewBaseAnalyzer("IDOR Adapter", "Finds Insecure Direct Object Reference vulnerabilities using active testing and semantic comparison.", core.TypeActive, logger),
		httpClient:   client,
		// Pass the logger to the JSON comparison service.
		comparer:     jsoncompare.NewService(logger),
	}
}

// SetHttpClient allows overriding the default HTTP client, primarily for testing.
func (a *IDORAdapter) SetHttpClient(client *http.Client) {
	if client != nil {
		a.httpClient = client
	}
}

func (a *IDORAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if a.httpClient == nil {
		return fmt.Errorf("critical error: HTTP client not initialized in IDORAdapter")
	}
	if a.comparer == nil {
		return fmt.Errorf("critical error: JSON comparer not initialized in IDORAdapter")
	}

	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Starting active IDOR analysis.")

	// 1. Parameter Validation and Extraction
	params, err := a.extractParams(analysisCtx)
	if err != nil {
		return err
	}

	// Ensure TargetURL is valid.
	if analysisCtx.TargetURL == nil {
		return fmt.Errorf("TargetURL is required but missing in AnalysisContext")
	}

	// 2. Baseline Request
	baseRespBody, baseStatusCode, err := a.performBaselineRequest(ctx, analysisCtx.TargetURL.String(), params)
	if err != nil {
		// If baseline fails, we cannot continue. Check if it was due to cancellation.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	// If the baseline request was unauthorized or failed, IDOR testing is irrelevant.
	if baseStatusCode < 200 || baseStatusCode >= 400 {
		logger.Info("Baseline request was not successful, skipping IDOR scan.", zap.Int("status_code", baseStatusCode))
		return nil // Not an error, just not scannable.
	}
	logger.Info("Baseline request successful.", zap.Int("status_code", baseStatusCode))

	// 3. Identifier Extraction
	identifiers := a.extractIdentifiers(analysisCtx.TargetURL.String(), params)
	if len(identifiers) == 0 {
		logger.Info("No potential identifiers found to test for IDOR.")
		return nil
	}
	logger.Info("Found potential identifiers to test.", zap.Int("count", len(identifiers)))

	// 4. Execution and Comparison
	for _, ident := range identifiers {
		// Check for cancellation before testing each identifier.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.testIdentifier(ctx, analysisCtx, params, ident, baseRespBody, baseStatusCode)
	}

	return nil
}

// extractParams handles the type assertion and validation of the task parameters.
func (a *IDORAdapter) extractParams(analysisCtx *core.AnalysisContext) (schemas.IDORTaskParams, error) {
	var params schemas.IDORTaskParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.IDORTaskParams:
		params = p
	case *schemas.IDORTaskParams:
		if p == nil {
			return schemas.IDORTaskParams{}, fmt.Errorf("invalid parameters: nil pointer for IDOR task")
		}
		params = *p
	default:
		return schemas.IDORTaskParams{}, fmt.Errorf("invalid parameters type for IDOR task; expected schemas.IDORTaskParams or *schemas.IDORTaskParams, got %T", analysisCtx.Task.Parameters)
	}
	return params, nil
}

func (a *IDORAdapter) performBaselineRequest(ctx context.Context, targetURL string, params schemas.IDORTaskParams) ([]byte, int, error) {
	baseReq, err := http.NewRequestWithContext(ctx, params.HTTPMethod, targetURL, bytes.NewReader([]byte(params.HTTPBody)))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create baseline request: %w", err)
	}
	for k, v := range params.HTTPHeaders {
		baseReq.Header.Set(k, v)
	}

	baseResp, err := a.httpClient.Do(baseReq)
	if err != nil {
		return nil, 0, fmt.Errorf("baseline request failed: %w", err)
	}
	defer baseResp.Body.Close()

	// Read the body, limiting the size.
	baseRespBody, err := io.ReadAll(io.LimitReader(baseResp.Body, maxIDORResponseBodyRead))
	if err != nil {
		return nil, baseResp.StatusCode, fmt.Errorf("failed to read baseline response body: %w", err)
	}

	return baseRespBody, baseResp.StatusCode, nil
}

func (a *IDORAdapter) extractIdentifiers(targetURL string, params schemas.IDORTaskParams) []idor.ObservedIdentifier {
	// Create a dummy request object for the extraction logic.
	// Errors are ignored here as the request is only used for parsing structures.
	reqForExtraction, _ := http.NewRequest(params.HTTPMethod, targetURL, bytes.NewReader([]byte(params.HTTPBody)))

	// Apply headers to the dummy request.
	if reqForExtraction != nil {
		for k, v := range params.HTTPHeaders {
			reqForExtraction.Header.Set(k, v)
		}
		// Use the specialized idor package to find identifiers.
		return idor.ExtractIdentifiers(reqForExtraction, []byte(params.HTTPBody)) // Pass the body here
	}
	return nil
}

func (a *IDORAdapter) testIdentifier(ctx context.Context, analysisCtx *core.AnalysisContext, params schemas.IDORTaskParams, ident idor.ObservedIdentifier, baseRespBody []byte, baseStatusCode int) {
	logger := analysisCtx.Logger.With(zap.String("identifier_value", ident.Value), zap.String("location", string(ident.Location)))

	// Generate a predictable test value (e.g., incrementing an integer).
	testValue, err := idor.GenerateTestValue(ident)
	if err != nil {
		logger.Debug("Cannot generate predictable test value for identifier.", zap.Error(err))
		return
	}
	logger.Debug("Generated test value", zap.String("test_value", testValue))

	// Create the modified request.
	// Start by recreating the original request structure.
	originalReq, err := http.NewRequestWithContext(ctx, params.HTTPMethod, analysisCtx.TargetURL.String(), bytes.NewReader([]byte(params.HTTPBody)))
	if err != nil {
		logger.Error("Failed to recreate original request structure for modification", zap.Error(err))
		return
	}
	for k, v := range params.HTTPHeaders {
		originalReq.Header.Set(k, v)
	}

	// Apply the modification using the idor package.
	modifiedReq, _, err := idor.ApplyTestValue(ctx, originalReq, []byte(params.HTTPBody), ident, testValue)
	if err != nil {
		logger.Error("Failed to apply test value to request", zap.Error(err))
		return
	}

	// Execute the manipulated request.
	testResp, err := a.httpClient.Do(modifiedReq)
	if err != nil {
		// Only log network errors if the context wasn't cancelled.
		if ctx.Err() == nil {
			logger.Warn("Modified IDOR test request failed", zap.Error(err), zap.String("test_value", testValue))
		}
		return
	}
	defer testResp.Body.Close()

	// Read the body, limiting the size.
	testRespBody, err := io.ReadAll(io.LimitReader(testResp.Body, maxIDORResponseBodyRead))
	if err != nil {
		logger.Warn("Failed to read test response body for IDOR check", zap.Error(err), zap.Int("status_code", testResp.StatusCode))
		// Continue to check status code even if body read failed.
	}

	// Check if the authorization mechanism blocked the request.
	if testResp.StatusCode >= 400 {
		logger.Debug("Modified request was blocked (likely secure).", zap.Int("status_code", testResp.StatusCode))
		return
	}

	// Perform semantic comparison.
	// Configure comparison options to ignore the specific values that were intentionally changed.
	opts := jsoncompare.DefaultOptions()
	// Ignore the original and tested identifier values.
	opts.SpecificValuesToIgnore = map[string]struct{}{
		ident.Value: {},
		testValue:   {},
	}
	// For semantic equivalence in IDOR, we should also normalize all primitive values
	// to focus purely on structural equivalence. This handles cases where names, timestamps, etc.
	// change between two user objects, which is expected.
	if baseStatusCode == testResp.StatusCode {
		opts.NormalizeAllValuesForStructure = true
	}

	comparisonResult, err := a.comparer.CompareWithOptions(baseRespBody, testRespBody, opts)
	if err != nil {
		logger.Error("Failed to compare IDOR responses", zap.Error(err), zap.String("identifier_value", ident.Value))
		return
	}

	// If the responses are semantically equivalent, it indicates a likely IDOR.
	if comparisonResult.AreEquivalent {
		logger.Warn("Potential IDOR detected based on semantic equivalence!", zap.Int("base_status", baseStatusCode), zap.Int("test_status", testResp.StatusCode))
		a.createIdorFinding(analysisCtx, ident, testValue, baseStatusCode, testResp.StatusCode)
	} else {
		logger.Debug("Responses are not semantically equivalent.", zap.String("diff_summary", comparisonResult.Diff))
	}
}

// createIdorFinding generates and reports an IDOR finding.
func (a *IDORAdapter) createIdorFinding(analysisCtx *core.AnalysisContext, ident idor.ObservedIdentifier, testValue string, originalStatus, testStatus int) {
	desc := fmt.Sprintf("A potential IDOR vulnerability was found. An identifier ('%s') located in the %s was changed to a predictable value ('%s'). The server responded with a semantically equivalent response (Status %d) compared to the original authorized request (Status %d), suggesting access controls may be missing.",
		ident.Value, ident.Location, testValue, testStatus, originalStatus)

	evidenceMap := map[string]interface{}{
		"originalIdentifier": ident,
		"testedValue":        testValue,
		"originalStatusCode": originalStatus,
		"testStatusCode":     testStatus,
		"targetUrl":          analysisCtx.TargetURL.String(),
		"comparisonResult":   "Responses were semantically equivalent, ignoring the intentionally modified identifier values.",
	}
	evidence, err := json.Marshal(evidenceMap)
	if err != nil {
		analysisCtx.Logger.Error("Failed to marshal IDOR evidence", zap.Error(err), zap.String("identifier_value", ident.Value))
		evidence = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %s"}`, err.Error()))
	}

	finding := schemas.Finding{
		ID:        uuid.New().String(),
		TaskID:    analysisCtx.Task.TaskID,
		Timestamp: time.Now().UTC(),
		Target:    analysisCtx.TargetURL.String(),
		Module:    a.Name(),
		Vulnerability: schemas.Vulnerability{
			Name: "Insecure Direct Object Reference (IDOR)",
		},
		Severity:       schemas.SeverityHigh,
		Description:    desc,
		Evidence:       string(evidence),
		Recommendation: "Implement robust server-side authorization checks. Verify that the current authenticated user has the necessary permissions to access or modify the requested resource ID before performing any action. Do not rely solely on client-side validation or obfuscated IDs.",
		CWE:            []string{"CWE-639"}, // CWE-639: Authorization Bypass Through User-Controlled Key
	}
	analysisCtx.AddFinding(finding)
	analysisCtx.Logger.Info("IDOR finding generated",
		zap.String("vulnerability", "Insecure Direct Object Reference (IDOR)"),
		zap.String("severity", string(schemas.SeverityHigh)),
		zap.String("identifier_location", string(ident.Location)),
		zap.String("original_identifier", ident.Value),
	)
}
