// File: internal/analysis/passive/headers/analyzer_test.go
package headers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// -- Test Helper Functions --

func createTestContext(t *testing.T, targetURL string, har *schemas.HAR, logger *zap.Logger) *core.AnalysisContext {
	t.Helper()

	parsedURL, err := url.Parse(targetURL)
	require.NoError(t, err, "Test setup failed: invalid target URL")

	var rawHarPtr *json.RawMessage
	if har != nil {
		harBytes, err := json.Marshal(har)
		require.NoError(t, err, "Test setup failed: could not marshal HAR data")
		rawMsg := json.RawMessage(harBytes)
		rawHarPtr = &rawMsg
	}

	return &core.AnalysisContext{
		// No more global context, we use the logger passed in.
		Task:      schemas.Task{TaskID: "test-task-123"},
		TargetURL: parsedURL,
		Logger:    logger,
		Artifacts: &schemas.Artifacts{
			HAR: rawHarPtr,
		},
	}
}

// findFindingByVulnName searches for a finding with a specific vulnerability name.
func findFindingByVulnName(findings []schemas.Finding, name string) *schemas.Finding {
	for i, f := range findings {
		// Refactored: Check VulnerabilityName instead of Vulnerability.Name
		if f.VulnerabilityName == name {
			return &findings[i]
		}
	}
	return nil
}

// -- Test Cases --

func TestHeadersAnalyzer_Analyze(t *testing.T) {
	t.Parallel()
	logger := zap.NewNop() // Use a Nop logger for these tests to keep output clean.

	target := "https://example.com/"
	otherURL := "https://example.com/styles.css"

	t.Run("should do nothing if HAR is missing", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
		ctx := createTestContext(t, target, nil, logger)
		ctx.Artifacts = nil
		err := analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)
		assert.Empty(t, ctx.Findings)
	})

	t.Run("should do nothing if main response is not found", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
		har := &schemas.HAR{
			Log: schemas.HARLog{
				Entries: []schemas.Entry{
					{Request: schemas.Request{URL: otherURL}, Response: schemas.Response{}},
				},
			},
		}
		ctx := createTestContext(t, target, har, logger)
		err := analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)
		assert.Empty(t, ctx.Findings)
	})

	t.Run("should correctly identify all missing security headers", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
		har := &schemas.HAR{Log: schemas.HARLog{Entries: []schemas.Entry{{
			Request:  schemas.Request{URL: target},
			Response: schemas.Response{Headers: []schemas.NVPair{}},
		}}}}
		ctx := createTestContext(t, target, har, logger)
		err := analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)

		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: x-frame-options"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: x-content-type-options"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: referrer-policy"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: strict-transport-security"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: content-security-policy"))
	})

	t.Run("should identify information disclosure headers", func(t *testing.T) {
		t.Parallel()
		analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
		har := &schemas.HAR{Log: schemas.HARLog{Entries: []schemas.Entry{{
			Request: schemas.Request{URL: target},
			Response: schemas.Response{Headers: []schemas.NVPair{
				{Name: "Server", Value: "nginx/1.18.0"},
				{Name: "X-Powered-By", Value: "PHP/7.4.3"},
			}},
		}}}}
		ctx := createTestContext(t, target, har, logger)
		err := analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)

		// Your implementation finds multiple, but this tests for at least one.
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Information Disclosure in HTTP Headers"))
	})
}

// TestHSTSChecks provides granular tests for the HSTS logic.
func TestHSTSChecks(t *testing.T) {
	t.Parallel()
	logger := zap.NewNop()
	target := "https://example.com/"

	testCases := []struct {
		name             string
		headerValue      string
		expectFinding    bool
		expectedVulnName string
		expectedSeverity schemas.Severity
	}{
		{"missing max-age", "includeSubDomains", true, "Weak HSTS Configuration: Missing max-age", schemas.SeverityLow},
		{"max-age is zero", "max-age=0", true, "Weak HSTS Configuration: max-age is Zero", schemas.SeverityMedium},
		{"max-age is too short", fmt.Sprintf("max-age=%d", MinHstsMaxAge-1), true, "Weak HSTS Configuration: Short max-age", schemas.SeverityLow},
		{"max-age is sufficient", fmt.Sprintf("max-age=%d", MinHstsMaxAge), false, "", ""},
		{"large max-age is valid", "max-age=31536000; includeSubDomains", false, "", ""},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable for parallel execution.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
			ctx := createTestContext(t, target, nil, logger)

			headersMap := map[string]string{"strict-transport-security": tc.headerValue}
			analyzer.checkHSTS(ctx, headersMap)

			if tc.expectFinding {
				finding := findFindingByVulnName(ctx.Findings, tc.expectedVulnName)
				require.NotNil(t, finding, "Expected finding was not generated")
				assert.Equal(t, tc.expectedSeverity, finding.Severity, "Severity level mismatch")
			} else {
				for _, f := range ctx.Findings {
					// Refactored: Check VulnerabilityName
					assert.NotContains(t, f.VulnerabilityName, "HSTS")
				}
			}
		})
	}
}

// TestCSPChecks provides granular tests for the CSP logic.
func TestCSPChecks(t *testing.T) {
	t.Parallel()
	logger := zap.NewNop()
	target := "https://example.com/"

	testCases := []struct {
		name          string
		headerValue   string
		expectFinding bool
	}{
		{"unsafe-inline without mitigation", "default-src 'self'; script-src 'unsafe-inline'", true},
		{"unsafe-inline with nonce", "default-src 'self'; script-src 'nonce-R4nd0m' 'unsafe-inline'", false},
		{"unsafe-inline with hash", "default-src 'self'; script-src 'sha256-Abc...' 'unsafe-inline'", false},
		{"strong policy with no unsafe directives", "default-src 'self'; script-src 'self' https://apis.example.com", false},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable for parallel execution.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			analyzer := NewHeadersAnalyzer() // Create a fresh analyzer for the test.
			ctx := createTestContext(t, target, nil, logger)

			headersMap := map[string]string{"content-security-policy": tc.headerValue}
			analyzer.checkCSP(ctx, headersMap)

			finding := findFindingByVulnName(ctx.Findings, "Weak Content-Security-Policy (CSP)")
			if tc.expectFinding {
				assert.NotNil(t, finding, "Expected a CSP finding to be generated")
			} else {
				assert.Nil(t, finding, "Should not generate a finding for a strong CSP")
			}
		})
	}
}
