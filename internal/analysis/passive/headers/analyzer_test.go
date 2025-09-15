// internal/analysis/passive/headers/analyzer_test.go
package headers

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// -- Test Fixture Setup --

// headersTestFixture holds the shared resources for all tests in this package.
type headersTestFixture struct {
	Logger   *zap.Logger
	Analyzer *HeadersAnalyzer
}

// globalFixture is the single, shared instance of our test fixture.
var globalFixture *headersTestFixture

// TestMain sets up the global test fixture before any tests are run.
func TestMain(m *testing.M) {
	logger, _ := zap.NewDevelopment()
	globalFixture = &headersTestFixture{
		Logger:   logger,
		Analyzer: NewHeadersAnalyzer(),
	}
	exitCode := m.Run()
	_ = globalFixture.Logger.Sync()
	os.Exit(exitCode)
}

// -- Test Helper Functions --

// createTestContext is a helper to build a consistent AnalysisContext for tests.
func createTestContext(t *testing.T, targetURL string, har *schemas.HAR) *core.AnalysisContext {
	t.Helper()

	parsedURL, err := url.Parse(targetURL)
	require.NoError(t, err, "Test setup failed: invalid target URL")

	return &core.AnalysisContext{
		Global: &core.GlobalContext{
			Logger: globalFixture.Logger,
		},
		Task:      schemas.Task{TaskID: "test-task-123"},
		TargetURL: parsedURL,
		Logger:    globalFixture.Logger,
		Artifacts: &schemas.Artifacts{
			HAR: har,
		},
	}
}

// findFindingByVulnName searches for a finding with a specific vulnerability name.
func findFindingByVulnName(findings []schemas.Finding, name string) *schemas.Finding {
	for i, f := range findings {
		if f.Vulnerability.Name == name {
			return &findings[i]
		}
	}
	return nil
}

// -- Test Cases --

// TestHeadersAnalyzer_Analyze is the main test function for the analyzer's logic.
func TestHeadersAnalyzer_Analyze(t *testing.T) {
	t.Parallel()

	target := "https://example.com/"
	otherURL := "https://example.com/styles.css"

	t.Run("should do nothing if HAR is missing", func(t *testing.T) {
		t.Parallel()
		ctx := createTestContext(t, target, nil)
		ctx.Artifacts = nil // -- explicitly nil artifacts --
		err := globalFixture.Analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)
		assert.Empty(t, ctx.Findings, "No findings should be generated without HAR data")
	})

	t.Run("should do nothing if main response is not found", func(t *testing.T) {
		t.Parallel()
		har := &schemas.HAR{
			Log: schemas.Log{
				Entries: []schemas.Entry{
					{Request: schemas.Request{URL: otherURL}, Response: schemas.Response{}},
				},
			},
		}
		ctx := createTestContext(t, target, har)
		err := globalFixture.Analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)
		assert.Empty(t, ctx.Findings, "No findings should be generated if the target URL is not in HAR")
	})

	t.Run("should correctly identify all missing security headers", func(t *testing.T) {
		t.Parallel()
		// -- an empty set of headers --
		har := &schemas.HAR{Log: schemas.Log{Entries: []schemas.Entry{{
			Request:  schemas.Request{URL: target},
			Response: schemas.Response{Headers: []schemas.Header{}},
		}}}}
		ctx := createTestContext(t, target, har)
		err := globalFixture.Analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)

		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: x-frame-options"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: x-content-type-options"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: referrer-policy"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: strict-transport-security"))
		assert.NotNil(t, findFindingByVulnName(ctx.Findings, "Missing Security Header: content-security-policy"))
	})

	t.Run("should identify information disclosure headers", func(t *testing.T) {
		t.Parallel()
		har := &schemas.HAR{Log: schemas.Log{Entries: []schemas.Entry{{
			Request: schemas.Request{URL: target},
			Response: schemas.Response{Headers: []schemas.Header{
				{Name: "Server", Value: "nginx/1.18.0"},
				{Name: "X-Powered-By", Value: "PHP/7.4.3"},
			}},
		}}}}
		ctx := createTestContext(t, target, har)
		err := globalFixture.Analyzer.Analyze(context.Background(), ctx)
		require.NoError(t, err)

		require.Len(t, ctx.Findings, 1, "Should generate one finding for info disclosure")
		finding := findFindingByVulnName(ctx.Findings, "Information Disclosure in HTTP Headers")
		require.NotNil(t, finding)
		assert.Contains(t, finding.Description, "The 'server' header discloses technology stack", "Description mismatch")
	})
}

// TestHSTSChecks provides granular tests for the HSTS logic.
func TestHSTSChecks(t *testing.T) {
	t.Parallel()
	target := "https://example.com/"

	testCases := []struct {
		name              string
		headerValue       string
		expectFinding     bool
		expectedVulnName  string
		expectedSeverity  schemas.Severity
	}{
		{"missing max-age", "includeSubDomains", true, "Weak HSTS Configuration: Missing max-age", schemas.SeverityLow},
		{"max-age is zero", "max-age=0", true, "Weak HSTS Configuration: max-age is Zero", schemas.SeverityMedium},
		{"max-age is too short", fmt.Sprintf("max-age=%d", MinHstsMaxAge-1), true, "Weak HSTS Configuration: Short max-age", schemas.SeverityLow},
		{"max-age is sufficient", fmt.Sprintf("max-age=%d", MinHstsMaxAge), false, "", ""},
		{"large max-age is valid", "max-age=31536000; includeSubDomains", false, "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			har := &schemas.HAR{Log: schemas.Log{Entries: []schemas.Entry{{
				Request:  schemas.Request{URL: target},
				Response: schemas.Response{Headers: []schemas.Header{{Name: "Strict-Transport-Security", Value: tc.headerValue}}},
			}}}}
			ctx := createTestContext(t, target, har)

			// -- we call the specific function to isolate the test --
			globalFixture.Analyzer.checkHSTS(ctx, map[string]string{"strict-transport-security": tc.headerValue})

			if tc.expectFinding {
				finding := findFindingByVulnName(ctx.Findings, tc.expectedVulnName)
				require.NotNil(t, finding, "Expected finding was not generated")
				assert.Equal(t, tc.expectedSeverity, finding.Severity, "Severity level mismatch")
			} else {
				assert.Empty(t, ctx.Findings, "No findings should be generated for a valid HSTS policy")
			}
		})
	}
}

// TestCSPChecks provides granular tests for the CSP logic.
func TestCSPChecks(t *testing.T) {
	t.Parallel()
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			har := &schemas.HAR{Log: schemas.Log{Entries: []schemas.Entry{{
				Request:  schemas.Request{URL: target},
				Response: schemas.Response{Headers: []schemas.Header{{Name: "Content-Security-Policy", Value: tc.headerValue}}},
			}}}}
			ctx := createTestContext(t, target, har)

			globalFixture.Analyzer.checkCSP(ctx, map[string]string{"content-security-policy": tc.headerValue})

			finding := findFindingByVulnName(ctx.Findings, "Weak Content-Security-Policy (CSP)")
			if tc.expectFinding {
				assert.NotNil(t, finding, "Expected a CSP finding to be generated")
			} else {
				assert.Nil(t, finding, "Should not generate a finding for a strong CSP")
			}
		})
	}
}
