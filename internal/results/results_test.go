package results

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)


// Mock Definitions
// Comprehensive mocks for isolating logic from external dependencies.


// Mocks the CWEProvider interface.
type MockCWEProvider struct {
	mock.Mock
}

// Mocks the retrieval of CWE details.
// It adheres to the improved interface signature including context.Context.
func (m *MockCWEProvider) GetFullName(ctx context.Context, cweID string) (string, bool) {
	// Record the call
	args := m.Called(ctx, cweID)

	// Robustness: Check if the context is done *before* returning the mocked result.
	// This allows tests (especially those using .Run() or .WaitUntil())
	// to accurately simulate cancellation during the provider's operation.
	select {
	case <-ctx.Done():
		// If cancelled, return "not found" regardless of the configured mock return.
		return "", false
	default:
		// Proceed normally
	}

	return args.String(0), args.Bool(1)
}


// Test Helpers and Fixtures


// Creates a sample schemas.Finding for testing input.
func newRawFinding(id, severity, cwe, description string) schemas.Finding {
	return schemas.Finding{
		ID:          id,
		Severity:    schemas.Severity(severity),
		CWE:         cwe,
		Description: description,
	}
}

// Provides a standard configuration for prioritization tests.
func defaultTestScoreConfig() ScoreConfig {
	return ScoreConfig{
		SeverityWeights: map[string]float64{
			string(SeverityCritical): 10.0,
			string(SeverityHigh):     7.5,
			string(SeverityMedium):   5.0,
			string(SeverityLow):      2.5,
			string(SeverityInfo):     0.1,
			// SeverityUnknown intentionally omitted to test default 0.0 behavior
		},
	}
}


// Test Cases: Normalization (normalize.go)


// Rigorously verifies the internal mapping logic.
// This critical white box test ensures robustness against diverse tool outputs.
func TestNormalizeSeverity_WhiteBox(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected StandardSeverity
	}{
		// Standard Cases
		{"Critical", "CRITICAL", SeverityCritical},
		{"High", "HIGH", SeverityHigh},

		// Case Variations
		{"Mixed Case (Medium)", "Medium", SeverityMedium},
		{"Lower Case (Low)", "low", SeverityLow},

		// Whitespace Handling
		{"Whitespace (Info)", "  INFO  ", SeverityInfo},

		// Aliases and Synonyms
		{"Alias (Fatal)", "FATAL", SeverityCritical},
		{"Alias (Important)", "Important", SeverityHigh},
		{"Alias (Error)", "Error", SeverityHigh},
		{"Alias (Moderate)", "Moderate", SeverityMedium},
		{"Alias (Warning)", "Warning", SeverityMedium},
		{"Alias (Informational)", "Informational", SeverityInfo},
		{"Alias (Negligible)", "Negligible", SeverityInfo},

		// Unknown and Empty
		{"Unknown Value", "CVSS 9.0", SeverityUnknown},
		{"Empty String", "", SeverityUnknown},
		{"Whitespace Only", "    ", SeverityUnknown},
	}

	for _, tt := range tests {
		tc := tt // Capture range variable for parallel execution
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Testing the unexported function directly.
			result := normalizeSeverity(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Verifies the Normalize function correctly converts the struct
// and applies the severity normalization logic.
func TestNormalize_Integration(t *testing.T) {
	t.Parallel()
	rawFinding := newRawFinding("F1", "Moderate", "CWE-79", "Description")

	normalized := Normalize(rawFinding)

	// Verify data integrity (original data preserved)
	assert.Equal(t, "F1", normalized.ID)
	assert.Equal(t, schemas.Severity("Moderate"), normalized.Finding.Severity, "Original severity must be preserved")

	// Verify normalization logic applied
	assert.Equal(t, string(SeverityMedium), normalized.NormalizedSeverity)

	// Verify initialization
	assert.Equal(t, 0.0, normalized.Score)
}


// Test Cases: Enrichment (enrich.go)


// Verifies that findings are correctly updated when CWE data is available.
func TestEnrich_Success(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Input reflected")},
	}

	// Setup Expectations
	expectedName := "Cross-site Scripting"
	// Ensure the context passed to Enrich is propagated to the provider.
	mockProvider.On("GetFullName", ctx, "CWE-79").Return(expectedName, true).Once()

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	require.NoError(t, err)
	expectedDescription := fmt.Sprintf("[%s] Input reflected", expectedName)
	assert.Equal(t, expectedDescription, enrichedFindings[0].Description)

	mockProvider.AssertExpectations(t)
}

// Verifies handling when data is missing or findings lack CWE IDs.
func TestEnrich_MixedStatus(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Found")},
		{Finding: newRawFinding("F2", "MEDIUM", "", "No CWE ID")},      // Skipped
		{Finding: newRawFinding("F3", "LOW", "CWE-999", "Unknown CWE")}, // Not found
	}

	// Setup Expectations
	mockProvider.On("GetFullName", ctx, "CWE-79").Return("XSS", true).Once()
	mockProvider.On("GetFullName", ctx, "CWE-999").Return("", false).Once()

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "[XSS] Found", enrichedFindings[0].Description)
	assert.Equal(t, "No CWE ID", enrichedFindings[1].Description)
	assert.Equal(t, "Unknown CWE", enrichedFindings[2].Description)

	mockProvider.AssertExpectations(t)
	// Ensure optimization: Provider is not called for empty CWE ID.
	mockProvider.AssertNotCalled(t, "GetFullName", ctx, "")
}

// Verifies robustness when no provider is configured.
func TestEnrich_NilProvider(t *testing.T) {
	ctx := context.Background()
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Original")},
	}

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, nil)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "Original", enrichedFindings[0].Description)
}

// Verifies that the enrichment process stops if the context
// is cancelled before processing begins (testing the loop's select statement).
func TestEnrich_Cancellation_InLoop(t *testing.T) {
	// Create a context that is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockProvider := new(MockCWEProvider) // Provider is required to enter the loop logic.

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Test")},
	}

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, enrichedFindings)
	assert.Contains(t, err.Error(), "enrichment cancelled")
	// Crucially, verify the provider was never called because the loop check caught the cancellation first.
	mockProvider.AssertNotCalled(t, "GetFullName", mock.Anything, mock.Anything)
}

// Verifies that cancellation during the provider's execution
// is handled gracefully (based on the robust mock implementation simulating this scenario).
func TestEnrich_Cancellation_DuringProviderCall(t *testing.T) {
	// Setup context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Original")},
	}

	// Configure the mock to acknowledge the call.
	// We use .WaitUntil() to simulate work that takes longer than the context timeout.
	// The robust mock implementation itself detects the cancellation during this wait.
	mockProvider.On("GetFullName", ctx, "CWE-79").Return("XSS", true).Once().WaitUntil(time.After(100 * time.Millisecond))

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	// The Enrich function itself doesn't return an error in this specific case, because the *provider*
	// returned (string, false) when it detected the cancellation (as implemented in the Mock).
	// The Enrich loop continues (as only 1 finding exists) and finishes successfully.
	require.NoError(t, err)

	// The finding should remain unenriched because the provider returned false due to cancellation.
	assert.Equal(t, "Original", enrichedFindings[0].Description)

	mockProvider.AssertExpectations(t)
}


// Test Cases: Prioritization (prioritize.go)


// Verifies correct score calculation and descending sort order.
func TestPrioritize_ScoringAndSorting(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	// Input (Unsorted)
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_MED", "", "", ""), NormalizedSeverity: "MEDIUM"},   // 5.0
		{Finding: newRawFinding("F_CRIT", "", "", ""), NormalizedSeverity: "CRITICAL"}, // 10.0
		{Finding: newRawFinding("F_LOW", "", "", ""), NormalizedSeverity: "LOW"},      // 2.5
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	require.Len(t, prioritized, 3)

	// Check Order and Scores
	assert.Equal(t, "F_CRIT", prioritized[0].ID)
	assert.Equal(t, 10.0, prioritized[0].Score)

	assert.Equal(t, "F_MED", prioritized[1].ID)
	assert.Equal(t, 5.0, prioritized[1].Score)

	assert.Equal(t, "F_LOW", prioritized[2].ID)
	assert.Equal(t, 2.5, prioritized[2].Score)
}

// Verifies that findings with unmapped severities receive a default score of 0.0.
func TestPrioritize_UnknownSeverity(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_HIGH", "", "", ""), NormalizedSeverity: "HIGH"},
		// SeverityUnknown is intentionally omitted from defaultTestScoreConfig.
		{Finding: newRawFinding("F_UNKNOWN", "", "", ""), NormalizedSeverity: string(SeverityUnknown)},
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, 7.5, prioritized[0].Score)
	assert.Equal(t, 0.0, prioritized[1].Score, "Unmapped severities must default to 0.0")
}

// Ensures that the sort algorithm is stable (Crucial requirement).
func TestPrioritize_Stability(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	// Input findings ordered A, B, C with the same severity/score.
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_A", "", "", ""), NormalizedSeverity: "MEDIUM"},
		{Finding: newRawFinding("F_B", "", "", ""), NormalizedSeverity: "MEDIUM"},
		{Finding: newRawFinding("F_C", "", "", ""), NormalizedSeverity: "MEDIUM"},
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	// The order must be preserved (A, B, C) because the implementation uses sort.SliceStable.
	assert.Equal(t, "F_A", prioritized[0].ID)
	assert.Equal(t, "F_B", prioritized[1].ID)
	assert.Equal(t, "F_C", prioritized[2].ID)
}


// Test Cases: Reporting (report.go)


// Verifies the structure and summary text.
func TestGenerateReport(t *testing.T) {
	t.Parallel()
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "", "", "")},
		{Finding: newRawFinding("F2", "", "", "")},
	}

	// Execute
	report, err := GenerateReport(findings)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, findings, report.Findings)
	assert.Equal(t, "Generated report with 2 prioritized findings.", report.Summary)
}


// Test Cases: Pipeline Integration (pipeline.go)


// Verifies the entire orchestration:
// Normalization (Mapping) -> Enrichment (Mocked) -> Prioritization (Sorting/Scoring).
func TestRunPipeline_EndToEnd(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	config := PipelineConfig{
		ScoreConfig: defaultTestScoreConfig(),
		CWEProvider: mockProvider,
	}

	// Input Data: Unsorted, Non-normalized severities, requiring enrichment.
	rawFindings := []schemas.Finding{
		newRawFinding("F_LOW", "low", "", "No CWE"),                      // N: LOW (2.5)
		newRawFinding("F_HIGH", "Important", "CWE-79", "Needs Enrichment"),      // N: HIGH (7.5)
		newRawFinding("F_UNKNOWN", "WeirdLevel", "CWE-89", "Also Needs Enrichment"), // N: UNKNOWN (0.0)
	}

	// Setup Enrichment Expectations (Called in the order findings appear after normalization)
	mockProvider.On("GetFullName", ctx, "CWE-79").Return("XSS", true).Once()
	mockProvider.On("GetFullName", ctx, "CWE-89").Return("SQLi", true).Once()

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, report)
	mockProvider.AssertExpectations(t)

	require.Len(t, report.Findings, 3)

	// Verify Prioritization (Order: F_HIGH, F_LOW, F_UNKNOWN)
	f1 := report.Findings[0]
	f2 := report.Findings[1]
	f3 := report.Findings[2]

	assert.Equal(t, "F_HIGH", f1.ID)
	assert.Equal(t, "F_LOW", f2.ID)
	assert.Equal(t, "F_UNKNOWN", f3.ID)

	// Verify Normalization and Scoring
	assert.Equal(t, "HIGH", f1.NormalizedSeverity)
	assert.Equal(t, 7.5, f1.Score)
	assert.Equal(t, "UNKNOWN", f3.NormalizedSeverity)
	assert.Equal(t, 0.0, f3.Score)

	// Verify Enrichment
	assert.Equal(t, "[XSS] Needs Enrichment", f1.Description)
	assert.Equal(t, "No CWE", f2.Description)
	assert.Equal(t, "[SQLi] Also Needs Enrichment", f3.Description)
}

// Verifies cancellation during the first stage.
func TestRunPipeline_Cancellation_Normalization(t *testing.T) {
	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rawFindings := []schemas.Finding{newRawFinding("F1", "HIGH", "", "")}
	config := PipelineConfig{ScoreConfig: defaultTestScoreConfig()}

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "pipeline cancelled during normalization")
	assert.True(t, errors.Is(err, context.Canceled))
}

// Verifies cancellation during the second stage propagates correctly.
func TestRunPipeline_Cancellation_Enrichment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	mockProvider := new(MockCWEProvider)

	// We need a finding to pass normalization and reach enrichment.
	rawFindings := []schemas.Finding{newRawFinding("F1", "HIGH", "CWE-79", "")}
	config := PipelineConfig{
		ScoreConfig: defaultTestScoreConfig(),
		CWEProvider: mockProvider,
	}

	// Configure the mock provider to cancel the context when called.
	mockProvider.On("GetFullName", mock.Anything, "CWE-79").Return("XSS", true).Once().Run(func(args mock.Arguments) {
		cancel() // Cancel the context mid-process
	})

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	// The Enrich function detects the cancellation (either in its loop check or because the robust mock returns false)
	// and the pipeline should report the error from the enrichment stage.
	assert.Error(t, err)
	assert.Nil(t, report)
	// The exact error message depends on the race condition between the loop check and the provider call detection.
	// We check for the stage wrapper error.
	assert.Contains(t, err.Error(), "error enriching findings")
}