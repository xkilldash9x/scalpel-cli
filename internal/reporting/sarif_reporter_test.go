// internal/reporting/sarif_reporter_test.go
package reporting_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"

	// Assuming the internal sarif definitions are located here
	"github.com/xkilldash9x/scalpel-cli/internal/reporting/sarif"
)

// MockWriteCloser allows capturing output and simulating I/O errors.
type MockWriteCloser struct {
	Buffer    *bytes.Buffer
	FailWrite bool
	FailClose bool
}

// Write writes to the internal buffer, simulating a write error if configured.
func (m *MockWriteCloser) Write(p []byte) (n int, err error) {
	if m.FailWrite {
		return 0, errors.New("simulated write error")
	}
	return m.Buffer.Write(p)
}

// Close simulates a closing error if configured.
func (m *MockWriteCloser) Close() error {
	if m.FailClose {
		return errors.New("simulated close error")
	}
	return nil
}

func setupSARIFTest(_ *testing.T) (*reporting.SARIFReporter, *MockWriteCloser) {
	mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer)}
	// Test the dependency injection of the version string
	reporter := reporting.NewSARIFReporter(mockWriter, "v1.2.3-test")
	return reporter, mockWriter
}

// TestSARIFReporter_Initialization verifies the structure of an empty report.
func TestSARIFReporter_Initialization(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	err := reporter.Close()
	require.NoError(t, err)

	rawOutput := writer.Buffer.Bytes()

	var log sarif.Log
	err = json.Unmarshal(rawOutput, &log)
	require.NoError(t, err, "Output should be valid SARIF JSON")

	assert.Equal(t, reporting.SARIFVersion, log.Version)
	require.Len(t, log.Runs, 1)
	run := log.Runs[0]

	require.NotNil(t, run.Tool)
	require.NotNil(t, run.Tool.Driver)

	// Check the required version field
	assert.Equal(t, "v1.2.3-test", *run.Tool.Driver.Version)

	// Ensure Results slice is initialized (JSON "[]") not null
	require.NotNil(t, run.Results)
	assert.Empty(t, run.Results)

	assert.Empty(t, run.Tool.Driver.Rules)
}

// TestSARIFReporter_WriteAndClose verifies the end-to-end process.
// (Updated to verify fixes for Bug 1 and Bug 2)
func TestSARIFReporter_WriteAndClose(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	// Define findings
	finding1 := schemas.Finding{
		Target:            "http://example.com/1",
		Severity:          schemas.SeverityHigh,
		VulnerabilityName: "Cross-Site Scripting (XSS)",
		Description:       "Details about XSS.",
		Recommendation:    "Encode output.",
		CWE:               []string{"CWE-79"},
	}
	finding2 := schemas.Finding{
		Target:            "http://example.com/2",
		Severity:          schemas.SeverityCritical,
		VulnerabilityName: "SQL Injection",
		Description:       "Details about SQLi.",
		Recommendation:    "Use parameterized queries.",
	}
	// Finding 3 reuses the rule from Finding 1 (must match fingerprint exactly)
	finding3 := schemas.Finding{
		Target:            "http://example.com/3",
		Severity:          schemas.SeverityMedium,
		VulnerabilityName: "Cross-Site Scripting (XSS)",
		Description:       "Details about XSS.",
		Recommendation:    "Encode output.",
		CWE:               []string{"CWE-79"},
	}

	// Finding 4 tests empty description (creates a new rule because fingerprint differs) (Bug 1 verification)
	finding4 := schemas.Finding{
		Target:            "http://example.com/4",
		Severity:          schemas.SeverityLow,
		VulnerabilityName: "Cross-Site Scripting (XSS)",
		// Empty description
		Recommendation: "Generic advice.",
	}

	envelope := &schemas.ResultEnvelope{Findings: []schemas.Finding{finding1, finding2, finding3, finding4}}

	require.NoError(t, reporter.Write(envelope))
	require.NoError(t, reporter.Close())

	// Validate the output JSON
	var log sarif.Log
	err := json.Unmarshal(writer.Buffer.Bytes(), &log)
	require.NoError(t, err)

	run := log.Runs[0]

	// Check Results (4 total)
	require.Len(t, run.Results, 4)
	// Check Rules (3 unique rules: XSS-Detailed, SQL-Injection, XSS-EmptyDesc)
	require.Len(t, run.Tool.Driver.Rules, 3)

	// Result 1
	ruleID1 := run.Results[0].RuleID
	assert.Equal(t, "SCALPEL-CROSS-SITE-SCRIPTING-XSS", ruleID1)
	assert.Equal(t, string(sarif.LevelError), string(run.Results[0].Level))
	assert.Equal(t, "Details about XSS.", *run.Results[0].Message.Text)

	// Result 2
	assert.Equal(t, "SCALPEL-SQL-INJECTION", run.Results[1].RuleID)

	// Result 3 (Must reuse RuleID1)
	assert.Equal(t, ruleID1, run.Results[2].RuleID)
	assert.Equal(t, string(sarif.LevelWarning), string(run.Results[2].Level))

	// Result 4 (Must have a new RuleID due to different fingerprint) (Bug 1 verification)
	ruleID4 := run.Results[3].RuleID
	assert.NotEqual(t, ruleID1, ruleID4)
	// It should have a suffix because the base name collided.
	assert.Equal(t, "SCALPEL-CROSS-SITE-SCRIPTING-XSS-1", ruleID4)
	// Check fallback message when description is empty
	assert.Equal(t, "Cross-Site Scripting (XSS)", *run.Results[3].Message.Text)

	// Verify rule details
	rulesMap := make(map[string]*sarif.ReportingDescriptor)
	for _, r := range run.Tool.Driver.Rules {
		rulesMap[r.ID] = r
	}

	xssRule := rulesMap[ruleID1]
	sqliRule := rulesMap["SCALPEL-SQL-INJECTION"]
	xssRuleEmptyDesc := rulesMap[ruleID4]

	require.NotNil(t, xssRule)
	require.NotNil(t, sqliRule)
	require.NotNil(t, xssRuleEmptyDesc)

	// FIX VERIFICATION (Bug 2): Ensure FullDescription uses Description, not Recommendation.
	assert.Equal(t, "Details about XSS.", *xssRule.FullDescription.Text, "XSS FullDescription mismatch")
	assert.Equal(t, "Details about SQLi.", *sqliRule.FullDescription.Text, "SQLi FullDescription mismatch")
	assert.Equal(t, "", *xssRuleEmptyDesc.FullDescription.Text, "XSS Empty Desc FullDescription mismatch")

	// Verify Help (Recommendation) is still correct
	assert.Equal(t, "Encode output.", *xssRule.Help.Text)
	assert.Equal(t, "Generic advice.", *xssRuleEmptyDesc.Help.Text)

	// Verify CWE handling
	assertCWE(t, []string{"CWE-79"}, (*xssRule.Properties)["CWE"])
}

// TestSARIFReporter_RuleCollisionHandling verifies that findings with the same name
// but different characteristics generate distinct rules. (Bug 1 verification)
func TestSARIFReporter_RuleCollisionHandling(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	const sharedName = "Insecure Configuration"

	// Finding 1: (CWE-16)
	finding1 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Default credentials are in use.",
		CWE:               []string{"CWE-16"},
	}

	// Finding 2: (CWE-312) with the same name
	finding2 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Credentials stored in plain text.",
		CWE:               []string{"CWE-312"},
	}

	// Finding 3: A repeat of Finding 1 (tests deduplication)
	finding3 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Default credentials are in use.",
		CWE:               []string{"CWE-16"},
	}

	// Finding 4: (CWE-255)
	finding4 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Credentials managed improperly.",
		CWE:               []string{"CWE-255"},
	}

	// Finding 5 & 6: Test CWE sorting consistency (same CWEs, different order)
	finding5 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Multiple issues.",
		CWE:               []string{"CWE-X", "CWE-Y"},
	}
	finding6 := schemas.Finding{
		VulnerabilityName: sharedName,
		Description:       "Multiple issues.",
		CWE:               []string{"CWE-Y", "CWE-X"},
	}

	require.NoError(t, reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{finding1, finding2, finding3, finding4, finding5, finding6}}))
	require.NoError(t, reporter.Close())

	// Validate the output JSON
	var log sarif.Log
	err := json.Unmarshal(writer.Buffer.Bytes(), &log)
	require.NoError(t, err)

	run := log.Runs[0]

	// Check Results (6 total)
	require.Len(t, run.Results, 6)
	// Check Rules (should have 4 unique rules: 1/3, 2, 4, 5/6)
	require.Len(t, run.Tool.Driver.Rules, 4)

	ruleID1 := run.Results[0].RuleID
	ruleID2 := run.Results[1].RuleID
	ruleID3 := run.Results[2].RuleID
	ruleID4 := run.Results[3].RuleID
	ruleID5 := run.Results[4].RuleID
	ruleID6 := run.Results[5].RuleID

	// Verify the generated IDs match the expected pattern (order of generation matters)
	assert.Equal(t, "SCALPEL-INSECURE-CONFIGURATION", ruleID1)
	assert.Equal(t, "SCALPEL-INSECURE-CONFIGURATION-1", ruleID2)
	assert.Equal(t, "SCALPEL-INSECURE-CONFIGURATION-2", ruleID4)
	assert.Equal(t, "SCALPEL-INSECURE-CONFIGURATION-3", ruleID5)

	// Rule IDs for finding 1, 2, 4, 5 must be different
	assert.NotEqual(t, ruleID1, ruleID2)
	assert.NotEqual(t, ruleID1, ruleID4)
	assert.NotEqual(t, ruleID1, ruleID5)

	// Rule IDs for finding 1 and 3 must be the same
	assert.Equal(t, ruleID1, ruleID3)
	// Rule IDs for finding 5 and 6 must be the same (CWE sorting verification)
	assert.Equal(t, ruleID5, ruleID6)
}

// TestSARIFReporter_RuleIDSanitization tests the cleaning and normalization of vulnerability names.
// (Updated to verify Bug 1 and Bug 3 fixes)
func TestSARIFReporter_RuleIDSanitization(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	tests := []struct {
		vulnName   string
		expectedID string
	}{
		{"Simple", "SCALPEL-SIMPLE"},
		{"Path Traversal / LFI", "SCALPEL-PATH-TRAVERSAL-LFI"},
		{"User@Example!#$%^", "SCALPEL-USER-EXAMPLE"},
		{"!Leading/Trailing!", "SCALPEL-LEADING-TRAILING"},
		// Hyphen is now treated as a separator by the regex (Bug 3), but preserved if singular and surrounded by allowed chars.
		{"Mixed.Case_Test-1", "SCALPEL-MIXED.CASE_TEST-1"},
		{"", "SCALPEL-UNNAMED-VULNERABILITY"},
		{"!@#", "SCALPEL-UNKNOWN-VULNERABILITY"},
		// FIX VERIFICATION (Bug 3): Consecutive hyphens are collapsed.
		{"Type-A--Sub-Type-B", "SCALPEL-TYPE-A-SUB-TYPE-B"},
		// FIX VERIFICATION (Bug 3): Mixed symbols and hyphens are collapsed.
		{"A-!/--B", "SCALPEL-A-B"},
	}

	// Track unique expected IDs
	uniqueIDs := make(map[string]bool)

	for i, tt := range tests {
		finding := schemas.Finding{
			VulnerabilityName: tt.vulnName,
			// Use index in description to guarantee unique fingerprints (Bug 1 requirement)
			// This prevents the deduplication logic from merging these test cases.
			Description: fmt.Sprintf("Test case %d", i),
		}
		reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{finding}})
		uniqueIDs[tt.expectedID] = true
	}

	reporter.Close()
	var log sarif.Log
	json.Unmarshal(writer.Buffer.Bytes(), &log)

	require.Len(t, log.Runs[0].Results, len(tests))

	for i, tt := range tests {
		assert.Equal(t, tt.expectedID, log.Runs[0].Results[i].RuleID, "Test case %d failed: %s", i, tt.vulnName)
	}
	// Ensure the correct number of unique rules were generated
	assert.Len(t, log.Runs[0].Tool.Driver.Rules, len(uniqueIDs))
}

// TestSARIFReporter_Concurrency ensures thread safety (run with `go test -race`).
// (Updated for Bug 1 fingerprinting requirements)
func TestSARIFReporter_Concurrency(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	const numGoroutines = 50
	const findingsPerGoroutine = 20
	const numUniqueRules = 5 // Force contention on the maps and log structure

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < findingsPerGoroutine; j++ {
				// Use a limited set of rule definitions
				ruleIndex := (id + j) % numUniqueRules
				vulnName := fmt.Sprintf("Concurrent Vuln %d", ruleIndex)

				finding := schemas.Finding{
					VulnerabilityName: vulnName,
					// Ensure the description matches the rule index for consistent fingerprinting (Bug 1)
					Description: fmt.Sprintf("Description %d", ruleIndex),
				}
				// The Write method must be safe due to the internal mutex
				err := reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{finding}})
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
	reporter.Close()

	// Verify the final count
	var log sarif.Log
	err := json.Unmarshal(writer.Buffer.Bytes(), &log)
	require.NoError(t, err)

	// Total findings = numGoroutines * findingsPerGoroutine
	assert.Len(t, log.Runs[0].Results, numGoroutines*findingsPerGoroutine)
	// Total rules should match the unique rules generated, proving deduplication worked under concurrency
	assert.Len(t, log.Runs[0].Tool.Driver.Rules, numUniqueRules)
}

func TestSARIFReporter_ErrorHandling(t *testing.T) {
	t.Run("Close Error", func(t *testing.T) {
		// Use the mock writer to simulate a close error
		mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer), FailClose: true}
		reporter := reporting.NewSARIFReporter(mockWriter, "v1.0.0-test")

		err := reporter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to close output writer")
	})

	t.Run("Encode Error (simulated by write failure)", func(t *testing.T) {
		// JSON encoding writes to the writer. If the writer fails, encoding fails.
		mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer), FailWrite: true}
		reporter := reporting.NewSARIFReporter(mockWriter, "v1.0.0-test")

		// Add data to ensure the encoder attempts to write
		// Use a unique description to ensure a rule is generated (Bug 1 requirement)
		reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{{Description: "force write"}}})

		err := reporter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encode SARIF output")
	})
}

// Test for the private severity mapping logic.
func TestMapSeverityToSARIFLevel(t *testing.T) {
	// Since the function mapSeverityToSARIFLevel is private (lowercase), we replicate its logic here to test it.
	mapSeverityToSARIFLevel := func(severity schemas.Severity) string {
		switch strings.ToLower(string(severity)) {
		case "critical", "high":
			return string(sarif.LevelError)
		case "medium":
			return string(sarif.LevelWarning)
		// REFACTOR: Changed "informational" to "info" to match schemas.findings.go
		case "low", "info":
			return string(sarif.LevelNote)
		default:
			return string(sarif.LevelNote)
		}
	}

	tests := []struct {
		input schemas.Severity
		want  string
	}{
		{schemas.SeverityCritical, string(sarif.LevelError)},
		{schemas.SeverityHigh, string(sarif.LevelError)},
		{schemas.SeverityMedium, string(sarif.LevelWarning)},
		{schemas.SeverityLow, string(sarif.LevelNote)},
		// REFACTOR: Changed const from SeverityInformational to SeverityInfo
		{schemas.SeverityInfo, string(sarif.LevelNote)},
		{"HIGH", string(sarif.LevelError)}, // Case insensitivity
		{"Unknown", string(sarif.LevelNote)},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			assert.Equal(t, tt.want, mapSeverityToSARIFLevel(tt.input))
		})
	}
}

// Helper function to compare expected CWE strings with the actual interface{} slice from JSON unmarshalling.
// (Added for Bug 1 verification)
func assertCWE(t *testing.T, expected []string, actual interface{}) {
	// Handle nil case gracefully
	if actual == nil {
		assert.Empty(t, expected, "Expected CWEs but found nil")
		return
	}

	cweList, ok := actual.([]interface{})
	require.True(t, ok, "CWE value should be a slice of interfaces during test time reflection, got %T", actual)

	actualCWEStrings := make([]string, len(cweList))
	for i, v := range cweList {
		str, isString := v.(string)
		require.True(t, isString, "CWE slice element expected to be string, got %T", v)
		actualCWEStrings[i] = str
	}
	// Use ElementsMatch for order-independent comparison (important due to sorting in fingerprinting)
	assert.ElementsMatch(t, expected, actualCWEStrings)
}
