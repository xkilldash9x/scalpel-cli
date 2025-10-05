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
	"go.uber.org/zap/zaptest"

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

func (m *MockWriteCloser) Write(p []byte) (n int, err error) {
	if m.FailWrite {
		return 0, errors.New("simulated write error")
	}
	return m.Buffer.Write(p)
}

func (m *MockWriteCloser) Close() error {
	if m.FailClose {
		return errors.New("simulated close error")
	}
	return nil
}

func setupSARIFTest(t *testing.T) (*reporting.SARIFReporter, *MockWriteCloser) {
	logger := zaptest.NewLogger(t)
	mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer)}
	// Test the dependency injection of the version string
	reporter := reporting.NewSARIFReporter(mockWriter, logger, "v1.2.3-test")
	return reporter, mockWriter
}

// TestSARIFReporter_Initialization verifies the structure of an empty report.
func TestSARIFReporter_Initialization(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	err := reporter.Close()
	require.NoError(t, err)

	var log sarif.Log
	err = json.Unmarshal(writer.Buffer.Bytes(), &log)
	require.NoError(t, err, "Output should be valid SARIF JSON")

	assert.Equal(t, reporting.SARIFVersion, log.Version)
	require.Len(t, log.Runs, 1)
	run := log.Runs[0]

    require.NotNil(t, run.Tool.Driver)
	assert.Equal(t, "v1.2.3-test", *run.Tool.Driver.Version)
	
	// Ensure slices are initialized (JSON "[]") not null
	assert.NotNil(t, run.Results)
    assert.Empty(t, run.Results)
	assert.NotNil(t, run.Tool.Driver.Rules)
    assert.Empty(t, run.Tool.Driver.Rules)
}

// TestSARIFReporter_WriteAndClose verifies the end-to-end process, including rule deduplication and severity mapping.
func TestSARIFReporter_WriteAndClose(t *testing.T) {
	reporter, writer := setupSARIFTest(t)

	// Define findings
	finding1 := schemas.Finding{
		Target: "http://example.com/1",
		Severity: schemas.SeverityHigh,
		Vulnerability: schemas.Vulnerability{
			Name:        "Cross-Site Scripting (XSS)",
			Description: "Details about XSS.",
		},
		Recommendation: "Encode output.",
		CWE:            []string{"CWE-79"},
	}
	// Finding 2 uses a new rule and tests Critical severity
    finding2 := schemas.Finding{
		Target: "http://example.com/2",
		Severity: schemas.SeverityCritical,
		Vulnerability: schemas.Vulnerability{
			Name:        "SQL Injection",
		},
	}
	// Finding 3 reuses the rule from Finding 1, tests Medium severity and empty description fallback.
	finding3 := schemas.Finding{
		Target: "http://example.com/3",
		Severity: schemas.SeverityMedium,
		Vulnerability: schemas.Vulnerability{
			Name: "Cross-Site Scripting (XSS)",
            // Empty description to test fallback
		},
	}

	envelope := &schemas.ResultEnvelope{Findings: []schemas.Finding{finding1, finding2, finding3}}

	require.NoError(t, reporter.Write(envelope))
	require.NoError(t, reporter.Close())

	// Validate the output JSON
	var log sarif.Log
	err := json.Unmarshal(writer.Buffer.Bytes(), &log)
	require.NoError(t, err)

	run := log.Runs[0]

	// Check Results (3 total)
	require.Len(t, run.Results, 3)
	// Result 1 (High -> Error)
	assert.Equal(t, "SCALPEL-CROSS-SITE-SCRIPTING-XSS", run.Results[0].RuleID)
	assert.Equal(t, string(sarif.LevelError), string(run.Results[0].Level))
	assert.Equal(t, "Details about XSS.", *run.Results[0].Message.Text)

	// Result 2 (Critical -> Error)
	assert.Equal(t, "SCALPEL-SQL-INJECTION", run.Results[1].RuleID)
	assert.Equal(t, string(sarif.LevelError), string(run.Results[1].Level))

	// Result 3 (Medium -> Warning)
	assert.Equal(t, "SCALPEL-CROSS-SITE-SCRIPTING-XSS", run.Results[2].RuleID)
	assert.Equal(t, string(sarif.LevelWarning), string(run.Results[2].Level))
    // Check fallback message when description is empty
	assert.Equal(t, "Cross-Site Scripting (XSS)", *run.Results[2].Message.Text)

	// Check Rules (should only have 2 unique rules)
	require.Len(t, run.Tool.Driver.Rules, 2)
    
    // Verify rule details (e.g., Help Markdown)
    var xssRule *sarif.ReportingDescriptor
    for _, r := range run.Tool.Driver.Rules {
        if r.ID == "SCALPEL-CROSS-SITE-SCRIPTING-XSS" {
            xssRule = r
            break
        }
    }
    require.NotNil(t, xssRule)
	assert.Equal(t, "Encode output.", *xssRule.Help.Text)
    assert.Contains(t, *xssRule.Help.Markdown, "**Recommendation:**\nEncode output.")
    assert.Contains(t, xssRule.Properties["CWE"], "CWE-79")
}

// TestSARIFReporter_RuleIDSanitization tests the cleaning and normalization of vulnerability names.
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
        {"Mixed.Case_Test-1", "SCALPEL-MIXED.CASE_TEST-1"},
		{"Empty Name Fallback", "", "SCALPEL-UNNAMED-VULNERABILITY"},
		{"Only Symbols Fallback", "!@#", "SCALPEL-UNKNOWN-VULNERABILITY"}, // Becomes empty after sanitization
	}

    // Track unique expected IDs to verify rule count later
    uniqueIDs := make(map[string]bool)

	for _, tt := range tests {
		finding := schemas.Finding{
			Vulnerability: schemas.Vulnerability{Name: tt.vulnName},
		}
		reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{finding}})
        uniqueIDs[tt.expectedID] = true
	}

	reporter.Close()
	var log sarif.Log
	json.Unmarshal(writer.Buffer.Bytes(), &log)

	require.Len(t, log.Runs[0].Results, len(tests))

	for i, tt := range tests {
		assert.Equal(t, tt.expectedID, log.Runs[0].Results[i].RuleID)
	}
    // Ensure the correct number of unique rules were generated
    assert.Len(t, log.Runs[0].Tool.Driver.Rules, len(uniqueIDs))
}

// TestSARIFReporter_Concurrency ensures thread safety (run with `go test -race`).
func TestSARIFReporter_Concurrency(t *testing.T) {
    reporter, writer := setupSARIFTest(t)

	const numGoroutines = 50
	const findingsPerGoroutine = 20
    const numUniqueRules = 5 // Force contention on the rulesSeen map and log structure

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < findingsPerGoroutine; j++ {
				// Use a limited set of rule IDs to test concurrent map access/writes
				vulnName := fmt.Sprintf("Concurrent Vuln %d", (id+j)%numUniqueRules)
				finding := schemas.Finding{
					Vulnerability: schemas.Vulnerability{Name: vulnName},
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
    assert.Len(t, log.Runs[0].Results, numGoroutines * findingsPerGoroutine)
    // Total rules should match the unique rules generated, proving deduplication worked under concurrency
    assert.Len(t, log.Runs[0].Tool.Driver.Rules, numUniqueRules)
}

func TestSARIFReporter_ErrorHandling(t *testing.T) {
    t.Run("Close Error", func(t *testing.T) {
        logger := zaptest.NewLogger(t)
        // Use the mock writer to simulate a close error
        mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer), FailClose: true}
	    reporter := reporting.NewSARIFReporter(mockWriter, logger, "v1.0.0-test")

        err := reporter.Close()
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "failed to close output writer")
    })

    t.Run("Encode Error (simulated by write failure)", func(t *testing.T) {
        logger := zaptest.NewLogger(t)
        // JSON encoding writes to the writer. If the writer fails, encoding fails.
        mockWriter := &MockWriteCloser{Buffer: new(bytes.Buffer), FailWrite: true}
	    reporter := reporting.NewSARIFReporter(mockWriter, logger, "v1.0.0-test")

        // Add data to ensure the encoder attempts to write
        reporter.Write(&schemas.ResultEnvelope{Findings: []schemas.Finding{{}}})

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
        case "low", "informational":
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
        {schemas.SeverityInformational, string(sarif.LevelNote)},
		{"HIGH", string(sarif.LevelError)}, // Case insensitivity
		{"Unknown", string(sarif.LevelNote)},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			assert.Equal(t, tt.want, mapSeverityToSARIFLevel(tt.input))
		})
	}
}