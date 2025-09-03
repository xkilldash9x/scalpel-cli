// -- pkg/reporting/sarif_reporter.go --
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/pkg/reporting/sarif"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// SARIFReporter implements the Reporter interface for the SARIF 2.1.0 format.
type SARIFReporter struct {
	writer    io.WriteCloser
	log       *sarif.Log
	mu        sync.Mutex
	rulesSeen map[string]struct{} // Add cache for rule IDs
}

// NewSARIFReporter creates a new reporter that writes SARIF output.
func NewSARIFReporter(writer io.WriteCloser) *SARIFReporter {
	// Initialize the SARIF log structure with tool information.
	log := &sarif.Log{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		// Correctly initialize a slice of pointers to sarif.Run
		Runs: []*sarif.Run{
			{
				Tool: &sarif.Tool{
					Driver: &sarif.ToolComponent{
						Name:           "Scalpel CLI",
						Version:        "2.0.0",
						InformationURI: "https://github.com/xkilldash9x/scalpel-cli",
						// Correctly initialize an empty slice of pointers
						Rules: []*sarif.ReportingDescriptor{},
					},
				},
				// Correctly initialize an empty slice of pointers
				Results: []*sarif.Result{},
			},
		},
	}

	return &SARIFReporter{
		writer:    writer,
		log:       log,
		rulesSeen: make(map[string]struct{}), // Initialize the cache
	}
}

// Write converts a ResultEnvelope into one or more SARIF results and adds them to the log.
func (r *SARIFReporter) Write(result *schemas.ResultEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Assuming there's only one run for simplicity.
	run := r.log.Runs[0]

	for _, finding := range result.Findings {
		ruleID := r.ensureRule(finding)

		// Create string pointers for fields that require them
		descPtr := &finding.Description

		sarifResult := &sarif.Result{
			RuleID:    ruleID, // Use value type directly
			Message:   &sarif.Message{Text: descPtr},
			Level:     sarif.Level(mapSeverityToSARIFLevel(finding.Severity)),
			Locations: r.createLocations(finding),
		}
		run.Results = append(run.Results, sarifResult)
	}

	return nil
}

// Close finalizes the SARIF log and writes it to the output writer.
func (r *SARIFReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")

	encodeErr := encoder.Encode(r.log)
	// Always attempt to close the writer.
	closeErr := r.writer.Close()

	if encodeErr != nil {
		// Prioritize the encoding error.
		return encodeErr
	}

	return closeErr
}

// ensureRule checks if a rule for the finding's vulnerability type already exists.
// NOTE: Must be called while holding the mutex.
func (r *SARIFReporter) ensureRule(finding schemas.Finding) string {
	// Use a sanitized version of the vulnerability name as the rule ID.
	ruleID := "SCALPEL-" + strings.ToUpper(strings.ReplaceAll(finding.Vulnerability, " ", "-"))

	// O(1) Lookup
	if _, exists := r.rulesSeen[ruleID]; exists {
		return ruleID
	}

	// Assuming there's only one run.
	driver := r.log.Runs[0].Tool.Driver

	// Create pointers for string fields
	vulnPtr := &finding.Vulnerability
	recPtr := &finding.Recommendation

	// Create a new rule.
	newRule := &sarif.ReportingDescriptor{
		ID:               ruleID, // Use value type directly
		Name:             vulnPtr,
		ShortDescription: &sarif.MultiformatMessageString{Text: vulnPtr},
		FullDescription:  &sarif.MultiformatMessageString{Text: recPtr},
		Help: &sarif.MultiformatMessageString{
			Text: recPtr,
			Markdown: func() *string {
				s := fmt.Sprintf("**Recommendation:**\n%s", finding.Recommendation)
				return &s
			}(),
		},
		Properties: &sarif.PropertyBag{
			"tags":      []string{"security", "scalpel"},
			"precision": "high",
			"CWE":       finding.CWE,
		},
	}
	driver.Rules = append(driver.Rules, newRule)
	r.rulesSeen[ruleID] = struct{}{} // Add to cache
	return ruleID
}

// createLocations converts finding details into SARIF location objects.
func (r *SARIFReporter) createLocations(finding schemas.Finding) []*sarif.Location {
	uriPtr := &finding.Target
	msgText := fmt.Sprintf("Vulnerability found at %s", finding.Target)
	msgPtr := &msgText

	location := &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{
				URI: uriPtr,
			},
		},
		Message: &sarif.Message{
			Text: msgPtr,
		},
	}
	// Correctly return a slice of pointers to location
	return []*sarif.Location{location}
}

// mapSeverityToSARIFLevel converts Scalpel's severity to the SARIF standard.
func mapSeverityToSARIFLevel(severity schemas.Severity) string {
	switch strings.ToLower(string(severity)) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}