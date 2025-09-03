package reporting

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/pkg/reporting/sarif"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// SARIFReporter implements the Reporter interface for the SARIF 2.1.0 format.
type SARIFReporter struct {
	writer io.WriteCloser
	log    *sarif.Log
	mu     sync.Mutex
}

// NewSARIFReporter creates a new reporter that writes SARIF output.
func NewSARIFReporter(writer io.WriteCloser) *SARIFReporter {
	// Initialize the SARIF log structure with tool information.
	log := &sarif.Log{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
		Runs:*sarif.Run{
			{
				Tool: &sarif.Tool{
					Driver: &sarif.ToolComponent{
						Name:           "Scalpel CLI",
						Version:        "2.0.0", // Example version
						InformationURI: "https://github.com/xkilldash9x/scalpel-cli",
						Rules:         *sarif.ReportingDescriptor{},
					},
				},
				Results:*sarif.Result{},
			},
		},
	}

	return &SARIFReporter{
		writer: writer,
		log:    log,
	}
}

// Write converts a ResultEnvelope into one or more SARIF results and adds them to the log.
func (r *SARIFReporter) Write(result *schemas.ResultEnvelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	run := r.log.Runs

	for _, finding := range result.Findings {
		ruleID := r.ensureRule(finding)
		
		sarifResult := &sarif.Result{
			RuleID:    ruleID,
			Message:   &sarif.Message{Text: finding.Description},
			Level:     mapSeverityToSARIFLevel(finding.Severity),
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
	encoder.SetIndent("", "  ") // Pretty-print the JSON output.
	if err := encoder.Encode(r.log); err!= nil {
		return err
	}
	return r.writer.Close()
}

// ensureRule checks if a rule for the finding's vulnerability type already exists.
// If not, it creates one. It returns the stable rule ID.
func (r *SARIFReporter) ensureRule(finding schemas.Finding) string {
	driver := r.log.Runs.Tool.Driver
	
	// Use a sanitized version of the vulnerability name as the rule ID.
	ruleID := "SCALPEL-" + strings.ToUpper(strings.ReplaceAll(finding.Vulnerability, " ", "-"))

	for _, rule := range driver.Rules {
		if rule.ID == ruleID {
			return ruleID // Rule already exists.
		}
	}

	// Create a new rule.
	newRule := &sarif.ReportingDescriptor{
		ID:               ruleID,
		Name:             finding.Vulnerability,
		ShortDescription: &sarif.MultiformatMessageString{Text: finding.Vulnerability},
		FullDescription:  &sarif.MultiformatMessageString{Text: finding.Recommendation},
		Help: &sarif.MultiformatMessageString{
			Text:     finding.Recommendation,
			Markdown: fmt.Sprintf("**Recommendation:**\n%s", finding.Recommendation),
		},
		Properties: &sarif.PropertyBag{
			"tags":string{"security", "scalpel"},
			"precision": "high",
			"CWE": finding.CWE,
		},
	}
	driver.Rules = append(driver.Rules, newRule)
	return ruleID
}

// createLocations converts finding details into SARIF location objects.
func (r *SARIFReporter) createLocations(finding schemas.Finding)*sarif.Location {
	location := &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{
				URI: &finding.Target,
			},
		},
		Message: &sarif.Message{
			Text: fmt.Sprintf("Vulnerability found at %s", finding.Target),
		},
	}
	// TODO: Enhance this to parse line numbers or specific regions if evidence provides it.
	return*sarif.Location{location}
}

// mapSeverityToSARIFLevel converts Scalpel's severity to the SARIF standard.
func mapSeverityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
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

// NOTE: The `sarif` package (`github.com/xkilldash9x/scalpel-cli/pkg/reporting/sarif`)
// would contain Go structs matching the SARIF 2.1.0 JSON schema. These structs are omitted here
// for brevity but are a required dependency for this code to function.
