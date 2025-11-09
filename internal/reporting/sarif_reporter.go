// internal/reporting/sarif_reporter.go
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// The import "github.com/xkilldash9x/scalpel-cli/cmd" has been removed to break the import cycle.
	"github.com/xkilldash9x/scalpel-cli/internal/reporting/sarif"
)

// Constants for tool identification in the SARIF report.
const (
	ToolName     = "Scalpel CLI"
	ToolInfoURI  = "https://github.com/xkilldash9x/scalpel-cli"
	SARIFVersion = "2.1.0"
	SARIFSchema  = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
)

// ruleIDSanitizer replaces characters not typically safe or allowed in SARIF Rule IDs.
// We allow alphanumeric, underscore, dot, and hyphen. Everything else is replaced by a hyphen.
var ruleIDSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// SARIFReporter implements the Reporter interface for the SARIF 2.1.0 format.
// It is thread safe.
type SARIFReporter struct {
	writer io.WriteCloser
	logger *zap.Logger
	log    *sarif.Log
	// mu protects the log structure and rulesSeen map.
	mu        sync.Mutex
	rulesSeen map[string]struct{} // Cache for rule IDs
}

// NewSARIFReporter creates a new reporter that writes SARIF output.
// The signature is updated to accept the toolVersion via dependency injection.
func NewSARIFReporter(writer io.WriteCloser, logger *zap.Logger, toolVersion string) *SARIFReporter {
	// Initialize the SARIF log structure with tool information.
	// The tool version is now passed in as an argument.
	log := &sarif.Log{
		Version: SARIFVersion,
		Schema:  SARIFSchema,
		Runs: []*sarif.Run{
			{
				// FIX: Explicitly initialize the Tool field with a pointer to sarif.Tool.
				Tool: &sarif.Tool{
					Driver: &sarif.ToolComponent{
						Name:           ToolName,
						Version:        pString(toolVersion),
						InformationURI: pString(ToolInfoURI),
						// Initialize empty slices (not nil) for proper JSON marshalling
						Rules: []*sarif.ReportingDescriptor{},
					},
				},
				// Initialize empty slices (not nil)
				Results: []*sarif.Result{},
			},
		},
	}

	return &SARIFReporter{
		writer:    writer,
		logger:    logger,
		log:       log,
		rulesSeen: make(map[string]struct{}), // Initialize the cache
	}
}

// Write converts a ResultEnvelope into one or more SARIF results and adds them to the log.
func (r *SARIFReporter) Write(result *schemas.ResultEnvelope) error {
	startTime := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	run := r.log.Runs[0]
	findingsCount := 0

	for _, finding := range result.Findings {
		ruleID := r.ensureRule(finding)

		// REFACTOR: Use flattened finding.Description and finding.VulnerabilityName fields.
		messageText := finding.Description
		if messageText == "" {
			messageText = finding.VulnerabilityName
		}

		sarifResult := &sarif.Result{
			RuleID:    ruleID,
			Message:   &sarif.Message{Text: pString(messageText)},
			Level:     sarif.Level(mapSeverityToSARIFLevel(finding.Severity)),
			Locations: r.createLocations(finding),
		}
		run.Results = append(run.Results, sarifResult)
		findingsCount++
	}

	if findingsCount > 0 {
		r.logger.Debug("Wrote findings to SARIF buffer",
			zap.Int("findings_count", findingsCount),
			zap.Duration("duration_ms", time.Since(startTime)),
		)
	}

	return nil
}

// Close finalizes the SARIF log and writes it to the output writer.
func (r *SARIFReporter) Close() error {
	startTime := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Log final statistics
	var resultsCount, rulesCount int
	if len(r.log.Runs) > 0 && r.log.Runs[0] != nil {
		resultsCount = len(r.log.Runs[0].Results)
		if r.log.Runs[0].Tool != nil && r.log.Runs[0].Tool.Driver != nil {
			rulesCount = len(r.log.Runs[0].Tool.Driver.Rules)
		}
	}

	r.logger.Info("Finalizing SARIF report",
		zap.Int("total_results", resultsCount),
		zap.Int("total_rules", rulesCount),
	)

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ") // Pretty print

	encodeErr := encoder.Encode(r.log)
	// Always attempt to close the writer, regardless of encoding success.
	closeErr := r.writer.Close()

	if encodeErr != nil {
		r.logger.Error("Failed to encode SARIF log to JSON", zap.Error(encodeErr))
		// Prioritize the encoding error as it indicates corrupted/incomplete output.
		return fmt.Errorf("failed to encode SARIF output: %w", encodeErr)
	}

	if closeErr != nil {
		r.logger.Error("Failed to close output writer", zap.Error(closeErr))
		return fmt.Errorf("failed to close output writer: %w", closeErr)
	}

	r.logger.Info("Successfully wrote SARIF report",
		zap.Duration("duration_ms", time.Since(startTime)),
	)

	return nil
}

// ensureRule checks if a rule for the finding's vulnerability type already exists.
// Implements robust sanitization for the Rule ID.
// NOTE: Must be called while holding the mutex.
func (r *SARIFReporter) ensureRule(finding schemas.Finding) string {
	// REFACTOR: Use flattened finding.VulnerabilityName field.
	baseID := finding.VulnerabilityName
	if baseID == "" {
		baseID = "Unnamed-Vulnerability"
	}

	// 1. Convert to uppercase.
	sanitizedName := strings.ToUpper(baseID)
	// 2. Sanitize invalid characters using regex.
	sanitizedName = ruleIDSanitizer.ReplaceAllString(sanitizedName, "-")
	// 3. Trim potential leading/trailing hyphens resulting from sanitization.
	sanitizedName = strings.Trim(sanitizedName, "-")

	// Robustness: Fallback for empty names after sanitization (e.g., if the name was only symbols).
	if sanitizedName == "" {
		sanitizedName = "UNKNOWN-VULNERABILITY"
	}

	ruleID := "SCALPEL-" + sanitizedName

	// O(1) Lookup
	if _, exists := r.rulesSeen[ruleID]; exists {
		return ruleID
	}

	// Rule does not exist, create it.
	r.logger.Debug("Registering new SARIF rule definition", zap.String("rule_id", ruleID))

	driver := r.log.Runs[0].Tool.Driver

	// Create enhanced Markdown help text.
	// REFACTOR: Use flattened finding.VulnerabilityName and finding.Description fields.
	markdownHelp := fmt.Sprintf("**Vulnerability:** %s\n\n**Description:**\n%s\n\n**Recommendation:**\n%s",
		finding.VulnerabilityName, finding.Description, finding.Recommendation)

	// Create a new rule.
	// REFACTOR: Use flattened finding.VulnerabilityName field.
	newRule := &sarif.ReportingDescriptor{
		ID:               ruleID,
		Name:             pString(finding.VulnerabilityName),
		ShortDescription: &sarif.MultiformatMessageString{Text: pString(finding.VulnerabilityName)},
		FullDescription:  &sarif.MultiformatMessageString{Text: pString(finding.Recommendation)},
		Help: &sarif.MultiformatMessageString{
			Text:     pString(finding.Recommendation),
			Markdown: pString(markdownHelp),
		},
		Properties: &sarif.PropertyBag{
			"tags":      []string{"security", "scalpel"},
			"precision": "high",
			// This conversion is correct and necessary to store []string in map[string]interface{}.
			"CWE": finding.CWE,
		},
	}
	driver.Rules = append(driver.Rules, newRule)
	r.rulesSeen[ruleID] = struct{}{} // Add to cache
	return ruleID
}

// createLocations converts finding details into SARIF location objects.
func (r *SARIFReporter) createLocations(finding schemas.Finding) []*sarif.Location {
	msgText := fmt.Sprintf("Vulnerability found at %s", finding.Target)

	location := &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{
				URI: pString(finding.Target),
			},
		},
		Message: &sarif.Message{
			Text: pString(msgText),
		},
	}
	return []*sarif.Location{location}
}

// mapSeverityToSARIFLevel converts Scalpel's severity to the SARIF standard.
func mapSeverityToSARIFLevel(severity schemas.Severity) string {
	switch strings.ToLower(string(severity)) {
	case "critical", "high":
		return string(sarif.LevelError)
	case "medium":
		return string(sarif.LevelWarning)
	// REFACTOR: Updated "informational" to "info" to match schemas.findings.go
	case "low", "info":
		return string(sarif.LevelNote)
	default:
		return string(sarif.LevelNote)
	}
}

// pString returns a pointer to the given string value. Helper for optional SARIF fields.
func pString(s string) *string {
	return &s
}
