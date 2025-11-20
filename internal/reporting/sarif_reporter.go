// internal/reporting/sarif_reporter.go
package reporting

import (
	// Added imports for fingerprinting (Bug 1)
	"crypto/sha1"
	"encoding/hex"
	"sort"

	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"

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
// FIX (Bug 3): We allow alphanumeric, underscore, and dot. Everything else (including hyphens) is replaced
// by a single hyphen, collapsing consecutive sequences.
var ruleIDSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.]+`)

// RuleFingerprint is used to uniquely identify a rule definition based on its content.
// (Implementation for Bug 1)
type RuleFingerprint string

// calculateFingerprint generates a unique hash for the defining characteristics of a finding.
func calculateFingerprint(finding schemas.Finding) RuleFingerprint {
	// Sort CWEs to ensure consistent hashing regardless of input order.
	sortedCWEs := append([]string(nil), finding.CWE...)
	sort.Strings(sortedCWEs)

	data := struct {
		Name           string
		Description    string
		Recommendation string
		CWEs           []string
	}{
		Name:           finding.VulnerabilityName,
		Description:    finding.Description,
		Recommendation: finding.Recommendation,
		CWEs:           sortedCWEs,
	}

	// Use SHA1 to hash the structure.
	h := sha1.New()
	// Encoding errors are highly unlikely for this simple struct.
	_ = json.NewEncoder(h).Encode(data)
	return RuleFingerprint(hex.EncodeToString(h.Sum(nil)))
}

// SARIFReporter implements the Reporter interface for the SARIF 2.1.0 format.
// It is thread safe.
type SARIFReporter struct {
	writer io.WriteCloser
	logger *zap.Logger
	log    *sarif.Log
	// mu protects the log structure and the maps.
	mu sync.Mutex
	// rulesByFingerprint maps a content fingerprint to the generated Rule ID. (Bug 1)
	rulesByFingerprint map[RuleFingerprint]string
	// ruleIDUsage tracks how many times a base Rule ID has been used, to handle collisions. (Bug 1)
	ruleIDUsage map[string]int
}

// NewSARIFReporter creates a new reporter that writes SARIF output.
// The signature is updated to accept the toolVersion via dependency injection.
func NewSARIFReporter(writer io.WriteCloser, toolVersion string) *SARIFReporter {
	logger := observability.GetLogger().Named("sarif_reporter")
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
		writer:             writer,
		logger:             logger,
		log:                log,
		rulesByFingerprint: make(map[RuleFingerprint]string),
		ruleIDUsage:        make(map[string]int),
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

// sanitizeRuleName creates a standardized base name for the rule ID. (Refactored for Bug 1)
func (r *SARIFReporter) sanitizeRuleName(name string) string {
	if name == "" {
		return "UNNAMED-VULNERABILITY"
	}

	// 1. Convert to uppercase.
	sanitizedName := strings.ToUpper(name)
	// 2. Sanitize invalid characters and collapse sequences using regex. (Relies on Bug 3 fix)
	sanitizedName = ruleIDSanitizer.ReplaceAllString(sanitizedName, "-")
	// 3. Trim potential leading/trailing hyphens resulting from sanitization.
	sanitizedName = strings.Trim(sanitizedName, "-")

	// Robustness: Fallback for empty names after sanitization (e.g., if the name was only symbols).
	if sanitizedName == "" {
		return "UNKNOWN-VULNERABILITY"
	}
	return sanitizedName
}

// ensureRule ensures a unique rule definition exists for the finding and returns its ID.
// (Rewritten for Bug 1, incorporates Bug 2 fix)
// NOTE: Must be called while holding the mutex.
func (r *SARIFReporter) ensureRule(finding schemas.Finding) string {
	// 1. Check if we have already seen this exact rule definition (Bug 1).
	fingerprint := calculateFingerprint(finding)
	if ruleID, exists := r.rulesByFingerprint[fingerprint]; exists {
		return ruleID
	}

	// 2. This is a new rule definition. Generate a unique Rule ID (Bug 1).
	baseName := r.sanitizeRuleName(finding.VulnerabilityName)
	baseRuleID := "SCALPEL-" + baseName

	// Track usage to generate suffixes if necessary.
	usageCount := r.ruleIDUsage[baseRuleID]
	r.ruleIDUsage[baseRuleID] = usageCount + 1

	finalRuleID := baseRuleID
	if usageCount > 0 {
		// If the base ID has already been used (by a different fingerprint), append a suffix.
		finalRuleID = fmt.Sprintf("%s-%d", baseRuleID, usageCount)
		r.logger.Debug("Rule ID collision detected, generated new ID with suffix",
			zap.String("base_id", baseRuleID),
			zap.String("final_id", finalRuleID),
		)
	}

	// 3. Register the new rule.
	r.logger.Debug("Registering new SARIF rule definition", zap.String("rule_id", finalRuleID))

	driver := r.log.Runs[0].Tool.Driver

	// Create enhanced Markdown help text.
	// REFACTOR: Use flattened finding.VulnerabilityName and finding.Description fields.
	markdownHelp := fmt.Sprintf("**Vulnerability:** %s\n\n**Description:**\n%s\n\n**Recommendation:**\n%s",
		finding.VulnerabilityName, finding.Description, finding.Recommendation)

	// Create a new rule.
	// REFACTOR: Use flattened finding.VulnerabilityName field.
	newRule := &sarif.ReportingDescriptor{
		ID:               finalRuleID,
		Name:             pString(finding.VulnerabilityName),
		ShortDescription: &sarif.MultiformatMessageString{Text: pString(finding.VulnerabilityName)},
		// FIX (Bug 2): Use Description for FullDescription, not Recommendation.
		FullDescription: &sarif.MultiformatMessageString{Text: pString(finding.Description)},
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
	r.rulesByFingerprint[fingerprint] = finalRuleID // Map fingerprint to the final ID
	return finalRuleID
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
