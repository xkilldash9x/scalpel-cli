// internal/reporting/sarif_reporter.go
package reporting

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting/sarif"
)

// Constants for tool identification in the SARIF report.
const (
	ToolName     = "Scalpel CLI"
	ToolInfoURI  = "https://github.com/xkilldash9x/scalpel-cli"
	SARIFVersion = "2.1.0"
	SARIFSchema  = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
)

var ruleIDSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.]+`)

// --- Rule Manager ---

type RuleFingerprint string

type ruleManager struct {
	logger             *zap.Logger
	rulesByFingerprint map[RuleFingerprint]string
	ruleIDUsage        map[string]int
	driver             *sarif.ToolComponent
}

func newRuleManager(logger *zap.Logger, driver *sarif.ToolComponent) *ruleManager {
	return &ruleManager{
		logger:             logger.Named("rule_manager"),
		rulesByFingerprint: make(map[RuleFingerprint]string),
		ruleIDUsage:        make(map[string]int),
		driver:             driver,
	}
}

func (rm *ruleManager) ensureRule(rule *sarif.ReportingDescriptor) string {
	fingerprint := rm.calculateFingerprint(rule)
	if ruleID, exists := rm.rulesByFingerprint[fingerprint]; exists {
		return ruleID
	}

	baseName := rm.sanitizeRuleName(rule.Name)
	baseRuleID := "SCALPEL-" + baseName

	usageCount := rm.ruleIDUsage[baseRuleID]
	rm.ruleIDUsage[baseRuleID] = usageCount + 1

	finalRuleID := baseRuleID
	if usageCount > 0 {
		finalRuleID = fmt.Sprintf("%s-%d", baseRuleID, usageCount)
		rm.logger.Debug("Rule ID collision detected, generated new ID with suffix",
			zap.String("base_id", baseRuleID),
			zap.String("final_id", finalRuleID),
		)
	}

	rule.ID = finalRuleID
	rm.logger.Debug("Registering new SARIF rule definition", zap.String("rule_id", finalRuleID))

	rm.driver.Rules = append(rm.driver.Rules, rule)
	rm.rulesByFingerprint[fingerprint] = finalRuleID
	return finalRuleID
}

func (rm *ruleManager) calculateFingerprint(rule *sarif.ReportingDescriptor) RuleFingerprint {
	var cwes []string
	if rule.Properties != nil {
		if cweProp, ok := (*rule.Properties)["CWE"]; ok {
			if cweSlice, ok := cweProp.([]string); ok {
				cwes = cweSlice
			}
		}
	}
	sort.Strings(cwes)

	data := struct {
		Name            *string
		FullDescription *sarif.MultiformatMessageString
		Help            *sarif.MultiformatMessageString
		CWEs            []string
	}{
		Name:            rule.Name,
		FullDescription: rule.FullDescription,
		Help:            rule.Help,
		CWEs:            cwes,
	}
	h := sha1.New()
	_ = json.NewEncoder(h).Encode(data)
	return RuleFingerprint(hex.EncodeToString(h.Sum(nil)))
}

func (rm *ruleManager) sanitizeRuleName(name *string) string {
	if name == nil || *name == "" {
		return "UNNAMED-VULNERABILITY"
	}
	sanitizedName := strings.ToUpper(*name)
	sanitizedName = ruleIDSanitizer.ReplaceAllString(sanitizedName, "-")
	sanitizedName = strings.Trim(sanitizedName, "-")
	if sanitizedName == "" {
		return "UNKNOWN-VULNERABILITY"
	}
	return sanitizedName
}

// --- SARIF Converter ---

type sarifConverter struct{}

func newSarifConverter() *sarifConverter {
	return &sarifConverter{}
}

func (c *sarifConverter) toRule(finding schemas.Finding) *sarif.ReportingDescriptor {
	markdownHelp := fmt.Sprintf("**Vulnerability:** %s\n\n**Description:**\n%s\n\n**Recommendation:**\n%s",
		finding.VulnerabilityName, finding.Description, finding.Recommendation)

	// We use pStringRequired for fields that are mandatory in the struct (like Text)
	// but might be empty in our data, to avoid nil pointer dereferences.
	return &sarif.ReportingDescriptor{
		Name:             pString(finding.VulnerabilityName),
		ShortDescription: &sarif.MultiformatMessageString{Text: pStringRequired(finding.VulnerabilityName)},
		FullDescription:  &sarif.MultiformatMessageString{Text: pStringRequired(finding.Description)},
		Help: &sarif.MultiformatMessageString{
			Text:     pStringRequired(finding.Recommendation),
			Markdown: pString(markdownHelp),
		},
		Properties: &sarif.PropertyBag{
			"tags":      []string{"security", "scalpel"},
			"precision": "high",
			"CWE":       finding.CWE,
		},
	}
}

func (c *sarifConverter) toResult(finding schemas.Finding, ruleID string) *sarif.Result {
	messageText := finding.Description
	if messageText == "" {
		messageText = finding.VulnerabilityName
	}

	return &sarif.Result{
		RuleID:    ruleID,
		Message:   &sarif.Message{Text: pStringRequired(messageText)},
		Level:     sarif.Level(c.mapSeverityToSARIFLevel(finding.Severity)),
		Locations: c.createLocations(finding),
	}
}

func (c *sarifConverter) createLocations(finding schemas.Finding) []*sarif.Location {
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

func (c *sarifConverter) mapSeverityToSARIFLevel(severity schemas.Severity) string {
	switch strings.ToLower(string(severity)) {
	case "critical", "high":
		return string(sarif.LevelError)
	case "medium":
		return string(sarif.LevelWarning)
	case "low", "info":
		return string(sarif.LevelNote)
	default:
		return string(sarif.LevelNote)
	}
}

// --- SARIF Reporter ---

type SARIFReporter struct {
	writer    io.WriteCloser
	logger    *zap.Logger
	log       *sarif.Log
	mu        sync.Mutex
	rules     *ruleManager
	converter *sarifConverter
}

func NewSARIFReporter(writer io.WriteCloser, toolVersion string) *SARIFReporter {
	logger := observability.GetLogger().Named("sarif_reporter")
	driver := &sarif.ToolComponent{
		Name:           ToolName,
		Version:        pString(toolVersion),
		InformationURI: pString(ToolInfoURI),
		Rules:          []*sarif.ReportingDescriptor{},
	}
	log := &sarif.Log{
		Version: SARIFVersion,
		Schema:  SARIFSchema,
		Runs: []*sarif.Run{
			{
				Tool:    &sarif.Tool{Driver: driver},
				Results: []*sarif.Result{},
			},
		},
	}

	return &SARIFReporter{
		writer:    writer,
		logger:    logger,
		log:       log,
		rules:     newRuleManager(logger, driver),
		converter: newSarifConverter(),
	}
}

func (r *SARIFReporter) Write(result *schemas.ResultEnvelope) error {
	startTime := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	run := r.log.Runs[0]
	findingsCount := 0

	for _, finding := range result.Findings {
		rule := r.converter.toRule(finding)
		ruleID := r.rules.ensureRule(rule)
		sarifResult := r.converter.toResult(finding, ruleID)

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

func (r *SARIFReporter) Close() error {
	startTime := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

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
	encoder.SetIndent("", "  ")

	encodeErr := encoder.Encode(r.log)
	closeErr := r.writer.Close()

	if encodeErr != nil {
		r.logger.Error("Failed to encode SARIF log to JSON", zap.Error(encodeErr))
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

// pString returns a pointer to the string, or nil if empty.
// Use this for optional fields where empty means "omit".
func pString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// pStringRequired returns a pointer to the string, even if empty.
// Use this for required fields like 'text' in Message objects.
func pStringRequired(s string) *string {
	return &s
}
