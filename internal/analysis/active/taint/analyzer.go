// -- internal/analysis/active/timeslip/analyzer.go --
package timeslip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// Analyzer orchestrates the TimeSlip module, managing strategy execution and result analysis.
type Analyzer struct {
	ScanID   uuid.UUID
	config   *Config
	logger   *zap.Logger
	reporter core.Reporter
}

// NewAnalyzer initializes the TimeSlip Analyzer.
// The signature is updated to return an error if the configuration, like its regex patterns, is invalid.
func NewAnalyzer(scanID uuid.UUID, config *Config, logger *zap.Logger, reporter core.Reporter) (*Analyzer, error) {
	if logger == nil {
		// This is a safety net. If no logger is provided, we use a no-op one
		// so we don't have to deal with nil pointer panics down the line.
		logger = observability.GetLogger().Named("timeslip_analyzer_nop")
	}
	log := logger.Named("timeslip_analyzer")

	if config == nil {
		// Provide a safe default configuration if none is supplied.
		log.Info("Configuration missing, using default TimeSlip settings.")
		config = &Config{
			Concurrency: 20,
			Timeout:     15 * time.Second,
			ThresholdMs: 500,
		}
	}

	// Configuration validation is key.
	if config.Concurrency < 2 {
		log.Warn("Concurrency must be at least 2 for race condition testing. Adjusting to minimum.", zap.Int("configured_concurrency", config.Concurrency))
		config.Concurrency = 2
	}

	// We'll try to initialize the Oracle here just to validate the configuration (especially the regexes).
	// The actual Oracle used during the analysis will be specific to the candidate type (GraphQL or not).
	_, err := NewSuccessOracle(config, false) // Test with standard HTTP config
	if err != nil {
		log.Error("Invalid TimeSlip configuration detected during initialization.", zap.Error(err))
		return nil, err
	}

	return &Analyzer{
		ScanID:   scanID,
		config:   config,
		logger:   log,
		reporter: reporter,
	}, nil
}

// Analyze executes the analysis pipeline against a specific candidate request.
func (a *Analyzer) Analyze(ctx context.Context, candidate *RaceCandidate) error {
	a.logger.Info("Starting TimeSlip analysis",
		zap.String("url", candidate.URL),
		zap.String("method", candidate.Method),
		zap.Int("concurrency", a.config.Concurrency))

	// Initialize the SuccessOracle specific to this candidate which handles the IsGraphQL flag.
	oracle, err := NewSuccessOracle(a.config, candidate.IsGraphQL)
	if err != nil {
		// This indicates an internal inconsistency.
		a.logger.Error("Internal Error: Failed to initialize SuccessOracle despite prior validation.", zap.Error(err))
		return fmt.Errorf("internal error initializing SuccessOracle: %w", err)
	}

	strategies := a.determineStrategies(candidate)

	for _, strategy := range strategies {
		// Check for context cancellation before kicking off a new strategy.
		if ctx.Err() != nil {
			a.logger.Info("TimeSlip analysis cancelled", zap.Error(ctx.Err()))
			return ctx.Err()
		}

		a.logger.Debug("Executing strategy", zap.String("strategy", string(strategy)))

		var result *RaceResult
		var execErr error

		// Execute the selected strategy, passing the configuration and the oracle.
		switch strategy {
		case H1Concurrent:
			result, execErr = ExecuteH1Concurrent(ctx, candidate, a.config, oracle)
		case H1SingleByteSend:
			result, execErr = ExecuteH1SingleByteSend(ctx, candidate, a.config, oracle)
		case H2Multiplexing:
			result, execErr = ExecuteH2Multiplexing(ctx, candidate, a.config, oracle)
		case AsyncGraphQL:
			result, execErr = ExecuteGraphQLAsync(ctx, candidate, a.config, oracle)
		}

		if execErr != nil {
			// If a strategy fails, we need to know why so we can decide whether to continue.
			if errors.Is(execErr, ErrH2Unsupported) || errors.Is(execErr, ErrPipeliningRejected) {
				a.logger.Info("Strategy not supported by target or intermediate proxy.", zap.String("strategy", string(strategy)), zap.Error(execErr))
			} else if errors.Is(execErr, ErrTargetUnreachable) {
				a.logger.Warn("Strategy failed due to target being unreachable or timing out.", zap.String("strategy", string(strategy)), zap.Error(execErr))
				// Could consider breaking here if the target seems completely down.
			} else if errors.Is(execErr, ErrConfigurationError) || errors.Is(execErr, ErrPayloadMutationFail) {
				a.logger.Error("Strategy failed due to configuration or payload issues. Halting analysis for this candidate.", zap.String("strategy", string(strategy)), zap.Error(execErr))
				break // Stop analysis for this candidate if the input or config is just plain wrong.
			} else {
				a.logger.Warn("Strategy execution encountered an unexpected error.", zap.String("strategy", string(strategy)), zap.Error(execErr))
			}
			continue // Try the next strategy.
		}

		// Analyze the results.
		analysis := AnalyzeResults(result, a.config)

		// Report findings if vulnerable or if confidence indicates an informational finding (>= 0.3).
		if analysis.Vulnerable || analysis.Confidence >= 0.3 {
			a.logger.Info("Race condition indicator detected",
				zap.Float64("confidence", analysis.Confidence),
				zap.Bool("vulnerable", analysis.Vulnerable),
				zap.String("details", analysis.Details))

			// Report the finding (handles both vulnerable and informational).
			a.reportFinding(candidate, analysis, result)

			// Optimization: If Confidence is 1.0 (a confirmed TOCTOU) and it is vulnerable, we can stop further analysis.
			if analysis.Vulnerable && analysis.Confidence == 1.0 {
				a.logger.Info("Critical TOCTOU detected (Confidence 1.0). Halting further strategies.")
				break
			}
		}
	}

	return nil
}

// determineStrategies selects the appropriate attack strategies based on the candidate characteristics.
func (a *Analyzer) determineStrategies(candidate *RaceCandidate) []RaceStrategy {
	// GraphQL endpoints get a specialized strategy all to themselves.
	if candidate.IsGraphQL {
		return []RaceStrategy{AsyncGraphQL}
	}

	// For standard HTTP endpoints, we attempt all applicable strategies in order of preference.
	return []RaceStrategy{
		H2Multiplexing,   // Preferred for efficiency if the target supports it.
		H1SingleByteSend, // The most precise technique for HTTP/1.1.
		H1Concurrent,     // The classic brute force fallback.
	}
}

// TimeSlipEvidence provides structured data for race condition findings.
type TimeSlipEvidence struct {
	Strategy        RaceStrategy              `json:"strategy"`
	TotalDurationMs int64                     `json:"total_duration_ms"`
	Statistics      ResponseStatistics        `json:"statistics"`
	SampleResponses []core.SerializedResponse `json:"sample_responses"`
}

// reportFinding formats the vulnerability details and publishes them via the core reporter interface.
func (a *Analyzer) reportFinding(candidate *RaceCandidate, analysis *AnalysisResult, result *RaceResult) {
	title := fmt.Sprintf("Race Condition Detected (%s)", analysis.Strategy)
	description := analysis.Details

	// Initialize CWEs and vulnerability description
	var cwes []string
	vulnDescription := "The application processes concurrent requests in a way that leads to an inconsistent or exploitable state, violating intended synchronization or atomicity."

	// Determine severity based on the Confidence Score and Vulnerability status.
	var severity schemas.Severity

	if analysis.Vulnerable {
		cweGeneric := "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"

		if analysis.Confidence == 1.0 {
			severity = schemas.SeverityCritical
			title = fmt.Sprintf("Critical TOCTOU Race Condition Detected (%s)", analysis.Strategy)
			cwes = append(cwes, "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition")
		} else if analysis.Confidence >= 0.8 {
			severity = schemas.SeverityHigh
			cwes = append(cwes, cweGeneric)
		} else if analysis.Confidence >= 0.6 {
			severity = schemas.SeverityMedium
			cwes = append(cwes, cweGeneric)
		} else {
			severity = schemas.SeverityLow
			cwes = append(cwes, cweGeneric)
		}
	} else {
		// Informational findings (e.g., timing anomalies, Confidence >= 0.3 but Vulnerable=false)
		severity = schemas.SeverityInformational
		title = fmt.Sprintf("Informational: Concurrency Anomaly Detected (%s)", analysis.Strategy)
		vulnDescription = "Observed behavior suggests potential resource contention or sequential locking under load, but a direct security vulnerability was not confirmed."
		cwes = append(cwes, "CWE-362") // Contextual CWE
	}

	// Compile all the juicy evidence.
	evidenceData := TimeSlipEvidence{
		Strategy:        analysis.Strategy,
		TotalDurationMs: result.Duration.Milliseconds(),
		Statistics:      analysis.Stats,
		SampleResponses: a.sampleUniqueResponses(result.Responses),
	}

	// Marshal evidence. Use MarshalIndent for better readability in reports.
	evidenceBytes, err := json.MarshalIndent(evidenceData, "", "  ")
	if err != nil {
		a.logger.Error("Failed to marshal evidence data", zap.Error(err))
		// Fallback if marshalling fails.
		evidenceBytes = []byte(fmt.Sprintf("{\"error\": \"Failed to serialize evidence: %v\"}", err))
	}

	// Define the vulnerability details (using the schemas.Vulnerability struct).
	vulnerability := schemas.Vulnerability{
		Name:        title,
		Description: vulnDescription,
	}

	finding := schemas.Finding{
		ID:             uuid.NewString(),
		Timestamp:      time.Now().UTC(),
		Target:         candidate.URL,
		Module:         "TimeSlipAnalyzer",
		Vulnerability:  vulnerability, // Use the struct
		Severity:       severity,
		Description:    description,
		Evidence:       string(evidenceBytes), // Use the string representation
		Recommendation: "Implement proper synchronization mechanisms such as atomic transactions, database constraints (e.g., uniqueness constraints), or pessimistic/optimistic locking to ensure operations on shared resources are processed safely and consistently.",
		CWE:            cwes, // Use the slice
	}

	// If a reporter is configured, this is where we use it.
	if a.reporter != nil {
		// Let's get this finding packaged up for delivery in a ResultEnvelope.
		// The envelope provides scan-level context around the individual finding.
		envelope := &schemas.ResultEnvelope{
			Timestamp: time.Now().UTC(),
			ScanID:    a.ScanID.String(),
			Findings:  []schemas.Finding{finding},
		}

		// Fire it off to the reporter. If something goes wrong, we need to log it
		// so we don't silently fail to report a vulnerability.
		if err := a.reporter.Write(envelope); err != nil {
			a.logger.Error("Failed to report finding via reporter",
				zap.String("finding_id", finding.ID),
				zap.Error(err),
			)
		}
	}
}

// sampleUniqueResponses selects a representative sample of unique responses for the evidence report.
func (a *Analyzer) sampleUniqueResponses(responses []*RaceResponse) []core.SerializedResponse {
	samples := make([]core.SerializedResponse, 0)
	maxSamples := 5
	sampledFingerprints := make(map[string]bool)

	for _, resp := range responses {
		if len(samples) >= maxSamples {
			break
		}

		// Skip if we already sampled this fingerprint, or if the response is invalid or errored out.
		if resp.Fingerprint == "" || sampledFingerprints[resp.Fingerprint] || resp.ParsedResponse == nil || resp.Error != nil {
			continue
		}

		// SpecificBody holds the relevant data for both standard and batched GraphQL responses.
		bodyStr := string(resp.SpecificBody)

		const maxBodyLen = 1024
		if len(bodyStr) > maxBodyLen {
			originalByteLen := len(bodyStr)
			endIndex := maxBodyLen

			// Ensure we don't slice in the middle of a UTF-8 character.
			// If the byte at endIndex is not the start of a rune (i.e., it's a continuation byte), backtrack.
			// Indexing a string (bodyStr[endIndex]) yields the byte value.
			for ; endIndex > 0 && !utf8.RuneStart(bodyStr[endIndex]); endIndex-- {
				// Backtrack until we find the start of a rune.
			}

			// If endIndex is 0, the first rune is longer than maxBodyLen; we truncate it entirely.
			truncatedBody := bodyStr[:endIndex]

			// Create a more informative suffix.
			suffix := fmt.Sprintf("... [TRUNCATED - %d bytes omitted]", originalByteLen-len(truncatedBody))
			bodyStr = truncatedBody + suffix
		}

		samples = append(samples, core.SerializedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       bodyStr,
		})
		sampledFingerprints[resp.Fingerprint] = true
	}
	return samples
}