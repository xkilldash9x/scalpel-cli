// internal/analysis/active/timeslip/analyzer.go
package timeslip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// Define the standard deviation multiplier threshold for timing anomalies.
const timingAnomalyStdDevThreshold = 3.0

// This var block holds the strategy execution functions. By making them variables,
// we can replace them in our tests to mock their behavior without actually
// executing them. This is key to fixing the "cannot assign to" error.
var (
	executeH1Concurrent     = ExecuteH1Concurrent     // Takes logger
	executeH1SingleByteSend = ExecuteH1SingleByteSend // Takes logger
	executeH2Multiplexing   = ExecuteH2Multiplexing   // Takes logger
	executeH2Dependency     = ExecuteH2Dependency     // Takes logger
	executeGraphQLAsync     = ExecuteGraphQLAsync     // Takes logger
)

// Analyzer orchestrates the TimeSlip module, managing strategy execution and result analysis.
type Analyzer struct {
	ScanID   uuid.UUID
	config   *Config
	logger   *zap.Logger
	reporter core.Reporter

	// testOnlyHTTP1 is a flag for forcing HTTP/1 strategies in tests.
	testOnlyHTTP1 bool
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

// UseHTTP1OnlyForTests is a test helper to disable H2 strategies.
func (a *Analyzer) UseHTTP1OnlyForTests() {
	a.testOnlyHTTP1 = true
	a.logger.Warn("Forcing HTTP/1 strategies for testing purposes.")
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
		// These now call the package-level variables, enabling mocks.
		switch strategy {
		case H1Concurrent:
			result, execErr = executeH1Concurrent(ctx, candidate, a.config, oracle, a.logger.Named("h1_concurrent"))
		case H1SingleByteSend:
			result, execErr = executeH1SingleByteSend(ctx, candidate, a.config, oracle, a.logger.Named("h1_singlebyte"))
		case H2Multiplexing:
			result, execErr = executeH2Multiplexing(ctx, candidate, a.config, oracle, a.logger.Named("h2_multiplex"))
		case H2Dependency:
			result, execErr = executeH2Dependency(ctx, candidate, a.config, oracle, a.logger.Named("h2_dependency"))
		case AsyncGraphQL:
			result, execErr = executeGraphQLAsync(ctx, candidate, a.config, oracle, a.logger.Named("graphql_async"))
		}

		if execErr != nil {
			// If a strategy fails, we need to know why so we can decide whether to continue.
			// Added ErrH2FrameError to the list of recoverable errors.
			if errors.Is(execErr, ErrH2Unsupported) || errors.Is(execErr, ErrPipeliningRejected) || errors.Is(execErr, ErrH2FrameError) {
				a.logger.Info("Strategy not supported by target or encountered protocol error.", zap.String("strategy", string(strategy)), zap.Error(execErr))
			} else if errors.Is(execErr, ErrTargetUnreachable) {
				// Allow stress tests to continue even if target is unreachable under load
				if ctx.Err() != nil {
					return ctx.Err()
				}
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
		analysis := a.analyzeResults(result, a.config)

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

	// Test hook to force H1 strategies.
	if a.testOnlyHTTP1 {
		return []RaceStrategy{
			// H1Concurrent *must* run first in tests, as it's the only H1 strategy
			// that accurately measures individual response durations, which is
			// required for the timing anomaly heuristic in the patched E2E test.
			H1Concurrent,
			H1SingleByteSend,
		}
	}
	// For standard HTTP endpoints, we attempt all applicable strategies in order of preference (most precise first).
	return []RaceStrategy{
		H2Dependency,     // Preferred: Offers the tightest synchronization if H2 is supported.
		H2Multiplexing,   // Efficient H2 strategy.
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
		// We require a ParsedResponse to extract details, and we skip explicit errors.
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
			// Indexing a string (bodyStr[endIndex]) yields the byte value.
			for ; endIndex > 0 && endIndex < len(bodyStr) && !utf8.RuneStart(bodyStr[endIndex]); endIndex-- {
				// Backtrack until we find the start of a rune.
			}

			// Handle edge case where backtracking might go past the start or end
			if endIndex > len(bodyStr) {
				endIndex = len(bodyStr)
			} else if endIndex < 0 {
				endIndex = 0
			}

			// If endIndex is 0, the first rune might be longer than maxBodyLen; we truncate it entirely if needed.
			truncatedBody := bodyStr[:endIndex]

			// Create a more informative suffix.
			suffix := fmt.Sprintf("... [TRUNCATED - %d bytes omitted]", originalByteLen-len(truncatedBody))
			bodyStr = truncatedBody + suffix
		}

		// Handle cases where StatusCode might be 0 (e.g., synthetic responses for H2 RST_STREAM)
		statusCode := 0
		if resp.ParsedResponse != nil {
			statusCode = resp.ParsedResponse.StatusCode
		}

		samples = append(samples, core.SerializedResponse{
			StatusCode: statusCode,
			Headers:    resp.ParsedResponse.Headers,
			Body:       bodyStr,
		})
		sampledFingerprints[resp.Fingerprint] = true
	}
	return samples
}

// analyzeResults is the core logic for processing the raw results of a race attempt.
func (a *Analyzer) analyzeResults(result *RaceResult, config *Config) *AnalysisResult {
	analysis := &AnalysisResult{
		Strategy:        result.Strategy,
		UniqueResponses: make(map[string]int),
	}

	if len(result.Responses) == 0 {
		analysis.Details = "No responses received."
		return analysis
	}

	validResponses := a.prepareAndAggregate(result, analysis)

	if len(validResponses) == 0 {
		analysis.Details = fmt.Sprintf("All %d requests resulted in errors or unprocessable responses.", len(result.Responses))
		return analysis
	}

	if len(validResponses) > 1 {
		analysis.Stats = a.calculateStatistics(validResponses)
	}

	for _, heuristic := range heuristicsPipeline {
		if heuristic(result, config, analysis) {
			break
		}
	}

	if analysis.Details == "" {
		analysis.Details = "No clear indication of a race condition vulnerability found."
		if analysis.Stats.StdDevMs > 0 && analysis.Stats.AvgDurationMs > 50 && (analysis.Stats.StdDevMs/analysis.Stats.AvgDurationMs) > 0.3 {
			analysis.Confidence = 0.1
			analysis.Details += fmt.Sprintf(" Note: High standard deviation observed (%.2fms).", analysis.Stats.StdDevMs)
		}
	}

	return analysis
}

// prepareAndAggregate filters valid responses and counts successes/unique fingerprints.
func (a *Analyzer) prepareAndAggregate(result *RaceResult, analysis *AnalysisResult) []*RaceResponse {
	validResponses := make([]*RaceResponse, 0, len(result.Responses))

	for _, resp := range result.Responses {
		// Check for errors or invalid responses (e.g. missing ParsedResponse)
		if resp.Error != nil || resp.ParsedResponse == nil {
			continue
		}

		// Specific check for responses that might lack a fingerprint (should be rare if ParsedResponse exists)
		if resp.Fingerprint == "" {
			continue
		}

		// Specific check for H2 RST_STREAM responses (StatusCode 0) - these are handled as errors upstream but filtered here too.
		if resp.ParsedResponse.StatusCode == 0 {
			continue
		}

		validResponses = append(validResponses, resp)
		analysis.UniqueResponses[resp.Fingerprint]++

		if resp.IsSuccess {
			analysis.SuccessCount++
		}
	}
	return validResponses
}

// calculateStatistics computes Min, Max, Avg, Median, and Standard Deviation of response durations.
func (a *Analyzer) calculateStatistics(responses []*RaceResponse) ResponseStatistics {
	durationsMs := make([]int64, 0, len(responses))

	for _, resp := range responses {
		// Accessing Duration from the correct nested struct and ignoring zero values.
		if resp.ParsedResponse != nil && resp.ParsedResponse.Duration > 0 {
			durationsMs = append(durationsMs, resp.ParsedResponse.Duration.Milliseconds())
		}
	}

	if len(durationsMs) < 2 {
		return ResponseStatistics{}
	}

	sort.Slice(durationsMs, func(i, j int) bool {
		return durationsMs[i] < durationsMs[j]
	})

	stats := ResponseStatistics{
		Count:         len(durationsMs), // Populate the count for statistical analysis.
		MinDurationMs: durationsMs[0],
		MaxDurationMs: durationsMs[len(durationsMs)-1],
	}
	stats.TimingDeltaMs = stats.MaxDurationMs - stats.MinDurationMs

	var sum int64
	for _, d := range durationsMs {
		sum += d
	}
	stats.AvgDurationMs = float64(sum) / float64(len(durationsMs))

	// Calculate Median
	n := len(durationsMs)
	if n%2 == 0 {
		stats.MedDurationMs = float64(durationsMs[n/2-1]+durationsMs[n/2]) / 2.0
	} else {
		stats.MedDurationMs = float64(durationsMs[n/2])
	}

	// Calculate Standard Deviation
	var varianceSum float64
	for _, d := range durationsMs {
		varianceSum += math.Pow(float64(d)-stats.AvgDurationMs, 2)
	}
	variance := varianceSum / float64(len(durationsMs))
	stats.StdDevMs = math.Sqrt(variance)

	return stats
}

// analysisHeuristic defines a function that checks for a specific indicator of a race condition.
type analysisHeuristic func(result *RaceResult, config *Config, analysis *AnalysisResult) bool

// The order and logic of the pipeline is crucial for correct analysis.
// We check for the strongest signals (TOCTOU) first and weakest (timing) last.
var heuristicsPipeline = []analysisHeuristic{
	checkTOCTOU,
	checkTimingAnomalies, // <-- Moved up
	checkDifferentialState,
	checkStateFlutter,
}

// -- Heuristics --

func checkTOCTOU(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	expectedSuccesses := 1
	if config.ExpectedSuccesses > 0 {
		expectedSuccesses = config.ExpectedSuccesses
	}

	if analysis.SuccessCount > expectedSuccesses {
		analysis.Vulnerable = true
		analysis.Confidence = 1.0
		analysis.Details = fmt.Sprintf("VULNERABLE: Confirmed TOCTOU race condition. %d operations succeeded (expected <= %d).", analysis.SuccessCount, expectedSuccesses)

		if len(analysis.UniqueResponses) > 1 {
			analysis.Details += " Differential responses observed."
		}
		return true
	}
	return false
}

func checkDifferentialState(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	if len(analysis.UniqueResponses) > 1 && analysis.SuccessCount >= 1 {
		analysis.Vulnerable = true
		analysis.Confidence = 0.8
		analysis.Details = fmt.Sprintf("VULNERABLE: Differential responses detected (%d unique responses) including successful operations. Indicates inconsistent state during concurrent processing.", len(analysis.UniqueResponses))
		return true
	}
	return false
}

func checkStateFlutter(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	if len(analysis.UniqueResponses) > 1 && analysis.SuccessCount == 0 {
		// This is a key change. If there's a significant timing delta or high variation,
		// we should not classify this as a "State Flutter". Instead, we should fall through
		// to the timing anomaly heuristic, which is a better fit for that scenario.

		// Calculate the Coefficient of Variation (CoV) = StdDev / Mean.
		coefficientOfVariation := 0.0
		if analysis.Stats.AvgDurationMs > 0 {
			coefficientOfVariation = analysis.Stats.StdDevMs / analysis.Stats.AvgDurationMs
		}

		// If CoV is high (e.g. > 0.5) OR the simple delta threshold is met, defer to timing analysis.
		const highVariationThreshold = 0.5
		isHighVariation := coefficientOfVariation > highVariationThreshold
		isLargeDelta := config.ThresholdMs > 0 && analysis.Stats.TimingDeltaMs > int64(config.ThresholdMs)

		if isHighVariation || isLargeDelta {
			return false // Defer to the timing anomaly heuristic.
		}

		analysis.Vulnerable = true
		analysis.Confidence = 0.6
		// Update details to include CoV for better context.
		analysis.Details = fmt.Sprintf("VULNERABLE: State flutter detected. %d unique failure responses observed with low timing variation (CoV: %.2f). Indicates unstable state under concurrency.", len(analysis.UniqueResponses), coefficientOfVariation)
		return true
	}
	return false
}

// checkTimingAnomalies analyzes response times using statistical outlier detection.
func checkTimingAnomalies(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	// Timing anomalies are unreliable for strategies where individual request timing is obscured or artificial.
	// H2Dependency timing is not measured per request in the current implementation.
	if result.Strategy == AsyncGraphQL || result.Strategy == H2Dependency {
		return false
	}

	stats := analysis.Stats

	// We need a minimum number of data points for meaningful statistics (e.g. 5).
	minDataPoints := 5
	if stats.Count < minDataPoints {
		// Fallback to legacy threshold check if not enough data for stats, but enough for a simple delta.
		if config.ThresholdMs > 0 && stats.TimingDeltaMs > int64(config.ThresholdMs) && stats.Count >= 2 {
			analysis.Vulnerable = false
			analysis.Confidence = 0.2 // Low confidence due to insufficient data.
			analysis.Details = fmt.Sprintf("INFO: Timing delta detected (%dms), but insufficient data (%d points) for robust statistical analysis.", stats.TimingDeltaMs, stats.Count)
			return true
		}
		return false
	}

	// IMPROVEMENT: Heuristic 1: Outlier Detection (Bimodal distribution indicator)
	// A true race often manifests as N-1 fast responses and 1 slow response (the one that acquired the lock).

	// Basic noise filtering: If StdDev or Median is very low, timing analysis is unreliable.
	const minStdDevMs = 10.0
	const minMedianMs = 20.0

	if stats.StdDevMs >= minStdDevMs && stats.MedDurationMs >= minMedianMs {
		// Calculate the upper bound: Median + (Threshold * StdDev).
		upperBound := stats.MedDurationMs + (timingAnomalyStdDevThreshold * stats.StdDevMs)

		// Check if the maximum duration significantly exceeds this bound.
		if float64(stats.MaxDurationMs) > upperBound {
			// Strong signal detected. Verify the distribution (looking for bimodal pattern).
			outliers := 0
			// We iterate over responses again to count outliers, as stats only holds aggregates.
			for _, resp := range result.Responses {
				if resp.Error == nil && resp.ParsedResponse != nil && resp.ParsedResponse.Duration > 0 {
					if float64(resp.ParsedResponse.Duration.Milliseconds()) > upperBound {
						outliers++
					}
				}
			}

			// If only a small fraction of requests are outliers (e.g., 1-2 requests, or < 15%), it strongly suggests a lock-wait.
			if outliers > 0 && (outliers <= 2 || float64(outliers)/float64(stats.Count) < 0.15) {
				analysis.Vulnerable = false
				analysis.Confidence = 0.4 // Stronger signal than simple delta (0.3).

				analysis.Details = fmt.Sprintf(
					"INFO: Significant timing anomaly (Lock-Wait pattern) detected. %d/%d response(s) were statistical outliers (>%.1f SDs from median). Median: %.0fms, Max: %dms. Suggests sequential locking or significant resource contention.",
					outliers, stats.Count, timingAnomalyStdDevThreshold, stats.MedDurationMs, stats.MaxDurationMs)

				// If the distribution is clearly bimodal (e.g., only 1 outlier among many requests), the confidence increases.
				if outliers == 1 && stats.Count >= 10 {
					analysis.Confidence = 0.5
					analysis.Details += " Bimodal distribution strongly suggests serialization."
				}
				return true
			}
		}
	}

	// Heuristic 2: Fallback to simple delta threshold (Legacy check)
	if config.ThresholdMs > 0 && stats.TimingDeltaMs > int64(config.ThresholdMs) {
		analysis.Vulnerable = false
		analysis.Confidence = 0.3
		analysis.Details = fmt.Sprintf("INFO: Significant timing delta detected (%dms) exceeds threshold. Suggests resource contention or sequential locking.", stats.TimingDeltaMs)
		return true
	}
	return false
}
