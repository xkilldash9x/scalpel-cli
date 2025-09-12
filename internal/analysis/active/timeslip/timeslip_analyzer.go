// internal/analysis/active/timeslip/analysis.go
package timeslip

import (
	"fmt"
	"math"
	"sort"
)

// analysisHeuristic defines a function that checks for a specific indicator of a race condition.
// It returns true if the heuristic conclusively determines the result.
type analysisHeuristic func(result *RaceResult, config *Config, analysis *AnalysisResult) bool

// Define the pipeline of heuristics in order of priority (most severe first).
var heuristicsPipeline = []analysisHeuristic{
	checkTOCTOU,
	checkDifferentialState,
	checkStateFlutter,
	checkTimingAnomalies,
}

// AnalyzeResults processes the raw results using the heuristic pipeline.
func AnalyzeResults(result *RaceResult, config *Config) *AnalysisResult {
	analysis := &AnalysisResult{
		Strategy:        result.Strategy,
		UniqueResponses: make(map[string]int),
	}

	if len(result.Responses) == 0 {
		analysis.Details = "No responses received."
		return analysis
	}

	// 1. Data preparation and aggregation.
	validResponses := prepareAndAggregate(result, analysis)

	if len(validResponses) == 0 {
		analysis.Details = fmt.Sprintf("All %d requests resulted in errors or unprocessable responses.", len(result.Responses))
		return analysis
	}

	// 2. Calculate statistics.
	if len(validResponses) > 1 {
		analysis.Stats = calculateStatistics(validResponses)
	}

	// 3. Execute the heuristics pipeline.
	for _, heuristic := range heuristicsPipeline {
		// If a heuristic returns true, it has conclusively identified the state, and we stop.
		if heuristic(result, config, analysis) {
			break
		}
	}

	// 4. Final determination if no heuristic matched strongly.
	if analysis.Details == "" {
		analysis.Details = "No clear indication of a race condition vulnerability found."
		// Assign very low confidence if high deviation was observed but didn't meet the timing anomaly threshold.
		if analysis.Stats.StdDevMs > 0 && analysis.Stats.AvgDurationMs > 50 && (analysis.Stats.StdDevMs/analysis.Stats.AvgDurationMs) > 0.3 {
			analysis.Confidence = 0.1 // Informational
			analysis.Details += fmt.Sprintf(" Note: High standard deviation observed (%.2fms).", analysis.Stats.StdDevMs)
		}
	}

	return analysis
}

// prepareAndAggregate filters valid responses and counts successes/unique fingerprints.
func prepareAndAggregate(result *RaceResult, analysis *AnalysisResult) []*RaceResponse {
	validResponses := make([]*RaceResponse, 0, len(result.Responses))

	for _, resp := range result.Responses {
		// Filter out transport errors or unparseable responses.
		if resp.Error != nil || resp.ParsedResponse == nil {
			continue
		}

		// Ensure we have a fingerprint to compare.
		if resp.Fingerprint == "" {
			continue
		}

		validResponses = append(validResponses, resp)

		// Use the composite fingerprint.
		analysis.UniqueResponses[resp.Fingerprint]++

		// Was this a "successful" action? (Determined by the SuccessOracle during execution).
		if resp.IsSuccess {
			analysis.SuccessCount++
		}
	}
	return validResponses
}

// --- Heuristics ---

// Heuristic A: Time-of-check Time-of-use (TOCTOU).
func checkTOCTOU(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	expectedSuccesses := 1
	if config.ExpectedSuccesses > 0 {
		expectedSuccesses = config.ExpectedSuccesses
	}

	if analysis.SuccessCount > expectedSuccesses {
		analysis.Vulnerable = true
		analysis.Confidence = 1.0 // 1.0 (Certain): Confirmed TOCTOU.
		analysis.Details = fmt.Sprintf("VULNERABLE: Confirmed TOCTOU race condition. %d operations succeeded (expected <= %d).", analysis.SuccessCount, expectedSuccesses)

		if len(analysis.UniqueResponses) > 1 {
			analysis.Details += " Differential responses observed."
		}
		return true
	}
	return false
}

// Heuristic B: Differential responses including success and failure.
func checkDifferentialState(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	if len(analysis.UniqueResponses) > 1 && analysis.SuccessCount >= 1 {
		// Multiple unique responses AND at least one success.
		analysis.Vulnerable = true
		// 0.8 (High): Mix of success and failure.
		analysis.Confidence = 0.8
		analysis.Details = fmt.Sprintf("VULNERABLE: Differential responses detected (%d unique responses) including successful operations. Indicates inconsistent state during concurrent processing.", len(analysis.UniqueResponses))
		return true
	}
	return false
}

// Heuristic C: State Flutter (Multiple unique failure responses).
func checkStateFlutter(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	if len(analysis.UniqueResponses) > 1 && analysis.SuccessCount == 0 {
		// All operations failed, but in different ways.
		analysis.Vulnerable = true
		// 0.6 (Medium): Multiple unique failure responses.
		analysis.Confidence = 0.6
		analysis.Details = fmt.Sprintf("VULNERABLE: State flutter detected. %d unique failure responses observed. Indicates unstable state under concurrency.", len(analysis.UniqueResponses))
		return true
	}
	return false
}

// Heuristic D: Timing anomalies.
func checkTimingAnomalies(result *RaceResult, config *Config, analysis *AnalysisResult) bool {
	// Timing analysis is less relevant for single-request strategies.
	if result.Strategy == AsyncGraphQL {
		return false
	}

	if config.ThresholdMs > 0 && analysis.Stats.TimingDeltaMs > int64(config.ThresholdMs) {
		// Indicates heavy locking or resource contention.
		analysis.Vulnerable = false // Informational, not necessarily a vulnerability.
		// 0.3 (Low): Significant timing delta without other indicators.
		analysis.Confidence = 0.3
		analysis.Details = fmt.Sprintf("INFO: Significant timing delta detected (%dms). Suggests resource contention or sequential locking.", analysis.Stats.TimingDeltaMs)
		return true
	}
	return false
}

// --- Statistics Calculation ---

// calculateStatistics computes Min, Max, Avg, Median, and Standard Deviation of response durations.
func calculateStatistics(responses []*RaceResponse) ResponseStatistics {
	durationsMs := make([]int64, 0, len(responses))

	for _, resp := range responses {
		if resp.ParsedResponse != nil && resp.Duration > 0 {
			durationsMs = append(durationsMs, resp.Duration.Milliseconds())
		}
	}

	if len(durationsMs) < 2 {
		return ResponseStatistics{}
	}

	// Sort durations for Min, Max, and Median calculation.
	sort.Slice(durationsMs, func(i, j int) bool {
		return durationsMs[i] < durationsMs[j]
	})

	stats := ResponseStatistics{
		MinDurationMs: durationsMs[0],
		MaxDurationMs: durationsMs[len(durationsMs)-1],
	}
	stats.TimingDeltaMs = stats.MaxDurationMs - stats.MinDurationMs

	// Calculate Average (Mean).
	var sum int64
	for _, d := range durationsMs {
		sum += d
	}
	stats.AvgDurationMs = float64(sum) / float64(len(durationsMs))

	// Calculate Median.
	n := len(durationsMs)
	if n%2 == 0 {
		stats.MedDurationMs = float64(durationsMs[n/2-1]+durationsMs[n/2]) / 2.0
	} else {
		stats.MedDurationMs = float64(durationsMs[n/2])
	}

	// Calculate Standard Deviation.
	var varianceSum float64
	for _, d := range durationsMs {
		varianceSum += math.Pow(float64(d)-stats.AvgDurationMs, 2)
	}
	// Using N for population standard deviation as we have all the data points from the race.
	variance := varianceSum / float64(len(durationsMs))
	stats.StdDevMs = math.Sqrt(variance)

	return stats
}
