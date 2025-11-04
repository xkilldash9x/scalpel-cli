package timeslip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// MockReporter implements
// core.Reporter for testing purposes. It is thread safe.
type MockReporter struct {
	mu                sync.Mutex
	ReceivedEnvelopes []*schemas.ResultEnvelope
	FindingsCount     int
}

func (mr *MockReporter) Write(envelope *schemas.ResultEnvelope) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.ReceivedEnvelopes = append(mr.ReceivedEnvelopes, envelope)
	mr.FindingsCount += len(envelope.Findings)
	return nil
}

// Helper to set up a default Analyzer instance for testing.
func setupAnalyzer(t *testing.T, config *Config) (*Analyzer, *MockReporter) {
	// Use zaptest logger which integrates with testing.T
	// Use NewNop() for cleaner logs unless debugging specific log output.
	logger := zap.NewNop()
	reporter := &MockReporter{}
	scanID := uuid.New()

	analyzer, err := NewAnalyzer(scanID, config, logger, reporter)

	// We only assert NoError if we expect success.
	// Tests for invalid config handle the error themselves.
	if err == nil {
		require.NotNil(t, analyzer)
	}

	return analyzer, reporter
}

// -- 1.1.
// Analyzer Configuration & Initialization Tests --

func TestNewAnalyzer_Configuration(t *testing.T) {
	scanID := uuid.New()
	logger := zap.NewNop()
	reporter := &MockReporter{}

	t.Run("Valid Config", func(t *testing.T) {
		config := &Config{Concurrency: 10, Timeout: 5 * time.Second}
		analyzer, err := NewAnalyzer(scanID, config, logger, reporter)
		require.NoError(t, err)
		assert.Equal(t, 10, analyzer.config.Concurrency)
	})

	t.Run("Nil Config - Defaults Applied", func(t *testing.T) {
		analyzer, err := NewAnalyzer(scanID, nil, logger, reporter)
		require.NoError(t, err)
		// Assert defaults (as defined in analyzer.go)
		assert.Equal(t, 20, analyzer.config.Concurrency)
		assert.Equal(t, 15*time.Second, analyzer.config.Timeout)
	})

	t.Run("Low Concurrency - Adjusted to Minimum", func(t *testing.T) {
		config := &Config{Concurrency: 1} // Too low
		analyzer, err := NewAnalyzer(scanID, config, logger, reporter)
		require.NoError(t, err)
		// Assert adjustment to minimum
		assert.Equal(t, 2, analyzer.config.Concurrency)
	})

	t.Run("Invalid Regex - Initialization Fails", func(t *testing.T) {
		config := &Config{
			Success: SuccessCondition{
				BodyRegex: "[invalid-regex", // Invalid regex syntax
			},
		}
		// Initialization should fail because the Oracle initialization validates regexes
		_, err := NewAnalyzer(scanID, config, logger, reporter)
		require.Error(t, err)
		// The error message comes from the regexp package via NewSuccessOracle.
		assert.Contains(t, err.Error(), "invalid BodyRegex")
	})

	t.Run("Nil Logger - No-op Logger Used", func(t *testing.T) {
		// Use zaptest logger here specifically to capture the warning log during initialization when nil is passed.
		zaptest.NewLogger(t)
		analyzer, err := NewAnalyzer(scanID, nil, nil, reporter)
		require.NoError(t, err)
		assert.NotNil(t, analyzer.logger)
	})
}

// -- 1.1.
// Strategy Determination Tests --

func TestDetermineStrategies(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)

	tests := []struct {
		name      string
		candidate RaceCandidate
		expected  []RaceStrategy
	}{
		{
			name:      "Standard HTTP",
			candidate: RaceCandidate{IsGraphQL: false},
			// FIX: Updated expectation to include H2Dependency first.
			expected: []RaceStrategy{H2Dependency, H2Multiplexing, H1SingleByteSend, H1Concurrent},
		},
		{
			name:      "GraphQL",
			candidate: RaceCandidate{IsGraphQL: true},
			expected:  []RaceStrategy{AsyncGraphQL},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategies := analyzer.determineStrategies(&tt.candidate)
			assert.Equal(t, tt.expected, strategies)
		})
	}
}

// -- 1.1.
// Analysis Heuristics (Table-Driven) --

// Helper function to create a mock RaceResponse
func mockResponse(fingerprint string, success bool, durationMs int64) *RaceResponse {
	return &RaceResponse{
		ParsedResponse: &ParsedResponse{
			StatusCode: 200,
			// Duration field is now correctly nested inside ParsedResponse.
			Duration: time.Duration(durationMs) * time.Millisecond,
		},
		Fingerprint: fingerprint,
		IsSuccess:   success,
	}
}

func TestAnalyzeResults_Heuristics(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)
	config := &Config{
		ExpectedSuccesses: 1,
		ThresholdMs:       500,
	}

	tests := []struct {
		name          string
		responses     []*RaceResponse
		strategy      RaceStrategy
		expectVuln    bool
		expectConf    float64
		expectDetails string
	}{
		{
			name: "TOCTOU (Confirmed 1.0)",
			responses: []*RaceResponse{
				mockResponse("FP1", true, 100),
				mockResponse("FP1", true, 110), // Success > 1
			},
			strategy:      H1Concurrent,
			expectVuln:    true,
			expectConf:    1.0,
			expectDetails: "VULNERABLE: Confirmed TOCTOU race condition.",
		},
		{
			name: "Differential State (High 0.8)",
			responses: []*RaceResponse{
				mockResponse("FP_OK", true, 100),
				mockResponse("FP_ERR_A", false, 110),
			},
			strategy:      H1Concurrent,
			expectVuln:    true,
			expectConf:    0.8,
			expectDetails: "VULNERABLE: Differential responses detected (2 unique responses)",
		},
		{
			name: "State Flutter (Medium 0.6)",
			responses: []*RaceResponse{
				mockResponse("FP_ERR_A", false, 100),
				mockResponse("FP_ERR_B", false, 110),
			},
			strategy:   H1Concurrent,
			expectVuln: true,
			expectConf: 0.6,
			// FIX: Updated expectation to match the improved details
			// (including CoV).
			expectDetails: "VULNERABLE: State flutter detected. 2 unique failure responses observed with low timing variation",
		},
		{
			// FIX: Renamed to reflect the actual confidence level (0.2 due to insufficient data).
			name: "Timing Anomaly (Insufficient Data 0.2)",
			// This test case triggers the timing anomaly fallback when < 5 data points exist.
			// It avoids "State Flutter" because the timing delta is large (600ms > 500ms).
			responses: []*RaceResponse{
				mockResponse("FP1", false, 100),
				mockResponse("FP2", false, 700), // Delta 600ms > Threshold 500ms
			},
			strategy:   H1Concurrent,
			expectVuln: false,
			// FIX: Confidence is lowered to 0.2 when data points < 5.
			expectConf: 0.2,
			// FIX: Details updated to reflect insufficient data.
			expectDetails: "INFO: Timing delta detected (600ms), but insufficient data (2 points)",
		},
		{
			name: "Timing Anomaly Ignored for GraphQL",
			// Testing that timing is ignored, but other heuristics still apply
			responses: []*RaceResponse{
				mockResponse("FP1", true, 100),
				mockResponse("FP1", true, 700),
			},
			strategy:   AsyncGraphQL, // Timing heuristic is ignored
			expectVuln: true,         // Falls through to TOCTOU because Success > 1
			expectConf: 1.0,
		},
		{
			name: "Timing Anomaly Ignored for H2Dependency",
			responses: []*RaceResponse{
				// H2Dependency typically has Duration=0 in the current implementation.
				mockResponse("FP1", true, 0),
				mockResponse("FP1", true, 0),
			},
			strategy:   H2Dependency, // Timing heuristic is ignored
			expectVuln: true,         // Falls through to TOCTOU
			expectConf: 1.0,
		},
		{
			name:          "No Responses",
			responses:     []*RaceResponse{},
			expectDetails: "No responses received.",
		},
		{
			name: "All Errors",
			responses: []*RaceResponse{
				{Error: errors.New("timeout")}, {Error: errors.New("refused")},
			},
			expectDetails: "All 2 requests resulted in errors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &RaceResult{
				Strategy:  tt.strategy,
				Responses: tt.responses,
			}

			analysis := analyzer.analyzeResults(result, config)

			assert.Equal(t, tt.expectVuln, analysis.Vulnerable)
			assert.InDelta(t, tt.expectConf, analysis.Confidence, 0.001)
			if tt.expectDetails != "" {
				assert.Contains(t, analysis.Details, tt.expectDetails)
			}
		})
	}
}

// Added test for advanced timing heuristics coverage (Statistical analysis)
func TestAnalyzeResults_Heuristics_AdvancedTiming(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)
	config := &Config{
		ThresholdMs:       500,
		ExpectedSuccesses: 1, // Ensure ExpectedSuccesses is explicitly 1.
	}

	// Helper to generate a bimodal distribution: N-1 fast responses, 1 slow response.
	generateBimodal := func(n int, fastMs int64, slowMs int64) []*RaceResponse {
		responses := make([]*RaceResponse, n)

		// FIX: Ensure only 1 success occurs to prevent the TOCTOU heuristic (1.0) from firing,
		// allowing the timing heuristics (0.3-0.5) to be tested.
		if n > 0 {
			responses[0] = mockResponse("FP1", true, fastMs)
		}

		for i := 1; i < n-1; i++ {
			// Add slight variation to fast responses, make them unsuccessful.
			responses[i] = mockResponse("FP1", false, fastMs+int64(i%5))
		}

		if n > 1 {
			// The slow response should also be unsuccessful.
			responses[n-1] = mockResponse("FP1", false, slowMs)
		}
		return responses
	}

	// Helper to generate a distribution with high variation but no clear outlier pattern
	generateHighVariation := func(n int, baseMs int64) []*RaceResponse {
		responses := make([]*RaceResponse, n)
		for i := 0; i < n; i++ {
			// FIX: Ensure only 1 success occurs.
			isSuccess := (i == 0)
			// Spread out responses linearly
			responses[i] = mockResponse("FP1", isSuccess, baseMs+int64(i*100))
		}
		return responses
	}

	tests := []struct {
		name          string
		responses     []*RaceResponse
		expectConf    float64
		expectDetails string
	}{
		{
			name: "Statistical Outlier (Bimodal Lock-Wait Pattern 0.5)",
			// 10 responses, Median ~100ms.
			// Max 400ms.
			// StdDev will be significant enough (>10ms) and Median > 20ms.
			// The pattern is clearly bimodal (1 outlier in >= 10 requests).
			responses:     generateBimodal(10, 100, 400),
			expectConf:    0.5,
			expectDetails: "INFO: Significant timing anomaly (Lock-Wait pattern) detected.",
		},
		{
			name: "Statistical Outlier (Multiple Outliers 0.4)",
			// 20 responses, 2 outliers.
			responses: func() []*RaceResponse {
				// Start with 20 responses (1 slow outlier at the end)
				// We need at least 20 responses for this specific test case setup.
				if 20 < 2 {
					return generateBimodal(20, 100, 400)
				}
				r := generateBimodal(20, 100, 400)
				// Manually add a second slow outlier (ensure it's not the successful one at index 0)
				// We modify index 1 to be the second outlier.
				r[1] = mockResponse("FP1", false, 410)
				return r
			}(),
			expectConf:    0.4, // Confidence 0.4 because multiple outliers (<15%)
			expectDetails: "INFO: Significant timing anomaly (Lock-Wait pattern) detected.",
		},
		{
			name: "High Variation (No clear pattern, fallback to delta 0.3)",
			// High variation but no specific bimodal pattern.
			// Delta > threshold (100 to 1000 = 900ms).
			responses:     generateHighVariation(10, 100),
			expectConf:    0.3,
			expectDetails: "INFO: Significant timing delta detected",
		},
		{
			name: "Low StdDev/Median (Ignored)",
			// Delta is large (95ms), but StdDev and Median are too low (minStdDevMs=10, minMedianMs=20) for reliable stats.
			responses:  generateBimodal(10, 5, 100),
			expectConf: 0.0, // Ignored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &RaceResult{
				Strategy:  H1Concurrent,
				Responses: tt.responses,
			}

			analysis := analyzer.analyzeResults(result, config)

			assert.InDelta(t, tt.expectConf, analysis.Confidence, 0.001)
			if tt.expectDetails != "" {
				assert.Contains(t, analysis.Details, tt.expectDetails)
			}
		})
	}
}

//
// -- 1.1. Utilities Tests --

func TestCalculateStatistics(t *testing.T) {
	analyzer := &Analyzer{}
	// Dataset: 50, 100, 150, 200, 300 (Sorted)
	responses := []*RaceResponse{
		mockResponse("FP1", true, 100),
		mockResponse("FP1", true, 150),
		mockResponse("FP1", true, 200),
		mockResponse("FP1", true, 50),
		mockResponse("FP1", true, 300),
	}

	stats := analyzer.calculateStatistics(responses)

	// Expected values:
	// Avg: 160
	// Median: 150
	// StdDev: sqrt(7400) ≈ 86.023
	assert.Equal(t, 5, stats.Count)
	assert.Equal(t, int64(50), stats.MinDurationMs)
	assert.Equal(t, int64(300), stats.MaxDurationMs)
	assert.Equal(t, float64(160.0), stats.AvgDurationMs)
	assert.Equal(t, float64(150.0), stats.MedDurationMs)
	assert.InDelta(t, 86.023, stats.StdDevMs, 0.001)
	assert.Equal(t, int64(250), stats.TimingDeltaMs)
}

func TestCalculateStatistics_EdgeCases(t *testing.T) {
	analyzer := &Analyzer{}

	t.Run("Even Count Median", func(t *testing.T) {
		// Dataset: 10, 20, 30, 40
		responses := []*RaceResponse{
			mockResponse("FP1", true, 10), mockResponse("FP1", true, 20),
			mockResponse("FP1", true, 30), mockResponse("FP1", true, 40),
		}
		stats := analyzer.calculateStatistics(responses)
		// Median
		// should be (20+30)/2 = 25
		assert.Equal(t, float64(25.0), stats.MedDurationMs)
	})

	t.Run("Insufficient Data (<2)", func(t *testing.T) {
		responses := []*RaceResponse{mockResponse("FP1", true, 10)}
		stats := analyzer.calculateStatistics(responses)
		assert.Equal(t, ResponseStatistics{}, stats)

		statsEmpty := analyzer.calculateStatistics([]*RaceResponse{})
		assert.Equal(t, ResponseStatistics{}, statsEmpty)
	})

	t.Run("Zero Durations Ignored", func(t *testing.T) {
		// Ensure zero durations (e.g., from H2Dependency) are ignored
		responses := []*RaceResponse{
			mockResponse("FP1", true, 10),
			mockResponse("FP1", true, 20),
			mockResponse("FP1", true, 0),
		}
		stats := analyzer.calculateStatistics(responses)
		assert.Equal(t, 2, stats.Count)
		assert.Equal(t, float64(15.0), stats.AvgDurationMs)
	})
}

func TestReportFinding_SeverityMapping(t *testing.T) {
	analyzer, reporter := setupAnalyzer(t, nil)
	candidate := &RaceCandidate{URL: "http://example.com"}
	result := &RaceResult{Duration: 500 * time.Millisecond}

	tests := []struct {
		name       string
		confidence float64
		vulnerable bool
		expected   schemas.Severity
		expectCWEs []string
	}{ // FIX: Updated expected CWE strings to match the descriptive format from the analyzer.
		{"Critical", 1.0, true, schemas.SeverityCritical, []string{"CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition"}},
		{"High", 0.8, true, schemas.SeverityHigh, []string{"CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"}},
		{"Medium", 0.6, true, schemas.SeverityMedium, []string{"CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"}},
		{"Low", 0.5, true, schemas.SeverityLow, []string{"CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"}},
		// Informational findings still use the simple CWE ID.
		{"Informational", 0.3, false, schemas.SeverityInformational, []string{"CWE-362"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter.ReceivedEnvelopes = nil // Clear previous findings
			analysis := &AnalysisResult{Confidence: tt.confidence, Vulnerable: tt.vulnerable, Strategy: H1Concurrent}
			analyzer.reportFinding(candidate, analysis, result)

			require.Len(t, reporter.ReceivedEnvelopes, 1)
			envelope := reporter.ReceivedEnvelopes[0]
			finding := envelope.Findings[0]

			assert.Equal(t, tt.expected, finding.Severity)
			assert.Equal(t, tt.expectCWEs, finding.CWE)
			assert.NotEmpty(t, envelope.ScanID)
			assert.NotEmpty(t, finding.ID)

			// Validate evidence structure
			var evidence TimeSlipEvidence
			err := json.Unmarshal([]byte(finding.Evidence), &evidence)
			assert.NoError(t, err, "Evidence should be valid JSON")
			assert.Equal(t, H1Concurrent, evidence.Strategy)
			assert.Equal(t, int64(500), evidence.TotalDurationMs)
		})
	}
}

// Test case for nil reporter (should not panic).
func TestReportFinding_NilReporter(t *testing.T) {
	logger := zap.NewNop()
	analyzer, err := NewAnalyzer(uuid.New(), nil, logger, nil) // Nil reporter
	require.NoError(t, err)

	analysis := &AnalysisResult{Confidence: 1.0, Vulnerable: true}
	assert.NotPanics(t, func() {
		analyzer.reportFinding(&RaceCandidate{}, analysis, &RaceResult{})
	})
}

func TestSampleUniqueResponses_SamplingAndTruncation(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)

	// Create a long response (more than 1024 bytes)
	longBody := strings.Repeat("X", 1100)
	respLong := mockResponse("FP_LONG", true, 100)
	respLong.SpecificBody = []byte(longBody)
	respLong.ParsedResponse.StatusCode = 200

	// Test UTF-8 boundary truncation
	// "€" is 3 bytes (E2 82 AC).
	// If we truncate near it, it should handle it gracefully.
	utf8Body := strings.Repeat("A", 1022) + "€" // Total 1025 bytes
	respUTF8 := mockResponse("FP_UTF8", true, 100)
	respUTF8.SpecificBody = []byte(utf8Body)
	respUTF8.ParsedResponse.StatusCode = 200

	respErr := &RaceResponse{
		Fingerprint: "FP_ERR",
		Error:       errors.New("error"),
	}

	// Generate 7 unique responses to test the limit of 5
	var manyUnique []*RaceResponse
	for i := 0; i < 7; i++ {
		fp := fmt.Sprintf("U%d", i)
		resp := mockResponse(fp, true, 100)
		resp.SpecificBody = []byte(fmt.Sprintf("Unique %d", i))
		resp.ParsedResponse = &ParsedResponse{StatusCode: 200}
		manyUnique = append(manyUnique, resp)
	}

	// Combine responses, including duplicates and errors
	responses := append([]*RaceResponse{respLong, respUTF8, respErr, manyUnique[0]}, manyUnique...)

	samples := analyzer.sampleUniqueResponses(responses)

	// We expect exactly 5 samples (the max limit)
	assert.Len(t, samples, 5)

	// Check truncation for the long response
	foundLong := false
	foundUTF8 := false
	for _, sample := range samples {
		if strings.HasPrefix(sample.Body, "XXXXX") {
			foundLong = true
			// Should be truncated at 1024 bytes + the suffix length
			assert.LessOrEqual(t, len(sample.Body), 1024+100)
			assert.Contains(t, sample.Body, "... [TRUNCATED -")
		}
		if strings.HasPrefix(sample.Body, "AAAAA") && strings.Contains(sample.Body, "TRUNCATED") {
			foundUTF8 = true
			// Should be truncated before the '€' (at 1022 bytes) because including it exceeds 1024.
			assert.NotContains(t, sample.Body, "€")
		}
	}
	assert.True(t, foundLong, "Long response should be included and truncated")
	assert.True(t, foundUTF8, "UTF-8 response should be included and safely truncated")
}

// -- Analyzer.Analyze Execution Flow Tests (Mocked Strategies) --
// These tests validate the orchestration logic: error handling, continuation, and halting.

// Helper to mock all strategies and track execution.
func mockStrategies(t *testing.T, behaviorMap map[RaceStrategy]func() (*RaceResult, error)) map[RaceStrategy]bool {
	executed := make(map[RaceStrategy]bool)

	// Store originals and setup defer to restore them.
	originalH2Dep := executeH2Dependency
	originalH2Mux := executeH2Multiplexing
	originalH1Single := executeH1SingleByteSend
	originalH1Conc := executeH1Concurrent
	originalGQL := executeGraphQLAsync

	t.Cleanup(func() {
		executeH2Dependency = originalH2Dep
		executeH2Multiplexing = originalH2Mux
		executeH1SingleByteSend = originalH1Single
		executeH1Concurrent = originalH1Conc
		executeGraphQLAsync = originalGQL
	})

	// Define mock wrapper.
	mockWrapper := func(strategy RaceStrategy) func(context.Context, *RaceCandidate, *Config, *SuccessOracle, *zap.Logger) (*RaceResult, error) {
		return func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle, l *zap.Logger) (*RaceResult, error) {
			executed[strategy] = true
			if behavior, exists := behaviorMap[strategy]; exists {
				return behavior()
			}
			// Default behavior if not specified: return empty success.
			return &RaceResult{Strategy: strategy, Responses: []*RaceResponse{}}, nil
		}
	}

	executeH2Dependency = mockWrapper(H2Dependency)
	executeH2Multiplexing = mockWrapper(H2Multiplexing)
	executeH1SingleByteSend = mockWrapper(H1SingleByteSend)
	executeH1Concurrent = mockWrapper(H1Concurrent)
	executeGraphQLAsync = mockWrapper(AsyncGraphQL)

	return executed
}

func TestAnalyze_StrategyExecutionFlow_ContinueOnError(t *testing.T) {
	// Setup
	analyzer, reporter := setupAnalyzer(t, &Config{Concurrency: 5})
	// Use HTTPS URL to satisfy preconditions for H2 strategies, ensuring mocks control the flow.
	candidate := &RaceCandidate{URL: "https://example.com", IsGraphQL: false}

	// Define mock behaviors for specific strategies.
	behaviors := map[RaceStrategy]func() (*RaceResult, error){
		H2Dependency: func() (*RaceResult, error) {
			// Simulate recoverable error (e.g., unsupported protocol).
			// Should continue.
			return nil, ErrH2Unsupported
		},
		H2Multiplexing: func() (*RaceResult, error) {
			// Simulate a network timeout.
			// Should continue.
			return nil, ErrTargetUnreachable
		},
		H1SingleByteSend: func() (*RaceResult, error) {
			// Simulate pipelining rejected.
			// Should continue.
			return nil, ErrPipeliningRejected
		},
		// H1Concurrent will use the default behavior (success).
	}

	// FIX: Initialize mocks using the helper which includes H2Dependency.
	executedStrategies := mockStrategies(t, behaviors)

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions: All strategies should have been attempted despite errors.
	assert.True(t, executedStrategies[H2Dependency], "H2Dependency should execute")
	assert.True(t, executedStrategies[H2Multiplexing], "H2Multiplexing should execute")
	assert.True(t, executedStrategies[H1SingleByteSend], "H1SingleByteSend should execute")
	assert.True(t, executedStrategies[H1Concurrent], "H1Concurrent should execute")

	// With all strategies properly mocked to return non-vulnerable results, the finding count should be zero.
	assert.Equal(t, 0, reporter.FindingsCount)
}

func TestAnalyze_HaltingOnConfigurationError(t *testing.T) {
	// Setup
	analyzer, _ := setupAnalyzer(t, &Config{})
	// Use https to ensure the mock behavior triggers the halt.
	candidate := &RaceCandidate{URL: "https://example.com", IsGraphQL: false}

	// Define mock behavior: Strategy 1 fails with a critical configuration error.
	behaviors := map[RaceStrategy]func() (*RaceResult, error){
		H2Dependency: func() (*RaceResult, error) {
			return nil, ErrConfigurationError // This should halt further analysis
		},
	}

	// FIX: Initialize mocks.
	executedStrategies := mockStrategies(t, behaviors)

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions
	assert.True(t, executedStrategies[H2Dependency], "H2Dependency should execute")
	// Subsequent strategies should not be executed.
	assert.False(t, executedStrategies[H2Multiplexing], "Analysis should halt after configuration error")
	assert.False(t, executedStrategies[H1Concurrent], "Analysis should halt after configuration error")
}

func TestAnalyze_HaltingOnConfirmedTOCTOU(t *testing.T) {
	// Setup
	config := &Config{ExpectedSuccesses: 1}
	analyzer, reporter := setupAnalyzer(t, config)
	candidate := &RaceCandidate{URL: "https://example.com", IsGraphQL: false}

	// Define mock behavior: Strategy 1 finds a Confirmed TOCTOU (Confidence 1.0).
	behaviors := map[RaceStrategy]func() (*RaceResult, error){
		H2Dependency: func() (*RaceResult, error) {
			return &RaceResult{
				Strategy: H2Dependency,
				Responses: []*RaceResponse{
					mockResponse("FP1", true, 100),
					mockResponse("FP1", true, 105), // Success > 1
				},
			}, nil
		},
	}

	// FIX: Initialize mocks.
	executedStrategies := mockStrategies(t, behaviors)

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions
	assert.True(t, executedStrategies[H2Dependency], "H2Dependency should execute")
	// Subsequent strategies should not be executed.
	assert.False(t, executedStrategies[H2Multiplexing], "Analysis should halt after confirmed TOCTOU")
	assert.False(t, executedStrategies[H1Concurrent], "Analysis should halt after confirmed TOCTOU")

	require.Equal(t, 1, reporter.FindingsCount)
	assert.Equal(t, schemas.SeverityCritical, reporter.ReceivedEnvelopes[0].Findings[0].Severity)
}
