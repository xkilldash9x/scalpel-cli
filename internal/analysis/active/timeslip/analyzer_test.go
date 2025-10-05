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

// MockReporter implements core.Reporter for testing purposes. It is thread safe.
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
	logger := zaptest.NewLogger(t)
	reporter := &MockReporter{}
	scanID := uuid.New()

	analyzer, err := NewAnalyzer(scanID, config, logger, reporter)

	// We only assert NoError if we expect success. Tests for invalid config handle the error themselves.
	if err == nil {
		require.NotNil(t, analyzer)
	}

	return analyzer, reporter
}

// -- 1.1. Analyzer Configuration & Initialization Tests --

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
		assert.Contains(t, err.Error(), "error parsing regexp")
	})

	t.Run("Nil Logger - No-op Logger Used", func(t *testing.T) {
		analyzer, err := NewAnalyzer(scanID, nil, nil, reporter)
		require.NoError(t, err)
		assert.NotNil(t, analyzer.logger)
	})
}

// -- 1.1. Strategy Determination Tests --

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
			expected:  []RaceStrategy{H2Multiplexing, H1SingleByteSend, H1Concurrent},
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

// -- 1.1. Analysis Heuristics (Table-Driven) --

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
			strategy:      H1Concurrent,
			expectVuln:    true,
			expectConf:    0.6,
			expectDetails: "VULNERABLE: State flutter detected. 2 unique failure responses observed.",
		},
		{
			name: "Timing Anomaly (Informational 0.3)",
			// This test case is specifically crafted to only trigger the timing anomaly.
			// By having two different fingerprints but both being failures, it avoids
			// the "Differential State" and "State Flutter" heuristics.
			responses: []*RaceResponse{
				mockResponse("FP1", false, 100),
				mockResponse("FP2", false, 700), // Delta 600ms > Threshold 500ms
			},
			strategy:      H1Concurrent,
			expectVuln:    false,
			expectConf:    0.3,
			expectDetails: "INFO: Significant timing delta detected (600ms).",
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
	assert.Equal(t, int64(50), stats.MinDurationMs)
	assert.Equal(t, int64(300), stats.MaxDurationMs)
	assert.Equal(t, float64(160.0), stats.AvgDurationMs)
	assert.Equal(t, float64(150.0), stats.MedDurationMs)
	assert.InDelta(t, 86.023, stats.StdDevMs, 0.001)
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
		// Median should be (20+30)/2 = 25
		assert.Equal(t, float64(25.0), stats.MedDurationMs)
	})

	t.Run("Insufficient Data (<2)", func(t *testing.T) {
		responses := []*RaceResponse{mockResponse("FP1", true, 10)}
		stats := analyzer.calculateStatistics(responses)
		assert.Equal(t, ResponseStatistics{}, stats)
	})
}

func TestReportFinding_SeverityMapping(t *testing.T) {
	analyzer, reporter := setupAnalyzer(t, nil)
	candidate := &RaceCandidate{URL: "http://example.com"}
	result := &RaceResult{}

	tests := []struct {
		name       string
		confidence float64
		vulnerable bool
		expected   schemas.Severity
	}{
		{"Critical", 1.0, true, schemas.SeverityCritical},
		{"High", 0.8, true, schemas.SeverityHigh},
		{"Medium", 0.6, true, schemas.SeverityMedium},
		{"Low", 0.5, true, schemas.SeverityLow},
		{"Informational", 0.3, false, schemas.SeverityInformational},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter.ReceivedEnvelopes = nil // Clear previous findings
			analysis := &AnalysisResult{Confidence: tt.confidence, Vulnerable: tt.vulnerable}
			analyzer.reportFinding(candidate, analysis, result)

			require.Len(t, reporter.ReceivedEnvelopes, 1)
			finding := reporter.ReceivedEnvelopes[0].Findings[0]
			assert.Equal(t, tt.expected, finding.Severity)

			// Validate evidence structure
			var evidence TimeSlipEvidence
			err := json.Unmarshal([]byte(finding.Evidence), &evidence)
			assert.NoError(t, err, "Evidence should be valid JSON")
		})
	}
}

func TestSampleUniqueResponses_SamplingAndTruncation(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)

	// Create a long response (more than 1024 bytes)
	longBody := strings.Repeat("X", 1100)
	respLong := mockResponse("FP_LONG", true, 100)
	respLong.SpecificBody = []byte(longBody)
	respLong.ParsedResponse.StatusCode = 200

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
	responses := append([]*RaceResponse{respLong, respErr, manyUnique[0]}, manyUnique...)

	samples := analyzer.sampleUniqueResponses(responses)

	// We expect exactly 5 samples (the max limit)
	assert.Len(t, samples, 5)

	// Check truncation for the long response
	foundLong := false
	for _, sample := range samples {
		if strings.HasPrefix(sample.Body, "XXXXX") {
			foundLong = true
			// Should be truncated near 1024 bytes + the suffix length
			assert.LessOrEqual(t, len(sample.Body), 1024+100)
			assert.Contains(t, sample.Body, "... [TRUNCATED -")
		}
	}
	assert.True(t, foundLong, "Long response should be included and truncated")
}

// -- Analyzer.Analyze Execution Flow Tests (Mocked Strategies) --
// These tests validate the orchestration logic: error handling, continuation, and halting.

func TestAnalyze_StrategyExecutionFlow_ContinueOnError(t *testing.T) {
	// Setup
	analyzer, reporter := setupAnalyzer(t, &Config{Concurrency: 5})
	candidate := &RaceCandidate{URL: "http://example.com", IsGraphQL: false}

	// Mock the strategy execution functions
	originalH2 := executeH2Multiplexing
	originalH1Single := executeH1SingleByteSend
	originalH1Concurrent := executeH1Concurrent // Mock all strategies in the chain
	defer func() {
		executeH2Multiplexing = originalH2
		executeH1SingleByteSend = originalH1Single
		executeH1Concurrent = originalH1Concurrent
	}()

	executedStrategies := make(map[RaceStrategy]bool)

	// Define mock behavior
	executeH2Multiplexing = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H2Multiplexing] = true
		return nil, ErrH2Unsupported // Simulate recoverable error, should continue
	}

	executeH1SingleByteSend = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H1SingleByteSend] = true
		// Return an empty result, which should not generate a finding
		return &RaceResult{Strategy: H1SingleByteSend, Responses: []*RaceResponse{}}, nil
	}

	executeH1Concurrent = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H1Concurrent] = true
		return &RaceResult{Strategy: H1Concurrent, Responses: []*RaceResponse{}}, nil
	}

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions: All strategies should have been attempted
	assert.True(t, executedStrategies[H2Multiplexing])
	assert.True(t, executedStrategies[H1SingleByteSend])
	assert.True(t, executedStrategies[H1Concurrent])

	// With all strategies properly mocked to return
	// non-vulnerable results, the finding count should be zero.
	assert.Equal(t, 0, reporter.FindingsCount)
}

func TestAnalyze_HaltingOnConfigurationError(t *testing.T) {
	// Setup
	analyzer, _ := setupAnalyzer(t, &Config{})
	candidate := &RaceCandidate{IsGraphQL: false}

	// Mock setup
	originalH2 := executeH2Multiplexing
	originalH1 := executeH1Concurrent
	defer func() {
		executeH2Multiplexing = originalH2
		executeH1Concurrent = originalH1
	}()

	executedStrategies := make(map[RaceStrategy]bool)

	// Strategy 1: Fails with a critical configuration error
	executeH2Multiplexing = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H2Multiplexing] = true
		return nil, ErrConfigurationError // This should halt further analysis
	}

	// Strategy 2: Should not be executed
	executeH1Concurrent = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H1Concurrent] = true
		return nil, nil
	}

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions
	assert.True(t, executedStrategies[H2Multiplexing])
	assert.False(t, executedStrategies[H1Concurrent], "Analysis should halt after configuration error")
}

func TestAnalyze_HaltingOnConfirmedTOCTOU(t *testing.T) {
	// Setup
	config := &Config{ExpectedSuccesses: 1}
	analyzer, reporter := setupAnalyzer(t, config)
	candidate := &RaceCandidate{IsGraphQL: false}

	// Mock setup
	originalH2 := executeH2Multiplexing
	originalH1 := executeH1Concurrent
	defer func() {
		executeH2Multiplexing = originalH2
		executeH1Concurrent = originalH1
	}()

	executedStrategies := make(map[RaceStrategy]bool)

	// Strategy 1: Finds a Confirmed TOCTOU (Confidence 1.0)
	executeH2Multiplexing = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H2Multiplexing] = true
		return &RaceResult{
			Strategy: H2Multiplexing,
			Responses: []*RaceResponse{
				mockResponse("FP1", true, 100),
				mockResponse("FP1", true, 105), // Success > 1
			},
		}, nil
	}

	// Strategy 2: Should not be executed
	executeH1Concurrent = func(ctx context.Context, c *RaceCandidate, cfg *Config, o *SuccessOracle) (*RaceResult, error) {
		executedStrategies[H1Concurrent] = true
		return nil, nil
	}

	// Execution
	err := analyzer.Analyze(context.Background(), candidate)
	assert.NoError(t, err)

	// Assertions
	assert.True(t, executedStrategies[H2Multiplexing])
	assert.False(t, executedStrategies[H1Concurrent], "Analysis should halt after confirmed TOCTOU")
	require.Equal(t, 1, reporter.FindingsCount)
	assert.Equal(t, schemas.SeverityCritical, reporter.ReceivedEnvelopes[0].Findings[0].Severity)
}
