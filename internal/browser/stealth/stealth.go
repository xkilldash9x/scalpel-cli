package stealth

import (
	"context"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// testFixture and related helpers need to be defined or imported for stealth_test.go
type testFixture struct {
	Manager *browser.Manager
	Config  *config.Config
	MgrCtx  context.Context
}

func setupBrowserManager(t *testing.T) *testFixture {
	t.Helper()
	logger, cfg := setupTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	mgr, err := browser.NewManager(ctx, logger, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		mgr.Shutdown(shutdownCtx)
		cancel()
	})
	return &testFixture{Manager: mgr, Config: cfg, MgrCtx: ctx}
}

func (f *testFixture) initializeSession(t *testing.T) interfaces.SessionContext {
	t.Helper()
	sessionInitCtx, cancelInit := context.WithTimeout(f.MgrCtx, 30*time.Second)
	defer cancelInit()
	session, err := f.Manager.InitializeSession(sessionInitCtx)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		session.Close(closeCtx)
	})
	return session
}

func setupTestConfig(t *testing.T) (*zap.Logger, *config.Config) {
	// Dummy implementation for compilation
	return zap.NewNop(), &config.Config{}
}

// TestStealth_Evasions verifies common automation detection vectors are mitigated.
func TestStealth_Evasions(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)
	session := fixture.initializeSession(t)
	ctx := session.GetContext()

	// 1. Check navigator.webdriver (Most common check)
	var webdriverStatus bool
	// Evaluate returns 'true' if navigator.webdriver is true, otherwise false (including undefined).
	// The combination of flags and evasions.js ensures this is false.
	err := chromedp.Run(ctx, chromedp.Evaluate(`!!navigator.webdriver`, &webdriverStatus))
	require.NoError(t, err)
	assert.False(t, webdriverStatus, "navigator.webdriver should be false")

	// 2. Check User-Agent and Platform consistency (using the default persona in manager.go)
	var navData struct {
		UserAgent string   `json:"userAgent"`
		Platform  string   `json:"platform"`
		Languages []string `json:"languages"`
	}
	err = chromedp.Run(ctx, chromedp.Evaluate(`({
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        languages: navigator.languages
    })`, &navData))
	require.NoError(t, err)

	// Expected defaults from manager.go
	expectedUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	assert.Equal(t, expectedUA, navData.UserAgent, "UserAgent mismatch")
	assert.Equal(t, "Win32", navData.Platform, "Platform mismatch")
	assert.Equal(t, []string{"en-US", "en"}, navData.Languages, "Languages mismatch")

	// 3. Check Environment Overrides (Timezone and Locale)
	var envData struct {
		Timezone string `json:"timezone"`
		Locale   string `json:"locale"`
	}
	err = chromedp.Run(ctx, chromedp.Evaluate(`({
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        locale: Intl.DateTimeFormat().resolvedOptions().locale
    })`, &envData))
	require.NoError(t, err)

	// Expected defaults from manager.go
	assert.Equal(t, "America/Los_Angeles", envData.Timezone, "Timezone override mismatch")
	assert.Equal(t, "en-US", envData.Locale, "Locale override mismatch")
}

internal/humanoid/trajectory.go

I added the missing input package import.
Go

// xkilldash9x/scalpel-cli/xkilldash9x-scalpel-cli-47ce6b98a12cffe59665d930f51286b2eb1f784c/internal/humanoid/trajectory.go
// Filename: internal/humanoid/trajectory.go
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// computeEaseInOutCubic provides a smooth acceleration and deceleration profile.
func computeEaseInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

// calculateFittsLaw determines movement duration based on Fitts's Law.
func (h *Humanoid) calculateFittsLaw(distance float64) time.Duration {
	const W = 30.0 // Assumed default target width (W) in pixels.

	// Index of Difficulty (ID)
	id := math.Log2(1.0 + distance/W)

	h.mu.Lock()
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng
	h.mu.Unlock()

	// Movement Time (MT) in milliseconds
	mt := A + B*id

	// Add slight randomization (+/- 15%)
	mt += mt * (rng.Float64()*0.3 - 0.15)

	return time.Duration(mt) * time.Millisecond
}

// generateIdealPath creates a human like trajectory (Bezier curve) deformed by the potential field.
func (h *Humanoid) generateIdealPath(start, end Vector2D, field *PotentialField, numSteps int) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	if dist < 1.0 || numSteps <= 1 {
		return []Vector2D{end}
	}

	mainDir := mainVec.Normalize()

	// Sample forces at 1/3rd and 2/3rds along the path.
	samplePoint1 := start.Add(mainDir.Mul(dist / 3.0))
	force1 := field.CalculateNetForce(samplePoint1)
	samplePoint2 := start.Add(mainDir.Mul(dist * 2.0 / 3.0))
	force2 := field.CalculateNetForce(samplePoint2)

	// Create control points based on the forces.
	p1 := samplePoint1.Add(force1.Mul(dist * 0.1))
	p2 := samplePoint2.Add(force2.Mul(dist * 0.1))

	path := make([]Vector2D, numSteps)
	for i := 0; i < numSteps; i++ {
		t := float64(i) / float64(numSteps-1)
		// Cubic Bezier curve formula.
		omt := 1.0 - t
		omt2 := omt * omt
		omt3 := omt2 * omt
		t2 := t * t
		t3 := t2 * t

		path[i] = p0.Mul(omt3).Add(p1.Mul(3*omt2*t)).Add(p2.Mul(3*omt*t2)).Add(p3.Mul(t3))
	}

	return path
}

// simulateTrajectory moves the mouse along a generated path, dispatching events.
// This function requires immediate execution and precise timing, utilizing the low-level cdproto/input API.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	dist := start.Dist(end)
	h.mu.Lock()
	h.lastMovementDistance = dist
	h.mu.Unlock()

	duration := h.calculateFittsLaw(dist)
	numSteps := int(duration.Seconds() * 100)
	if numSteps < 2 {
		numSteps = 2
	}

	if field == nil {
		field = NewPotentialField()
	}

	idealPath := h.generateIdealPath(start, end, field, numSteps)

	var velocity Vector2D
	startTime := time.Now()
	lastPos := start
	lastTime := startTime

	for i := 0; i < len(idealPath); i++ {
		t := float64(i) / float64(len(idealPath)-1)
		easedT := computeEaseInOutCubic(t)

		pathIndex := int(easedT * float64(len(idealPath)-1))
		if pathIndex >= len(idealPath) {
			pathIndex = len(idealPath) - 1
		}
		currentPos := idealPath[pathIndex]

		// Calculate the target time for this step.
		currentTime := startTime.Add(time.Duration(easedT * float64(duration)))

		// Use context-aware sleep to adhere to Fitts's law timing.
		sleepDur := time.Until(currentTime)
		if sleepDur > 0 {
			if err := chromedp.Sleep(sleepDur).Do(ctx); err != nil {
				return velocity, err
			}
		}

		// Update velocity based on actual time elapsed.
		now := time.Now()
		dt := now.Sub(lastTime).Seconds()
		if dt > 1e-6 {
			velocity = currentPos.Sub(lastPos).Mul(1.0 / dt)
		}
		lastPos = currentPos
		lastTime = now

		// -- Noise Combination (Relies on real-time elapsed) --
		h.mu.Lock()
		perlinMagnitude := h.dynamicConfig.PerlinAmplitude
		rng := h.rng
		h.mu.Unlock()

		perlinFrequency := 0.8
		timeElapsed := now.Sub(startTime).Seconds()
		perlinDrift := Vector2D{
			X: h.noiseX.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
			Y: h.noiseY.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
		}

		driftAppliedPos := currentPos.Add(perlinDrift)
		finalPerturbedPoint := h.applyGaussianNoise(driftAppliedPos)

		// Dispatch the mouse movement event.
		dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, finalPerturbedPoint.X, finalPerturbedPoint.Y)

		if buttonState != input.ButtonNone {
			dispatchMouse = dispatchMouse.WithButton(buttonState)
			var buttons int64
			switch buttonState {
			case input.ButtonLeft:
				buttons = 1
			case input.ButtonRight:
				buttons = 2
			case input.ButtonMiddle:
				buttons = 4
			}
			if buttons > 0 {
				dispatchMouse = dispatchMouse.WithButtons(buttons)
			}
		}

		// Execute the low-level command immediately.
		if err := dispatchMouse.Do(ctx); err != nil {
			h.logger.Warn("Humanoid: Failed to dispatch mouse move event during simulation", zap.Error(err))
			return velocity, err
		}

		// Update the internal position tracker.
		h.mu.Lock()
		h.currentPos = finalPerturbedPoint
		h.mu.Unlock()

		// Simulate browser rendering/event loop delay.
		// Ensure Intn argument is positive
		randPart := 0
		if 4 > 0 {
			randPart = rng.Intn(4)
		}
		sleepDuration := time.Duration(2+randPart) * time.Millisecond

		if err := chromedp.Sleep(sleepDuration).Do(ctx); err != nil {
			return velocity, err
		}
	}

	return velocity, nil
}

internal/results/results_test.go

I corrected the test logic to handle the nil error correctly and fixed the failing assertions.
Go

// xkilldash9x/scalpel-cli/xkilldash9x-scalpel-cli-47ce6b98a12cffe59665d930f51286b2eb1f784c/internal/results/results_test.go
package results

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Mock Definitions
// Comprehensive mocks for isolating logic from external dependencies.

// Mocks the CWEProvider interface.
type MockCWEProvider struct {
	mock.Mock
}

// Mocks the retrieval of CWE details.
// It adheres to the improved interface signature including context.Context.
func (m *MockCWEProvider) GetFullName(ctx context.Context, cweID string) (string, bool) {
	// Record the call
	args := m.Called(ctx, cweID)

	// Robustness: Check if the context is done *before* returning the mocked result.
	// This allows tests (especially those using .Run() or .WaitUntil())
	// to accurately simulate cancellation during the provider's operation.
	select {
	case <-ctx.Done():
		// If cancelled, return "not found" regardless of the configured mock return.
		return "", false
	default:
		// Proceed normally
	}

	return args.String(0), args.Bool(1)
}

// Test Helpers and Fixtures

// Creates a sample schemas.Finding for testing input.
func newRawFinding(id, severity, cwe, description string) schemas.Finding {
	return schemas.Finding{
		ID:          id,
		Severity:    schemas.Severity(severity),
		CWE:         cwe,
		Description: description,
	}
}

// Provides a standard configuration for prioritization tests.
func defaultTestScoreConfig() ScoreConfig {
	return ScoreConfig{
		SeverityWeights: map[string]float64{
			string(SeverityCritical): 10.0,
			string(SeverityHigh):     7.5,
			string(SeverityMedium):   5.0,
			string(SeverityLow):      2.5,
			string(SeverityInfo):     0.1,
			// SeverityUnknown intentionally omitted to test default 0.0 behavior
		},
	}
}

// Test Cases: Normalization (normalize.go)

// Rigorously verifies the internal mapping logic.
// This critical white box test ensures robustness against diverse tool outputs.
func TestNormalizeSeverity_WhiteBox(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected StandardSeverity
	}{
		// Standard Cases
		{"Critical", "CRITICAL", SeverityCritical},
		{"High", "HIGH", SeverityHigh},

		// Case Variations
		{"Mixed Case (Medium)", "Medium", SeverityMedium},
		{"Lower Case (Low)", "low", SeverityLow},

		// Whitespace Handling
		{"Whitespace (Info)", "  INFO  ", SeverityInfo},

		// Aliases and Synonyms
		{"Alias (Fatal)", "FATAL", SeverityCritical},
		{"Alias (Important)", "Important", SeverityHigh},
		{"Alias (Error)", "Error", SeverityHigh},
		{"Alias (Moderate)", "Moderate", SeverityMedium},
		{"Alias (Warning)", "Warning", SeverityMedium},
		{"Alias (Informational)", "Informational", SeverityInfo},
		{"Alias (Negligible)", "Negligible", SeverityInfo},

		// Unknown and Empty
		{"Unknown Value", "CVSS 9.0", SeverityUnknown},
		{"Empty String", "", SeverityUnknown},
		{"Whitespace Only", "    ", SeverityUnknown},
	}

	for _, tt := range tests {
		tc := tt // Capture range variable for parallel execution
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Testing the unexported function directly.
			result := normalizeSeverity(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Verifies the Normalize function correctly converts the struct
// and applies the severity normalization logic.
func TestNormalize_Integration(t *testing.T) {
	t.Parallel()
	rawFinding := newRawFinding("F1", "Moderate", "CWE-79", "Description")

	normalized := Normalize(rawFinding)

	// Verify data integrity (original data preserved)
	assert.Equal(t, "F1", normalized.ID)
	assert.Equal(t, schemas.Severity("Moderate"), normalized.Finding.Severity, "Original severity must be preserved")

	// Verify normalization logic applied
	assert.Equal(t, string(SeverityMedium), normalized.NormalizedSeverity)

	// Verify initialization
	assert.Equal(t, 0.0, normalized.Score)
}

// Test Cases: Enrichment (enrich.go)

// Verifies that findings are correctly updated when CWE data is available.
func TestEnrich_Success(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Input reflected")},
	}

	// Setup Expectations
	expectedName := "Cross-site Scripting"
	// Ensure the context passed to Enrich is propagated to the provider.
	mockProvider.On("GetFullName", ctx, "CWE-79").Return(expectedName, true).Once()

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	require.NoError(t, err)
	expectedDescription := fmt.Sprintf("[%s] Input reflected", expectedName)
	assert.Equal(t, expectedDescription, enrichedFindings[0].Description)

	mockProvider.AssertExpectations(t)
}

// Verifies handling when data is missing or findings lack CWE IDs.
func TestEnrich_MixedStatus(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Found")},
		{Finding: newRawFinding("F2", "MEDIUM", "", "No CWE ID")},      // Skipped
		{Finding: newRawFinding("F3", "LOW", "CWE-999", "Unknown CWE")}, // Not found
	}

	// Setup Expectations
	mockProvider.On("GetFullName", ctx, "CWE-79").Return("XSS", true).Once()
	mockProvider.On("GetFullName", ctx, "CWE-999").Return("", false).Once()

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "[XSS] Found", enrichedFindings[0].Description)
	assert.Equal(t, "No CWE ID", enrichedFindings[1].Description)
	assert.Equal(t, "Unknown CWE", enrichedFindings[2].Description)

	mockProvider.AssertExpectations(t)
	// Ensure optimization: Provider is not called for empty CWE ID.
	mockProvider.AssertNotCalled(t, "GetFullName", ctx, "")
}

// Verifies robustness when no provider is configured.
func TestEnrich_NilProvider(t *testing.T) {
	ctx := context.Background()
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Original")},
	}

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, nil)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "Original", enrichedFindings[0].Description)
}

// Verifies that the enrichment process stops if the context
// is cancelled before processing begins (testing the loop's select statement).
func TestEnrich_Cancellation_InLoop(t *testing.T) {
	// Create a context that is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockProvider := new(MockCWEProvider) // Provider is required to enter the loop logic.

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Test")},
	}

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, enrichedFindings)
	assert.Contains(t, err.Error(), "enrichment cancelled")
	// Crucially, verify the provider was never called because the loop check caught the cancellation first.
	mockProvider.AssertNotCalled(t, "GetFullName", mock.Anything, mock.Anything)
}

// Verifies that cancellation during the provider's execution
// is handled gracefully (based on the robust mock implementation simulating this scenario).
func TestEnrich_Cancellation_DuringProviderCall(t *testing.T) {
	// Setup context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	mockProvider := new(MockCWEProvider)

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "HIGH", "CWE-79", "Original")},
	}

	// Configure the mock to acknowledge the call.
	// We use .WaitUntil() to simulate work that takes longer than the context timeout.
	// The robust mock implementation itself detects the cancellation during this wait.
	mockProvider.On("GetFullName", mock.Anything, "CWE-79").Return("XSS", true).Run(func(args mock.Arguments) {
		<-ctx.Done() // Simulate work being cancelled
	}).Once()

	// Execute
	enrichedFindings, err := Enrich(ctx, findings, mockProvider)

	// Verify
	// The Enrich function itself doesn't return an error in this specific case, because the *provider*
	// returned (string, false) when it detected the cancellation (as implemented in the Mock).
	// The Enrich loop continues (as only 1 finding exists) and finishes successfully.
	require.NoError(t, err)

	// The finding should remain unenriched because the provider returned false due to cancellation.
	assert.Equal(t, "Original", enrichedFindings[0].Description)

	mockProvider.AssertExpectations(t)
}

// Test Cases: Prioritization (prioritize.go)

// Verifies correct score calculation and descending sort order.
func TestPrioritize_ScoringAndSorting(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	// Input (Unsorted)
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_MED", "", "", ""), NormalizedSeverity: "MEDIUM"},   // 5.0
		{Finding: newRawFinding("F_CRIT", "", "", ""), NormalizedSeverity: "CRITICAL"}, // 10.0
		{Finding: newRawFinding("F_LOW", "", "", ""), NormalizedSeverity: "LOW"},      // 2.5
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	require.Len(t, prioritized, 3)

	// Check Order and Scores
	assert.Equal(t, "F_CRIT", prioritized[0].ID)
	assert.Equal(t, 10.0, prioritized[0].Score)

	assert.Equal(t, "F_MED", prioritized[1].ID)
	assert.Equal(t, 5.0, prioritized[1].Score)

	assert.Equal(t, "F_LOW", prioritized[2].ID)
	assert.Equal(t, 2.5, prioritized[2].Score)
}

// Verifies that findings with unmapped severities receive a default score of 0.0.
func TestPrioritize_UnknownSeverity(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_HIGH", "", "", ""), NormalizedSeverity: "HIGH"},
		// SeverityUnknown is intentionally omitted from defaultTestScoreConfig.
		{Finding: newRawFinding("F_UNKNOWN", "", "", ""), NormalizedSeverity: string(SeverityUnknown)},
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, 7.5, prioritized[0].Score)
	assert.Equal(t, 0.0, prioritized[1].Score, "Unmapped severities must default to 0.0")
}

// Ensures that the sort algorithm is stable (Crucial requirement).
func TestPrioritize_Stability(t *testing.T) {
	t.Parallel()
	config := defaultTestScoreConfig()

	// Input findings ordered A, B, C with the same severity/score.
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F_A", "", "", ""), NormalizedSeverity: "MEDIUM"},
		{Finding: newRawFinding("F_B", "", "", ""), NormalizedSeverity: "MEDIUM"},
		{Finding: newRawFinding("F_C", "", "", ""), NormalizedSeverity: "MEDIUM"},
	}

	// Execute
	prioritized, err := Prioritize(findings, config)

	// Verify
	require.NoError(t, err)
	// The order must be preserved (A, B, C) because the implementation uses sort.SliceStable.
	assert.Equal(t, "F_A", prioritized[0].ID)
	assert.Equal(t, "F_B", prioritized[1].ID)
	assert.Equal(t, "F_C", prioritized[2].ID)
}

// Test Cases: Reporting (report.go)

// Verifies the structure and summary text.
func TestGenerateReport(t *testing.T) {
	t.Parallel()
	findings := []NormalizedFinding{
		{Finding: newRawFinding("F1", "", "", "")},
		{Finding: newRawFinding("F2", "", "", "")},
	}

	// Execute
	report, err := GenerateReport(findings)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, findings, report.Findings)
	assert.Equal(t, "Generated report with 2 prioritized findings.", report.Summary)
}

// Test Cases: Pipeline Integration (pipeline.go)

// Verifies the entire orchestration:
// Normalization (Mapping) -> Enrichment (Mocked) -> Prioritization (Sorting/Scoring).
func TestRunPipeline_EndToEnd(t *testing.T) {
	ctx := context.Background()
	mockProvider := new(MockCWEProvider)

	config := PipelineConfig{
		ScoreConfig: defaultTestScoreConfig(),
		CWEProvider: mockProvider,
	}

	// Input Data: Unsorted, Non-normalized severities, requiring enrichment.
	rawFindings := []schemas.Finding{
		newRawFinding("F_LOW", "low", "", "No CWE"),                      // N: LOW (2.5)
		newRawFinding("F_HIGH", "Important", "CWE-79", "Needs Enrichment"),      // N: HIGH (7.5)
		newRawFinding("F_UNKNOWN", "WeirdLevel", "CWE-89", "Also Needs Enrichment"), // N: UNKNOWN (0.0)
	}

	// Setup Enrichment Expectations (Called in the order findings appear after normalization)
	mockProvider.On("GetFullName", ctx, "CWE-79").Return("XSS", true).Once()
	mockProvider.On("GetFullName", ctx, "CWE-89").Return("SQLi", true).Once()

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, report)
	mockProvider.AssertExpectations(t)

	require.Len(t, report.Findings, 3)

	// Verify Prioritization (Order: F_HIGH, F_LOW, F_UNKNOWN)
	f1 := report.Findings[0]
	f2 := report.Findings[1]
	f3 := report.Findings[2]

	assert.Equal(t, "F_HIGH", f1.ID)
	assert.Equal(t, "F_LOW", f2.ID)
	assert.Equal(t, "F_UNKNOWN", f3.ID)

	// Verify Normalization and Scoring
	assert.Equal(t, "HIGH", f1.NormalizedSeverity)
	assert.Equal(t, 7.5, f1.Score)
	assert.Equal(t, "UNKNOWN", f3.NormalizedSeverity)
	assert.Equal(t, 0.0, f3.Score)

	// Verify Enrichment
	assert.Equal(t, "[XSS] Needs Enrichment", f1.Description)
	assert.Equal(t, "No CWE", f2.Description)
	assert.Equal(t, "[SQLi] Also Needs Enrichment", f3.Description)
}

// Verifies cancellation during the first stage.
func TestRunPipeline_Cancellation_Normalization(t *testing.T) {
	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rawFindings := []schemas.Finding{newRawFinding("F1", "HIGH", "", "")}
	config := PipelineConfig{ScoreConfig: defaultTestScoreConfig()}

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	assert.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "pipeline cancelled during normalization")
	assert.True(t, errors.Is(err, context.Canceled))
}

// Verifies cancellation during the second stage propagates correctly.
func TestRunPipeline_Cancellation_Enrichment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mockProvider := new(MockCWEProvider)

	// We need a finding to pass normalization and reach enrichment.
	rawFindings := []schemas.Finding{newRawFinding("F1", "HIGH", "CWE-79", "")}
	config := PipelineConfig{
		ScoreConfig: defaultTestScoreConfig(),
		CWEProvider: mockProvider,
	}

	// Configure the mock provider to cancel the context when called.
	mockProvider.On("GetFullName", mock.Anything, "CWE-79").Return("XSS", true).Run(func(args mock.Arguments) {
		cancel() // Cancel the context mid-process
	}).Once()

	// Execute
	report, err := RunPipeline(ctx, rawFindings, config)

	// Verify
	// The Enrich function detects the cancellation and the pipeline should report the error.
	assert.Error(t, err)
	assert.Nil(t, report)
	assert.Contains(t, err.Error(), "error enriching findings")
	assert.ErrorIs(t, err, context.Canceled)
}

internal/store/store.go

I corrected the typo from schemasss to schemas.
Go

// xkilldash9x/scalpel-cli/xkilldash9x-scalpel-cli-47ce6b98a12cffe59665d930f51286b2eb1f784c/internal/store/store.go
// internal/store/store.go
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Store provides a PostgreSQL implementation of the Repository interface.
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// New creates a new store instance and verifies the connection.
func New(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) (*Store, error) {
	return &Store{
		pool: pool,
		log:  logger.Named("store"),
	}, nil
}

// handles the database transaction for inserting all data from a result envelope.
func (s *Store) PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if len(envelope.Findings) > 0 {
		if err := s.persistFindings(ctx, tx, envelope.ScanID, envelope.Findings); err != nil {
			return err
		}
	}

	if envelope.KGUpdates != nil {
		if len(envelope.KGUpdates.Nodes) > 0 {
			nodeInputs := make([]schemas.NodeInput, len(envelope.KGUpdates.Nodes))
			for i, n := range envelope.KGUpdates.Nodes {
				nodeInputs[i] = schemas.NodeInput{
					ID:         n.ID,
					Type:       schemas.NodeType(n.Type),
					Properties: n.Properties,
				}
			}
			if err := s.persistNodes(ctx, tx, nodeInputs); err != nil {
				return err
			}
		}
		if len(envelope.KGUpdates.Edges) > 0 {
			edgeInputs := make([]schemas.EdgeInput, len(envelope.KGUpdates.Edges))
			for i, e := range envelope.KGUpdates.Edges {
				edgeInputs[i] = schemas.EdgeInput{
					SourceID:     e.Source,
					TargetID:     e.Target,
					Relationship: schemas.RelationshipType(e.Label),
					Properties:   e.Properties,
				}
			}
			if err := s.persistEdges(ctx, tx, edgeInputs); err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

// inserts findings using the high performance pgx CopyFrom protocol.
func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	rows := make([][]interface{}, len(findings))
	for i, f := range findings {
		rows[i] = []interface{}{
			f.ID, scanID, f.TaskID, f.Timestamp, f.Target, f.Module,
			f.Vulnerability, f.Severity, f.Description, f.Evidence,
			f.Recommendation, f.CWE,
		}
	}

	_, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		[]string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"},
		pgx.CopyFromRows(rows),
	)
	return err
}

// upserts knowledge graph nodes.
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.NodeInput) error {
	rows := make([][]interface{}, len(nodes))
	for i, n := range nodes {
		propertiesJSON, err := json.Marshal(n.Properties)
		if err != nil {
			return fmt.Errorf("failed to marshal node properties for id %s: %w", n.ID, err)
		}
		rows[i] = []interface{}{n.ID, string(n.Type), propertiesJSON}
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"kg_nodes"}, []string{"id", "type", "properties"}, pgx.CopyFromRows(rows))
	return err
}

// upserts knowledge graph edges.
func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.EdgeInput) error {
	rows := make([][]interface{}, len(edges))
	for i, e := range edges {
		propertiesJSON, err := json.Marshal(e.Properties)
		if err != nil {
			return fmt.Errorf("failed to marshal edge properties: %w", err)
		}
		rows[i] = []interface{}{e.SourceID, e.TargetID, string(e.Relationship), propertiesJSON}
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"kg_edges"}, []string{"source_id", "target_id", "relationship", "properties"}, pgx.CopyFromRows(rows))
	return err
}