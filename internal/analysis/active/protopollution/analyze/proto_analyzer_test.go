// Package proto implements the active analysis logic for detecting client-side
// prototype pollution vulnerabilities.
package proto

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- Test Cases --

func TestNewAnalyzer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	cfg := config.NewDefaultConfig()
	// Set to 0 to test the default fallback logic.
	cfg.ScannersCfg.Active.ProtoPollution.WaitDuration = 0

	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	assert.NotNil(t, analyzer)
	assert.Equal(t, logger.Named("pp_analyzer"), analyzer.logger)
	assert.Equal(t, mockBrowserManager, analyzer.browser)
	// Check that the default wait duration is applied correctly.
	assert.Equal(t, 8*time.Second, analyzer.config.Scanners().Active.ProtoPollution.WaitDuration)
}

func TestAnalyze_FindingFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	cfg := config.NewDefaultConfig()
	cfg.ScannersCfg.Active.ProtoPollution.WaitDuration = 150 * time.Millisecond

	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	ctx := context.Background()
	testURL := "http://example.com/test"
	var capturedCanary string
	var reportedFinding schemas.Finding
	var findingReported sync.WaitGroup
	findingReported.Add(1)

	// --- Mocks ---
	mockBrowserManager.On("NewAnalysisContext", ctx, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(mockSession, nil).Once()

	// The callback name is now randomized, so we need to capture it.
	var capturedCallbackName string
	mockSession.On("ExposeFunction", ctx, mock.MatchedBy(func(name string) bool {
		return strings.HasPrefix(name, "sclp_cb_")
	}), mock.AnythingOfType("func(proto.PollutionProofEvent)")).Return(nil).Once().Run(func(args mock.Arguments) {
		capturedCallbackName = args.String(1)
	})

	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil).Once().Run(func(args mock.Arguments) {
		script := args.String(1)
		canaryRe := regexp.MustCompile(`let pollutionCanary = '([^']+)';`)
		canaryMatches := canaryRe.FindStringSubmatch(script)
		require.Len(t, canaryMatches, 2, "Could not find canary in injected script.")
		capturedCanary = canaryMatches[1]

		callbackRe := regexp.MustCompile(`let detectionCallbackName = '([^']+)';`)
		callbackMatches := callbackRe.FindStringSubmatch(script)
		require.Len(t, callbackMatches, 2, "Could not find callback name in injected script.")
		// We assert that the callback name in the script matches the one passed to ExposeFunction.
		assert.Equal(t, capturedCallbackName, callbackMatches[1])
	})

	mockSession.On("AddFinding", ctx, mock.AnythingOfType("schemas.Finding")).Return(nil).Once().Run(func(args mock.Arguments) {
		reportedFinding = args.Get(1).(schemas.Finding)
		findingReported.Done()
	})

	mockSession.On("Navigate", ctx, testURL).Return(nil).Once().Run(func(args mock.Arguments) {
		// Simulate the browser finding a vulnerability after a short delay.
		go func() {
			time.Sleep(20 * time.Millisecond)
			require.NotEmpty(t, capturedCanary, "Canary was not captured before navigation simulation")
			require.NotEmpty(t, capturedCallbackName, "Callback name was not captured before navigation simulation")

			// Use the mock's helper to get the function and call it.
			fn, ok := mockSession.GetExposedFunction(capturedCallbackName)
			require.True(t, ok, "Callback function was not set via ExposeFunction")
			callback, ok := fn.(func(PollutionProofEvent))
			require.True(t, ok, "Exposed function has the wrong signature")

			callback(PollutionProofEvent{
				Source:     "URL_SearchParams",
				Canary:     capturedCanary,
				Vector:     "__proto__[polluted]=true",
				StackTrace: "at trigger (app.js:10)",
			})
		}()
	})

	mockSession.On("Close", mock.Anything).Return(nil).Once()

	// --- Execute ---
	err := analyzer.Analyze(ctx, "task-1", testURL)

	// --- Assertions ---
	require.NoError(t, err)

	waitChan := make(chan struct{})
	go func() {
		findingReported.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		// Finding was reported successfully.
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out waiting for finding to be reported")
	}

	assert.Equal(t, "Client-Side Prototype Pollution", reportedFinding.VulnerabilityName)
	assert.Equal(t, schemas.SeverityHigh, reportedFinding.Severity)
	assert.Equal(t, "task-1", reportedFinding.TaskID)
	assert.Equal(t, testURL, reportedFinding.Target)

	var evidenceData PollutionProofEvent
	err = json.Unmarshal([]byte(reportedFinding.Evidence), &evidenceData)
	require.NoError(t, err)
	assert.Equal(t, capturedCanary, evidenceData.Canary)
	assert.Equal(t, "at trigger (app.js:10)", evidenceData.StackTrace)

	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_NoFinding(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	cfg := config.NewDefaultConfig()
	cfg.ScannersCfg.Active.ProtoPollution.WaitDuration = 50 * time.Millisecond

	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()

	mockBrowserManager.On("NewAnalysisContext", ctx, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(mockSession, nil)
	mockSession.On("ExposeFunction", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("func(proto.PollutionProofEvent)")).Return(nil).Once()
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", ctx, "http://clean.example.com").Return(nil)
	mockSession.On("Close", mock.Anything).Return(nil)

	err := analyzer.Analyze(ctx, "task-clean", "http://clean.example.com")

	assert.NoError(t, err)
	mockSession.AssertNotCalled(t, "AddFinding", mock.Anything, mock.Anything)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_BrowserError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	cfg := config.NewDefaultConfig()
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()
	expectedErr := errors.New("failed to launch browser")

	mockBrowserManager.On("NewAnalysisContext", ctx, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(nil, expectedErr)

	err := analyzer.Analyze(ctx, "task-fail", "http://example.com")

	assert.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Contains(t, err.Error(), "could not initialize browser analysis context")
	mockBrowserManager.AssertExpectations(t)
}

func TestAnalyze_ContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	cfg := config.NewDefaultConfig()
	cfg.ScannersCfg.Active.ProtoPollution.WaitDuration = 5 * time.Second
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	mockBrowserManager.On("NewAnalysisContext", mock.Anything, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(mockSession, nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("func(proto.PollutionProofEvent)")).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", mock.Anything, "http://slow.example.com").Return(nil).Run(func(args mock.Arguments) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
	})
	mockSession.On("Close", mock.Anything).Return(nil)

	startTime := time.Now()
	err := analyzer.Analyze(ctx, "task-cancel", "http://slow.example.com")
	duration := time.Since(startTime)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "Analysis should return a context canceled error")
	assert.Less(t, duration, 1*time.Second, "Analysis should stop quickly after cancellation")

	time.Sleep(20 * time.Millisecond)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_InstrumentationError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	cfg := config.NewDefaultConfig()
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()
	expectedErr := errors.New("browser disconnected")

	mockBrowserManager.On("NewAnalysisContext", ctx, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(mockSession, nil)
	mockSession.On("ExposeFunction", ctx, mock.AnythingOfType("string"), mock.Anything).Return(expectedErr)
	mockSession.On("Close", ctx).Return(nil)

	err := analyzer.Analyze(ctx, "task-instrument-fail", "http://example.com")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to instrument browser session")
	assert.ErrorIs(t, err, expectedErr)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_MismatchedCanary(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	cfg := config.NewDefaultConfig()
	cfg.ScannersCfg.Active.ProtoPollution.WaitDuration = 100 * time.Millisecond
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()

	var capturedCallbackName string
	mockBrowserManager.On("NewAnalysisContext", ctx, cfg, schemas.Persona{}, "", "", (chan<- schemas.Finding)(nil)).Return(mockSession, nil)
	mockSession.On("ExposeFunction", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("func(proto.PollutionProofEvent)")).Return(nil).Run(func(args mock.Arguments) {
		capturedCallbackName = args.String(1)
	})
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", ctx, "http://example.com").Return(nil).Run(func(args mock.Arguments) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			require.NotEmpty(t, capturedCallbackName)
			// Use the mock's helper to get the function and call it.
			fn, ok := mockSession.GetExposedFunction(capturedCallbackName)
			require.True(t, ok, "Callback function was not set via ExposeFunction")
			callback, ok := fn.(func(PollutionProofEvent))
			require.True(t, ok, "Exposed function has the wrong signature")

			callback(PollutionProofEvent{
				Source: "StrayEvent",
				Canary: "wrong_canary",
				Vector: "N/A",
			})
		}()
	})
	mockSession.On("Close", mock.Anything).Return(nil)
	// We do not expect AddFinding to be called.
	mockSession.On("AddFinding", mock.Anything, mock.Anything).Return(nil)

	err := analyzer.Analyze(ctx, "task-mismatch", "http://example.com")

	assert.NoError(t, err)
	mockSession.AssertNotCalled(t, "AddFinding", mock.Anything, mock.Anything)
	mockBrowserManager.AssertExpectations(t)
}

func TestDetermineVulnerability(t *testing.T) {
	tests := []struct {
		source           string
		expectedName     string
		expectedSeverity schemas.Severity
	}{
		{"URL_SearchParams", "Client-Side Prototype Pollution", schemas.SeverityHigh},
		{"Fetch_Response_JSON_payload", "Client-Side Prototype Pollution", schemas.SeverityHigh},
		{"DOM_Clobbering", "DOM Clobbering", schemas.SeverityMedium},
		{"Something_DOM_Clobbering_Related", "DOM Clobbering", schemas.SeverityMedium},
		{"Unknown_Source", "Client-Side Prototype Pollution", schemas.SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			name, _, severity := determineVulnerability(tt.source)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedSeverity, severity)
		})
	}
}

func TestGetRecommendation(t *testing.T) {
	ppRec := getRecommendation("Client-Side Prototype Pollution")
	assert.Contains(t, ppRec, "Object.freeze(Object.prototype)")

	dcRec := getRecommendation("DOM Clobbering")
	assert.Contains(t, dcRec, "Avoid using `id` attributes")

	unknownRec := getRecommendation("Some Other Vulnerability")
	assert.Contains(t, unknownRec, "Object.freeze(Object.prototype)", "Should default to Prototype Pollution recommendation")
}
