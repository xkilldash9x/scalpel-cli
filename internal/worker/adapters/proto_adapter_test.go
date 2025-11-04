// File: internal/worker/adapters/proto_adapter_test.go
package adapters_test

import (
	"context"
	"sync"
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// -- Test Suite Setup --

// testSetup holds all the components needed for a single test case.
type testSetup struct {
	adapter       *adapters.ProtoAdapter // Use the actual type
	mockLogger    *zap.Logger
	mockBrowser   *mocks.MockBrowserManager
	mockConfig    *mocks.MockConfig
	task          *schemas.Task
	globalContext *core.GlobalContext
}

// setup creates a fresh test environment for each test case.
func setup(t *testing.T) *testSetup {
	t.Helper()

	// Initialize components using mocks.
	logger := zaptest.NewLogger(t)
	browserManager := &mocks.MockBrowserManager{}
	cfg := &mocks.MockConfig{}

	task := &schemas.Task{
		TaskID:    "test-task-123",
		TargetURL: "https://example.com",
		Type:      schemas.TaskAnalyzeWebPageProtoPP,
	}

	globalCtx := &core.GlobalContext{
		BrowserManager: browserManager,
		Config:         cfg,
	}

	return &testSetup{
		adapter:       adapters.NewProtoAdapter(), // Use the constructor
		mockLogger:    logger,
		mockBrowser:   browserManager,
		mockConfig:    cfg,
		task:          task,
		globalContext: globalCtx,
	}
}

// -- Unit Tests --

func TestProtoAdapter_Metadata(t *testing.T) {
	adapter := adapters.NewProtoAdapter()
	assert.Equal(t, "ProtoAdapter", adapter.Name())
	assert.Contains(t, adapter.Description(), "Analyzes web pages for client-side prototype pollution")
	assert.Equal(t, core.TypeActive, adapter.Type())
}

func TestProtoAdapter_UnitTests(t *testing.T) {
	testCases := []struct {
		name          string
		setupModifier func(ts *testSetup)
		expectError   bool
		expectedErr   string
	}{
		{
			name: "Success Case: Valid task with scanner enabled",
			setupModifier: func(ts *testSetup) {
				// Mock config: enabled
				scannersConfig := config.ScannersConfig{
					Active: config.ActiveScannersConfig{
						ProtoPollution: config.ProtoPollutionConfig{Enabled: true},
					},
				}
				ts.mockConfig.On("Scanners").Return(scannersConfig)

				// Mock the browser manager interaction required by the underlying analyzer.
				mockSession := mocks.NewMockSessionContext()
				ts.mockBrowser.On("NewAnalysisContext",
					mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything,
				).Return(mockSession, nil)
				mockSession.On("Close", mock.Anything).Return(nil)
				// Mocks required by the underlying proto analyzer implementation
				mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
				mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Skipped Case: Scanner is disabled",
			setupModifier: func(ts *testSetup) {
				// Mock config: disabled
				scannersConfig := config.ScannersConfig{
					Active: config.ActiveScannersConfig{
						ProtoPollution: config.ProtoPollutionConfig{Enabled: false},
					},
				}
				ts.mockConfig.On("Scanners").Return(scannersConfig)
			},
			expectError: false, // Skipping is not an error
		},
		{
			name: "Failure Case: Missing TargetURL",
			setupModifier: func(ts *testSetup) {
				ts.task.TargetURL = ""
			},
			expectError: true,
			expectedErr: "TargetURL is required",
		},
		{
			name: "Failure Case: GlobalContext is missing",
			// No setupModifier needed, we modify the analysisCtx directly in the test runner loop.
			setupModifier: nil,
			expectError:   true,
			expectedErr:   "GlobalContext is required",
		},
		{
			name: "Failure Case: BrowserManager is missing",
			setupModifier: func(ts *testSetup) {
				ts.globalContext.BrowserManager = nil
			},
			expectError: true,
			expectedErr: "browser manager is required",
		},
		{
			name: "Failure Case: Config is missing",
			setupModifier: func(ts *testSetup) {
				ts.globalContext.Config = nil
			},
			expectError: true,
			expectedErr: "configuration is not available",
		},
		{
			name: "Context Handling: Canceled before execution",
			// No setupModifier needed, we control the context in the test runner loop.
			setupModifier: nil,
			expectError:   true,
			expectedErr:   "context canceled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := setup(t)
			if tc.setupModifier != nil {
				tc.setupModifier(ts)
			}

			analysisCtx := &core.AnalysisContext{
				Task:   *ts.task,
				Logger: ts.mockLogger,
				Global: ts.globalContext,
			}

			// Specific modification for the "GlobalContext is missing" case.
			if tc.name == "Failure Case: GlobalContext is missing" {
				analysisCtx.Global = nil
			}

			var ctx context.Context
			var cancel context.CancelFunc

			// Specific context setup for the cancellation case.
			if tc.name == "Context Handling: Canceled before execution" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel() // Cancel immediately
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				defer cancel()
			}

			err := ts.adapter.Analyze(ctx, analysisCtx)

			if tc.expectError {
				require.Error(t, err)
				if tc.expectedErr != "" {
					assert.Contains(t, err.Error(), tc.expectedErr)
				}
			} else {
				require.NoError(t, err)
			}

			// Verify that all mock expectations were met.
			ts.mockConfig.AssertExpectations(t)
			ts.mockBrowser.AssertExpectations(t)
		})
	}
}

// TestProtoAdapter_ContextCancellation_DuringAnalysis ensures the adapter respects
// context cancellation that occurs *during* a simulated analysis.
func TestProtoAdapter_ContextCancellation_DuringAnalysis(t *testing.T) {
	ts := setup(t)

	// Configure scanner enabled with long duration.
	scannersConfig := config.ScannersConfig{
		Active: config.ActiveScannersConfig{
			ProtoPollution: config.ProtoPollutionConfig{
				Enabled:      true,
				WaitDuration: 10 * time.Second,
			},
		},
	}
	ts.mockConfig.On("Scanners").Return(scannersConfig)

	// Setup browser manager mocks.
	mockSession := mocks.NewMockSessionContext()
	ts.mockBrowser.On("NewAnalysisContext",
		mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(mockSession, nil)
	mockSession.On("Close", mock.Anything).Return(nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Mock Navigate to block until the context is canceled.
	mockSession.On("Navigate", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		// Wait for the context passed to Navigate to be Done.
		<-args.Get(0).(context.Context).Done()
	}).Return(context.DeadlineExceeded) // Return the context error.

	analysisCtx := &core.AnalysisContext{
		Task:   *ts.task,
		Logger: ts.mockLogger,
		Global: ts.globalContext,
	}

	// Create a context with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Run the analysis in a goroutine.
	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		err = ts.adapter.Analyze(ctx, analysisCtx)
	}()

	wg.Wait()

	// Assertions: We expect the adapter to return the context error.
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Expected a context deadline exceeded error")

	// Verify mocks.
	ts.mockConfig.AssertExpectations(t)
	ts.mockBrowser.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

// -- Fuzz Testing --
// Fuzz tests ensure robustness against unexpected inputs.

// FuzzProtoAdapter_Analyze provides a fuzz test for the Analyze method using basic inputs.
func FuzzProtoAdapter_Analyze(f *testing.F) {
	// Seed corpus
	f.Add("https://example.com", "task-seed-1", true)
	f.Add("http://test.internal/path", "task-seed-2", false)
	f.Add("", "task-seed-3", true)

	f.Fuzz(func(t *testing.T, targetURL string, taskID string, scannerEnabled bool) {
		t.Parallel() // Run fuzz inputs in parallel

		// Setup environment for fuzzing (Nop loggers and mocks)
		logger := zap.NewNop()
		browserManager := &mocks.MockBrowserManager{}
		cfg := &mocks.MockConfig{}

		// Configure mocks based on fuzzed input.
		scannersConfig := config.ScannersConfig{
			Active: config.ActiveScannersConfig{
				ProtoPollution: config.ProtoPollutionConfig{Enabled: scannerEnabled},
			},
		}
		// Only set the expectation if the config is actually needed (i.e., URL is not empty).
		if targetURL != "" {
			cfg.On("Scanners").Return(scannersConfig)
		}

		// Mock browser interaction if the path leads to execution.
		if scannerEnabled && targetURL != "" {
			mockSession := mocks.NewMockSessionContext()
			browserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
			mockSession.On("Close", mock.Anything).Return(nil)
			// Add necessary mocks required by the underlying analyzer to prevent panics.
			mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
			mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil)
		}

		// Prepare context
		task := &schemas.Task{
			TaskID:    taskID,
			TargetURL: targetURL,
			Type:      schemas.TaskAnalyzeWebPageProtoPP,
		}
		globalCtx := &core.GlobalContext{
			BrowserManager: browserManager,
			Config:         cfg,
		}
		analysisCtx := &core.AnalysisContext{
			Task:   *task,
			Logger: logger,
			Global: globalCtx,
		}

		// Execute
		adapter := adapters.NewProtoAdapter()
		err := adapter.Analyze(context.Background(), analysisCtx)

		// Basic validation: if the input URL is empty, we MUST get an error.
		if targetURL == "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), "TargetURL is required")
		}
	})
}

// FuzzProtoAdapter_Analyze_Structured fuzzes the entire AnalysisContext structure.
func FuzzProtoAdapter_Analyze_Structured(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		analysisCtx := &core.AnalysisContext{}

		// Attempt to populate the struct from fuzzed data.
		err := fuzzConsumer.GenerateStruct(analysisCtx)
		if err != nil {
			return // Ignore inputs that can't be mapped to the struct.
		}

		// --- Sanitization for Fuzzing ---
		// Ensure required pointers are not nil to prevent trivial panics.

		if analysisCtx.Logger == nil {
			analysisCtx.Logger = zap.NewNop()
		}

		// If Global context is generated, ensure its components are safe.
		if analysisCtx.Global != nil {
			if analysisCtx.Global.Config == nil {
				// Provide a mock config that returns safe defaults.
				mockCfg := &mocks.MockConfig{}
				// Only set the expectation if the URL is valid, otherwise the mock might not be called if validation fails early.
				if analysisCtx.Task.TargetURL != "" {
					mockCfg.On("Scanners").Return(config.ScannersConfig{})
				}
				analysisCtx.Global.Config = mockCfg
			}
			if analysisCtx.Global.BrowserManager == nil {
				// Provide a mock browser manager.
				analysisCtx.Global.BrowserManager = &mocks.MockBrowserManager{}
			}
		}

		adapter := adapters.NewProtoAdapter()
		ctx := context.Background()

		// Gracefully catch any panics during execution.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Caught a panic during structured fuzzing: %v", r)
			}
		}()

		// Execute the function. The goal is survival without panicking.
		_ = adapter.Analyze(ctx, analysisCtx)
	})
}
