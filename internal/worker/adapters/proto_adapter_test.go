// File: internal/worker/adapters/proto_adapter_test.go
package adapters

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
)

// -- Test Suite Setup --

// testSetup holds all the components needed for a single test case.
type testSetup struct {
	adapter       *ProtoAdapter
	mockLogger    *zap.Logger
	mockBrowser   *mocks.MockBrowserManager
	mockConfig    *mocks.MockConfig
	task          *schemas.Task
	globalContext *core.GlobalContext
}

// setup creates a fresh test environment for each test case.
// This is key to ensuring tests are isolated and don't interfere with each other.
func setup(t *testing.T) *testSetup {
	t.Helper()

	// Initialize components using mocks from the global mocks package.
	logger := zaptest.NewLogger(t)
	browserManager := &mocks.MockBrowserManager{}
	// Use the mock config for better isolation and control.
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
		adapter:       NewProtoAdapter(),
		mockLogger:    logger,
		mockBrowser:   browserManager,
		mockConfig:    cfg,
		task:          task,
		globalContext: globalCtx,
	}
}

// -- Unit Tests --

func TestProtoAdapter_UnitTests(t *testing.T) {
	// Test cases are defined as a table to cover various scenarios clearly.
	// This approach makes it easy to add new tests and understand the coverage.
	testCases := []struct {
		name          string
		setupModifier func(ts *testSetup)
		expectError   bool
		expectedErr   string
	}{
		{
			name: "Success Case: Valid task with scanner enabled",
			setupModifier: func(ts *testSetup) {
				// Mock config to say the scanner is enabled
				scannersConfig := config.ScannersConfig{
					Active: config.ActiveScannersConfig{
						ProtoPollution: config.ProtoPollutionConfig{Enabled: true},
					},
				}
				ts.mockConfig.On("Scanners").Return(scannersConfig)

				// Mock the browser manager interaction that was causing the panic.
				mockSession := mocks.NewMockSessionContext()
				ts.mockBrowser.On("NewAnalysisContext",
					mock.Anything, mock.Anything, mock.Anything,
					mock.Anything, mock.Anything, mock.Anything,
				).Return(mockSession, nil)
				mockSession.On("Close", mock.Anything).Return(nil)
				mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
				mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Skipped Case: Scanner is disabled in configuration",
			setupModifier: func(ts *testSetup) {
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
			name: "Failure Case: Task is missing the required TargetURL",
			setupModifier: func(ts *testSetup) {
				ts.task.TargetURL = ""
				// No config mock needed as validation fails before config is accessed.
			},
			expectError: true,
			expectedErr: "TargetURL is required",
		},
		{
			name: "Failure Case: GlobalContext is missing from AnalysisContext",
			setupModifier: func(ts *testSetup) {
				// This modifier will be applied before the analysis context is created for the test.
			},
			expectError: true,
			expectedErr: "GlobalContext is required",
		},
		{
			name: "Failure Case: BrowserManager is missing from GlobalContext",
			setupModifier: func(ts *testSetup) {
				ts.globalContext.BrowserManager = nil
			},
			expectError: true,
			expectedErr: "browser manager is required",
		},
		{
			name: "Failure Case: Config is missing from GlobalContext",
			setupModifier: func(ts *testSetup) {
				ts.globalContext.Config = nil
			},
			expectError: true,
			expectedErr: "configuration is not available",
		},
		{
			name: "Context Handling: Context is canceled before execution",
			setupModifier: func(ts *testSetup) {
				// Removed the mock expectation for `Scanners()`.
				// The adapter should return immediately due to the
				// ctx.Err() check at the top of Analyze(),
				// so no mocks will be called.
			},
			expectError: true,
			expectedErr: "context canceled",
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

			if tc.name == "Failure Case: GlobalContext is missing from AnalysisContext" {
				analysisCtx.Global = nil
			}

			var ctx context.Context
			var cancel context.CancelFunc

			if tc.name == "Context Handling: Context is canceled before execution" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel() // Cancel immediately
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()

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
	scannersConfig := config.ScannersConfig{
		Active: config.ActiveScannersConfig{
			ProtoPollution: config.ProtoPollutionConfig{
				Enabled:      true,
				WaitDuration: 10 * time.Second, // Long duration to ensure it would block without cancellation
			},
		},
	}
	ts.mockConfig.On("Scanners").Return(scannersConfig)

	// Add the required mock setup to prevent the initial panic.
	// This allows the test to proceed to the part where it actually tests the timeout.
	mockSession := mocks.NewMockSessionContext()
	ts.mockBrowser.On("NewAnalysisContext",
		mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(mockSession, nil)
	mockSession.On("Close", mock.Anything).Return(nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Add missing mock for InjectScriptPersistently to prevent panic
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Add mock for Navigate and make it block until context is canceled
	mockSession.On("Navigate", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		// Wait for the context passed to Navigate to be Done
		<-args.Get(0).(context.Context).Done()
	}).Return(context.DeadlineExceeded)

	analysisCtx := &core.AnalysisContext{
		Task:   *ts.task,
		Logger: ts.mockLogger,
		Global: ts.globalContext,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	var err error
	go func() {
		defer wg.Done()
		err = ts.adapter.Analyze(ctx, analysisCtx)
	}()

	wg.Wait()

	// We expect an error related to the context being done.
	require.Error(t, err)
	assert.ErrorContains(t, err, context.DeadlineExceeded.Error(), "Expected a context deadline exceeded error")
}

// TestProtoAdapter_Metadata verifies that the adapter's metadata methods
// return the expected constant values.
func TestProtoAdapter_Metadata(t *testing.T) {
	adapter := NewProtoAdapter()
	assert.Equal(t, "ProtoAdapter", adapter.Name())
	assert.Equal(t, "Analyzes web pages for prototype pollution vulnerabilities.", adapter.Description())
	assert.Equal(t, core.TypeActive, adapter.Type())
}

// -- Fuzz Testing --

// FuzzProtoAdapter_Analyze provides a fuzz test for the Analyze method.
func FuzzProtoAdapter_Analyze(f *testing.F) {
	f.Add("https://example.com", "task-seed-1", true)
	f.Add("http://test.internal/path", "task-seed-2", false)
	f.Add("", "task-seed-3", true) // Empty URL

	f.Fuzz(func(t *testing.T, targetURL string, taskID string, scannerEnabled bool) {
		// Using a subtest for each fuzz input for better isolation
		// Corrected invalid syntax func(t, *testing.T) to func(t *testing.T)
		t.Run("Fuzz", func(t *testing.T) {
			t.Parallel() // Run fuzz inputs in parallel
			logger := zap.NewNop()
			browserManager := &mocks.MockBrowserManager{}
			cfg := &mocks.MockConfig{}

			// Set up mock based on fuzzed input.
			scannersConfig := config.ScannersConfig{
				Active: config.ActiveScannersConfig{
					ProtoPollution: config.ProtoPollutionConfig{Enabled: scannerEnabled},
				},
			}
			cfg.On("Scanners").Return(scannersConfig)

			// Add mock setup for browser manager if the scanner is enabled
			// and the URL is valid, which is the path where it would be called.
			if scannerEnabled && targetURL != "" {
				mockSession := mocks.NewMockSessionContext()
				browserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
				mockSession.On("Close", mock.Anything).Return(nil)
				mockSession.On("ExposeFunction",
					mock.Anything, mock.Anything, mock.Anything).Return(nil)
				// Add missing mocks to prevent panics during fuzzing
				mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
				mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil)
			}

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

			adapter := NewProtoAdapter()
			err := adapter.Analyze(context.Background(), analysisCtx)

			// Basic validation: if the input URL is empty, we MUST get an error.
			if targetURL == "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "TargetURL is required")
			}
		})
	})
}

// FuzzProtoAdapter_Analyze_Structured fuzzes the entire AnalysisContext.
func FuzzProtoAdapter_Analyze_Structured(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		analysisCtx := &core.AnalysisContext{}

		err := fuzzConsumer.GenerateStruct(analysisCtx)
		if err != nil {
			return // Ignore inputs that can't be mapped to our struct.
		}

		// Ensure logger is not nil to prevent panics in the tested code.
		if analysisCtx.Logger == nil {
			analysisCtx.Logger = zap.NewNop()
		}

		// Prevent panics from nil pointers when fuzzer generates a valid Global context.
		if analysisCtx.Global != nil {
			if analysisCtx.Global.Config == nil {
				mockCfg := &mocks.MockConfig{}
				// Return a default, safe value to allow fuzzing to proceed.
				mockCfg.On("Scanners").Return(config.ScannersConfig{})
				analysisCtx.Global.Config = mockCfg
			}
			if analysisCtx.Global.BrowserManager == nil {
				analysisCtx.Global.BrowserManager = &mocks.MockBrowserManager{}
			}
		}

		adapter := NewProtoAdapter()
		ctx := context.Background()

		// Gracefully catch any panics, report them as a test failure,
		//
		// and continue fuzzing.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Caught a panic: %v", r)
			}
		}()

		_ = adapter.Analyze(ctx, analysisCtx)
		// We don't assert on the error here.
		// The goal is simply to survive
		// the execution without panicking, no matter how malformed the input struct is.
	})
}
