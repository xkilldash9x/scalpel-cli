// internal/autofix/watcher_test.go
package autofix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// --- Mock Config for Testing ---

// mockConfig is a mock implementation of the config.Interface for testing purposes.
type mockConfig struct {
	loggerCfg  config.LoggerConfig
	autofixCfg config.AutofixConfig
	// Add other config structs here if needed by other tests
}

// SetBrowserHumanoidKeyHoldMu implements config.Interface.
func (m *mockConfig) SetBrowserHumanoidKeyHoldMu(ms float64) {
	panic("unimplemented")
}

// SetATOConfig implements config.Interface.
func (m *mockConfig) SetATOConfig(atoCfg config.ATOConfig) {
	panic("unimplemented")
}

// JWT implements config.Interface.
func (m *mockConfig) JWT() config.JWTConfig {
	panic("unimplemented")
}

// SetBrowserHumanoidKeyHoldMean implements config.Interface.
func (m *mockConfig) SetBrowserHumanoidKeyHoldMean(ms float64) {
	panic("unimplemented")
}

// SetJWTBruteForceEnabled implements config.Interface.
func (m *mockConfig) SetJWTBruteForceEnabled(bool) {
	panic("unimplemented")
}

// SetJWTEnabled implements config.Interface.
func (m *mockConfig) SetJWTEnabled(bool) {
	panic("unimplemented")
}

// SetBrowserDebug implements config.Interface.
func (m *mockConfig) SetBrowserDebug(bool) {
	panic("unimplemented")
}

// SetBrowserDisableCache implements config.Interface.
func (m *mockConfig) SetBrowserDisableCache(bool) {
	panic("unimplemented")
}

// SetBrowserHeadless implements config.Interface.
func (m *mockConfig) SetBrowserHeadless(bool) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMaxMs implements config.Interface.
func (m *mockConfig) SetBrowserHumanoidClickHoldMaxMs(int) {
	panic("unimplemented")
}

// SetBrowserHumanoidClickHoldMinMs implements config.Interface.
func (m *mockConfig) SetBrowserHumanoidClickHoldMinMs(int) {
	panic("unimplemented")
}

// SetBrowserHumanoidKeyHoldMeanMs implements config.Interface.
func (m *mockConfig) SetBrowserHumanoidKeyHoldMeanMs(float64) {
	panic("unimplemented")
}

// SetBrowserIgnoreTLSErrors implements config.Interface.
func (m *mockConfig) SetBrowserIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetIASTEnabled implements config.Interface.
func (m *mockConfig) SetIASTEnabled(bool) {
	panic("unimplemented")
}

// SetNetworkCaptureResponseBodies implements config.Interface.
func (m *mockConfig) SetNetworkCaptureResponseBodies(bool) {
	panic("unimplemented")
}

// SetNetworkIgnoreTLSErrors implements config.Interface.
func (m *mockConfig) SetNetworkIgnoreTLSErrors(bool) {
	panic("unimplemented")
}

// SetNetworkNavigationTimeout implements config.Interface.
func (m *mockConfig) SetNetworkNavigationTimeout(time.Duration) {
	panic("unimplemented")
}

// Ensure mockConfig satisfies the interface.
var _ config.Interface = (*mockConfig)(nil)

func (m *mockConfig) Logger() config.LoggerConfig          { return m.loggerCfg }
func (m *mockConfig) Autofix() config.AutofixConfig        { return m.autofixCfg }
func (m *mockConfig) Database() config.DatabaseConfig      { return config.DatabaseConfig{} }
func (m *mockConfig) Engine() config.EngineConfig          { return config.EngineConfig{} }
func (m *mockConfig) Browser() config.BrowserConfig        { return config.BrowserConfig{} }
func (m *mockConfig) Network() config.NetworkConfig        { return config.NetworkConfig{} }
func (m *mockConfig) IAST() config.IASTConfig              { return config.IASTConfig{} }
func (m *mockConfig) Scanners() config.ScannersConfig      { return config.ScannersConfig{} }
func (m *mockConfig) Agent() config.AgentConfig            { return config.AgentConfig{} }
func (m *mockConfig) Discovery() config.DiscoveryConfig    { return config.DiscoveryConfig{} }
func (m *mockConfig) Scan() config.ScanConfig              { return config.ScanConfig{} }
func (m *mockConfig) SetScanConfig(sc config.ScanConfig)   {}
func (m *mockConfig) SetDiscoveryMaxDepth(int)             {}
func (m *mockConfig) SetEngineWorkerConcurrency(int)       {}
func (m *mockConfig) SetDiscoveryIncludeSubdomains(bool)   {}
func (m *mockConfig) SetBrowserHumanoidEnabled(bool)       {}
func (m *mockConfig) SetNetworkPostLoadWait(time.Duration) {}

// --- Unit Tests (Parsing) ---

func TestParsePanicLocation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		stackTrace   string
		expectedFile string
		expectedLine int
		expectError  bool
	}{
		{
			name:         "Standard Application Panic",
			stackTrace:   "main.process()\n\t/app/src/processor.go:42\nmain.main()\n\t/app/src/main.go:20",
			expectedFile: "/app/src/processor.go",
			expectedLine: 42,
		},
		{
			name:         "Prioritizes Application Code over Runtime",
			stackTrace:   "sync.(*WaitGroup).Add()\n\t/usr/local/go/src/sync/waitgroup.go:79\nmain.worker()\n\t/app/src/buggy_worker.go:15",
			expectedFile: "/app/src/buggy_worker.go",
			expectedLine: 15,
		},
		{
			name:         "Prioritizes Application Code over Vendor",
			stackTrace:   "github.com/some/library.Do()\n\t/app/vendor/github.com/some/library/client.go:100\nmain.callLibrary()\n\t/app/src/service.go:55",
			expectedFile: "/app/src/service.go",
			expectedLine: 55,
		},
		{
			name:        "No Application Code Found",
			stackTrace:  `runtime.gopanic()\n\t/usr/local/go/src/runtime/panic.go:969`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture loop variable for parallel execution
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file, line, err := parsePanicLocation(tt.stackTrace)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFile, file)
				assert.Equal(t, tt.expectedLine, line)
			}
		})
	}
}

// --- Integration Tests (Log Tailing and Processing) ---

// Helper to setup Watcher for integration tests.
type testHarness struct {
	Watcher     *Watcher
	LogFile     string
	ReportChan  chan PostMortem
	ProjectRoot string
	logMutex    sync.Mutex // FIX: Add a mutex to serialize writes to the log file.
}

func setupWatcherIntegration(t *testing.T) *testHarness {
	t.Helper()
	logger := zaptest.NewLogger(t)
	projectRoot := t.TempDir()
	logFile := filepath.Join(projectRoot, "app.log")

	// Create the log file (required by tail configuration)
	f, err := os.Create(logFile)
	require.NoError(t, err)
	f.Close()

	// Corrected: Use the mockConfig that implements the interface.
	cfg := &mockConfig{
		loggerCfg: config.LoggerConfig{LogFile: logFile},
		// DASTLogPath is intentionally left empty to test the debug log path.
		autofixCfg: config.AutofixConfig{},
	}
	reportChan := make(chan PostMortem, 10) // Buffered for concurrency tests

	watcher, err := NewWatcher(logger, cfg, reportChan, projectRoot)
	require.NoError(t, err)

	return &testHarness{
		Watcher:     watcher,
		LogFile:     logFile,
		ReportChan:  reportChan,
		ProjectRoot: projectRoot,
	}
}

// Helper to simulate writing to the log file atomically.
func (h *testHarness) writeToLog(t *testing.T, content string) {
	t.Helper()
	h.logMutex.Lock() // FIX: Lock before writing to prevent interleaved log entries.
	defer h.logMutex.Unlock()

	f, err := os.OpenFile(h.LogFile, os.O_APPEND|os.O_WRONLY, 0644)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString(content)
	require.NoError(t, err)
	// Small sleep helps ensure the OS notifies the tailer promptly in integration tests
	time.Sleep(10 * time.Millisecond)
}

// Tests the full lifecycle: monitoring, detection, normalization, and reporting.
func TestWatcher_Synchronization(t *testing.T) {
	harness := setupWatcherIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	require.NoError(t, harness.Watcher.Start(ctx))
	time.Sleep(100 * time.Millisecond) // Allow tailer to initialize

	const panicCount = 5
	var writerWg sync.WaitGroup
	writerWg.Add(panicCount)

	expectedFiles := make(map[string]bool)
	// FIX: Use a mutex to protect the 'expectedFiles' map from concurrent writes.
	// This lock is internal to the test and does not involve the Watcher.
	var mapMutex sync.Mutex

	for i := 0; i < panicCount; i++ {
		go func(i int) {
			defer writerWg.Done()
			workerFileRel := fmt.Sprintf(filepath.Join("app", "worker_%d.go"), i)

			// The lock is acquired here, within the test's public-facing API (the test func itself).
			mapMutex.Lock()
			expectedFiles[filepath.ToSlash(workerFileRel)] = true
			mapMutex.Unlock()

			workerFileAbs := filepath.Join(harness.ProjectRoot, workerFileRel)
			panicLog := fmt.Sprintf("panic: Error number %d\n\ngoroutine %d [running]:\nmain.worker()\n\t%s:%d +0x20\n",
				i, i+10, workerFileAbs, i*10+1)
			harness.writeToLog(t, panicLog)
		}(i)
	}

	// Wait for all panics to be written to the log file.
	writerWg.Wait()
	time.Sleep(250 * time.Millisecond) // Give a moment for file system events to propagate

	// Loop to receive all reports, with a timeout for the whole operation.
	receivedReports := make(map[string]bool)
	for len(receivedReports) < panicCount {
		select {
		case report := <-harness.ReportChan:
			receivedReports[report.FilePath] = true
		case <-ctx.Done():
			t.Fatalf("Test timed out. Received %d/%d reports. Missing reports for: %v",
				len(receivedReports),
				panicCount,
				getMissingKeys(expectedFiles, receivedReports),
			)
		}
	}

	// Final verification.
	assert.Equal(t, expectedFiles, receivedReports, "The set of received reports does not match the expected set")
}

// Helper function for better error messages.
func getMissingKeys(expected, actual map[string]bool) []string {
	var missing []string
	for key := range expected {
		if !actual[key] {
			missing = append(missing, key)
		}
	}
	return missing
}
