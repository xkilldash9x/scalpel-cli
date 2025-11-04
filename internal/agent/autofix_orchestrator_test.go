// internal/agent/autofix_orchestrator_test.go
package agent

import ( // This is a comment to force a change
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// Note: Testing the core workflow (processReport) requires mocking the dependencies
// (Watcher, Analyzer, Developer). Since these are implemented using concrete types
// in the provided source code (e.g., *autofix.Analyzer) rather than interfaces,
// we cannot easily inject mocks without refactoring autofix_orchestrator.go.
// Therefore, these tests focus on initialization, helper functions, and standalone logic (like cooldown).

// TestNewSelfHealOrchestrator_Initialization checks various initialization scenarios based on configuration.
func TestNewSelfHealOrchestrator_Initialization(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockLLM := new(mocks.MockLLMClient)

	t.Run("DisabledConfig", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		autofixCfg := cfg.Autofix()
		autofixCfg.Enabled = false
		t.Logf("Testing with Autofix.Enabled = %v", autofixCfg.Enabled)
		orch, err := NewSelfHealOrchestrator(logger, cfg, mockLLM)
		require.NoError(t, err)
		assert.Nil(t, orch)
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		autofixCfg := cfg.Autofix()
		autofixCfg.Enabled = true
		t.Logf("Testing with Autofix.Enabled = %v", autofixCfg.Enabled)
		// MinConfidenceThreshold > 1.0 is invalid according to Validate() (assuming implementation in config package)
		// We rely on the fact that the default config package provides this validation.
		// If we assume the config package validation works:
		autofixCfg.MinConfidenceThreshold = 1.5
		t.Logf("Testing with Autofix.MinConfidenceThreshold = %v", autofixCfg.MinConfidenceThreshold)
		orch, err := NewSelfHealOrchestrator(logger, cfg, mockLLM)
		// The implementation logs an error but returns nil, nil on invalid config.
		require.NoError(t, err)
		assert.Nil(t, orch)
	})
}

// TestSelfHealOrchestrator_CooldownLogic verifies the cooldown mechanism independently.
func TestSelfHealOrchestrator_CooldownLogic(t *testing.T) {
	// Initialize the orchestrator struct directly for unit testing the logic.
	cfg := config.AutofixConfig{CooldownSeconds: 1}
	orch := &SelfHealOrchestrator{
		logger:        zaptest.NewLogger(t),
		autofixCfg:    &cfg,
		cooldownCache: make(map[string]time.Time),
	}

	testFile := "src/app/buggy.go"

	// 1. Not in cooldown initially
	assert.False(t, orch.isInCooldown(testFile))

	// 2. Update cooldown
	orch.updateCooldown(testFile)
	assert.True(t, orch.isInCooldown(testFile))

	// 3. Verify another file is not in cooldown
	assert.False(t, orch.isInCooldown("other_file.go"))

	// 4. Wait for expiration (CooldownSeconds: 1)
	time.Sleep(1100 * time.Millisecond)

	// 5. Check again (should be expired)
	assert.False(t, orch.isInCooldown(testFile), "Cooldown should have expired")

	// 6. Verify cache cleanup after expiration check
	orch.cooldownMu.Lock()
	_, exists := orch.cooldownCache[testFile]
	orch.cooldownMu.Unlock()
	assert.False(t, exists, "Cache entry should be deleted after expired check")
}

// TestDetermineSourceProjectRoot tests the logic for finding the project root directory.
func TestDetermineSourceProjectRoot(t *testing.T) {
	t.Run("Configured Root (Valid Absolute)", func(t *testing.T) {
		// Use the current working directory as a known valid path
		cwd, err := os.Getwd()
		require.NoError(t, err)

		root, err := determineSourceProjectRoot(cwd)
		require.NoError(t, err)
		assert.Equal(t, cwd, root)
	})

	t.Run("Configured Root (Valid Relative)", func(t *testing.T) {
		// Test relative path
		relPath := "."
		absPath, err := filepath.Abs(relPath)
		require.NoError(t, err)

		root, err := determineSourceProjectRoot(relPath)
		require.NoError(t, err)
		assert.Equal(t, absPath, root)
	})

	// Testing invalid paths robustly is difficult as filepath.Abs behavior varies by OS and might not error on non-existent paths.

	t.Run("Fallback (Git or CWD)", func(t *testing.T) {
		// This tests the behavior when configuredRoot is empty.
		// It attempts Git detection, then falls back to CWD.

		cwd, err := os.Getwd()
		require.NoError(t, err)

		root, err := determineSourceProjectRoot("")
		require.NoError(t, err)

		// Check if git is present and if we are in a repo in the test environment
		if _, err := exec.LookPath("git"); err == nil {
			cmd := exec.Command("git", "rev-parse", "--show-toplevel")
			output, err := cmd.Output()
			if err == nil {
				// We are in a git repo, expect the git root
				expectedRoot := strings.TrimSpace(string(output))
				// Use filepath.Clean for robust comparison across different OS path separators
				assert.Equal(t, filepath.Clean(expectedRoot), filepath.Clean(root))
				return
			}
		}

		// Otherwise, expect CWD
		assert.Equal(t, cwd, root)
	})
}

// TestStart_NilOrchestrator ensures Start and WaitForShutdown handle nil receiver gracefully.
func TestStart_NilOrchestrator(t *testing.T) {
	var orch *SelfHealOrchestrator
	// Should not panic
	assert.NotPanics(t, func() {
		orch.Start(context.Background())
	})
	assert.NotPanics(t, func() {
		orch.WaitForShutdown()
	})
}
