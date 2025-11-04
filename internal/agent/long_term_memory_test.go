// internal/agent/long_term_memory_test.go
package agent

import ( // This is a comment to force a change
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Helper to set up LTM for testing.
func setupLTMTest(t *testing.T, cfg config.LTMConfig) *ltm {
	t.Helper()
	logger := zaptest.NewLogger(t)
	// We cast to the internal type *ltm to access internal state (cache) for testing.
	ltmInstance := NewLTM(cfg, logger).(*ltm)
	t.Cleanup(func() {
		ltmInstance.Stop()
	})
	return ltmInstance
}

// TestLTM_HeuristicFlagging verifies that observations are correctly flagged based on content.
func TestLTM_HeuristicFlagging(t *testing.T) {
	ltm := setupLTMTest(t, config.LTMConfig{})
	ctx := context.Background()

	tests := []struct {
		name          string
		obs           Observation
		expectedFlags map[string]bool
	}{
		{
			name: "Error Observation",
			obs: Observation{
				Data:   "error-data-unique-1", // Unique data to avoid redundancy flag interference
				Result: ExecutionResult{Status: "failed", ErrorCode: ErrCodeElementNotFound},
			},
			expectedFlags: map[string]bool{FlagError: true, FlagCritical: true},
		},
		{
			name: "Vulnerability Observation",
			obs: Observation{
				Data:   "vuln-data-unique-1",
				Result: ExecutionResult{Status: "success", Findings: []schemas.Finding{{ID: "f1"}}},
			},
			expectedFlags: map[string]bool{FlagVulnerability: true, FlagCritical: true},
		},
		{
			name: "Evolution Result",
			obs: Observation{
				Type:   ObservedEvolutionResult,
				Data:   "evo-data-unique-1",
				Result: ExecutionResult{Status: "success"},
			},
			expectedFlags: map[string]bool{FlagCritical: true},
		},
		{
			name: "Normal Observation",
			obs: Observation{
				Type:   ObservedDOMChange,
				Data:   "dom-data-unique-1",
				Result: ExecutionResult{Status: "success"},
			},
			expectedFlags: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := ltm.ProcessAndFlagObservation(ctx, tt.obs)
			// Remove redundancy flag for this test as it focuses only on heuristics.
			delete(flags, FlagRedundant)
			assert.Equal(t, tt.expectedFlags, flags)
		})
	}
}

// TestLTM_RedundancyDetection verifies the LTM correctly identifies duplicate observation data.
func TestLTM_RedundancyDetection(t *testing.T) {
	ltm := setupLTMTest(t, config.LTMConfig{})
	ctx := context.Background()

	obs1 := Observation{
		ID:     "obs-1",
		Data:   map[string]string{"key": "value", "status": "loaded"},
		Result: ExecutionResult{Status: "success"},
	}

	// 1. Process the first observation
	flags1 := ltm.ProcessAndFlagObservation(ctx, obs1)
	assert.False(t, flags1[FlagRedundant], "First observation should not be redundant")
	assert.Contains(t, ltm.cache, "obs-1")

	// 2. Process an identical observation
	obs2 := Observation{
		ID:     "obs-2",
		Data:   map[string]string{"key": "value", "status": "loaded"}, // Identical data
		Result: ExecutionResult{Status: "success"},
	}
	flags2 := ltm.ProcessAndFlagObservation(ctx, obs2)
	assert.True(t, flags2[FlagRedundant], "Second observation should be redundant")
	assert.NotContains(t, ltm.cache, "obs-2", "Redundant observation should not be cached")

	// 3. Process a different observation
	obs3 := Observation{
		ID:     "obs-3",
		Data:   map[string]string{"key": "value", "status": "updated"}, // Different data
		Result: ExecutionResult{Status: "success"},
	}
	flags3 := ltm.ProcessAndFlagObservation(ctx, obs3)
	assert.False(t, flags3[FlagRedundant], "Third observation should not be redundant")
	assert.Contains(t, ltm.cache, "obs-3")

	// 4. Process observation with different structure but same content (JSON marshal sorts keys)
	obs4 := Observation{
		ID:     "obs-4",
		Data:   map[string]string{"status": "loaded", "key": "value"}, // Same content as obs1
		Result: ExecutionResult{Status: "success"},
	}
	flags4 := ltm.ProcessAndFlagObservation(ctx, obs4)
	assert.True(t, flags4[FlagRedundant], "Fourth observation should be redundant (key order invariant)")
}

// TestLTM_CacheExpiration verifies that the background janitor correctly purges expired cache entries.
func TestLTM_CacheExpiration(t *testing.T) {
	// Configure LTM with a short TTL and fast janitor interval for testing.
	cfg := config.LTMConfig{
		CacheTTLSeconds:             1,
		CacheJanitorIntervalSeconds: 1,
	}
	ltm := setupLTMTest(t, cfg)
	ctx := context.Background()

	// Start the LTM background processes
	ltm.Start()

	obs1 := Observation{ID: "obs-1", Data: "data1"}
	obs2 := Observation{ID: "obs-2", Data: "data2"}

	// Add observations
	ltm.ProcessAndFlagObservation(ctx, obs1)
	ltm.ProcessAndFlagObservation(ctx, obs2)

	require.Len(t, ltm.cache, 2)
	require.Len(t, ltm.payloadHashes, 2)

	// Wait for the janitor to run and expire the entries (TTL=1s, Interval=1s)
	assert.Eventually(t, func() bool {
		ltm.mu.RLock()
		defer ltm.mu.RUnlock()
		return len(ltm.cache) == 0 && len(ltm.payloadHashes) == 0
	}, 3*time.Second, 500*time.Millisecond, "Cache entries did not expire")

	// Verify that the same data is no longer considered redundant
	obs3 := Observation{ID: "obs-3", Data: "data1"} // Same data as obs1
	flags3 := ltm.ProcessAndFlagObservation(ctx, obs3)
	assert.False(t, flags3[FlagRedundant], "Observation should not be redundant after cache expiration")
}

// NEW: TestLTM_Stop ensures the background janitor stops gracefully and Stop is idempotent.
func TestLTM_Stop(t *testing.T) {
	cfg := config.LTMConfig{CacheJanitorIntervalSeconds: 1}
	ltm := setupLTMTest(t, cfg)

	ltm.Start()

	// Allow the janitor to start
	time.Sleep(100 * time.Millisecond)

	// Stop the LTM
	ltm.Stop()

	// Verify that the WaitGroup is done (meaning the janitor goroutine has exited)
	done := make(chan struct{})
	go func() {
		ltm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for LTM background processes to stop")
	}

	// Calling Stop again should be safe (idempotent)
	ltm.Stop()
}

// NEW: TestLTM_DefaultConfigValues ensures defaults are used if config values are zero or negative.
func TestLTM_DefaultConfigValues(t *testing.T) {
	// Configure with zero values
	cfg := config.LTMConfig{
		CacheTTLSeconds:             0,
		CacheJanitorIntervalSeconds: -5,
	}
	ltm := setupLTMTest(t, cfg)

	// Start the LTM. If the default interval wasn't handled, NewTicker might panic.
	ltm.Start()

	// Add an observation
	ltm.ProcessAndFlagObservation(context.Background(), Observation{ID: "obs-1", Data: "data1"})

	// Manually trigger purge. If the default TTL (5 min) wasn't used and TTL was 0, it would be purged immediately.
	ltm.purgeExpiredCache()

	ltm.mu.RLock()
	assert.Len(t, ltm.cache, 1, "Cache should not be purged immediately if default TTL is used")
	ltm.mu.RUnlock()

	ltm.Stop()
}
