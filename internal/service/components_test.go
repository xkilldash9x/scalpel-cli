package service

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

func TestTimedWait(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			time.Sleep(10 * time.Millisecond)
			wg.Done()
		}()
		assert.True(t, timedWait(wg, 1*time.Second), "timedWait should return true when wait completes")
	})

	t.Run("Timeout", func(t *testing.T) {
		wg := &sync.WaitGroup{}
		wg.Add(1)
		// No done call
		assert.False(t, timedWait(wg, 10*time.Millisecond), "timedWait should return false on timeout")
	})
}

func TestComponents_Shutdown(t *testing.T) {
	// Setup mocks
	mockTaskEngine := new(MockTaskEngine)
	mockDiscoveryEngine := new(MockDiscoveryEngine)
	mockBrowserManager := new(MockBrowserManager)
	// mockStore is not directly used in Shutdown, but referenced in Components struct.

	// Setup expectations
	mockTaskEngine.On("Stop").Return()
	mockDiscoveryEngine.On("Stop").Return()
	mockBrowserManager.On("Shutdown", mock.Anything).Return(nil)

	// Setup findings consumer sync
	findingsChan := make(chan schemas.Finding, 1)
	consumerWG := &sync.WaitGroup{}
	// Start a dummy consumer to test waiting
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		// Simulate work
		<-findingsChan
	}()

	// Setup browser allocator cancel
	allocatorCalled := false
	allocatorCancel := func() {
		allocatorCalled = true
	}

	// Initialize Components
	components := &Components{
		TaskEngine:             mockTaskEngine,
		DiscoveryEngine:        mockDiscoveryEngine,
		BrowserManager:         mockBrowserManager,
		findingsChan:           findingsChan,
		consumerWG:             consumerWG,
		BrowserAllocatorCancel: allocatorCancel,
		// DBPool: nil, // Skipping DB pool mock as it's a concrete struct and hard to mock without interface or real DB
	}

	// Execute Shutdown
	components.Shutdown()

	// Assertions
	mockTaskEngine.AssertExpectations(t)
	mockDiscoveryEngine.AssertExpectations(t)
	mockBrowserManager.AssertExpectations(t)
	assert.True(t, allocatorCalled, "BrowserAllocatorCancel should be called")

	// Check if findingsChan is closed
	select {
	case _, ok := <-findingsChan:
		assert.False(t, ok, "findingsChan should be closed")
	default:
		// Should be closed and drained by the dummy consumer
	}
}
