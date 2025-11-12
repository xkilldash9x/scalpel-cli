// File: internal/service/components.go
package service

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Components holds all the initialized services required for a scan.
// This struct centralizes the lifecycle management of scan-related dependencies.
// (Moved from cmd/factory.go)
type Components struct {
	Store           schemas.Store
	BrowserManager  schemas.BrowserManager
	KnowledgeGraph  schemas.KnowledgeGraphClient
	TaskEngine      schemas.TaskEngine
	DiscoveryEngine schemas.DiscoveryEngine
	Orchestrator    schemas.Orchestrator
	DBPool          *pgxpool.Pool

	// findingsChan is used to decouple finding generation from persistence.
	findingsChan chan schemas.Finding

	// consumerWG is used to ensure the findings consumer has finished draining the channel.
	consumerWG *sync.WaitGroup

	// BrowserAllocatorCancel is the cancel function for the browser's root allocator context.
	BrowserAllocatorCancel context.CancelFunc
}

// Shutdown gracefully closes all components within a hard timeout. This function
// is designed to be called via defer and handles its own timeout context to ensure
// cleanup happens even if the main scan context is abruptly canceled.
func (c *Components) Shutdown() {
	logger := observability.GetLogger()
	logger.Info("Beginning graceful shutdown sequence...")

	// Create a master shutdown context with a timeout for all cleanup operations.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// 1. Stop Engines: Cease new work generation immediately.
	if c.TaskEngine != nil {
		c.TaskEngine.Stop()
		logger.Debug("Task engine stopped.")
	}
	if c.DiscoveryEngine != nil {
		c.DiscoveryEngine.Stop()
		logger.Debug("Discovery engine stopped.")
	}

	// 2. Signal Findings Consumer to Stop: Close the channel to let it drain.
	if c.findingsChan != nil {
		close(c.findingsChan)
		logger.Debug("Findings channel closed.")
	}

	// 3. Wait for Findings Consumer Gracefully: Wait for it to finish, but with a timeout.
	if c.consumerWG != nil {
		if timedWait(c.consumerWG, 15*time.Second) {
			logger.Debug("Findings consumer finished processing gracefully.")
		} else {
			logger.Warn("Timeout exceeded while waiting for the findings consumer to finish. Some findings may not have been saved.")
		}
	}

	// 4. Shut Down Browser Manager: This manages all active browser sessions.
	if c.BrowserManager != nil {
		if err := c.BrowserManager.Shutdown(shutdownCtx); err != nil {
			logger.Warn("Error during browser manager shutdown.", zap.Error(err))
		} else {
			logger.Debug("Browser manager shut down successfully.")
		}
	}

	// 5. Terminate Root Browser Process: The allocator context cancellation kills the browser.
	if c.BrowserAllocatorCancel != nil {
		c.BrowserAllocatorCancel()
		logger.Debug("Browser allocator context canceled.")
	}

	// 6. Close Database Connection Pool.
	if c.DBPool != nil {
		c.DBPool.Close()
		logger.Debug("Database connection pool closed.")
	}

	logger.Info("Graceful shutdown sequence complete.")
}

// timedWait waits for the WaitGroup for a maximum of the specified duration.
// It returns true if the wait completed, false if it timed out.
func timedWait(wg *sync.WaitGroup, timeout time.Duration) bool {
	// Create a channel that will be closed when the WaitGroup is done.
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()

	// Select will wait for either the done channel to be closed or the timeout to be reached.
	select {
	case <-done:
		return true // Wait completed.
	case <-time.After(timeout):
		return false // Timed out.
	}
}
