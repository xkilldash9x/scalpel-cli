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
}

// Shutdown gracefully closes all components, ensuring resources are released in the correct order.
func (c *Components) Shutdown() {
	logger := observability.GetLogger()
	logger.Debug("Beginning components shutdown sequence.")

	// 1. Stop the engines first (Producers) to cease generating new work.
	if c.TaskEngine != nil {
		c.TaskEngine.Stop()
		logger.Debug("Task engine stopped.")
	}

	if c.DiscoveryEngine != nil {
		c.DiscoveryEngine.Stop()
		logger.Debug("Discovery engine stopped.")
	}

	// 2. Close the findings channel. This signals the consumer to drain and stop.
	if c.findingsChan != nil {
		close(c.findingsChan)
		logger.Debug("Findings channel closed.")
	}

	// 3. Wait for the consumer to finish processing the drained channel.
	if c.consumerWG != nil {
		// The StartFindingsConsumer ensures the WaitGroup is decremented upon completion,
		// including after draining the final batch.
		c.consumerWG.Wait()
		logger.Debug("Findings consumer finished processing.")
	}

	// 4. Shut down the browser manager.
	if c.BrowserManager != nil {
		// Use a separate context with a timeout for shutdown to ensure it completes
		// even if the main application context was canceled.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := c.BrowserManager.Shutdown(shutdownCtx); err != nil {
			logger.Warn("Error during browser manager shutdown.", zap.Error(err))
		} else {
			logger.Debug("Browser manager shut down.")
		}
	}

	// 5. Close the database connection pool.
	// This is closed here if the pool was created by the ComponentFactory (i.e., during a scan).
	// If a component initializes the KG independently (e.g., 'evolve'), it is responsible for its cleanup.
	if c.DBPool != nil {
		c.DBPool.Close()
		logger.Debug("Database connection pool closed.")
	}

	logger.Info("All scan components shut down successfully.")
}