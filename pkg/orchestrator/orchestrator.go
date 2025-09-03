// pkg/orchestrator/orchestrator.go
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/discovery"
	"github.com/xkilldash9x/scalpel-cli/pkg/engine"
	"github.com/xkilldash9x/scalpel-cli/pkg/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/pkg/store"
	"go.uber.org/zap"
)

// Orchestrator manages the entire lifecycle of a scan.
type Orchestrator struct {
	cfg    *config.Config
	logger *zap.Logger
}

// New creates a new Orchestrator.
func New(cfg *config.Config, logger *zap.Logger) (*Orchestrator, error) {
	return &Orchestrator{cfg: cfg, logger: logger}, nil
}

// StartScan initializes all services and runs the scan to completion.
// It now returns the unique scanID for reporting purposes.
func (o *Orchestrator) StartScan(ctx context.Context, targets []string) (string, error) {
	scanID := uuid.New().String()

	// Create a derived context for this specific scan execution.
	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan() // Ensure cancellation happens when StartScan exits for any reason.

	o.logger.Info("Initializing services for scan", zap.Strings("targets", targets), zap.String("scanID", scanID))

	// Initialize Store (PostgreSQL)
	storeService, err := store.New(scanCtx, o.cfg.Postgres.URL, o.logger)
	if err != nil {
		return scanID, fmt.Errorf("failed to initialize store: %w", err)
	}
	defer func() {
		if err := storeService.Close(); err != nil {
			o.logger.Error("Failed to close store service cleanly", zap.Error(err))
		}
	}()

	// Initialize Knowledge Graph (PostgreSQL-backed)
	kg, err := knowledgegraph.NewPostgresKG(scanCtx, storeService.GetPool(), o.logger)
	if err != nil {
		return scanID, fmt.Errorf("failed to initialize knowledge graph: %w", err)
	}

	// Initialize Browser Manager
	browserManager, err := browser.NewManager(scanCtx, o.logger, o.cfg)
	if err != nil {
		return scanID, fmt.Errorf("failed to initialize browser manager: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := browserManager.Shutdown(shutdownCtx); err != nil {
			o.logger.Error("Error during browser manager shutdown", zap.Error(err))
		}
	}()

	// Initialize Task Engine
	taskEngine, err := engine.New(o.cfg, o.logger, storeService, browserManager, kg)
	if err != nil {
		return scanID, fmt.Errorf("failed to initialize task engine: %w", err)
	}

	// Initialize Discovery Engine
	discoveryEngine, err := discovery.New(o.cfg, taskEngine, browserManager, kg, o.logger)
	if err != nil {
		return scanID, fmt.Errorf("failed to initialize discovery engine: %w", err)
	}
	
	// 1. Start Engine Workers (launches background workers and returns immediately)
	taskEngine.Start(scanCtx)

	// 2. Start Discovery (This blocks until discovery is complete)
	discoveryErr := discoveryEngine.Start(scanCtx, targets, scanID)

	// 3. Discovery is finished. Signal the engine to stop and wait for it to drain.
	o.logger.Info("Discovery phase ended, waiting for task engine to drain...")
	taskEngine.Stop() // Stop signals workers to stop and blocks until drained.

	if discoveryErr != nil {
		return scanID, fmt.Errorf("discovery phase failed: %w", discoveryErr)
	}

	o.logger.Info("Orchestration complete.", zap.String("scanID", scanID))
	return scanID, nil
}