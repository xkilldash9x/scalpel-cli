package orchestrator

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	// CORRECTED: All dependencies are now abstract interfaces.
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// Orchestrator manages the high-level lifecycle of a scan.
// It is injected with fully configured engine components.
type Orchestrator struct {
	cfg             *config.Config
	logger          *zap.Logger
	discoveryEngine interfaces.DiscoveryEngine
	taskEngine      interfaces.TaskEngine
}

// New creates a new Orchestrator.
// It now accepts interfaces for its core components.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	discoveryEngine interfaces.DiscoveryEngine,
	taskEngine interfaces.TaskEngine,
) (*Orchestrator, error) {
	return &Orchestrator{
		cfg:             cfg,
		logger:          logger,
		discoveryEngine: discoveryEngine,
		taskEngine:      taskEngine,
	}, nil
}

// StartScan runs the scan to completion using the injected engines.
func (o *Orchestrator) StartScan(ctx context.Context, targets []string, scanID string) error {
	o.logger.Info("Orchestrator starting scan", zap.String("scanID", scanID))

	// 1. Start Engine Workers in the background.
	// The scan context is passed to allow for graceful shutdown.
	o.taskEngine.Start(ctx)

	// 2. Start Discovery (This is a blocking call).
	discoveryErr := o.discoveryEngine.Run(ctx, targets[0]) // Assuming one primary target for now
	if discoveryErr != nil {
		o.logger.Error("Discovery phase failed", zap.Error(discoveryErr))
		// We still proceed to shutdown gracefully to process any partial results.
	} else {
		o.logger.Info("Discovery phase completed.")
	}

	// 3. Stop the Task Engine. This blocks until all queued tasks are drained.
	o.logger.Info("Waiting for task engine to drain...")
	o.taskEngine.Stop()

	o.logger.Info("Orchestration complete.", zap.String("scanID", scanID))

	// Return the error from discovery, if any.
	return discoveryErr
}

