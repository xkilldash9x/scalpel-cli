// File: internal/orchestrator/orchestrator.go
// Description: Manages the high-level lifecycle of a scan. It is injected with
// fully configured engine components via interfaces, making it decoupled and testable.

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Global variable to track package initialization status.
var InitializationStatus string

// init is called by the Go runtime when the package is initialized.
func init() {
	log.Println("Orchestrator package initializing.")
	InitializationStatus = "Initialized"
}

// Orchestrator manages the high-level lifecycle of a scan.
// It is injected with fully configured engine components.
type Orchestrator struct {
	cfg             *config.Config
	logger          *zap.Logger
	discoveryEngine schemas.DiscoveryEngine
	taskEngine      schemas.TaskEngine
}

// New creates a new Orchestrator with its dependencies provided as schemas.
// This decoupling is crucial for testability and architectural flexibility.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	discoveryEngine schemas.DiscoveryEngine,
	taskEngine schemas.TaskEngine,
) (*Orchestrator, error) {
	// Fixed: Changed bitwise OR (|) to logical OR (||) and fixed formatting.
	if cfg == nil ||
		logger == nil ||
		discoveryEngine == nil ||
		taskEngine == nil {
		return nil, fmt.Errorf("cannot initialize orchestrator with nil dependencies")
	}
	return &Orchestrator{
		cfg:             cfg,
		logger:          logger,
		discoveryEngine: discoveryEngine,
		taskEngine:      taskEngine,
	}, nil
}

// StartScan executes the main scanning workflow.
// FIX: Changed signature to accept []string instead of a single string.
func (o *Orchestrator) StartScan(ctx context.Context, targets []string, scanID string) error {
	// FIX: Updated logging to include the targets slice.
	o.logger.Info("Orchestrator starting scan", zap.String("scanID", scanID), zap.Strings("targets", targets))

	// 1. Start the discovery engine. It will return a channel from which the
	//    orchestrator can read newly discovered tasks.
	// FIX: Pass the 'targets' slice, which matches the expected type for o.discoveryEngine.Start.
	taskChan, err := o.discoveryEngine.Start(ctx, targets)
	if err != nil {
		return fmt.Errorf("failed to start discovery engine: %w", err)
	}
	o.logger.Info("Discovery engine started")

	// 2. Start the task engine. It will begin consuming tasks from the channel
	//    as they are produced by the discovery engine.
	o.taskEngine.Start(ctx, taskChan)
	o.logger.Info("Task engine started and waiting for tasks")

	// 3. Wait for the context to be cancelled (e.g., by signal or timeout).
	//    The engines are designed to run until the context is done.
	<-ctx.Done()
	o.logger.Info("Orchestrator received context cancellation signal")

	// 4. Gracefully stop the engines.
	o.logger.Info("Shutting down engines...")
	o.discoveryEngine.Stop()
	o.taskEngine.Stop()

	// Allow a brief moment for final logs or cleanup to complete.
	time.Sleep(500 * time.Millisecond)

	o.logger.Info("Scan orchestration finished", zap.String("scanID", scanID))

	// The discovery engine might have encountered a non-fatal error during its run.
	// If the context was cancelled due to an error from one of the components,
	// that error should be propagated up.
	if err := ctx.Err(); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		return err
	}

	return nil
}