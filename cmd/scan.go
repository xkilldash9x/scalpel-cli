// File: cmd/scan.go
// Description: Defines the `scan` command, which serves as the application's composition root.
// This file is responsible for initializing all components and injecting them as interfaces
// into the orchestrator, following the Dependency Injection pattern.

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/discovery"
	"github.com/xkilldash9x/scalpel-cli/internal/engine"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
	"github.com/xkilldash9x/scalpel-cli/internal/worker"
)

func newScanCmd() *cobra.Command {
	var scanCfg config.ScanConfig

	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Long: `Initializes and runs the full scalpel-cli scanning pipeline.
This includes discovery, task execution, and analysis against one or more root targets.
Targets can be specified as command-line arguments.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, argsstring) error {
			scanCfg.Targets = args
			scanID := uuid.New().String()
			logger := observability.GetLogger()
			cfg := config.Get()

			logger.Info("Starting new scan", zap.String("scanID", scanID), zap.Strings("targets", scanCfg.Targets))

			// Setup context for graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle termination signals
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				sig := <-sigChan
				logger.Warn("Received termination signal, shutting down gracefully...", zap.String("signal", sig.String()))
				cancel()
				// Allow a moment for cleanup before force-exiting
				time.Sleep(2 * time.Second)
				os.Exit(1)
			}()

			// ========================================================================
			// 1. COMPOSITION ROOT: Initialize all concrete component implementations
			// ========================================================================

			// Initialize data stores
			dbStore, err := store.New(cfg.Database)
			if err!= nil {
				return fmt.Errorf("failed to initialize database store: %w", err)
			}
			defer dbStore.Close()

			kg, err := knowledgegraph.NewPostgresKG(cfg.Database, logger)
			if err!= nil {
				return fmt.Errorf("failed to initialize knowledge graph: %w", err)
			}

			// Initialize browser manager
			browserManager, err := browser.NewManager(ctx, *cfg, logger)
			if err!= nil {
				return fmt.Errorf("failed to initialize browser manager: %w", err)
			}
			defer browserManager.Close()

			// Initialize worker pool and task engine
			workerPool := worker.NewPool(cfg.Engine.WorkerConcurrency, cfg, logger, browserManager, kg, dbStore)
			taskEngine := engine.New(cfg.Engine, logger, workerPool)

			// Initialize discovery engine
			// Note: Passive runner is currently nil, can be implemented later
			var passiveRunner interfaces.DiscoveryEngine // Example of an injectable component
			discoveryEngine := discovery.NewEngine(cfg.Discovery, logger, kg, browserManager, passiveRunner)

			// ========================================================================
			// 2. DEPENDENCY INJECTION: Pass components as interfaces to the orchestrator
			// ========================================================================

			orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
			if err!= nil {
				return fmt.Errorf("failed to create orchestrator: %w", err)
			}

			// ========================================================================
			// 3. EXECUTION: Start the scan
			// ========================================================================

			if err := orch.StartScan(ctx, scanCfg.Targets, scanID); err!= nil {
				logger.Error("Scan failed", zap.Error(err), zap.String("scanID", scanID))
				return err
			}

			logger.Info("Scan completed successfully", zap.String("scanID", scanID))
			fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
			fmt.Println("To generate a report, run: scalpel-cli report --scan-id", scanID)

			return nil
		},
	}

	// Add flags for scan configuration here if needed, e.g., depth, etc.
	// For now, we rely on the config file.

	return scanCmd
}
--------------------------------------------
// File: internal/orchestrator/orchestrator.go
// Description: Manages the high-level lifecycle of a scan. It is injected with
// fully configured engine components via interfaces, making it decoupled and testable.

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	// CORRECTED: All dependencies are now abstract interfaces.
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// Orchestrator manages the high-level lifecycle of a scan.
// It is injected with fully configured engine components.
type Orchestrator struct {
	cfg             *config.Config
	logger          *zap.Logger
	discoveryEngine interfaces.DiscoveryEngine
	taskEngine      interfaces.TaskEngine
}

// New creates a new Orchestrator with its dependencies provided as interfaces.
// This decoupling is crucial for testability and architectural flexibility.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	discoveryEngine interfaces.DiscoveryEngine,
	taskEngine interfaces.TaskEngine,
) (*Orchestrator, error) {
	if cfg == nil |

| logger == nil |
| discoveryEngine == nil |
| taskEngine == nil {
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
func (o *Orchestrator) StartScan(ctx context.Context, targetsstring, scanID string) error {
	o.logger.Info("Orchestrator starting scan", zap.String("scanID", scanID))

	// 1. Start the discovery engine. It will return a channel from which the
	//    orchestrator can read newly discovered tasks.
	taskChan, err := o.discoveryEngine.Start(ctx, targets)
	if err!= nil {
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
	if err := ctx.Err(); err!= nil && err!= context.Canceled && err!= context.DeadlineExceeded {
		return err
	}

	return nil
}
