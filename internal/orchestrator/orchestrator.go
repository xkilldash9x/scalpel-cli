// File: internal/orchestrator/orchestrator.go
// Description: Manages the high-level lifecycle of a scan. It is injected with
// fully configured engine components via interfaces, making it decoupled and testable.

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
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
	// REFACTOR: Depends on the interface, not the concrete type.
	cfg             config.Interface
	logger          *zap.Logger
	discoveryEngine schemas.DiscoveryEngine
	taskEngine      schemas.TaskEngine
}

// New creates a new Orchestrator with its dependencies provided as schemas.
// This decoupling is crucial for testability and architectural flexibility.
func New(
	// REFACTOR: Accepts the interface, making the component more modular.
	cfg config.Interface,
	logger *zap.Logger,
	discoveryEngine schemas.DiscoveryEngine,
	taskEngine schemas.TaskEngine,
) (*Orchestrator, error) {
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
func (o *Orchestrator) StartScan(ctx context.Context, targets []string, scanID string) error {
	// Fix 1: Validate inputs to prevent panic if targets is empty.
	if len(targets) == 0 {
		o.logger.Error("Cannot start scan with an empty target list", zap.String("scanID", scanID))
		return fmt.Errorf("cannot start scan with an empty target list")
	}

	o.logger.Info("Orchestrator starting scan", zap.String("scanID", scanID), zap.Strings("targets", targets))

	// -- Discovery --

	// 1. Start the discovery engine. It returns a channel that streams tasks.
	discoveryTaskChan, err := o.discoveryEngine.Start(ctx, targets)
	if err != nil {
		return fmt.Errorf("failed to start discovery engine: %w", err)
	}
	o.logger.Info("Discovery engine started")

	// Create a new channel that merges orchestrator-dispatched tasks and discovery tasks.
	mergedTaskChan := make(chan schemas.Task, 100) // Buffer size can be tuned

	var wg sync.WaitGroup

	// Goroutine to forward tasks from discovery to the merged channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		if discoveryTaskChan == nil {
			return
		}
		for task := range discoveryTaskChan {
			select {
			case mergedTaskChan <- task:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Fix 3: Helper function to safely send tasks, respecting the context to prevent deadlocks.
	sendTask := func(task schemas.Task) bool {
		select {
		case mergedTaskChan <- task:
			return true
		case <-ctx.Done():
			o.logger.Info("Context cancelled during high-level task dispatch, stopping dispatch.")
			return false
		}
	}

	// -- Dispatcher --

	// Goroutine to dispatch high-level tasks and then close the merged channel
	go func() {
		// Dispatch high-level tasks here
		scanners := o.cfg.Scanners()

		// We know targets[0] is safe due to the initial validation.
		primaryTarget := targets[0]

		// We hoist the task declaration here so it is available to the entire scope.
		// This prevents "jump over declaration" linter errors when using goto.
		var task schemas.Task

		if scanners.Active.Auth.IDOR.Enabled {
			o.logger.Info("Dispatching IDOR task")
			task = schemas.Task{
				TaskID:     uuid.NewString(),
				ScanID:     scanID,
				Type:       schemas.TaskTestAuthIDOR,
				TargetURL:  primaryTarget,
				Parameters: schemas.IDORTaskParams{},
			}
			if !sendTask(task) {
				goto WaitForDiscovery
			}
		}
		if scanners.Active.Auth.ATO.Enabled {
			o.logger.Info("Dispatching ATO task")
			task = schemas.Task{
				TaskID:    uuid.NewString(),
				ScanID:    scanID,
				Type:      schemas.TaskTestAuthATO,
				TargetURL: primaryTarget,
				Parameters: schemas.ATOTaskParams{
					Usernames: []string{},
				},
			}
			if !sendTask(task) {
				goto WaitForDiscovery
			}
		}

		// Dispatch the main agent mission task
		o.logger.Info("Dispatching Agent Mission task")
		task = schemas.Task{
			TaskID:    uuid.NewString(),
			ScanID:    scanID,
			Type:      schemas.TaskAgentMission,
			TargetURL: primaryTarget, // Fix 2: Ensure TargetURL is set.
			Parameters: schemas.AgentMissionParams{
				MissionBrief: "Perform a comprehensive security audit of the target application.",
			},
		}
		if !sendTask(task) {
			goto WaitForDiscovery
		}

	WaitForDiscovery:
		// Wait for discovery to finish, then close the merged channel
		wg.Wait()
		close(mergedTaskChan)
	}()

	// -- Execution --

	// 2. Start the task engine, passing it the merged channel.
	o.taskEngine.Start(ctx, mergedTaskChan)
	o.logger.Info("Task engine started and consuming tasks")

	// 3. Wait for the context to be cancelled.
	// The engines will run until discovery is complete or the context is cancelled.
	<-ctx.Done()
	o.logger.Info("Orchestrator received context cancellation signal")

	// 4. Gracefully stop the engines.
	o.logger.Info("Shutting down engines...")
	o.discoveryEngine.Stop()
	o.taskEngine.Stop()

	// Allow a brief moment for final logs or cleanup to complete.
	time.Sleep(500 * time.Millisecond)

	o.logger.Info("Scan orchestration finished", zap.String("scanID", scanID))

	if err := ctx.Err(); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		return err
	}

	return nil
}
