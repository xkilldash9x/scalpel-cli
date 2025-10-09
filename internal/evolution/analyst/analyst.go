package analyst

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/chronicler"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/decider"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/executor"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	observer "github.com/xkilldash9x/scalpel-cli/internal/evolution/observe"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/synthesizer"
	"go.uber.org/zap"
)

// ImprovementAnalyst orchestrates the OODA loop for proactive self-improvement.
type ImprovementAnalyst struct {
	logger      *zap.Logger
	cfg         *config.Config
	bus         *bus.EvolutionBus
	projectRoot string

	// OODA Components (Steps 1-4)
	observer    *observer.Observer
	synthesizer *synthesizer.Synthesizer
	decider     *decider.Decider
	executor    *executor.Executor

	// Step 5 (REMEMBER)
	chronicler *chronicler.Chronicler

	wg sync.WaitGroup

	// Track active goals and state
	activeGoalID string
	currentState string
	mu           sync.Mutex
	maxCycles    int
	cycleCount   int
}

// NewImprovementAnalyst initializes the Analyst and all OODA components.
func NewImprovementAnalyst(logger *zap.Logger, cfg *config.Config, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (*ImprovementAnalyst, error) {
	projectRoot, err := determineProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine project root: %w", err)
	}
	logger.Info("Improvement Analyst initialized (Reflective OODA Loop).", zap.String("project_root", projectRoot))

	// Initialize the central event bus.
	// P2: Increased buffer size significantly to prevent gridlock under load.
	evoBus := bus.NewEvolutionBus(logger, 1000)

	// Initialize OODA components. They now subscribe in their constructors (Fix for Startup Race).
	obs := observer.NewObserver(logger, evoBus, projectRoot)
	synth := synthesizer.NewSynthesizer(logger, evoBus, llmClient, kgClient)
	dec := decider.NewDecider(logger, evoBus, llmClient)
	exec := executor.NewExecutor(logger, evoBus, projectRoot)

	// Initialize the Chronicler (Step 5: Remember). Assumes it also subscribes in constructor.
	chron := chronicler.NewChronicler(logger, evoBus, kgClient)

	return &ImprovementAnalyst{
		logger:       logger.Named("improvement_analyst"),
		cfg:          cfg,
		bus:          evoBus,
		projectRoot:  projectRoot,
		observer:     obs,
		synthesizer:  synth,
		decider:      dec,
		executor:     exec,
		chronicler:   chron,
		currentState: "Initialized",
		maxCycles:    15, // Limit OODA cycles to prevent infinite loops.
	}, nil
}

// Run starts the analyst and initiates the OODA loop for a specific goal.
func (a *ImprovementAnalyst) Run(ctx context.Context, objective string, targetFiles []string) error {
	a.mu.Lock()
	if a.currentState != "Initialized" {
		a.mu.Unlock()
		return fmt.Errorf("analyst is already running or finished")
	}
	a.currentState = "Running"

	// Fix for Data Race: Initialize Goal ID before starting components that read it.
	initialGoalID := uuid.New().String()
	a.activeGoalID = initialGoalID

	a.mu.Unlock()

	// This context will manage the lifecycle of all component goroutines.
	componentCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		a.wg.Wait()
		a.bus.Shutdown()
		a.mu.Lock()
		if a.currentState == "Running" || a.currentState == "TimedOut" {
			a.currentState = "Finished"
		}
		a.mu.Unlock()
	}()

	a.startComponents(componentCtx)

	// Create the initial goal using the pre-initialized ID.
	goal := models.Goal{
		ID:          initialGoalID,
		Objective:   objective,
		TargetFiles: targetFiles,
		Timestamp:   time.Now().UTC(),
	}

	// Start the loop by posting the Goal, which triggers the Observer.
	if err := a.bus.Post(ctx, models.TypeGoal, goal); err != nil {
		return fmt.Errorf("failed to post initial goal: %w", err)
	}

	// Block and monitor progress until completion, timeout, or error.
	return a.monitorProgress(componentCtx)
}

// startComponents launches all OODA+R components in separate goroutines.
func (a *ImprovementAnalyst) startComponents(ctx context.Context) {
	components := []func(context.Context){
		a.observer.Start,
		a.synthesizer.Start,
		a.decider.Start,
		a.executor.Start,
		a.chronicler.Start,
		a.monitorCycles,
	}

	a.wg.Add(len(components))
	for _, componentFunc := range components {
		go func(f func(context.Context)) {
			defer a.wg.Done()
			f(ctx)
		}(componentFunc)
	}
}

// P3: processMonitorMessage wraps message handling to guarantee acknowledgement and recover from panics.
// This prevents deadlocks if a panic occurs before Acknowledge().
func (a *ImprovementAnalyst) processMonitorMessage(msg bus.Message, handler func(bus.Message)) {
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("Panic recovered in Analyst monitor",
				zap.String("message_id", msg.ID),
				zap.Any("panic_value", r),
			)
		}
		// Ensure the message is always acknowledged.
		if msg.ID != "" { // Check if msg is not a zero value (e.g. from closed channel read)
			a.bus.Acknowledge(msg)
		}
	}()
	handler(msg)
}

// monitorProgress waits for the goal to be concluded or for a timeout/cancellation.
func (a *ImprovementAnalyst) monitorProgress(ctx context.Context) error {
	// Listen for the final action (CONCLUDE_GOAL).
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function as the bus handles cleanup during shutdown.
	msgChan, _ := a.bus.Subscribe(models.TypeAction)

	// Set a global timeout for the entire process.
	timeout := time.After(30 * time.Minute)

	var conclusionDetected bool
	handleProgressMsg := func(msg bus.Message) {
		action, ok := msg.Payload.(models.Action)

		// R1 FIX: Acquire lock before reading shared state (activeGoalID, currentState).
		a.mu.Lock()
		defer a.mu.Unlock()

		isActiveGoal := ok && action.GoalID == a.activeGoalID

		if isActiveGoal && action.Type == models.ActionConcludeGoal {
			// We already hold the lock.
			a.logger.Info("Goal conclusion detected.", zap.String("goal_id", a.activeGoalID), zap.String("reason", action.Description))
			a.currentState = "Concluded"
			conclusionDetected = true
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			a.mu.Lock()
			a.currentState = "TimedOut"
			a.mu.Unlock()
			return fmt.Errorf("evolution process timed out after 30 minutes")
		case msg, ok := <-msgChan:
			if !ok {
				// Bus closed (channel closed by Shutdown).
				a.mu.Lock()
				defer a.mu.Unlock()
				// If we concluded, shutdown is expected.
				if a.currentState == "Concluded" {
					return nil
				}
				// If context is done (timeout/cancel), that's the primary error.
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Otherwise, the bus closed unexpectedly.
				return fmt.Errorf("bus closed unexpectedly")
			}

			// P3: Use the wrapper for safe processing and acknowledgement.
			a.processMonitorMessage(msg, handleProgressMsg)

			if conclusionDetected {
				// Return nil to allow the defer in Run() to handle a graceful shutdown.
				return nil
			}
		}
	}
}

// monitorCycles tracks the number of OODA cycles and stops the process if it exceeds the limit.
func (a *ImprovementAnalyst) monitorCycles(ctx context.Context) {
	// A cycle completes when a Result is posted (Act phase finished).
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := a.bus.Subscribe(models.TypeResult)

	var maxCyclesReached bool
	handleCycleMsg := func(msg bus.Message) {
		result, ok := msg.Payload.(models.Result)

		// R1 FIX: Acquire lock before reading/writing shared state (activeGoalID, cycleCount).
		a.mu.Lock()

		isActiveGoal := ok && result.GoalID == a.activeGoalID

		if isActiveGoal {
			a.cycleCount++
			a.logger.Info("OODA Cycle completed.", zap.Int("cycle", a.cycleCount), zap.Int("max_cycles", a.maxCycles))

			if a.cycleCount >= a.maxCycles {
				a.logger.Warn("Maximum OODA cycles reached. Forcing conclusion.")

				// Capture GoalID while holding the lock.
				goalID := a.activeGoalID

				// CRITICAL: Unlock before potentially blocking Post call.
				a.mu.Unlock()

				// Force the process to stop by sending a Conclude action.
				concludeAction := models.Action{
					ID:          uuid.New().String(),
					GoalID:      goalID,
					StrategyID:  "", // No specific strategy, this is a system action.
					Type:        models.ActionConcludeGoal,
					Description: fmt.Sprintf("Forced conclusion after reaching max cycles (%d). Goal not fully achieved.", a.maxCycles),
					Timestamp:   time.Now().UTC(),
					Payload:     make(map[string]interface{}),
				}

				// Use a background context with a short timeout to ensure this message sends.
				postCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = a.bus.Post(postCtx, models.TypeAction, concludeAction)
				maxCyclesReached = true
				return // Return early since we unlocked manually
			}
		}
		a.mu.Unlock()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}

			// P3: Use the wrapper for safe processing and acknowledgement.
			a.processMonitorMessage(msg, handleCycleMsg)

			if maxCyclesReached {
				return // Stop this monitor.
			}
		}
	}
}

// determineProjectRoot tries to find the root of the repository.
func determineProjectRoot() (string, error) {
	// First, try using git, as it's the most reliable.
	if _, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
	}

	// Fallback to finding go.mod by walking up the directory tree.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir { // We've reached the filesystem root.
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find project root (no git repository or go.mod found)")
}
