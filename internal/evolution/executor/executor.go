package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Executor executes the decided action (Step 4: ACT) and publishes the result.
type Executor struct {
	logger      *zap.Logger
	bus         *bus.EvolutionBus
	projectRoot string
	// Field to hold the subscription
	msgChan <-chan bus.Message
}

// NewExecutor initializes the Executor component and subscribes to the bus.
func NewExecutor(logger *zap.Logger, bus *bus.EvolutionBus, projectRoot string) *Executor {
	// Subscribe immediately upon creation.
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := bus.Subscribe(models.TypeAction)

	return &Executor{
		logger:      logger.Named("executor"),
		bus:         bus,
		projectRoot: projectRoot,
		msgChan:     msgChan,
	}
}

func (e *Executor) Start(ctx context.Context) {
	e.logger.Info("Executor started, waiting for Actions...")

	for {
		select {
		case <-ctx.Done():
			// Return immediately on external cancellation. Bus handles draining.
			return
		case msg, ok := <-e.msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}
			e.handleAction(ctx, msg)
			e.bus.Acknowledge(msg)
		}
	}
}

func (e *Executor) handleAction(ctx context.Context, msg bus.Message) {
	action, ok := msg.Payload.(models.Action)
	if !ok {
		return
	}

	// The Analyst handles the conclusion state; the executor just reports it.
	if action.Type == models.ActionConcludeGoal {
		e.logger.Info("Executing conclusion action.", zap.String("goal_id", action.GoalID))
		// No actual work is needed, just report success.
		e.publishResult(ctx, action, true, action.Description)
		return
	}

	e.logger.Info(
		"Act phase started. Executing action.",
		zap.String("goal_id", action.GoalID),
		zap.String("action_type", string(action.Type)),
		zap.String("strategy_id", action.StrategyID),
	)

	// Step 4: ACT - Execute the action.
	success, output := e.execute(ctx, action)

	e.logger.Info("Act phase completed.", zap.Bool("success", success))

	// Publish the result, which triggers the Observer and the Chronicler.
	e.publishResult(ctx, action, success, output)
}

func (e *Executor) publishResult(ctx context.Context, action models.Action, success bool, output string) {
	result := models.Result{
		ID:         uuid.New().String(),
		GoalID:     action.GoalID,
		ActionID:   action.ID,
		StrategyID: action.StrategyID, // Propagate the StrategyID from Action to Result.
		Success:    success,
		Output:     output,
		Timestamp:  time.Now().UTC(),
	}

	if err := e.bus.Post(ctx, models.TypeResult, result); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			e.logger.Error("Failed to post result to bus.", zap.Error(err))
		}
	}
}

func (e *Executor) execute(ctx context.Context, action models.Action) (bool, string) {
	var err error
	output := ""

	switch action.Type {
	case models.ActionApplyPatch:
		patch := action.Payload["patch"].(string)
		err = e.applyPatch(ctx, patch)
		if err != nil {
			output = fmt.Sprintf("Failed to apply patch: %v", err)
		} else {
			output = "Patch applied successfully."
		}

	case models.ActionRunCommand:
		command := action.Payload["command"].(string)
		output, err = e.runCommand(ctx, command)
		if err != nil {
			// Prepend error to the command's own output.
			output = fmt.Sprintf("Command failed: %v\nOutput:\n%s", err, output)
		}

	case models.ActionCreateFile:
		path := action.Payload["path"].(string)
		content := action.Payload["content"].(string)
		err = e.createFile(ctx, path, content)
		if err != nil {
			output = fmt.Sprintf("Failed to create file '%s': %v", path, err)
		} else {
			output = fmt.Sprintf("File '%s' created successfully.", path)
		}

	default:
		output = fmt.Sprintf("Executor received unknown action type: %s", action.Type)
		err = fmt.Errorf("unknown action type")
	}

	return err == nil, output
}

// -- Action Implementations --
// All implementations use exec.CommandContext or check context appropriately.
func (e *Executor) applyPatch(ctx context.Context, patchContent string) error {
	// Uses 'git apply' which is robust for applying diffs.
	cmd := exec.CommandContext(ctx, "git", "apply", "-v", "--whitespace=nowarn", "-")
	cmd.Dir = e.projectRoot
	cmd.Stdin = strings.NewReader(patchContent)

	if output, err := cmd.CombinedOutput(); err != nil {
		e.logger.Error("Git apply failed.", zap.String("output", string(output)))
		return fmt.Errorf("git apply failed: %w. Output: %s", err, string(output))
	}
	return nil
}

func (e *Executor) runCommand(ctx context.Context, command string) (string, error) {
	// Use a platform-specific shell for consistency.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		// Assume a POSIX-compliant shell.
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}

	cmd.Dir = e.projectRoot
	cmd.Env = os.Environ() // Inherit the current environment.
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (e *Executor) createFile(_ context.Context, relPath, content string) error {
	// Security check to prevent path traversal attacks like writing to /etc/passwd.
	cleanRelPath := filepath.Clean(relPath)
	if strings.HasPrefix(cleanRelPath, "..") || filepath.IsAbs(cleanRelPath) {
		return fmt.Errorf("invalid file path (path traversal detected): %s", relPath)
	}

	fullPath := filepath.Join(e.projectRoot, cleanRelPath)

	// Ensure the parent directory exists.
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the file contents.
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", fullPath, err)
	}
	return nil
}
