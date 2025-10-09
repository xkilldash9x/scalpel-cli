package observer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Observer is responsible for gathering disparate information (Step 1: OBSERVE).
type Observer struct {
	logger      *zap.Logger
	bus         *bus.EvolutionBus
	projectRoot string
	// Field to hold the subscription
	msgChan <-chan bus.Message
}

// NewObserver initializes the Observer component and subscribes to the bus.
func NewObserver(logger *zap.Logger, bus *bus.EvolutionBus, projectRoot string) *Observer {
	// Subscribe immediately upon creation.
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := bus.Subscribe(models.TypeGoal, models.TypeResult)

	return &Observer{
		logger:      logger.Named("observer"),
		bus:         bus,
		projectRoot: projectRoot,
		msgChan:     msgChan,
	}
}

// P3: processMessage wraps message handling to guarantee acknowledgement and recover from panics.
func (o *Observer) processMessage(ctx context.Context, msg bus.Message) {
	defer func() {
		if r := recover(); r != nil {
			o.logger.Error("Panic recovered in Observer handler",
				zap.String("message_id", msg.ID),
				zap.String("message_type", string(msg.Type)),
				zap.Any("panic_value", r),
			)
		}
		o.bus.Acknowledge(msg)
	}()
	o.handleTrigger(ctx, msg)
}

// Start listening for events that trigger the observation phase.
func (o *Observer) Start(ctx context.Context) {
	o.logger.Info("Observer started, waiting for triggers (Goals or Results)...")

	for {
		select {
		case <-ctx.Done():
			// Return immediately on external cancellation. Bus handles draining.
			return
		case msg, ok := <-o.msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}
			// P3: Use the wrapper for safe processing and acknowledgement.
			o.processMessage(ctx, msg)
		}
	}
}

func (o *Observer) handleTrigger(ctx context.Context, msg bus.Message) {
	var goalID string
	var targetFiles []string
	var previousResult *models.Result

	switch msg.Type {
	case models.TypeGoal:
		goal, ok := msg.Payload.(models.Goal)
		if !ok {
			return
		}
		goalID = goal.ID
		targetFiles = goal.TargetFiles
		o.logger.Info("Observation phase triggered by new Goal.", zap.String("goal_id", goalID))

	case models.TypeResult:
		result, ok := msg.Payload.(models.Result)
		if !ok {
			return
		}
		goalID = result.GoalID
		previousResult = &result
		// We need the target files associated with this goal ID to re-observe them.
		// In this design, the Observer doesn't maintain state about Goals.
		// The Synthesizer tracks the goal context, so we rely on the initial list provided by the Goal message.
		// This requires the Synthesizer to have access to the Goal context when processing observations.
		// For now, we assume targetFiles are handled via the Goal context tracked elsewhere (e.g., Synthesizer).
		// If we need dynamic file tracking here, the Goal needs to be accessible by ID.
		o.logger.Info("Observation phase triggered by Action Result (Feedback loop).", zap.String("goal_id", goalID), zap.Bool("success", result.Success))
	default:
		return
	}

	// Start gathering context.
	// Note: targetFiles are only available from the initial TypeGoal trigger.
	// For subsequent cycles triggered by TypeResult, we rely on the components knowing the goal context.
	o.gatherContext(ctx, goalID, targetFiles, previousResult)
}

func (o *Observer) gatherContext(ctx context.Context, goalID string, targetFiles []string, previousResult *models.Result) {
	// 1. Publish the result of the previous action if available.
	if previousResult != nil {
		o.publish(ctx, goalID, models.ObsActionResult, "Observer/FeedbackLoop", previousResult, !previousResult.Success)
	}

	// 2. Check Current State (Build and Test)
	buildSuccess := o.checkBuildStatus(ctx, goalID)
	if buildSuccess {
		o.checkTestStatus(ctx, goalID)
	}

	// 3. Gather File Context (Source and Tests)
	// NOTE: This part requires the list of target files. In the current design, this is only reliably available
	// when triggered by TypeGoal. If triggered by TypeResult, targetFiles might be empty.
	// This is a limitation if the observer is fully stateless.
	if len(targetFiles) > 0 {
		for _, file := range targetFiles {
			o.readSourceFile(ctx, goalID, file)
			o.readTestFile(ctx, goalID, file)
			// 4. Gather Historical Context (Git Blame)
			o.getGitBlame(ctx, goalID, file)
		}
	} else {
		o.logger.Debug("Target files not available in trigger message. Skipping file-specific observations.")
	}

	// 5. Dependency Graph
	o.getDependencies(ctx, goalID)

	// 6. Static Analysis (Go Vet)
	o.runStaticAnalysis(ctx, goalID)

	o.logger.Info("Observation phase completed.", zap.String("goal_id", goalID))
}

// Helper to publish observations to the bus.
func (o *Observer) publish(ctx context.Context, goalID, obsType, source string, data interface{}, isError bool) {
	obs := models.Observation{
		ID:        uuid.New().String(),
		GoalID:    goalID,
		Type:      obsType,
		Source:    source,
		Data:      data,
		Timestamp: time.Now().UTC(),
		IsError:   isError,
	}
	if err := o.bus.Post(ctx, models.TypeObservation, obs); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			o.logger.Error("Failed to post observation to bus.", zap.Error(err), zap.String("type", obsType))
		}
	}
}

// -- Observation Implementations (Step 1) --
// All implementations use exec.CommandContext which respects the context.
func (o *Observer) checkBuildStatus(ctx context.Context, goalID string) bool {
	o.logger.Debug("Checking build status...")
	cmd := exec.CommandContext(ctx, "go", "build", "./...")
	cmd.Dir = o.projectRoot
	output, err := cmd.CombinedOutput()

	success := err == nil
	o.publish(ctx, goalID, models.ObsBuildStatus, "Observer/GoBuild", string(output), !success)
	return success
}

func (o *Observer) checkTestStatus(ctx context.Context, goalID string) {
	o.logger.Debug("Checking test status...")
	cmd := exec.CommandContext(ctx, "go", "test", "-v", "./...")
	cmd.Dir = o.projectRoot
	output, err := cmd.CombinedOutput()

	success := err == nil
	o.publish(ctx, goalID, models.ObsTestStatus, "Observer/GoTest", string(output), !success)
}

func (o *Observer) readSourceFile(ctx context.Context, goalID, filePath string) {
	fullPath := filepath.Join(o.projectRoot, filePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		o.logger.Warn("Failed to read source file.", zap.String("file", filePath), zap.Error(err))
		o.publish(ctx, goalID, models.ObsSourceCode, "Observer/FileRead/"+filePath, fmt.Sprintf("Error: %v", err), true)
		return
	}
	o.publish(ctx, goalID, models.ObsSourceCode, "Observer/FileRead/"+filePath, string(content), false)
}

func (o *Observer) readTestFile(ctx context.Context, goalID, sourceFilePath string) {
	ext := filepath.Ext(sourceFilePath)
	testFilePath := strings.TrimSuffix(sourceFilePath, ext) + "_test" + ext

	fullPath := filepath.Join(o.projectRoot, testFilePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			// It's fine if a test file doesn't exist yet.
			o.publish(ctx, goalID, models.ObsUnitTest, "Observer/FileRead/"+testFilePath, "Test file not found.", false)
		} else {
			o.publish(ctx, goalID, models.ObsUnitTest, "Observer/FileRead/"+testFilePath, fmt.Sprintf("Error: %v", err), true)
		}
		return
	}
	o.publish(ctx, goalID, models.ObsUnitTest, "Observer/FileRead/"+testFilePath, string(content), false)
}

func (o *Observer) getDependencies(ctx context.Context, goalID string) {
	// Use 'go mod graph' for dependency information.
	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = o.projectRoot
	output, err := cmd.CombinedOutput()

	if err != nil {
		o.publish(ctx, goalID, models.ObsDependencies, "Observer/GoModGraph", fmt.Sprintf("Error: %v\nOutput: %s", err, string(output)), true)
		return
	}
	o.publish(ctx, goalID, models.ObsDependencies, "Observer/GoModGraph", string(output), false)
}

func (o *Observer) getGitBlame(ctx context.Context, goalID, filePath string) {
	if _, err := exec.LookPath("git"); err != nil {
		o.publish(ctx, goalID, models.ObsGitBlame, "Observer/GitBlame/"+filePath, "Git executable not found.", false)
		return
	}

	// Use --porcelain for easier parsing
	cmd := exec.CommandContext(ctx, "git", "blame", "--porcelain", filePath)
	cmd.Dir = o.projectRoot
	output, err := cmd.CombinedOutput()

	if err != nil {
		o.publish(ctx, goalID, models.ObsGitBlame, "Observer/GitBlame/"+filePath, fmt.Sprintf("Error: %v\nOutput: %s", err, string(output)), true)
		return
	}

	// Parse the porcelain format for structured data
	structuredBlame := o.parseGitBlame(output)
	o.publish(ctx, goalID, models.ObsGitBlame, "Observer/GitBlame/"+filePath, structuredBlame, false)
}

func (o *Observer) parseGitBlame(output []byte) []map[string]string {
	var blameData []map[string]string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	currentLine := make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\t") {
			// Content line, marks the end of the block for this line of code.
			currentLine["content"] = strings.TrimPrefix(line, "\t")
			blameData = append(blameData, currentLine)
			currentLine = make(map[string]string)
		} else {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]
				// Handle the first line containing the hash
				if strings.Contains(key, " ") || len(key) >= 40 {
					currentLine["commit"] = key
				} else {
					currentLine[key] = value
				}
			}
		}
	}
	return blameData
}

func (o *Observer) runStaticAnalysis(ctx context.Context, goalID string) {
	cmd := exec.CommandContext(ctx, "go", "vet", "./...")
	cmd.Dir = o.projectRoot
	output, err := cmd.CombinedOutput()

	// go vet exits non-zero on findings, but this isn't an error in the observation process itself.
	// We treat it as an error only if the command failed to run completely.
	isError := err != nil && len(output) == 0

	o.publish(ctx, goalID, models.ObsStaticAnalysis, "Observer/GoVet", string(output), isError)
}
