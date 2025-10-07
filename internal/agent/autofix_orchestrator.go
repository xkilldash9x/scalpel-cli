// internal/agent/autofix_orchestrator.go
package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"[github.com/xkilldash9x/scalpel-cli/api/schemas](https://github.com/xkilldash9x/scalpel-cli/api/schemas)"
	"[github.com/xkilldash9x/scalpel-cli/internal/autofix](https://github.com/xkilldash9x/scalpel-cli/internal/autofix)"
	"[github.com/xkilldash9x/scalpel-cli/internal/config](https://github.com/xkilldash9x/scalpel-cli/internal/config)"
)

// SelfHealOrchestrator manages the entire autofix lifecycle.
type SelfHealOrchestrator struct {
	logger     *zap.Logger
	cfg        *config.Config
	autofixCfg *config.AutofixConfig
	watcher    *autofix.Watcher
	analyzer   *autofix.Analyzer
	developer  *autofix.Developer

	reportChan chan autofix.PostMortem
	wg         sync.WaitGroup

	// Cooldown mechanism to prevent repeated fix attempts on the same file rapidly.
	cooldownCache map[string]time.Time
	cooldownMu    sync.Mutex
}

// NewSelfHealOrchestrator creates and wires together the components.
func NewSelfHealOrchestrator(
	logger *zap.Logger,
	cfg *config.Config,
	llmClient schemas.LLMClient,
) (*SelfHealOrchestrator, error) {

	// Check if the feature is enabled in the configuration.
	// Assuming a structure like cfg.Autofix.Enabled
	if !cfg.Autofix.Enabled {
		logger.Info("Self-healing (Autofix) is disabled by configuration.")
		return nil, nil
	}

	reportChan := make(chan autofix.PostMortem, 5) // Buffered channel

	// Phase 1: Watcher
	watcher, err := autofix.NewWatcher(logger, cfg, reportChan)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize autofix watcher: %w", err)
	}

	// Phase 2: Analyzer
	analyzer := autofix.NewAnalyzer(logger, llmClient)

	// Phase 3: Developer
	// Determine the source project root for the Developer service.
	sourceProjectRoot, err := determineSourceProjectRoot(cfg.Autofix.ProjectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to determine source project root: %w", err)
	}
	logger.Info("Autofix using project root.", zap.String("path", sourceProjectRoot))

	developer := autofix.NewDeveloper(logger, llmClient, &cfg.Autofix, sourceProjectRoot)

	orchestrator := &SelfHealOrchestrator{
		logger:        logger.Named("self-heal-orch"),
		cfg:           cfg,
		autofixCfg:    &cfg.Autofix,
		watcher:       watcher,
		analyzer:      analyzer,
		developer:     developer,
		reportChan:    reportChan,
		cooldownCache: make(map[string]time.Time),
	}

	return orchestrator, nil
}

// Start activates the self-healing system.
func (o *SelfHealOrchestrator) Start(ctx context.Context) {
	if o == nil {
		return // System is disabled.
	}

	// Start the Watcher.
	if err := o.watcher.Start(ctx); err != nil {
		o.logger.Error("Failed to start autofix watcher. Self-healing disabled.", zap.Error(err))
		return
	}

	// Start the main processing loop.
	o.wg.Add(1)
	go o.runLoop(ctx)

	o.logger.Info("Self-healing system is active and monitoring.")
}

// WaitForShutdown blocks until the orchestrator has finished processing.
func (o *SelfHealOrchestrator) WaitForShutdown() {
	if o != nil {
		o.wg.Wait()
	}
}

// runLoop is the main control loop.
func (o *SelfHealOrchestrator) runLoop(ctx context.Context) {
	defer o.wg.Done()

	for {
		select {
		case <-ctx.Done():
			o.logger.Info("Shutting down self-healing system.")
			return

		case report, ok := <-o.reportChan:
			if !ok {
				return
			}
			// Process reports sequentially to ensure isolation between fix attempts.
			o.processReport(ctx, report)
		}
	}
}

// processReport handles the execution of Phases 2 and 3.
func (o *SelfHealOrchestrator) processReport(ctx context.Context, report autofix.PostMortem) {
	incidentID := report.IncidentID

	// Check cooldown status.
	if o.isInCooldown(report.FilePath) {
		o.logger.Info("Incident is within cooldown period, skipping.", zap.String("file", report.FilePath), zap.String("incident_id", incidentID))
		return
	}

	o.logger.Info("Initiating fix workflow.", zap.String("incident_id", incidentID))

	// Set a timeout for the entire workflow (e.g., 15 minutes).
	workflowCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	// Phase 2: Analysis
	analysisResult, err := o.analyzer.GeneratePatch(workflowCtx, report)
	if err != nil {
		o.logger.Error("Phase 2 Failed: Analysis and patch generation failed.", zap.Error(err), zap.String("incident_id", incidentID))
		o.updateCooldown(report.FilePath)
		return
	}

	// Confidence Check
	// Assuming a config option like cfg.Autofix.MinConfidenceThreshold
	threshold := o.autofixCfg.MinConfidenceThreshold
	if threshold == 0.0 {
		threshold = 0.75 // Default threshold if not set
	}
	if analysisResult.Confidence < threshold {
		o.logger.Warn("Phase 2 Complete: Patch confidence below threshold. Skipping Phase 3.",
			zap.Float64("confidence", analysisResult.Confidence), zap.Float64("threshold", threshold), zap.String("incident_id", incidentID))
		o.updateCooldown(report.FilePath)
		return
	}

	// Phase 3: Validation and Commit
	if err := o.developer.ValidateAndCommit(workflowCtx, report, analysisResult); err != nil {
		o.logger.Error("Phase 3 Failed: Validation and commit failed.", zap.Error(err), zap.String("incident_id", incidentID))
	} else {
		o.logger.Info("Self-healing workflow completed successfully. PR created.", zap.String("incident_id", incidentID))
	}

	// Update cooldown regardless of success or failure to prevent rapid retries.
	o.updateCooldown(report.FilePath)
}

// --- Cooldown Mechanism ---

func (o *SelfHealOrchestrator) isInCooldown(filePath string) bool {
	o.cooldownMu.Lock()
	defer o.cooldownMu.Unlock()

	if expiry, exists := o.cooldownCache[filePath]; exists {
		if time.Now().Before(expiry) {
			return true
		}
		// Cooldown expired.
		delete(o.cooldownCache, filePath)
	}
	return false
}

func (o *SelfHealOrchestrator) updateCooldown(filePath string) {
	o.cooldownMu.Lock()
	defer o.cooldownMu.Unlock()

	// Assuming a config option like cfg.Autofix.CooldownSeconds
	cooldownSeconds := o.autofixCfg.CooldownSeconds
	if cooldownSeconds == 0 {
		cooldownSeconds = 300 // Default 5 minutes
	}

	duration := time.Duration(cooldownSeconds) * time.Second
	o.cooldownCache[filePath] = time.Now().Add(duration)
}

// determineSourceProjectRoot finds the project root, prioritizing config, then git detection, then CWD.
func determineSourceProjectRoot(configuredRoot string) (string, error) {
	if configuredRoot != "" {
		return filepath.Abs(configuredRoot)
	}

	// Attempt to detect git root automatically.
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output)), nil
	}

	// Fallback to current working directory.
	return os.Getwd()
}