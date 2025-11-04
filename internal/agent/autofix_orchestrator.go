package agent

import ( // This is a comment to force a change
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/autofix"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// SelfHealOrchestrator manages the entire autofix lifecycle.
type SelfHealOrchestrator struct {
	logger        *zap.Logger
	cfg           config.Interface
	autofixCfg    *config.AutofixConfig
	watcher       *autofix.Watcher
	analyzer      *autofix.Analyzer
	developer     *autofix.Developer
	reportChan    chan autofix.PostMortem
	wg            sync.WaitGroup
	cooldownCache map[string]time.Time
	cooldownMu    sync.Mutex
}

// NewSelfHealOrchestrator creates and wires together the components.
func NewSelfHealOrchestrator(
	logger *zap.Logger,
	cfg config.Interface,
	llmClient schemas.LLMClient,
) (*SelfHealOrchestrator, error) {

	autofixCfg := cfg.Autofix()

	if !autofixCfg.Enabled {
		logger.Info("Self-healing (Autofix) is disabled by configuration.")
		return nil, nil
	}

	if err := autofixCfg.Validate(); err != nil {
		logger.Error("Autofix configuration is invalid. Disabling self-healing.", zap.Error(err))
		return nil, nil
	}

	sourceProjectRoot, err := determineSourceProjectRoot(autofixCfg.ProjectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to determine source project root: %w", err)
	}
	logger.Info("Autofix using project root context.", zap.String("path", sourceProjectRoot))

	reportChan := make(chan autofix.PostMortem, 10)

	watcher, err := autofix.NewWatcher(logger, cfg, reportChan, sourceProjectRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize autofix watcher: %w", err)
	}

	analyzer := autofix.NewAnalyzer(logger, llmClient, sourceProjectRoot)

	developer, err := autofix.NewDeveloper(logger, llmClient, &autofixCfg, sourceProjectRoot)
	if err != nil {
		logger.Error("Failed to initialize autofix developer. Disabling self-healing.", zap.Error(err))
		return nil, nil
	}

	orchestrator := &SelfHealOrchestrator{
		logger:        logger.Named("self-heal-orch"),
		cfg:           cfg,
		autofixCfg:    &autofixCfg,
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
	if err := o.watcher.Start(ctx); err != nil {
		o.logger.Error("Failed to start autofix watcher. Self-healing disabled.", zap.Error(err))
		return
	}
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
			o.processReport(ctx, report)
		}
	}
}

// processReport handles the execution of Phases 2 and 3.
func (o *SelfHealOrchestrator) processReport(ctx context.Context, report autofix.PostMortem) {
	incidentID := report.IncidentID
	if o.isInCooldown(report.FilePath) {
		o.logger.Info("Incident is within cooldown period, skipping.", zap.String("file", report.FilePath), zap.String("incident_id", incidentID))
		return
	}
	o.logger.Info("Initiating fix workflow.", zap.String("incident_id", incidentID))

	workflowCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	analysisResult, err := o.analyzer.GeneratePatch(workflowCtx, report)
	if err != nil {
		o.logger.Error("Phase 2 Failed: Analysis and patch generation failed.", zap.Error(err), zap.String("incident_id", incidentID))
		o.updateCooldown(report.FilePath)
		return
	}

	threshold := o.autofixCfg.MinConfidenceThreshold
	if analysisResult.Confidence < threshold {
		o.logger.Warn("Phase 2 Complete: Patch confidence below threshold. Skipping Phase 3.",
			zap.Float64("confidence", analysisResult.Confidence), zap.Float64("threshold", threshold), zap.String("incident_id", incidentID))
		o.updateCooldown(report.FilePath)
		return
	}

	if err := o.developer.ValidateAndCommit(workflowCtx, report, analysisResult); err != nil {
		o.logger.Error("Phase 3 Failed: Validation and commit failed.", zap.Error(err), zap.String("incident_id", incidentID))
	} else {
		o.logger.Info("Self-healing workflow completed successfully. PR created.", zap.String("incident_id", incidentID))
	}
	o.updateCooldown(report.FilePath)
}

func (o *SelfHealOrchestrator) isInCooldown(filePath string) bool {
	o.cooldownMu.Lock()
	defer o.cooldownMu.Unlock()
	if expiry, exists := o.cooldownCache[filePath]; exists {
		if time.Now().Before(expiry) {
			return true
		}
		delete(o.cooldownCache, filePath)
	}
	return false
}

func (o *SelfHealOrchestrator) updateCooldown(filePath string) {
	o.cooldownMu.Lock()
	defer o.cooldownMu.Unlock()
	cooldownSeconds := o.autofixCfg.CooldownSeconds
	duration := time.Duration(cooldownSeconds) * time.Second
	o.cooldownCache[filePath] = time.Now().Add(duration)
}

func determineSourceProjectRoot(configuredRoot string) (string, error) {
	if configuredRoot != "" {
		absPath, err := filepath.Abs(configuredRoot)
		if err != nil {
			return "", fmt.Errorf("invalid configured project root '%s': %w", configuredRoot, err)
		}
		return absPath, nil
	}
	if _, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	return cwd, nil
}
