// File: cmd/scan.go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/discovery"
	"github.com/xkilldash9x/scalpel-cli/internal/engine"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
	"github.com/xkilldash9x/scalpel-cli/internal/results"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
	"github.com/xkilldash9x/scalpel-cli/internal/worker"
)

// newScanCmd creates and configures the `scan` command.
func newScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := observability.GetLogger()

			cfg, err := getConfigFromContext(ctx)
			if err != nil {
				return err
			}

			if cmd.Flags().Changed("depth") {
				depth, _ := cmd.Flags().GetInt("depth")
				cfg.SetDiscoveryMaxDepth(depth)
			}
			if cmd.Flags().Changed("concurrency") {
				concurrency, _ := cmd.Flags().GetInt("concurrency")
				cfg.SetEngineWorkerConcurrency(concurrency)
			}

			scope, _ := cmd.Flags().GetString("scope")
			switch strings.ToLower(scope) {
			case "subdomain":
				cfg.SetDiscoveryIncludeSubdomains(true)
			case "strict":
				cfg.SetDiscoveryIncludeSubdomains(false)
			default:
				logger.Warn("Invalid scope value provided, defaulting to 'strict'", zap.String("scope", scope))
				cfg.SetDiscoveryIncludeSubdomains(false)
			}

			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			targets := args

			components, err := initializeScanComponents(ctx, cfg, targets, logger)
			if err != nil {
				if components != nil {
					components.Shutdown()
				}
				return fmt.Errorf("failed to initialize scan components: %w", err)
			}
			defer components.Shutdown()

			return runScan(ctx, logger, cfg, targets, output, format, components)
		},
	}

	scanCmd.Flags().StringP("output", "o", "", "Output file path for the report. If unset, no report is generated.")
	scanCmd.Flags().StringP("format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json').")
	scanCmd.Flags().IntP("depth", "d", 0, "Maximum crawl depth. (Overrides config/env)")
	scanCmd.Flags().IntP("concurrency", "j", 0, "Number of concurrent engine workers. (Overrides config/env)")
	scanCmd.Flags().String("scope", "strict", "Scan scope strategy (e.g., 'strict', 'subdomain'). (Overrides config/env)")

	return scanCmd
}

// runScan contains the core, testable logic for the scan command.
func runScan(
	ctx context.Context,
	logger *zap.Logger,
	cfg config.Interface,
	targets []string,
	output, format string,
	components *scanComponents,
) error {
	scanID := uuid.New().String()

	scanTargets := make([]string, len(targets))
	copy(scanTargets, targets)
	if len(scanTargets) > 0 {
		if !strings.HasPrefix(scanTargets[0], "http://") && !strings.HasPrefix(scanTargets[0], "https://") {
			scanTargets[0] = "https://" + scanTargets[0]
		}
	}

	logger.Info("Starting new scan",
		zap.String("scanID", scanID),
		zap.Strings("targets", scanTargets),
		zap.Int("discovery_depth", cfg.Discovery().MaxDepth),
		zap.Int("engine_concurrency", cfg.Engine().WorkerConcurrency),
		zap.Bool("include_subdomains", cfg.Discovery().IncludeSubdomains),
	)

	if err := components.Orchestrator.StartScan(ctx, scanTargets, scanID); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Warn("Scan aborted gracefully", zap.String("scanID", scanID))
			return fmt.Errorf("scan aborted by user signal")
		}
		logger.Error("Scan failed during orchestration", zap.Error(err), zap.String("scanID", scanID))
		return err
	}

	logger.Info("Scan execution completed successfully", zap.String("scanID", scanID))

	if output != "" {
		if err := generateReport(ctx, components.Store, scanID, format, output, logger); err != nil {
			return err
		}
	}

	fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
	if output == "" {
		fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
	}

	return nil
}

// scanComponents holds initialized services.
type scanComponents struct {
	Store           schemas.Store
	BrowserManager  schemas.BrowserManager
	KnowledgeGraph  schemas.KnowledgeGraphClient
	TaskEngine      schemas.TaskEngine
	DiscoveryEngine schemas.DiscoveryEngine
	Orchestrator    schemas.Orchestrator
	DBPool          *pgxpool.Pool
	// For managing the lifecycle of the findings consumer
	findingsChan   chan schemas.Finding
	cancelFindings context.CancelFunc
}

// Shutdown gracefully closes all components.
func (sc *scanComponents) Shutdown() {
	// Signal the findings consumer to stop, then close the channel.
	if sc.cancelFindings != nil {
		sc.cancelFindings()
	}
	if sc.findingsChan != nil {
		close(sc.findingsChan)
	}

	if sc.TaskEngine != nil {
		sc.TaskEngine.Stop()
	}
	if sc.DiscoveryEngine != nil {
		sc.DiscoveryEngine.Stop()
	}
	if sc.BrowserManager != nil {
		// Use a background context for shutdown to ensure it runs even if the main context is cancelled.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := sc.BrowserManager.Shutdown(shutdownCtx); err != nil {
			observability.GetLogger().Warn("Error during browser manager shutdown", zap.Error(err))
		}
	}
	if sc.DBPool != nil {
		sc.DBPool.Close()
	}
}

// initializeScanComponents handles dependency injection.
func initializeScanComponents(ctx context.Context, cfg config.Interface, targets []string, logger *zap.Logger) (*scanComponents, error) {
	components := &scanComponents{}

	// 1. Database Pool
	if cfg.Database().URL == "" {
		return nil, fmt.Errorf("database URL is not configured (SCALPEL_DATABASE_URL)")
	}
	dbPool, err := pgxpool.New(ctx, cfg.Database().URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	components.DBPool = dbPool

	// 2. Store
	dbStore, err := store.New(ctx, dbPool, logger)
	if err != nil {
		return components, fmt.Errorf("failed to initialize database store: %w", err)
	}
	components.Store = dbStore

	// 3. Findings Channel and Consumer
	findingsChan := make(chan schemas.Finding, 256)
	components.findingsChan = findingsChan

	findingsCtx, cancelFindings := context.WithCancel(context.Background())
	components.cancelFindings = cancelFindings
	go startFindingsConsumer(findingsCtx, findingsChan, dbStore, logger)

	// 4. Browser Manager
	browserManager, err := browser.NewManager(ctx, logger, cfg)
	if err != nil {
		return components, fmt.Errorf("failed to initialize browser manager: %w", err)
	}
	components.BrowserManager = browserManager

	// 5. Knowledge Graph
	kg := knowledgegraph.NewPostgresKG(dbPool, logger)
	components.KnowledgeGraph = kg

	// 6. OAST Provider (Out-of-Band Application Security Testing)
	// The analyzer handles a nil provider gracefully. We'll initialize it here
	// once it can be configured. For now, it remains an optional component.
	var oastProvider schemas.OASTProvider
	// TODO: When OAST is configurable, initialize it here. For example:
	// if cfg.OAST().Enabled {
	//     oastProvider, err = oast.NewProvider(cfg.OAST(), logger)
	//     if err != nil { return nil, err }
	// }

	// 7. Global Context
	// This is the fully wired-up context shared across all analysis tasks.
	globalCtx := &core.GlobalContext{
		Config:         cfg,
		Logger:         logger,
		BrowserManager: browserManager,
		DBPool:         dbPool,
		KGClient:       kg,
		OASTProvider:   oastProvider, // This will be nil for now, which is handled correctly.
		FindingsChan:   findingsChan,
	}

	// 8. Worker
	taskWorker, err := worker.NewMonolithicWorker(cfg, logger, globalCtx)
	if err != nil {
		return components, fmt.Errorf("failed to create worker: %w", err)
	}

	// 9. Task Engine
	taskEngine, err := engine.New(cfg, logger, dbStore, taskWorker, globalCtx)
	if err != nil {
		return components, fmt.Errorf("failed to initialize task engine: %w", err)
	}
	components.TaskEngine = taskEngine

	// 10. Discovery Engine
	scopeManager, err := discovery.NewBasicScopeManager(targets[0], cfg.Discovery().IncludeSubdomains)
	if err != nil {
		return components, fmt.Errorf("failed to initialize scope manager: %w", err)
	}
	httpClient := network.NewClient(nil)
	httpAdapter := discovery.NewHTTPClientAdapter(httpClient)
	discoveryCfg := discovery.Config{
		MaxDepth:           cfg.Discovery().MaxDepth,
		Concurrency:        cfg.Discovery().Concurrency,
		Timeout:            cfg.Discovery().Timeout,
		PassiveEnabled:     cfg.Discovery().PassiveEnabled,
		CrtShRateLimit:     cfg.Discovery().CrtShRateLimit,
		CacheDir:           cfg.Discovery().CacheDir,
		PassiveConcurrency: cfg.Discovery().PassiveConcurrency,
	}
	passiveRunner := discovery.NewPassiveRunner(discoveryCfg, httpAdapter, scopeManager, logger)
	discoveryEngine := discovery.NewEngine(discoveryCfg, scopeManager, kg, browserManager, passiveRunner, logger)
	components.DiscoveryEngine = discoveryEngine

	// 11. Orchestrator
	orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
	if err != nil {
		return components, fmt.Errorf("failed to create orchestrator: %w", err)
	}
	components.Orchestrator = orch

	return components, nil
}

// startFindingsConsumer runs a goroutine that reads from the findings channel and persists them.
func startFindingsConsumer(ctx context.Context, findingsChan <-chan schemas.Finding, dbStore schemas.Store, logger *zap.Logger) {
	logger.Info("Starting findings consumer goroutine...")
	for {
		select {
		case finding, ok := <-findingsChan:
			if !ok {
				logger.Info("Findings channel closed, consumer shutting down.")
				return
			}
			// Persist the single finding by wrapping it in an envelope.
			// This is inefficient (one transaction per finding) but robust.
			envelope := &schemas.ResultEnvelope{
				ScanID:    finding.ScanID,
				TaskID:    finding.TaskID,
				Timestamp: time.Now(),
				Findings:  []schemas.Finding{finding},
			}
			persistCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := dbStore.PersistData(persistCtx, envelope); err != nil {
				logger.Error("Failed to persist real-time finding", zap.Error(err), zap.String("finding_id", finding.ID))
			}
			cancel()
		case <-ctx.Done():
			logger.Info("Findings consumer context cancelled, shutting down.")
			return
		}
	}
}

// generateReport handles result processing and report writing.
func generateReport(ctx context.Context, dbStore schemas.Store, scanID, format, outputPath string, logger *zap.Logger) error {
	logger.Info("Generating scan report...", zap.String("format", format), zap.String("output_path", outputPath))

	reporter, err := reporting.New(format, outputPath, logger, Version)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer func() {
		if err := reporter.Close(); err != nil {
			logger.Error("Failed to close reporter", zap.Error(err))
		}
	}()

	pipeline := results.NewPipeline(dbStore, logger)
	processedResults, err := pipeline.ProcessScanResults(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to process scan results: %w", err)
	}

	finalEnvelope := &schemas.ResultEnvelope{
		ScanID:    scanID,
		Timestamp: time.Now(),
		Findings:  processedResults.Findings,
	}

	if err := reporter.Write(finalEnvelope); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	logger.Info("Report generated successfully.", zap.String("path", outputPath))
	return nil
}
