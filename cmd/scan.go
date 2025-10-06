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
	"github.com/spf13/viper"
	"go.uber.org/zap"

	// Import necessary internal packages
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/discovery"
	"github.com/xkilldash9x/scalpel-cli/internal/engine"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
	"github.com/xkilldash9x/scalpel-cli/internal/results"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
)

// newScanCmd creates and configures the `scan` command.
func newScanCmd() *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Args:  cobra.MinimumNArgs(1),
		// The PreRunE function is a good place to handle configuration finalization
		// before the main execution logic in RunE.
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind flags to their corresponding Viper keys. This is the idiomatic way
			// to ensure that command-line flags correctly override values from
			// the config file and environment variables.
			if err := viper.BindPFlag("discovery.max_depth", cmd.Flags().Lookup("depth")); err != nil {
				return err
			}
			if err := viper.BindPFlag("engine.worker_concurrency", cmd.Flags().Lookup("concurrency")); err != nil {
				return err
			}
			// Bind all other flags that don't have a direct mapping.
			return viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use the context passed from main.go (signal-aware).
			ctx := cmd.Context()
			logger := observability.GetLogger()

			// 1. Configuration Finalization
			cfg := config.Get()

			// Re-unmarshal the config. Now that flags are properly bound in PreRunE,
			// Viper will correctly apply the overrides with the right precedence.
			if err := viper.Unmarshal(cfg); err != nil {
				return fmt.Errorf("failed to re-unmarshal config with flag overrides: %w", err)
			}

			// Populate the ScanConfig from command line arguments and final config values.
			// This struct centralizes all runtime settings for the current scan.
			cfg.Scan.Targets = args
			cfg.Scan.Output = viper.GetString("output")
			cfg.Scan.Format = viper.GetString("format")
			cfg.Scan.Scope = viper.GetString("scope")
			// Use the final, resolved values from the main config.
			cfg.Scan.Concurrency = cfg.Engine.WorkerConcurrency
			cfg.Scan.Depth = cfg.Discovery.MaxDepth

			// Map the 'scope' flag to the appropriate discovery setting.
			switch strings.ToLower(cfg.Scan.Scope) {
			case "subdomain":
				cfg.Discovery.IncludeSubdomains = true
			case "strict":
				cfg.Discovery.IncludeSubdomains = false
			default:
				// If an unsupported scope value is given, log a warning and default to the safest option.
				logger.Warn("Invalid scope value provided, defaulting to 'strict'", zap.String("scope", cfg.Scan.Scope))
				cfg.Discovery.IncludeSubdomains = false
			}

			scanID := uuid.New().String()
			targets := cfg.Scan.Targets

			// Ensure the primary target has a scheme for the scope manager.
			if len(targets) > 0 {
				if !strings.HasPrefix(targets[0], "http://") && !strings.HasPrefix(targets[0], "https://") {
					targets[0] = "https://" + targets[0]
				}
			}

			logger.Info("Starting new scan",
				zap.String("scanID", scanID),
				zap.Strings("targets", targets),
				zap.Int("discovery_depth", cfg.Discovery.MaxDepth),
				zap.Int("engine_concurrency", cfg.Engine.WorkerConcurrency),
				zap.String("scope", cfg.Scan.Scope),
			)

			// 2. Initialize Core Components
			components, err := initializeScanComponents(ctx, cfg, targets, logger)
			if err != nil {
				if components != nil {
					components.Shutdown(ctx)
				}
				return fmt.Errorf("failed to initialize scan components: %w", err)
			}
			defer components.Shutdown(ctx)

			// 3. Execute Scan Orchestration
			if err := components.Orchestrator.StartScan(ctx, targets, scanID); err != nil {
				if errors.Is(err, context.Canceled) {
					logger.Warn("Scan aborted gracefully", zap.String("scanID", scanID))
					return fmt.Errorf("scan aborted by user signal")
				}
				logger.Error("Scan failed during orchestration", zap.Error(err), zap.String("scanID", scanID))
				return err
			}

			logger.Info("Scan execution completed successfully", zap.String("scanID", scanID))

			// 4. Reporting
			if cfg.Scan.Output != "" {
				if err := generateReport(ctx, components.Store, scanID, cfg.Scan.Format, cfg.Scan.Output, logger); err != nil {
					return err
				}
			}

			// 5. Final Output
			fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
			if cfg.Scan.Output == "" {
				fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
			}

			return nil
		},
	}

	// Reporting flags
	scanCmd.Flags().StringP("output", "o", "", "Output file path for the report. If unset, no report is generated.")
	scanCmd.Flags().StringP("format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json').")

	// Scan configuration override flags.
	scanCmd.Flags().IntP("depth", "d", 0, "Maximum crawl depth. (Overrides config/env)")
	scanCmd.Flags().IntP("concurrency", "j", 0, "Number of concurrent engine workers. (Overrides config/env)")
	scanCmd.Flags().String("scope", "strict", "Scan scope strategy (e.g., 'strict', 'subdomain'). (Overrides config/env)")

	return scanCmd
}

// scanComponents holds initialized services.
type scanComponents struct {
	Store           *store.Store
	BrowserManager  schemas.BrowserManager
	KnowledgeGraph  schemas.KnowledgeGraphClient
	TaskEngine      schemas.TaskEngine
	DiscoveryEngine schemas.DiscoveryEngine
	Orchestrator    *orchestrator.Orchestrator
	DBPool          *pgxpool.Pool
}

// Shutdown gracefully closes all components.
func (sc *scanComponents) Shutdown(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if sc.TaskEngine != nil {
		sc.TaskEngine.Stop()
	}
	if sc.DiscoveryEngine != nil {
		sc.DiscoveryEngine.Stop()
	}
	if sc.BrowserManager != nil {
		if err := sc.BrowserManager.Shutdown(shutdownCtx); err != nil {
			observability.GetLogger().Warn("Error during browser manager shutdown", zap.Error(err))
		}
	}
	if sc.DBPool != nil {
		sc.DBPool.Close()
	}
}

// initializeScanComponents handles dependency injection.
func initializeScanComponents(ctx context.Context, cfg *config.Config, targets []string, logger *zap.Logger) (*scanComponents, error) {
	components := &scanComponents{}

	// 1. Database and Store
	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("database URL is not configured (SCALPEL_DATABASE_URL)")
	}
	dbPool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	components.DBPool = dbPool

	dbStore, err := store.New(ctx, dbPool, logger)
	if err != nil {
		return components, fmt.Errorf("failed to initialize database store: %w", err)
	}
	components.Store = dbStore

	// 2. Browser Manager
	browserManager, err := browser.NewManager(ctx, logger, cfg)
	if err != nil {
		return components, fmt.Errorf("failed to initialize browser manager: %w", err)
	}
	components.BrowserManager = browserManager

	// 3. Knowledge Graph
	kg, err := agent.NewGraphStoreFromConfig(ctx, cfg.Agent.KnowledgeGraph, dbPool, logger)
	if err != nil {
		return components, fmt.Errorf("failed to initialize knowledge graph store: %w", err)
	}
	components.KnowledgeGraph = kg

	// 4. Task Engine
	taskEngine, err := engine.New(cfg, logger, dbStore, browserManager, kg)
	if err != nil {
		return components, fmt.Errorf("failed to initialize task engine: %w", err)
	}
	components.TaskEngine = taskEngine

	// 5. Discovery Engine
	scopeManager, err := discovery.NewBasicScopeManager(targets[0], cfg.Discovery.IncludeSubdomains)
	if err != nil {
		return components, fmt.Errorf("failed to initialize scope manager: %w", err)
	}

	httpClient := network.NewClient(nil)
	httpAdapter := discovery.NewHTTPClientAdapter(httpClient)

	discoveryCfg := discovery.Config{
		MaxDepth:           cfg.Discovery.MaxDepth,
		Concurrency:        cfg.Discovery.Concurrency,
		Timeout:            cfg.Discovery.Timeout,
		PassiveEnabled:     cfg.Discovery.PassiveEnabled,
		CrtShRateLimit:     cfg.Discovery.CrtShRateLimit,
		CacheDir:           cfg.Discovery.CacheDir,
		PassiveConcurrency: cfg.Discovery.PassiveConcurrency,
	}

	passiveRunner := discovery.NewPassiveRunner(discoveryCfg, httpAdapter, scopeManager, logger)
	discoveryEngine := discovery.NewEngine(discoveryCfg, scopeManager, kg, browserManager, passiveRunner, logger)
	components.DiscoveryEngine = discoveryEngine

	// 6. Orchestrator
	orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
	if err != nil {
		return components, fmt.Errorf("failed to create orchestrator: %w", err)
	}
	components.Orchestrator = orch

	return components, nil
}

// generateReport handles result processing and report writing.
func generateReport(ctx context.Context, dbStore *store.Store, scanID, format, outputPath string, logger *zap.Logger) error {
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

