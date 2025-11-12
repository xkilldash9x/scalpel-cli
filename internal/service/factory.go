// File: internal/service/factory.go
package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/chromedp/chromedp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/discovery"
	"github.com/xkilldash9x/scalpel-cli/internal/engine"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
	"github.com/xkilldash9x/scalpel-cli/internal/worker"
	"go.uber.org/zap"
)

// ComponentFactory defines the interface for creating the set of components needed for a scan.
// This abstraction is the key to making the scan command's logic testable.
// (Moved from cmd/factory.go)
// Returns interface{} to allow flexibility and avoid potential import cycles if mocks were in a separate package relying on this interface.
type ComponentFactory interface {
	Create(ctx context.Context, cfg config.Interface, targets []string, logger *zap.Logger) (interface{}, error)
}

// concreteFactory is the production implementation of the ComponentFactory.
type concreteFactory struct{}

// NewComponentFactory creates a new production-ready component factory.
func NewComponentFactory() ComponentFactory {
	return &concreteFactory{}
}

// getBrowserExecOptions translates the application config into chromedp allocator options.
func getBrowserExecOptions(cfg config.Interface) []chromedp.ExecAllocatorOption {
	// Start with chromedp defaults
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// This is the fix for the "Permission denied" error on hardened systems.
		chromedp.NoSandbox,
		// This flag is also recommended for stability in containers/headless envs
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	// Apply Headless configuration.
	if cfg.Browser().Headless {
		opts = append(opts, chromedp.Headless)
	}

	// Apply DisableGPU
	if cfg.Browser().DisableGPU {
		opts = append(opts, chromedp.DisableGPU)
	}

	// Add additional flags from the config file's 'args' slice.
	for _, arg := range cfg.Browser().Args {
		// Handle boolean flags (e.g., --no-zygote)
		if !strings.Contains(arg, "=") {
			// Ensure -- is prefixed if missing, for safety
			if !strings.HasPrefix(arg, "--") {
				arg = "--" + arg
			}
			opts = append(opts, chromedp.Flag(arg, true))
			continue
		}

		// Handle key=value flags
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			// Ensure -- is prefixed if missing
			if !strings.HasPrefix(key, "--") {
				key = "--" + key
			}
			opts = append(opts, chromedp.Flag(key, value))
		}
	}
	return opts
}

// Create handles the full dependency injection and initialization of scan components.
func (f *concreteFactory) Create(ctx context.Context, cfg config.Interface, targets []string, logger *zap.Logger) (interface{}, error) {
	components := &Components{
		// Initialize the findings channel early with a generous buffer.
		findingsChan: make(chan schemas.Finding, 1024),
		// Initialize the WaitGroup. It will be managed by StartFindingsConsumer.
		consumerWG: &sync.WaitGroup{},
	}

	// STABILITY ENHANCEMENT: Ensure cleanup happens if initialization fails midway.
	var initializationErr error
	defer func() {
		if initializationErr != nil {
			logger.Warn("Initialization failed, shutting down partially created components.", zap.Error(initializationErr))
			// Call Shutdown on the partially initialized components struct.
			components.Shutdown()
		}
	}()

	// 1. Database Pool
	if cfg.Database().URL == "" {
		initializationErr = fmt.Errorf("database URL is not configured (hint: check SCALPEL_DATABASE_URL)")
		return nil, initializationErr
	}

	dbPool, err := pgxpool.New(ctx, cfg.Database().URL)
	if err != nil {
		initializationErr = fmt.Errorf("failed to create database connection pool: %w", err)
		return nil, initializationErr
	}

	// Add to components immediately so the deferred Shutdown can close it if later steps fail.
	components.DBPool = dbPool

	if err := dbPool.Ping(ctx); err != nil {
		initializationErr = fmt.Errorf("failed to ping database: %w", err)
		return nil, initializationErr
	}
	logger.Debug("Database connection pool initialized.")

	// 2. Store
	dbStore, err := store.New(ctx, dbPool, logger)
	if err != nil {
		initializationErr = fmt.Errorf("failed to initialize database store: %w", err)
		return nil, initializationErr
	}
	components.Store = dbStore
	logger.Debug("Store service initialized.")

	// 3. Findings Consumer (Now with Batching)
	// Start the consumer. It manages the WaitGroup (Adds(1) internally and Done() on exit).
	StartFindingsConsumer(ctx, components.consumerWG, components.findingsChan, dbStore, logger)
	logger.Debug("Findings consumer started (with batching).")

	// 4. Browser Manager
	// Create a new root allocator context for the browser lifecycle.
	allocatorOpts := getBrowserExecOptions(cfg)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocatorOpts...)

	// Assign the cancel function to the components struct so it can be called during shutdown.
	components.BrowserAllocatorCancel = allocCancel

	browserManager, err := browser.NewManager(allocCtx, cfg, logger)
	if err != nil {
		initializationErr = fmt.Errorf("failed to initialize browser manager: %w", err)
		return nil, initializationErr
	}

	// Add manager immediately so deferred Shutdown can close browsers.
	components.BrowserManager = browserManager
	logger.Debug("Browser manager initialized.")

	// 5. Knowledge Graph
	// We use the specific Postgres implementation here because the scan factory assumes a persistent DB connection initialized in step 1.
	kg := knowledgegraph.NewPostgresKG(dbPool, logger)
	components.KnowledgeGraph = kg
	logger.Debug("Knowledge graph client initialized.")

	// 6. OAST Provider (Out of Band Application Security Testing)
	var oastProvider schemas.OASTProvider
	// TODO: When OAST is configurable, initialize it here.
	logger.Debug("OAST provider remains nil (not yet implemented).")

	// 7. Global Context for analyzers
	globalCtx := &core.GlobalContext{
		Config:         cfg,
		Logger:         logger,
		BrowserManager: browserManager,
		DBPool:         dbPool,
		KGClient:       kg,
		OASTProvider:   oastProvider,
		FindingsChan:   components.findingsChan,
	}
	logger.Debug("Global analysis context created.")

	// 8. Monolithic Worker
	taskWorker, err := worker.NewMonolithicWorker(cfg, logger, globalCtx)
	if err != nil {
		initializationErr = fmt.Errorf("failed to create monolithic worker: %w", err)
		return nil, initializationErr
	}
	logger.Debug("Monolithic worker created.")

	// 9. Task Engine
	taskEngine, err := engine.New(cfg, logger, dbStore, taskWorker, globalCtx)
	if err != nil {
		initializationErr = fmt.Errorf("failed to initialize task engine: %w", err)
		return nil, initializationErr
	}
	components.TaskEngine = taskEngine
	logger.Debug("Task engine initialized.")

	// 10. Discovery Engine
	// Ensure there is at least one target for the scope manager.
	if len(targets) == 0 {
		initializationErr = fmt.Errorf("at least one target is required to initialize the discovery engine")
		return nil, initializationErr
	}

	// Use the primary target (targets[0]) to initialize the scope.
	scopeManager, err := discovery.NewBasicScopeManager(targets[0], cfg.Discovery().IncludeSubdomains)
	if err != nil {
		initializationErr = fmt.Errorf("failed to initialize scope manager: %w", err)
		return nil, initializationErr
	}

	httpClient := network.NewClient(nil)
	httpAdapter := discovery.NewHTTPClientAdapter(httpClient)

	passiveRunner := discovery.NewPassiveRunner(cfg, httpAdapter, scopeManager, logger)
	discoveryEngine := discovery.NewEngine(cfg, scopeManager, kg, browserManager, passiveRunner, logger)
	components.DiscoveryEngine = discoveryEngine
	logger.Debug("Discovery engine initialized.")

	// 11. Orchestrator
	orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
	if err != nil {
		initializationErr = fmt.Errorf("failed to create orchestrator: %w", err)
		return nil, initializationErr
	}
	components.Orchestrator = orch
	logger.Debug("Orchestrator initialized.")

	logger.Info("All scan components initialized successfully.")

	// Return the components. The deferred function will not trigger Shutdown as initializationErr is nil.
	return components, nil
}
