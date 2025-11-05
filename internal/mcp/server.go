package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/findings"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph" // Added import
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	// "github.com/xkilldash9x/scalpel-cli/internal/store" // Store is used implicitly via findings processor or explicit calls if needed.
)

// Server is the main structure for the Master Control Program (MCP), hosting the persistent Agent and core services.
type Server struct {
	cfg        config.Interface
	logger     *zap.Logger
	dbPool     *pgxpool.Pool
	httpServer *http.Server
	agent      *agent.Agent

	// Core Services
	browserManager     schemas.BrowserManager
	browserAllocCancel context.CancelFunc
	findingsProcessor  *findings.Processor
	kgClient           schemas.KnowledgeGraphClient
}

// NewServer initializes the MCP server and its dependencies.
func NewServer() (*Server, error) {
	// Context for initialization phase
	initCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// 1. Initialize Configuration
	v := viper.New()
	config.SetDefaults(v)
	if err := config.LoadConfig(v, ""); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	// Use NewConfigFromViper for robust loading including Env Vars binding and validation
	cfg, err := config.NewConfigFromViper(v)
	if err != nil {
		return nil, fmt.Errorf("failed to process configuration: %w", err)
	}

	// 2. Initialize Logger
	// Use NewLogger for dependency injection and error handling.
	logger, err := observability.NewLogger(cfg.Logger())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.Info("MCP Server initialization started.")

	// 3. Initialize Database Connection
	dbURL := cfg.Database().URL
	var pool *pgxpool.Pool

	if dbURL == "" {
		// Allow initialization without DB for flexibility, but logging a warning.
		logger.Warn("Database URL (SCALPEL_DATABASE_URL) is not set. Proceeding without database persistence.")
	} else {
		pool, err = pgxpool.New(initCtx, dbURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create database connection pool: %w", err)
		}

		if err := pool.Ping(initCtx); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to ping database: %w", err)
		}
		logger.Info("Database connection established successfully.")
	}

	// 4. Initialize Knowledge Graph Client (NEW)
	var kgClient schemas.KnowledgeGraphClient
	if pool != nil {
		// Initialize the Postgres implementation of the KG client.
		// Note: We are using the main dbPool for the KG. If the configuration specifies a different
		// database for the KG (agent.knowledge_graph.postgres), that connection logic should be added here.
		kgClient = knowledgegraph.NewPostgresKG(pool, logger)
		logger.Info("Knowledge Graph client initialized (Postgres).")
	} else {
		logger.Warn("Database pool not available. Knowledge Graph client not initialized.")
		// TODO: Initialize an in-memory KG client here if required as a fallback.
	}

	// 5. Initialize Browser Manager
	browserCfg := cfg.Browser()
	opts := browser.DefaultAllocatorOptions(browserCfg)

	// Initialize the allocator. This context controls the lifetime of the browser process.
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	browserManager, err := browser.NewManager(allocCtx, cfg, logger)
	if err != nil {
		allocCancel() // Clean up browser process
		if pool != nil {
			pool.Close()
		}
		return nil, fmt.Errorf("failed to initialize browser manager: %w", err)
	}
	logger.Info("Browser manager initialized.")

	// 6. Initialize Global Context and Findings Channel
	// The findings channel connects producers (Agents) to the consumer (Processor).
	findingsChan := make(chan schemas.Finding, 5000) // High buffer for bursts

	// Initialize empty adapter registry (Placeholder - needs actual analyzer registration)
	adapters := make(core.AdapterRegistry)

	globalCtx := &core.GlobalContext{
		Config:         cfg,
		Logger:         logger,
		DBPool:         pool,
		KGClient:       kgClient, // Provide the KGClient
		BrowserManager: browserManager,
		// Ensure channel is write-only for context users
		FindingsChan: (chan<- schemas.Finding)(findingsChan),
		// OASTProvider initialization placeholder.
		Adapters: adapters,
	}

	// 7. Initialize Findings Processor
	engineCfg := cfg.Engine()
	// The processor consumes the findingsChan initialized above.
	findingsProcessor := findings.NewProcessor(findingsChan, pool, logger, engineCfg)
	logger.Info("Findings processor initialized.")

	// 8. Initialize the Core Agent
	// We initialize the agent without a specific mission (nil). Session management is internal.
	agentInstance, err := agent.New(initCtx, nil, globalCtx)
	if err != nil {
		// Cleanup on failure
		browserManager.Shutdown(context.Background())
		allocCancel()
		if pool != nil {
			pool.Close()
		}
		observability.Sync() // Sync logger before exiting on error
		return nil, fmt.Errorf("failed to initialize core agent: %w", err)
	}

	return &Server{
		cfg:                cfg,
		logger:             logger,
		dbPool:             pool,
		agent:              agentInstance,
		browserManager:     browserManager,
		browserAllocCancel: allocCancel,
		findingsProcessor:  findingsProcessor,
		kgClient:           kgClient,
	}, nil
}

// Start runs the MCP server, including the HTTP listener and graceful shutdown handling.
func (s *Server) Start() error {
	// Ensure logs are flushed when the server stops.
	defer observability.Sync()

	addr := s.cfg.MCP().ListenAddr
	// Default address is handled by config defaults.

	// --- HTTP Server Setup ---
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	// Use the observability package's middleware.
	r.Use(observability.ZapLogger(s.logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(90 * time.Second)) // Allow longer time for complex queries

	// The agent registers its own interaction routes.
	s.agent.RegisterInteractionRoutes(r)

	// Add a health check route for the server itself
	r.Get("/healthz/server", func(w http.ResponseWriter, r *http.Request) {
		// Basic check: if the HTTP server is responding, it's generally healthy.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("MCP Server OK"))
	})

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	s.logger.Info("MCP Server (Agent Host) starting", zap.String("address", addr))

	// Start the Findings Processor
	// We use context.Background() here as we manage shutdown explicitly via Stop().
	go s.findingsProcessor.Start(context.Background())

	// Start the Agent's cognitive loops
	agentCtx, agentCancel := context.WithCancel(context.Background())
	go func() {
		if err := s.agent.Start(agentCtx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Error("Agent cognitive loop stopped with error", zap.Error(err))
			// If the agent fails critically, we might want to initiate server shutdown.
		}
	}()

	// Goroutine for graceful shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		s.logger.Info("Received shutdown signal, shutting down gracefully...")

		// 1. Stop the agent loops (Stops generation of new findings, allows agent to close its session)
		agentCancel()

		// Create the main shutdown context
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 2. Shut down the HTTP server
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("HTTP server shutdown error", zap.Error(err))
		}

		// 3. Stop the Findings Processor (allows it to flush remaining items)
		s.findingsProcessor.Stop()

		// 4. Shutdown Browser Manager (closes any remaining sessions)
		if s.browserManager != nil {
			s.logger.Info("Shutting down browser manager...")
			if err := s.browserManager.Shutdown(ctx); err != nil {
				s.logger.Error("Browser manager shutdown error", zap.Error(err))
			}
		}

		// 5. Finally, terminate the browser process itself
		if s.browserAllocCancel != nil {
			s.logger.Info("Terminating browser process (allocator)...")
			s.browserAllocCancel()
		}

		// 6. Close database connection (This also closes the associated KG client connection)
		if s.dbPool != nil {
			s.logger.Info("Closing database connections...")
			s.dbPool.Close()
		}

		close(idleConnsClosed)
	}()

	// Start the server
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("HTTP server ListenAndServe error", zap.Error(err))
		// Ensure cleanup if server fails to start
		agentCancel()
		s.findingsProcessor.Stop()
		if s.browserManager != nil {
			s.browserManager.Shutdown(context.Background())
		}
		if s.browserAllocCancel != nil {
			s.browserAllocCancel()
		}
		if s.dbPool != nil {
			s.dbPool.Close()
		}
		// observability.Sync() is called by the defer at the start of Start()
		return err
	}

	// Wait for shutdown to complete
	<-idleConnsClosed
	// observability.Sync() is called by the defer at the start of Start()
	s.logger.Info("MCP Server stopped.")
	return nil
}
