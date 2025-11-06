package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	// "github.com/gorilla/websocket" // Removed: WebSocket handling is now managed by internal/agent/websocket.go
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/findings"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	// "github.com/xkilldash9x/scalpel-cli/internal/store" // Store is used implicitly via findings processor or explicit calls if needed.
)

// NOTE: All previous WebSocket definitions (upgrader, MessageType, WSMessage, wsClient, pumps) have been removed.
// This functionality is now implemented in internal/agent/websocket.go and managed by the Agent.

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
	// MCP Specific Services and Handlers (initialized in NewServer)
	queryService *QueryService
	scanService  *ScanService
	handlers     *Handlers
}

// NewServer initializes the MCP server and its dependencies.
// (NewServer implementation remains the same as provided in the prompt, as it correctly initializes the agent)
func NewServer() (*Server, error) {
	// Context for initialization phase
	initCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// 1. Initialize Configuration
	v := viper.New()
	config.SetDefaults(v)

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

	// 9. Initialize MCP Services (Query and Scan)
	// Initialize ScanService (only depends on logger, tracks jobs in memory)
	scanService := NewScanService(logger)
	logger.Info("MCP Scan Service initialized.")

	// Initialize QueryService (depends on DB pool)
	// We initialize it even if the pool is nil; the service methods (in database.go)
	// and the handlers (in handlers.go) handle the lack of connection robustly.
	queryService := NewQueryService(pool, logger)

	if pool != nil {
		logger.Info("MCP Query Service initialized.")
	} else {
		logger.Warn("MCP Query Service initialized without database. Query endpoints will be unavailable.")
	}

	// 10. Initialize MCP Handlers
	handlers := NewHandlers(logger, queryService, scanService)

	return &Server{
		cfg:                cfg,
		logger:             logger,
		dbPool:             pool,
		agent:              agentInstance,
		browserManager:     browserManager,
		browserAllocCancel: allocCancel,
		findingsProcessor:  findingsProcessor,
		kgClient:           kgClient,
		queryService:       queryService,
		scanService:        scanService,
		handlers:           handlers,
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

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)                  // Catches panics
	r.Use(middleware.Timeout(120 * time.Second)) // Increased timeout for potentially long-lived requests

	// Robustness: Add CORS Middleware for development flexibility (e.g., running frontend dev server on a different port)
	// In production, this should be more restrictive.
	r.Use(corsMiddleware)

	// 2. Define WebSocket and Agent routes FIRST, without the problematic logger

	// Register Agent Interaction Routes (including /ws/v1/interact)
	if s.agent != nil {
		// This delegates the handling of specific routes (defined in agent.go) to the agent's internal WSManager.
		// This replaces the previous direct call to s.handleAgentInteract().
		s.agent.RegisterInteractionRoutes(r)
		s.logger.Info("Agent interaction routes registered.")
	} else {
		// This should ideally not happen if NewServer() succeeded.
		s.logger.Error("Agent not initialized, interaction routes (/ws/v1/interact) will not be served.")
	}

	// MCP specific WebSocket route
	r.Get("/ws/v1/scan", s.handleScan())

	// 3. Create a new router group for HTTP-only routes that *will* use the logger
	r.Group(func(r chi.Router) {
		// Apply middlewares specific to HTTP API and file serving
		r.Use(middleware.Logger) // <-- The logger is now applied ONLY to this group

		// Register API routes using the Handlers struct.
		// This resolves the missing s.handleScanRequest and s.handleDashboardData errors.
		if s.handlers != nil {
			// This handles /healthz and /api/v1/* routes as defined in handlers.go.
			s.handlers.RegisterRoutes(r)
		} else {
			// This should ideally not happen if NewServer() succeeded.
			s.logger.Error("Handlers not initialized, API routes will not be served.")
		}

		// --- Static File Server ---
		// Assumes your frontend build is in "frontend/dist"
		staticPath := "frontend/dist"
		absPath, err := filepath.Abs(staticPath)
		if err != nil {
			// Robustness Improvement: Do not crash (Fatal) if static files path is invalid, just warn.
			s.logger.Warn("Failed to resolve static file path. Frontend may not be served.", zap.Error(err), zap.String("path", staticPath))
		} else {
			s.logger.Info("Attempting to serve static files", zap.String("path", absPath))

			// Robustness Improvement: Check if the directory actually exists before serving.
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				s.logger.Warn("Static file directory does not exist. Frontend will not be served. Ensure 'frontend/dist' is built.", zap.String("path", absPath))
			} else {
				fs := http.FileServer(http.Dir(absPath))
				r.Handle("/*", http.StripPrefix("/", fs))

				// Fallback for SPAs: serves index.html for any route not found
				r.NotFound(func(w http.ResponseWriter, r *http.Request) {
					// Don't serve index.html for API-like paths
					if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
						http.NotFound(w, r)
						return
					}
					http.ServeFile(w, r, filepath.Join(absPath, "index.html"))
				})
			}
		}
	})

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	s.logger.Info("MCP Server (Agent Host) starting", zap.String("address", addr))

	// Start the Findings Processor
	// We use context.Background() here as we manage shutdown explicitly via Stop().
	go s.findingsProcessor.Start(context.Background())

	// Start the Agent's cognitive loops (This also starts the Agent's WSManager loop)
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

		// 1. Stop the agent loops (Stops generation of new findings, allows agent to close its session, stops WSManager)
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

// corsMiddleware provides basic CORS support required for the dashboard.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: In a production environment, restrict the origin.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleAgentInteract is removed. The implementation is now delegated to the Agent via RegisterInteractionRoutes.

// handleScan is a placeholder for the WebSocket endpoint.
// Resolves compilation error: s.handleScan undefined.
func (s *Server) handleScan() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Warn("WebSocket /ws/v1/scan accessed but is not yet implemented.")
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	})
}