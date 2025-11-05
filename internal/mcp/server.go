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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Server is the main structure for the Master Control Program (MCP), now hosting the persistent Agent.
type Server struct {
	cfg        config.Interface
	logger     *zap.Logger
	dbPool     *pgxpool.Pool
	httpServer *http.Server
	agent      *agent.Agent
}

// NewServer initializes the MCP server and its dependencies.
// (The NewServer implementation remains the same as previously defined)
func NewServer() (*Server, error) {
	// Context for initialization phase
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Initialize Configuration (Reuse existing CLI logic)
	v := viper.New()
	config.SetDefaults(v)
	if err := config.LoadConfig(v, ""); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	cfg := config.NewViperConfig(v)

	// 2. Initialize Logger
	logger, err := observability.NewLogger(cfg.Logging())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	logger.Info("MCP Server initialization started.")

	// 3. Initialize Database Connection
	dbURL := cfg.Database().URL
	if dbURL == "" {
		// The MCP requires the database for the Agent's Knowledge Graph and finding storage.
		return nil, fmt.Errorf("database URL is required (SCALPEL_DATABASE_URL)")
	}

	pool, err := pgxpool.New(initCtx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection pool: %w", err)
	}

	// Keep the pool reference for full health checks later, but verify connectivity now.
	if err := pool.Ping(initCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	logger.Info("Database connection established successfully.")

	// 4. Initialize the Core Agent
	// Setup GlobalContext required by the Agent and its Executors.
	globalCtx := &core.GlobalContext{
		Config:       cfg,
		Logger:       logger,
		DBPool:       pool,
		// Findings Channel is required for sub-agents launched by ScanExecutor.
		// TODO: A centralized findings processor should be started here to consume this channel.
		FindingsChan: make(chan schemas.Finding, 1000),
		// Adapters initialization is complex, requires analysis/adapters package initialization.
		// Placeholder: Assume adapters are initialized elsewhere or are empty for now.
	}

	// We initialize the agent without a specific mission (nil) and without an initial session (nil).
	agentInstance, err := agent.New(initCtx, nil, globalCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize core agent: %w", err)
	}

	return &Server{
		cfg:      cfg,
		logger:   logger,
		dbPool:   pool,
		agent:    agentInstance,
	}, nil
}

// Start runs the MCP server, including the HTTP listener and graceful shutdown handling.
func (s *Server) Start() error {
	addr := s.cfg.MCP().ListenAddr
	if addr == "" {
		addr = ":8080" // Default address
	}

	// --- HTTP Server Setup ---
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(observability.ZapLogger(s.logger)) // Use the custom Zap logger middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(90 * time.Second)) // Allow longer time for complex queries

	// The agent registers its own interaction routes now.
	s.agent.RegisterInteractionRoutes(r)

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	s.logger.Info("MCP Server (Agent Host) starting", zap.String("address", addr))

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

		// Stop the agent loops
		agentCancel()

		s.logger.Info("Received shutdown signal, shutting down gracefully...")

		// Wait for 30 seconds for active connections to finish
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error("HTTP server shutdown error", zap.Error(err))
		}

		close(idleConnsClosed)
	}()

	// Start the server
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("HTTP server ListenAndServe error", zap.Error(err))
		agentCancel() // Ensure agent stops if server fails to start
		return err
	}

	// Wait for shutdown to complete
	<-idleConnsClosed
	s.logger.Info("MCP Server stopped.")
	return nil
}