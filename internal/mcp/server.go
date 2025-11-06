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
	"github.com/gorilla/websocket" // Added import
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

// --- WebSocket Definitions and Configuration ---

// WebSocket Upgrader configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Security: Check the origin of the request.
	// The existing CORS middleware (corsMiddleware) allows "*". To allow the WebSocket
	// handshake to succeed in a cross-origin development environment (e.g., Vite dev server),
	// we must configure the upgrader to skip the origin check.
	CheckOrigin: func(r *http.Request) bool {
		// WARNING: In a production environment, this MUST be restricted to allowed origins.
		return true
	},
}

// MessageType defines the kind of message being sent.
// These constants MUST match the frontend definitions (WebSocketContext.tsx).
type MessageType string

const (
	MsgTypeUserPrompt    MessageType = "UserPrompt"
	MsgTypeAgentResponse MessageType = "AgentResponse"
	MsgTypeStatusUpdate  MessageType = "StatusUpdate"
	MsgTypeSystemError   MessageType = "SystemError"
)

// WSMessage defines the standardized structure for communication over the WebSocket.
type WSMessage struct {
	Type MessageType `json:"type"`
	// Data payload. Using a generic map for flexibility; specific structures can be parsed from this.
	Data map[string]interface{} `json:"data,omitempty"`
	// Timestamp formatted as ISO 8601 (RFC3339) to match JS Date().toISOString().
	Timestamp string `json:"timestamp"`
	// RequestID is crucial for correlating requests/responses (used by the frontend's optimistic UI).
	RequestID string `json:"request_id,omitempty"`
}

// Constants for WebSocket timeouts and limits (based on Gorilla WebSocket examples).
const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// Maximum message size allowed from peer.
	maxMessageSize = 8192
	// Send buffer size
	sendChannelSize = 256
)

// wsClient represents a single active WebSocket connection.
// It manages the connection lifecycle and message pumps.
type wsClient struct {
	server *Server
	conn   *websocket.Conn
	// Buffered channel of outgoing messages. The writePump reads from this.
	send chan WSMessage
}

// --- End WebSocket Definitions ---

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

	// 2. Define WebSocket routes FIRST, without the problematic logger
	r.Get("/ws/v1/interact", s.handleAgentInteract())
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

// handleAgentInteract manages the WebSocket lifecycle for real-time agent interaction.
// It upgrades the connection and starts the necessary goroutines (pumps) to handle I/O.
func (s *Server) handleAgentInteract() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger.Debug("Received request to upgrade connection for agent interaction.", zap.String("remoteAddr", r.RemoteAddr))

		// 1. Upgrade the HTTP connection to a WebSocket connection
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			// upgrader.Upgrade automatically sends an HTTP error response if it fails.
			s.logger.Error("Failed to upgrade connection to WebSocket", zap.Error(err))
			return
		}

		s.logger.Info("WebSocket connection established successfully (/ws/v1/interact).", zap.String("remoteAddr", r.RemoteAddr))

		// 2. Initialize the client connection state
		client := &wsClient{
			server: s,
			conn:   conn,
			// Initialize the send channel. The writePump reads from this channel,
			// ensuring synchronized writes to the connection.
			send: make(chan WSMessage, sendChannelSize),
		}

		// 3. Start the pumps for handling I/O
		// Start the write pump in a new goroutine (handles sending messages and pings)
		go client.writePump()
		// Start the read pump in the current goroutine (handles incoming messages and pongs)
		// This function blocks until the connection is closed.
		client.readPump()

		// When readPump exits, the connection is closed and resources are cleaned up (handled by defers in the pumps).
		s.logger.Debug("WebSocket interaction handler finished.", zap.String("remoteAddr", r.RemoteAddr))
	}
}

// readPump pumps messages from the WebSocket connection to the server/agent.
// A dedicated readPump ensures the application quickly processes incoming data
// and control messages (like Pongs/Close), keeping the connection responsive.
func (c *wsClient) readPump() {
	// Ensure cleanup when the pump stops
	defer func() {
		// If integrating with an agent session manager, unregister the session here.
		c.conn.Close()
	}()

	// Configure connection parameters
	c.conn.SetReadLimit(maxMessageSize)
	// Initialize the read deadline
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		c.server.logger.Error("Failed to set initial read deadline", zap.Error(err))
		return
	}
	// Handle incoming PONG messages (response to our PINGs) to keep the connection alive by resetting the deadline.
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	// Main loop for reading incoming messages
	for {
		var incomingMsg WSMessage
		// ReadJSON blocks until a message is received or an error occurs (including timeout or closure).
		err := c.conn.ReadJSON(&incomingMsg)
		if err != nil {
			// Check if the closure was expected or unexpected
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.server.logger.Error("WebSocket closed unexpectedly", zap.Error(err))
			} else {
				// Expected closures (e.g., user navigated away, or read timeout occurred)
				c.server.logger.Info("WebSocket connection closed.")
			}
			// Break the loop on any error (including closure or timeout)
			break
		}

		c.server.logger.Debug("Received message from client", zap.String("type", string(incomingMsg.Type)), zap.String("requestID", incomingMsg.RequestID))

		// Process the incoming message
		c.processMessage(incomingMsg)
	}
}

// writePump pumps messages from the server/agent to the WebSocket connection.
// It centralizes all writes, ensuring synchronized access (as required by Gorilla WebSocket),
// and handles PING messages to keep the connection alive.
func (c *wsClient) writePump() {
	// Ticker for sending periodic PING messages.
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			// Set a deadline for the write operation.
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				c.server.logger.Error("Failed to set write deadline", zap.Error(err))
				return
			}

			if !ok {
				// The 'send' channel was closed (e.g., by the server during shutdown). Send a close message to the client and exit.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Write the JSON message to the connection.
			if err := c.conn.WriteJSON(message); err != nil {
				c.server.logger.Error("Error writing JSON message to WebSocket", zap.Error(err))
				// If writing fails, the connection is likely broken. Stop the pump.
				return
			}

		case <-ticker.C:
			// Time to send a PING message.
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				c.server.logger.Error("Failed to set write deadline for PING", zap.Error(err))
				return
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.server.logger.Error("Error sending PING message to WebSocket", zap.Error(err))
				// If PING fails, the connection is likely broken. Stop the pump.
				return
			}
		}
	}
}

// processMessage handles the logic for different incoming message types.
func (c *wsClient) processMessage(msg WSMessage) {
	switch msg.Type {
	case MsgTypeUserPrompt:
		// 1. Validation
		if msg.RequestID == "" {
			// The frontend relies on request_id for optimistic updates.
			c.sendError(msg.RequestID, "UserPrompt message requires a valid request_id.")
			return
		}

		// Robustly extract the prompt from the generic Data field
		promptRaw, ok := msg.Data["prompt"]
		if !ok {
			c.sendError(msg.RequestID, "Missing 'prompt' field in UserPrompt message.")
			return
		}
		prompt, ok := promptRaw.(string)
		if !ok || strings.TrimSpace(prompt) == "" {
			c.sendError(msg.RequestID, "Invalid or empty 'prompt' provided.")
			return
		}

		// 2. Offload Processing
		// Handle the interaction asynchronously so we don't block the readPump.
		// The readPump must remain responsive to handle control messages (Pongs/Close).
		go c.handleAgentInteraction(msg.RequestID, prompt)

	default:
		// Handle unknown message types
		c.server.logger.Warn("Received unknown message type from client", zap.String("type", string(msg.Type)))
		c.sendError(msg.RequestID, fmt.Sprintf("Unknown or unsupported message type: %s", msg.Type))
	}
}

// handleAgentInteraction is where the prompt is passed to the core agent logic.
// This runs in its own goroutine.
func (c *wsClient) handleAgentInteraction(requestID string, prompt string) {
	c.server.logger.Info("Processing user prompt", zap.String("requestID", requestID), zap.String("prompt", prompt))

	// TODO: Implement the actual interaction with the core agent (c.server.agent).
	// This involves sending the prompt to the agent (e.g., c.server.agent.SubmitPrompt(prompt))
	// and setting up a mechanism to stream the agent's responses back to this specific client.
	// The agent's output stream should utilize c.sendMessage() to communicate back.

	// --- Placeholder Implementation ---
	c.sendStatus(requestID, "Prompt received. Simulating agent processing...")

	// Simulate processing time
	time.Sleep(1 * time.Second)

	// Construct the response
	responseText := fmt.Sprintf("Agent (Placeholder) processed: '%s'. Full integration pending.", prompt)

	// Send the final response. The frontend might expect a specific key (e.g., 'content' or 'response').
	c.sendMessage(MsgTypeAgentResponse, requestID, map[string]interface{}{
		"content": responseText,
	})
}

// sendMessage is a helper to construct and queue a message for sending via the writePump.
func (c *wsClient) sendMessage(msgType MessageType, requestID string, data map[string]interface{}) {
	msg := WSMessage{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339), // ISO 8601 format expected by frontend
		RequestID: requestID,
	}

	// Queue the message safely.
	select {
	case c.send <- msg:
		// Message queued successfully.
	default:
		// If the send buffer is full, it indicates the client is slow or the connection is dead.
		// We log an error and drop the message to prevent blocking the sender (e.g., the agent).
		c.server.logger.Error("WebSocket send buffer full, dropping message. Client may be unresponsive.",
			zap.String("requestID", requestID), zap.String("type", string(msgType)))
		// Optionally, we might want to initiate connection closure if the buffer remains full for too long.
	}
}

// sendError is a helper function to send standardized SYSTEM_ERROR messages.
func (c *wsClient) sendError(requestID string, errorMessage string) {
	c.sendMessage(MsgTypeSystemError, requestID, map[string]interface{}{
		"error": errorMessage,
	})
}

// sendStatus is a helper function to send standardized STATUS_UPDATE messages.
func (c *wsClient) sendStatus(requestID string, statusMessage string) {
	c.sendMessage(MsgTypeStatusUpdate, requestID, map[string]interface{}{
		"status": statusMessage,
	})
}

// handleScan is a placeholder for the WebSocket endpoint.
// Resolves compilation error: s.handleScan undefined.
func (s *Server) handleScan() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Warn("WebSocket /ws/v1/scan accessed but is not yet implemented.")
		// Potential improvement: Upgrade and immediately close with a specific code if implemented via WebSocket later.
		http.Error(w, "Not Implemented", http.StatusNotImplemented)
	})
}
