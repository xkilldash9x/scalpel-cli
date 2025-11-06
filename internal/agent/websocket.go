package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// Maximum message size allowed from peer.
	maxMessageSize = 2048 * 2048 // 2MB
	// Send buffer size
	sendChannelSize = 256
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all connections for now. This aligns with the CORS policy in MCP.
		// WARNING: In a production environment, this MUST be restricted to allowed origins.
		return true
	},
}

// --- Message Definitions (Aligned with Frontend) ---

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

// --- End Message Definitions ---

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	id        string
	wsManager *WSManager
	conn      *websocket.Conn
	// Buffered channel of outbound messages (as JSON bytes).
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.wsManager.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	// Initialize the read deadline
	if err := c.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		c.wsManager.logger.Error("Failed to set initial read deadline", zap.Error(err))
		return
	}
	// Handle incoming PONG messages to keep the connection alive.
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		// Use ReadJSON to automatically unmarshal into the standardized structure.
		var incomingMsg WSMessage
		err := c.conn.ReadJSON(&incomingMsg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.wsManager.logger.Warn("Websocket client closed unexpectedly or failed JSON decode", zap.Error(err))
			} else {
				// Expected closures (e.g., user navigated away, or read timeout occurred)
				c.wsManager.logger.Debug("WebSocket connection closed.")
			}
			break
		}

		c.wsManager.logger.Debug("Received message from client",
			zap.String("client_id", c.id),
			zap.String("type", string(incomingMsg.Type)),
			zap.String("requestID", incomingMsg.RequestID))

		// Process the incoming message and dispatch it to the agent architecture.
		c.processMessage(incomingMsg)
	}
}

// processMessage handles the logic for different incoming message types and integrates with the Cognitive Bus.
func (c *Client) processMessage(msg WSMessage) {
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

		// 2. Create an Observation for the user input
		// This allows the Mind to process the input within its normal cognitive loop.
		obs := Observation{
			ID:        uuid.New().String(),
			MissionID: c.wsManager.agent.GetMission().ID, // Associate with current mission if any
			Type:      ObservedUserInput,
			Data: map[string]interface{}{
				"prompt":     prompt,
				"request_id": msg.RequestID,
			},
			Timestamp: time.Now().UTC(),
			Result: ExecutionResult{
				Status:          "success",
				ObservationType: ObservedUserInput,
				// Rationale should explain the source of the observation.
				Rationale: "User initiated interaction via WebSocket.",
			},
		}

		c.wsManager.logger.Info("Dispatching user input to Cognitive Bus.",
			zap.String("request_id", msg.RequestID),
			// zap.String("prompt", prompt), // Optionally log the prompt content
		)

		// Dispatch the observation to the agent's mind via the Cognitive Bus
		// Use context.Background() as this is an asynchronous event triggered by the user.
		// The Mind will process this and eventually generate an ActionRespondToUser.
		if err := c.wsManager.agent.bus.Post(context.Background(), CognitiveMessage{
			Type:    MessageTypeObservation,
			Payload: obs,
		}); err != nil {
			c.wsManager.logger.Error("Failed to post user input to cognitive bus", zap.Error(err))
			c.sendError(msg.RequestID, fmt.Sprintf("Internal server error: failed to process prompt: %v", err))
		}

	default:
		// Handle unknown message types
		c.wsManager.logger.Warn("Received unknown message type from client", zap.String("type", string(msg.Type)))
		c.sendError(msg.RequestID, fmt.Sprintf("Unknown or unsupported message type: %s", msg.Type))
	}
}

// sendError is a helper function to send standardized SYSTEM_ERROR messages to this specific client.
func (c *Client) sendError(requestID string, errorMessage string) {
	msg := WSMessage{
		Type:      MsgTypeSystemError,
		Data:      map[string]interface{}{"error": errorMessage},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: requestID,
	}

	jsonMessage, err := json.Marshal(msg)
	if err != nil {
		c.wsManager.logger.Error("Failed to marshal error message", zap.Error(err))
		return
	}

	// Queue the message safely.
	select {
	case c.send <- jsonMessage:
		// Message queued successfully.
	default:
		// If the send buffer is full, the client is likely unresponsive.
		c.wsManager.logger.Error("WebSocket send buffer full, dropping error message.", zap.String("client_id", c.id))
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *Client) writePump() {
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
				c.wsManager.logger.Error("Failed to set write deadline", zap.Error(err))
				return
			}

			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				c.wsManager.logger.Error("Error getting next writer for WebSocket", zap.Error(err))
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				c.wsManager.logger.Error("Error closing writer for WebSocket", zap.Error(err))
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				c.wsManager.logger.Error("Failed to set write deadline for PING", zap.Error(err))
				return
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.wsManager.logger.Error("Error sending PING message to WebSocket", zap.Error(err))
				return
			}
		}
	}
}

// WSManager manages websocket clients.
type WSManager struct {
	agent      *Agent
	logger     *zap.Logger
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewWSManager creates a new WSManager.
func NewWSManager(logger *zap.Logger, agent *Agent) *WSManager {
	return &WSManager{
		agent:      agent,
		logger:     logger.Named("ws_manager"),
		broadcast:  make(chan []byte, sendChannelSize),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

// Run starts the websocket manager.
func (m *WSManager) Run(ctx context.Context) {
	m.logger.Info("WebSocket Manager started.")
	defer m.logger.Info("WebSocket Manager stopped.")

	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			for client := range m.clients {
				close(client.send)
				delete(m.clients, client)
			}
			m.mu.Unlock()
			return
		case client := <-m.register:
			m.mu.Lock()
			m.clients[client] = true
			m.logger.Info("New WebSocket client connected.", zap.String("client_id", client.id))
			m.mu.Unlock()
			// Send initial status update upon connection
			m.sendStatusUpdate(client, "Connected to Agent. Ready for interaction.")

		case client := <-m.unregister:
			m.mu.Lock()
			if _, ok := m.clients[client]; ok {
				delete(m.clients, client)
				close(client.send)
				m.logger.Info("WebSocket client disconnected.", zap.String("client_id", client.id))
			}
			m.mu.Unlock()
		case message := <-m.broadcast:
			m.mu.RLock()
			// Iterate over clients and try to send the message.
			for client := range m.clients {
				select {
				case client.send <- message:
					// Message queued.
				default:
					// Client buffer is full. Close the channel and remove the client.
					m.logger.Warn("WebSocket client buffer full. Disconnecting client.", zap.String("client_id", client.id))
					close(client.send)
					// We delete here under RLock for immediate effect in this loop.
					// The unregister channel will handle final cleanup if the readPump is still active.
					delete(m.clients, client)
				}
			}
			m.mu.RUnlock()
		}
	}
}

// sendStatusUpdate sends a status message to a specific client.
func (m *WSManager) sendStatusUpdate(client *Client, status string) {
	msg := WSMessage{
		Type:      MsgTypeStatusUpdate,
		Data:      map[string]interface{}{"status": status},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	jsonMessage, err := json.Marshal(msg)
	if err != nil {
		m.logger.Error("Failed to marshal status update", zap.Error(err))
		return
	}
	select {
	case client.send <- jsonMessage:
	default:
		m.logger.Warn("Failed to send initial status update: client buffer full.", zap.String("client_id", client.id))
	}
}

// BroadcastWSMessage constructs a WSMessage and sends it to all connected clients.
// This is used by the agent (e.g., handleRespondToUser) to send structured responses.
func (m *WSManager) BroadcastWSMessage(msgType MessageType, requestID string, data map[string]interface{}) error {
	msg := WSMessage{
		Type:      msgType,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339), // ISO 8601 format expected by frontend
		RequestID: requestID,
	}
	return m.BroadcastMessage(msg)
}

// BroadcastMessage sends a message (which will be marshaled) to all connected clients.
func (m *WSManager) BroadcastMessage(message interface{}) error {
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		m.logger.Error("Failed to marshal broadcast message", zap.Error(err))
		return err
	}
	// Use select to prevent blocking if the broadcast channel is full.
	select {
	case m.broadcast <- jsonMessage:
	default:
		m.logger.Error("Broadcast channel full, dropping message.")
		return fmt.Errorf("broadcast channel full")
	}
	return nil
}

// HandleWS handles websocket requests from the peer. This is the entry point used by RegisterInteractionRoutes.
func (m *WSManager) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		m.logger.Error("Failed to upgrade websocket", zap.Error(err))
		return
	}
	client := &Client{
		id:        uuid.New().String(),
		wsManager: m,
		conn:      conn,
		send:      make(chan []byte, sendChannelSize),
	}
	m.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

// InteractionRequest struct removed as it is superseded by the structured WSMessage format.