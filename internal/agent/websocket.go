package agent

import (
	"context"
	"encoding/json"
	"net/http"
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
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all connections for now.
		// TODO: Implement a proper origin check.
		return true
	},
}

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	id        string
	wsManager *WSManager
	conn      *websocket.Conn
	// Buffered channel of outbound messages.
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.wsManager.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.wsManager.logger.Warn("Websocket client read error", zap.Error(err))
			}
			break
		}
		// The agent currently does not process messages from the client, it only sends.
		// This is where we would handle incoming messages if needed.
		c.wsManager.logger.Debug("Received message from client, processing it.", zap.String("client_id", c.id), zap.ByteString("message", message))

		// We'll process incoming messages as interaction requests.
		var req InteractionRequest
		if err := json.Unmarshal(message, &req); err != nil {
			c.wsManager.logger.Error("Failed to unmarshal incoming message", zap.Error(err), zap.ByteString("message", message))
			continue
		}

		// Add a request ID if it's missing
		if req.RequestID == "" {
			req.RequestID = uuid.New().String()
		}

		c.wsManager.logger.Info("Received interaction from user via WebSocket.",
			zap.String("request_id", req.RequestID),
			zap.String("prompt", req.Prompt),
		)

		// Create an Observation for the user input
		obs := Observation{
			ID:        uuid.New().String(),
			MissionID: c.wsManager.agent.GetMission().ID, // Associate with current mission if any
			Type:      ObservedUserInput,
			Data: map[string]interface{}{
				"prompt":     req.Prompt,
				"request_id": req.RequestID,
			},
			Timestamp: time.Now().UTC(),
			Result: ExecutionResult{
				Status:          "success",
				ObservationType: ObservedUserInput,
			},
		}

		// Dispatch the observation to the agent's mind via the Cognitive Bus
		// Use context.Background() as this is an asynchronous event triggered by the user.
		if err := c.wsManager.agent.bus.Post(context.Background(), CognitiveMessage{
			Type:    MessageTypeObservation,
			Payload: obs,
		}); err != nil {
			c.wsManager.logger.Error("Failed to post user input to cognitive bus", zap.Error(err))
		}
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
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
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
		broadcast:  make(chan []byte),
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
			for client := range m.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(m.clients, client)
				}
			}
			m.mu.RUnlock()
		}
	}
}

// BroadcastMessage sends a message to all connected clients.
func (m *WSManager) BroadcastMessage(message interface{}) error {
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		m.logger.Error("Failed to marshal broadcast message", zap.Error(err))
		return err
	}
	m.broadcast <- jsonMessage
	return nil
}

// HandleWS handles websocket requests from the peer.
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
		send:      make(chan []byte, 256),
	}
	m.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

// InteractionRequest defines the structure for a user's request to the agent.
// This is now received over WebSocket.
type InteractionRequest struct {
	RequestID string `json:"request_id,omitempty"`
	Prompt    string `json:"prompt"`
}
