// File: internal/mcp/handlers.go
package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// Handlers manages the HTTP request handling for the MCP server.
type Handlers struct {
	log          *zap.Logger
	queryService *QueryService
	scanService  *ScanService
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(logger *zap.Logger, queryService *QueryService, scanService *ScanService) *Handlers {
	return &Handlers{
		log:          logger.Named("mcp_handlers"),
		queryService: queryService,
		scanService:  scanService,
	}
}

// RegisterRoutes sets up the routing for the MCP server.
// This is called by the Server in internal/mcp/server.go.
func (h *Handlers) RegisterRoutes(r chi.Router) {
	// Health check endpoint (unversioned)
	r.Get("/healthz", h.HandleHealthCheck)

	// API v1 Routes
	r.Route("/api/v1", func(r chi.Router) {
		// Primary endpoint for receiving commands
		r.Post("/command", h.HandleCommand)
		// Endpoint for checking the status of an asynchronous scan
		r.Get("/scan/{scanID}/status", h.HandleGetScanStatus)
	})
}

// HandleHealthCheck is a simple handler to confirm the server is responsive.
func (h *Handlers) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleCommand is the main entry point for commands from the Agent.
func (h *Handlers) HandleCommand(w http.ResponseWriter, r *http.Request) {
	// Decode the request body
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	h.log.Info("Received command", zap.String("command", req.Command))

	// Route the command
	switch strings.ToLower(req.Command) {
	case "query_findings", "query":
		h.handleQueryFindings(w, r, req.Params)
	case "start_scan", "scan":
		h.handleStartScan(w, r, req.Params)
	case "ping":
		h.respondWithSuccess(w, http.StatusOK, map[string]string{"message": "pong"})
	default:
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
	}
}

// handleQueryFindings processes the "query_findings" command (Use Case 2).
func (h *Handlers) handleQueryFindings(w http.ResponseWriter, r *http.Request, paramsMap map[string]interface{}) {
	// Use Case 2 example: "Gemini, show me all critical findings from the last scan."
	// Robustness: Check if the query service is available (it might be nil if the DB failed at startup).
	if h.queryService == nil {
		h.respondWithError(w, http.StatusServiceUnavailable, "Query service is unavailable (database not configured or connected).")
		return
	}
	// Gemini sends: {"command": "query_findings", "params": {"severity": "critical"}}

	// Convert the generic map into the specific struct.
	params, err := mapToStruct[QueryParams](paramsMap)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid parameters for query_findings: %v", err))
		return
	}

	findings, err := h.queryService.QueryFindings(r.Context(), params)
	if err != nil {
		h.log.Error("Failed to query findings", zap.Error(err))
		errMsg := err.Error()
		// Distinguish user input errors (e.g., invalid severity, no data) from internal errors.
		if strings.Contains(errMsg, "invalid severity") ||
			strings.Contains(errMsg, "invalid sort") ||
			strings.Contains(errMsg, "no scans found") {
			h.respondWithError(w, http.StatusBadRequest, errMsg)
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "Internal error retrieving findings.")
		}
		return
	}

	h.respondWithSuccess(w, http.StatusOK, map[string]interface{}{
		"count":    len(findings),
		"findings": findings,
	})
}

// handleStartScan processes the "start_scan" command (Use Case 1).
func (h *Handlers) handleStartScan(w http.ResponseWriter, _ *http.Request, paramsMap map[string]interface{}) {
	// Use Case 1 example: "Hey Gemini, run a full taint analysis on https://example.com."
	// Gemini sends: {"command": "start_scan", "params": {"target": "https://example.com", "type": "taint"}}

	// Convert the generic map into the specific struct.
	params, err := mapToStruct[ScanParams](paramsMap)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid parameters for start_scan: %v", err))
		return
	}

	if params.Target == "" {
		h.respondWithError(w, http.StatusBadRequest, "Target parameter is required.")
		return
	}

	// Start the scan asynchronously
	job, err := h.scanService.StartScan(params)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to initiate scan: %v", err))
		return
	}

	// Respond immediately that the scan is accepted and running.
	h.respondWithStatus(w, http.StatusAccepted, "accepted", job)
}

// HandleGetScanStatus retrieves the status of a scan job.
func (h *Handlers) HandleGetScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "scanID")
	job, exists := h.scanService.registry.GetJob(scanID)
	if !exists {
		// The ID might be a pending ID or a completed Scan ID. If not found in the registry, it's unknown.
		h.respondWithError(w, http.StatusNotFound, "Scan ID or Job ID not found in active/recent job registry.")
		return
	}
	h.respondWithSuccess(w, http.StatusOK, job)
}

// Generic utility function to convert map[string]interface{} to a specific struct using JSON marshaling.
func mapToStruct[T any](m map[string]interface{}) (T, error) {
	var result T
	// Handle nil map gracefully
	if m == nil {
		return result, nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

// respondWithError sends a standardized JSON error response.
func (h *Handlers) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithStatus(w, statusCode, "error", map[string]string{"error": message})
}

// respondWithSuccess sends a standardized JSON success response.
func (h *Handlers) respondWithSuccess(w http.ResponseWriter, statusCode int, data interface{}) {
	h.respondWithStatus(w, statusCode, "success", data)
}

// respondWithStatus sends a standardized JSON response with a specific status string.
func (h *Handlers) respondWithStatus(w http.ResponseWriter, statusCode int, status string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := CommandResponse{
		Status: status,
	}

	// Assign data or error depending on the structure of 'data'
	if errMap, ok := data.(map[string]string); ok && errMap["error"] != "" {
		resp.Error = errMap["error"]
	} else {
		resp.Data = data
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Error("Failed to encode response", zap.Error(err))
	}
}
