// File: internal/mcp/types.go
package mcp

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// CommandRequest defines the structure of the incoming JSON request from the Agent.
type CommandRequest struct {
	Command string                 `json:"command"`
	Params  map[string]interface{} `json:"params"`
}

// CommandResponse defines the structure of the outgoing JSON response to the Agent.
type CommandResponse struct {
	Status string      `json:"status"` // "success", "error", "accepted"
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// QueryParams defines parameters for the "query_findings" command.
type QueryParams struct {
	// If empty, defaults to the latest scan.
	ScanID string `json:"scan_id,omitempty"`
	// Filter by severity (e.g., "CRITICAL", "INFORMATIONAL"). Case-insensitive.
	Severity string `json:"severity,omitempty"`
	// Limit restricts the number of results. Defaults to 50, max 500.
	Limit int `json:"limit,omitempty"`
	// SortBy specifies the column (e.g., "observed_at", "severity").
	SortBy string `json:"sort_by,omitempty"`
	// SortOrder specifies the direction ("ASC" or "DESC"). Case-insensitive.
	SortOrder string `json:"sort_order,omitempty"`
}

// ScanParams defines parameters for the "start_scan" command.
type ScanParams struct {
	Target string `json:"target"`
	// Type is informational based on the prompt (e.g., "taint").
	Type string `json:"type,omitempty"`
	// Pointers are used to distinguish between zero values and unset values.
	Depth       *int   `json:"depth,omitempty"`
	Concurrency *int   `json:"concurrency,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// DBPool defines the necessary interface for database interactions (satisfied by pgxpool.Pool).
type DBPool interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}
