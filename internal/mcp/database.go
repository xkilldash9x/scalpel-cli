// File: internal/mcp/database.go
package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// QueryService handles database interactions for the MCP.
type QueryService struct {
	pool DBPool
	log  *zap.Logger
}

// NewQueryService creates a new QueryService.
func NewQueryService(pool DBPool, logger *zap.Logger) *QueryService {
	// Robustness: Log if the service is initialized without an active connection.
	if pool == nil {
		logger.Warn("QueryService initialized with a nil DBPool. Database operations will fail.")
	}
	return &QueryService{
		pool: pool,
		log:  logger.Named("mcp_query_service"),
	}
}

// GetLatestScanID retrieves the ID of the scan with the most recent activity.
func (s *QueryService) GetLatestScanID(ctx context.Context) (string, error) {
	// Robustness: Ensure the database connection is available before querying.
	if s.pool == nil {
		return "", fmt.Errorf("database connection not available")
	}
	// Determined by the most recent finding recorded in the database.
	query := `SELECT scan_id FROM findings ORDER BY observed_at DESC LIMIT 1;`
	var scanID string
	err := s.pool.QueryRow(ctx, query).Scan(&scanID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("no scans found in the database")
		}
		return "", fmt.Errorf("failed to query latest scan ID: %w", err)
	}
	return scanID, nil
}

// QueryFindings retrieves findings safely based on parameters.
func (s *QueryService) QueryFindings(ctx context.Context, params QueryParams) ([]schemas.Finding, error) {
	// Robustness: Ensure the database connection is available before querying.
	if s.pool == nil {
		return nil, fmt.Errorf("database connection not available. Ensure SCALPEL_DATABASE_URL is configured.")
	}
	// 1. Initialize query base and arguments
	queryBase := `
        SELECT id, scan_id, task_id, observed_at, target, module, vulnerability, severity, description, evidence, recommendation, cwe
        FROM findings
    `
	var conditions []string
	var args []interface{}
	argID := 1

	// 2. Determine ScanID (Default to latest if empty)
	scanID := params.ScanID
	if scanID == "" {
		latestScanID, err := s.GetLatestScanID(ctx)
		if err != nil {
			return nil, err
		}
		scanID = latestScanID
		s.log.Info("Defaulting query to latest scan", zap.String("scan_id", scanID))
	}

	// Apply ScanID filter (Parameterized)
	conditions = append(conditions, fmt.Sprintf("scan_id = $%d", argID))
	args = append(args, scanID)
	argID++

	// 3. Apply Severity Filter (Validate and Parameterize)
	if params.Severity != "" {
		severityLower := strings.ToLower(params.Severity)

		// Handle mapping from API schema ("INFORMATIONAL") to DB enum ("info")
		if severityLower == "informational" {
			severityLower = "info"
		}

		// Validate against the DB ENUM values defined in the migration (001_initial_schema.sql).
		validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
		if !validSeverities[severityLower] {
			return nil, fmt.Errorf("invalid severity level: %s. Valid options: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL", params.Severity)
		}
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argID))
		args = append(args, severityLower)
		argID++
	}

	// 4. Construct WHERE clause
	if len(conditions) > 0 {
		queryBase += " WHERE " + strings.Join(conditions, " AND ")
	}

	// 5. Apply Sorting (Whitelist columns to prevent SQL injection)
	sortBy := "severity" // Default sort: Prioritize severity
	if params.SortBy != "" {
		// Whitelist of allowed columns
		validSortColumns := map[string]string{
			"observed_at":   "observed_at",
			"severity":      "severity",
			"vulnerability": "vulnerability",
			"target":        "target",
			"module":        "module",
		}
		if col, ok := validSortColumns[params.SortBy]; ok {
			sortBy = col
		} else {
			return nil, fmt.Errorf("invalid sort column: %s", params.SortBy)
		}
	}

	sortOrder := "DESC"
	// The ENUM definition order ('info'...'critical') means DESC sorts Critical first.
	if params.SortOrder != "" {
		orderUpper := strings.ToUpper(params.SortOrder)
		if orderUpper == "ASC" || orderUpper == "DESC" {
			sortOrder = orderUpper
		} else {
			return nil, fmt.Errorf("invalid sort order: %s. Use ASC or DESC", params.SortOrder)
		}
	}
	// Safe concatenation because sortBy and sortOrder are validated/whitelisted.
	// Secondary sort ensures most recent findings are shown first within a severity level.
	queryBase += fmt.Sprintf(" ORDER BY %s %s, observed_at DESC", sortBy, sortOrder)

	// 6. Apply Limit
	limit := 50 // Default
	if params.Limit > 0 {
		if params.Limit <= 500 {
			limit = params.Limit
		} else {
			limit = 500 // Enforce Max
		}
	}
	queryBase += fmt.Sprintf(" LIMIT %d", limit)

	// 7. Execute Query
	s.log.Debug("Executing findings query", zap.String("query", queryBase), zap.Any("args", args))
	rows, err := s.pool.Query(ctx, queryBase, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// 8. Scan Results
	var findings []schemas.Finding
	for rows.Next() {
		var f schemas.Finding
		var vulnName string
		var severityStr string // DB returns lowercase string (e.g., "info", "critical")

		err := rows.Scan(
			&f.ID, &f.ScanID, &f.TaskID, &f.Timestamp, &f.Target, &f.Module,
			&vulnName,
			&severityStr,
			&f.Description, &f.Evidence, &f.Recommendation,
			&f.CWE,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}

		// Map DB severity (lowercase) back to Schema severity (UPPERCASE)
		f.Severity = schemas.Severity(strings.ToUpper(severityStr))

		// Handle "INFO" -> "INFORMATIONAL" mapping for API consistency
		if f.Severity == "INFO" {
			f.Severity = schemas.SeverityInformational
		}

		f.Vulnerability.Name = vulnName
		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	// Ensure an empty slice instead of nil is returned if no findings exist.
	if findings == nil {
		findings = []schemas.Finding{}
	}

	return findings, nil
}
