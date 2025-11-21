package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// DBPool is an interface that abstracts the pgxpool.Pool to allow for mocking in tests.
type DBPool interface {
	Ping(ctx context.Context) error
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	// Add Exec to the interface so we can mock it
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
}

// Store provides a PostgreSQL implementation of the Repository interface.
type Store struct {
	pool DBPool
	log  *zap.Logger
}

// New creates a new store instance and verifies the connection.
func New(ctx context.Context, pool DBPool, logger *zap.Logger) (*Store, error) {
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Store{
		pool: pool,
		log:  logger.Named("store"),
	}, nil
}

// PersistData handles the database transaction for inserting all data from a result envelope.
func (s *Store) PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		// FIX: Use errors.Is to correctly check for pgx.ErrTxClosed, even if wrapped.
		// This prevents spurious error logs when Rollback is called on an already committed (closed) transaction.
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			s.log.Error("Failed to rollback transaction", zap.Error(rollbackErr))
		}
	}()

	if len(envelope.Findings) > 0 {
		if err := s.persistFindings(ctx, tx, envelope.ScanID, envelope.Findings); err != nil {
			return err
		}
	}

	if envelope.KGUpdates != nil {
		// REFACTOR: Use a single batch operation for graph updates for efficiency.
		if err := s.persistGraphUpdates(ctx, tx, envelope.KGUpdates); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	rows := make([][]interface{}, len(findings))
	for i, f := range findings {
		// REFACTOR: f.Evidence is json.RawMessage (). Check length.
		evidence := f.Evidence
		if len(evidence) == 0 || string(evidence) == "null" {
			evidence = json.RawMessage("{}") // Ensure we don't insert a null or empty string.
		}

		// FIX: Ensure the timestamp is in UTC before insertion to prevent ambiguity.
		observedAtUTC := f.ObservedAt.UTC()

		// Use f.VulnerabilityName and f.ObservedAt
		rows[i] = []interface{}{
			f.ID, scanID, f.TaskID,
			f.Target, f.Module, f.VulnerabilityName,
			string(f.Severity), f.Description,
			evidence, // <-- Pass the (potentially modified) json.RawMessage
			f.Recommendation, f.CWE,
			observedAtUTC, // <-- Use the UTC timestamp
		}
	}

	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		[]string{"id", "scan_id", "task_id", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"},
		pgx.CopyFromRows(rows),
	)

	if err != nil {
		return fmt.Errorf("failed to copy findings: %w", err)
	}
	if int(copyCount) != len(findings) {
		return fmt.Errorf("mismatch in copied findings count: expected %d, got %d", len(findings), copyCount)
	}

	return nil
}

// REFACTOR: Combined persistNodes and persistEdges into a single batch operation for performance.
func (s *Store) persistGraphUpdates(ctx context.Context, tx pgx.Tx, updates *schemas.KnowledgeGraphUpdate) error {
	// Check if there's anything to update before creating the batch.
	if len(updates.NodesToAdd) == 0 && len(updates.EdgesToAdd) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	// FIX: Use UTC time for consistency
	now := time.Now().UTC()

	// 1. Queue Node Updates
	sqlNodes := `
        INSERT INTO kg_nodes (id, type, label, status, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE SET
            type = EXCLUDED.type,
            label = EXCLUDED.label,
            status = EXCLUDED.status,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
	for _, n := range updates.NodesToAdd {
		// FIX: Ensure consistency by checking for "null" string.
		properties := n.Properties
		if len(properties) == 0 || string(properties) == "null" {
			properties = json.RawMessage("{}")
		}
		batch.Queue(sqlNodes, n.ID, string(n.Type), n.Label, n.Status, properties, now, now)
	}

	// 2. Queue Edge Updates
	sqlEdges := `
        INSERT INTO kg_edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (from_node, to_node, type) DO UPDATE SET
            id = EXCLUDED.id,
            label = EXCLUDED.label,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
	for _, e := range updates.EdgesToAdd {
		// FIX: Ensure consistency by checking for "null" string.
		properties := e.Properties
		if len(properties) == 0 || string(properties) == "null" {
			properties = json.RawMessage("{}")
		}
		batch.Queue(sqlEdges, e.ID, e.From, e.To, string(e.Type), e.Label, properties, now, now)
	}

	// 3. Send the Batch
	br := tx.SendBatch(ctx, batch)
	// FIX: Check for nil br just in case the driver/mock returns garbage, preventing SEGV.
	// NOTE: pgxmock v2 often returns nil here. Upgrade to v4 to fix tests.
	if br == nil {
		return fmt.Errorf("failed to send batch: batch results is nil")
	}
	defer func() {
		_ = br.Close()
	}()

	// 4. Process Results (required to execute the batch and check for errors)
	expectedTotal := len(updates.NodesToAdd) + len(updates.EdgesToAdd)
	for i := 0; i < expectedTotal; i++ {
		// Executing Next() ensures the command ran and checks its status.
		if _, err := br.Exec(); err != nil {
			// Provide context about which item failed if possible.
			if i < len(updates.NodesToAdd) {
				nodeID := "unknown"
				if i >= 0 && i < len(updates.NodesToAdd) {
					nodeID = updates.NodesToAdd[i].ID
				}
				return fmt.Errorf("failed to execute batch insert for node %s (index %d): %w", nodeID, i, err)
			}

			edgeIndex := i - len(updates.NodesToAdd)
			edgeID := "unknown"
			if edgeIndex >= 0 && edgeIndex < len(updates.EdgesToAdd) {
				edgeID = updates.EdgesToAdd[edgeIndex].ID
			}
			return fmt.Errorf("failed to execute batch insert for edge %s (index %d): %w", edgeID, edgeIndex, err)
		}
	}

	return nil
}

func (s *Store) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	query := `
        SELECT id, task_id, observed_at, target, module, vulnerability_name, severity, description, evidence, recommendation, cwe
        FROM findings
        WHERE scan_id = $1
        ORDER BY observed_at ASC;
    `
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []schemas.Finding
	for rows.Next() {
		var f schemas.Finding
		var severityStr string

		err := rows.Scan(
			&f.ID, &f.TaskID, &f.ObservedAt, &f.Target, &f.Module,
			&f.VulnerabilityName,
			&severityStr,
			&f.Description, &f.Evidence, &f.Recommendation,
			&f.CWE,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}

		f.Severity = schemas.Severity(severityStr)
		f.ScanID = scanID
		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	return findings, nil
}
