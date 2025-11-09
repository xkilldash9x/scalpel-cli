package store

import (
	"context"
	"encoding/json"
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
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && rollbackErr != pgx.ErrTxClosed {
			s.log.Error("Failed to rollback transaction", zap.Error(rollbackErr))
		}
	}()

	if len(envelope.Findings) > 0 {
		if err := s.persistFindings(ctx, tx, envelope.ScanID, envelope.Findings); err != nil {
			return err
		}
	}

	if envelope.KGUpdates != nil {
		if len(envelope.KGUpdates.NodesToAdd) > 0 {
			if err := s.persistNodes(ctx, tx, envelope.KGUpdates.NodesToAdd); err != nil {
				return err
			}
		}
		if len(envelope.KGUpdates.EdgesToAdd) > 0 {
			if err := s.persistEdges(ctx, tx, envelope.KGUpdates.EdgesToAdd); err != nil {
				return err
			}
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

		//  Use f.VulnerabilityName and f.ObservedAt
		rows[i] = []interface{}{
			f.ID, scanID, f.TaskID,
			f.Target, f.Module, f.VulnerabilityName, // <-- Use VulnerabilityName
			string(f.Severity), f.Description,
			evidence, // <-- Pass the (potentially modified) json.RawMessage
			f.Recommendation, f.CWE,
			f.ObservedAt, // <-- Use ObservedAt
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

// use a simple loop of tx.Exec instead of SendBatch
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.NodeInput) error {

	sql := `
        INSERT INTO kg_nodes (id, type, label, status, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE SET
            type = EXCLUDED.type,
            label = EXCLUDED.label,
            status = EXCLUDED.status,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
	now := time.Now()

	for _, n := range nodes {
		if len(n.Properties) == 0 {
			n.Properties = json.RawMessage("{}")
		}
		// Match the columns to psql
		if _, err := tx.Exec(ctx, sql, n.ID, string(n.Type), n.Label, n.Status, n.Properties, now, now); err != nil {
			return fmt.Errorf("failed to execute insert for node %s: %w", n.ID, err)
		}
	}
	return nil
}

func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.EdgeInput) error {
	sql := `
        INSERT INTO kg_edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (from_node, to_node, type) DO UPDATE SET
            id = EXCLUDED.id,
            label = EXCLUDED.label,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
	now := time.Now()

	for _, e := range edges {
		if len(e.Properties) == 0 {
			e.Properties = json.RawMessage("{}")
		}
		if _, err := tx.Exec(ctx, sql, e.ID, e.From, e.To, string(e.Type), e.Label, e.Properties, now, now); err != nil {
			return fmt.Errorf("failed to execute insert for edge from %s to %s: %w", e.From, e.To, err)
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
