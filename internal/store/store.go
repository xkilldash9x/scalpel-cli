package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Store provides a PostgreSQL implementation of the Repository interface.
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// New creates a new store instance and verifies the connection.
func New(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) (*Store, error) {
	// Verify the connection
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
	// This deferred function safely rolls back the transaction if it hasn't been committed.
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
		if len(envelope.KGUpdates.NodesToAdd) > 0 { // CORRECTED
			// Convert schemas.Node to schemas.NodeInput
			nodeInputs := make([]schemas.NodeInput, len(envelope.KGUpdates.NodesToAdd)) // CORRECTED
			for i, n := range envelope.KGUpdates.NodesToAdd {                           // CORRECTED
				nodeInputs[i] = schemas.NodeInput{
					ID:         n.ID,
					Type:       n.Type,
					Label:      n.Label,
					Status:     n.Status,
					Properties: n.Properties,
				}
			}
			if err := s.persistNodes(ctx, tx, nodeInputs); err != nil {
				return err
			}
		}
		if len(envelope.KGUpdates.EdgesToAdd) > 0 { // CORRECTED
			// Convert schemas.Edge to schemas.EdgeInput
			edgeInputs := make([]schemas.EdgeInput, len(envelope.KGUpdates.EdgesToAdd)) // CORRECTED
			for i, e := range envelope.KGUpdates.EdgesToAdd {                           // CORRECTED
				edgeInputs[i] = schemas.EdgeInput{
					ID:         e.ID,
					From:       e.From,
					To:         e.To,
					Type:       e.Type,
					Label:      e.Label,
					Properties: e.Properties,
				}
			}
			if err := s.persistEdges(ctx, tx, edgeInputs); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}
// persistFindings inserts findings using the high performance pgx CopyFrom protocol.
func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	rows := make([][]interface{}, len(findings))
	for i, f := range findings {
		// Marshal the Vulnerability struct to JSON for storage in a JSONB column.
		vulnJSON, err := json.Marshal(f.Vulnerability)
		if err != nil {
			return fmt.Errorf("failed to marshal vulnerability details for finding %s: %w", f.ID, err)
		}

		rows[i] = []interface{}{
			f.ID, scanID, f.TaskID, f.Timestamp, f.Target, f.Module,
			vulnJSON,
			string(f.Severity), f.Description,
			f.Evidence,
			f.Recommendation, f.CWE,
		}
	}

	// Ensure column names here match your database schema exactly.
	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		[]string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"},
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

// persistNodes performs a batch upsert of knowledge graph nodes using INSERT ON CONFLICT.
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.NodeInput) error {
	batch := &pgx.Batch{}
	// This SQL statement inserts a new node or updates it if the ID already exists.
	// It also merges the new properties with existing ones.
	sql := `
		INSERT INTO kg_nodes (id, type, label, status, properties, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			label = EXCLUDED.label,
			status = EXCLUDED.status,
			properties = kg_nodes.properties || EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen;
	`
	now := time.Now()

	for _, n := range nodes {
		if n.Properties == nil || len(n.Properties) == 0 {
			n.Properties = json.RawMessage("{}")
		}
		batch.Queue(sql, n.ID, string(n.Type), n.Label, string(n.Status), n.Properties, now, now)
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(nodes); i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("failed to execute batch insert for nodes (item %d): %w", i, err)
		}
	}
	return nil
}

// persistEdges performs a batch upsert of knowledge graph edges.
func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.EdgeInput) error {
	batch := &pgx.Batch{}
	sql := `
		INSERT INTO kg_edges (id, source_id, target_id, relationship, label, properties, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			label = EXCLUDED.label,
			properties = kg_edges.properties || EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen;
	`
	now := time.Now()

	for _, e := range edges {
		edgeID := e.ID
		if edgeID == "" {
			edgeID = uuid.New().String()
		}

		if e.Properties == nil || len(e.Properties) == 0 {
			e.Properties = json.RawMessage("{}")
		}

		// Map EdgeInput fields (From, To, Type) to SQL columns (source_id, target_id, relationship).
		batch.Queue(sql, edgeID, e.From, e.To, string(e.Type), e.Label, e.Properties, now, now)
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(edges); i++ {
		_, err := br.Exec()
		if err != nil {
			return fmt.Errorf("failed to execute batch insert for edges (item %d): %w", i, err)
		}
	}
	return nil
}

// GetFindingsByScanID retrieves all findings associated with a specific scan ID.
func (s *Store) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	query := `
		SELECT id, task_id, timestamp, target, module, vulnerability, severity, description, evidence, recommendation, cwe
		FROM findings
		WHERE scan_id = $1
		ORDER BY timestamp ASC;
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []schemas.Finding
	for rows.Next() {
		var f schemas.Finding
		var vulnJSON []byte

		err := rows.Scan(
			&f.ID, &f.TaskID, &f.Timestamp, &f.Target, &f.Module,
			&vulnJSON,
			&f.Severity, &f.Description, &f.Evidence, &f.Recommendation,
			&f.CWE,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}

		// Unmarshal the vulnerability details from JSONB.
		if err := json.Unmarshal(vulnJSON, &f.Vulnerability); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vulnerability details for finding %s: %w", f.ID, err)
		}

		f.ScanID = scanID
		findings = append(findings, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	return findings, nil
}
