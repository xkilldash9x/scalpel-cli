// pkg/store/store.go
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Define custom error types for better error handling.
var (
	// ErrDataIntegrity indicates an issue with the data format (e.g., serialization failure).
	ErrDataIntegrity = errors.New("data integrity error")
)

// Store provides an interface to the persistence layer (PostgreSQL).
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// New creates a new store instance and verifies the connection.
func New(ctx context.Context, connString string, logger *zap.Logger) (*Store, error) {
	if connString == "" {
		return nil, errors.New("database connection string is required")
	}

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Verify the connection on startup to fail fast.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Store{
		pool: pool,
		log:  logger.Named("store"),
	}, nil
}

// Close closes the database connection pool.
func (s *Store) Close() {
	s.log.Info("Closing database connection pool")
	s.pool.Close()
}

// PersistData handles the database transaction for inserting all data from a result envelope.
// This is the primary entry point for saving results in the monolith.
func (s *Store) PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Defer a rollback. If the commit is successful, this is a no-op.
	defer func() {
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
		if len(envelope.KGUpdates.Nodes) > 0 {
			if err := s.persistNodes(ctx, tx, envelope.KGUpdates.Nodes); err != nil {
				return err
			}
		}
		if len(envelope.KGUpdates.Edges) > 0 {
			if err := s.persistEdges(ctx, tx, envelope.KGUpdates.Edges); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	s.log.Info("Successfully persisted results",
		zap.String("scan_id", envelope.ScanID),
		zap.String("task_id", envelope.TaskID),
		zap.Int("findings_count", len(envelope.Findings)),
	)
	return nil
}

// persistFindings bulk inserts findings using the high performance pgx CopyFrom protocol.
func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	rows := make([][]interface{}, len(findings))
	for i, f := range findings {
		// Ensure order matches the columns below.
		rows[i] = []interface{}{f.ID, scanID, f.TaskID, f.Timestamp, f.Target, f.Module, f.Vulnerability, f.Severity, f.Description, f.Evidence, f.Recommendation, f.CWE}
	}

	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		[]string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("failed to bulk insert findings: %w", err)
	}
	if int(copyCount) != len(findings) {
		s.log.Warn("Mismatch in inserted findings count", zap.Int("expected", len(findings)), zap.Int64("actual", copyCount))
	}

	s.log.Debug("Successfully inserted findings", zap.Int("count", len(findings)))
	return nil
}

// sanitizeValue recursively removes non-serializable types from an interface{}.
// This prevents json.Marshal failures when the data contains complex browser types.
func sanitizeValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return fmt.Sprintf("[unserializable type: %s]", rv.Type().String())
	case reflect.Map:
		sanitizedMap := make(map[string]interface{}, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			sanitizedMap[iter.Key().String()] = sanitizeValue(iter.Value().Interface())
		}
		return sanitizedMap
	case reflect.Slice, reflect.Array:
		sanitizedSlice := make([]interface{}, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			sanitizedSlice[i] = sanitizeValue(rv.Index(i).Interface())
		}
		return sanitizedSlice
	default:
		if rv.CanInterface() {
			return rv.Interface()
		}
		return fmt.Sprintf("[unreadable value: %s]", rv.Type().String())
	}
}

// persistNodes bulk inserts knowledge graph nodes.
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.KGNode) error {
	rows := make([][]interface{}, len(nodes))
	for i, n := range nodes {
		sanitizedProperties := sanitizeValue(n.Properties)
		propertiesJSON, err := json.Marshal(sanitizedProperties)
		if err != nil {
			s.log.Error("Failed to marshal sanitized node properties", zap.String("id", n.ID), zap.Error(err))
			return fmt.Errorf("%w: failed to marshal node properties for id %s: %w", ErrDataIntegrity, n.ID, err)
		}
		rows[i] = []interface{}{n.ID, n.Type, propertiesJSON}
	}
	// Use ON CONFLICT to perform an UPSERT, merging properties.
	query := `
		INSERT INTO kg_nodes (id, type, properties) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET
			properties = kg_nodes.properties || $3,
			updated_at = NOW();
	`
	b := &pgx.Batch{}
	for _, row := range rows {
		b.Queue(query, row...)
	}

	br := tx.SendBatch(ctx, b)
	defer br.Close()

	for i := 0; i < len(rows); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed to upsert node batch: %w", err)
		}
	}

	s.log.Debug("Successfully upserted nodes", zap.Int("count", len(nodes)))
	return nil
}

// persistEdges bulk inserts knowledge graph edges.
func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.KGEdge) error {
	rows := make([][]interface{}, len(edges))
	for i, e := range edges {
		sanitizedProperties := sanitizeValue(e.Properties)
		propertiesJSON, err := json.Marshal(sanitizedProperties)
		if err != nil {
			edgeID := fmt.Sprintf("%s->%s (%s)", e.SourceID, e.TargetID, e.Relationship)
			s.log.Error("Failed to marshal sanitized edge properties", zap.String("id", edgeID), zap.Error(err))
			return fmt.Errorf("%w: failed to marshal edge properties for %s: %w", ErrDataIntegrity, edgeID, err)
		}
		rows[i] = []interface{}{e.SourceID, e.TargetID, e.Relationship, propertiesJSON, e.Timestamp}
	}
	// Use ON CONFLICT to perform an UPSERT, merging properties.
	query := `
		INSERT INTO kg_edges (source_id, target_id, relationship, properties, timestamp)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (source_id, target_id, relationship) DO UPDATE SET
			properties = kg_edges.properties || $4,
			timestamp = NOW();
	`

	b := &pgx.Batch{}
	for _, row := range rows {
		b.Queue(query, row...)
	}

	br := tx.SendBatch(ctx, b)
	defer br.Close()

	for i := 0; i < len(rows); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("failed to upsert edge batch: %w", err)
		}
	}

	s.log.Debug("Successfully upserted edges", zap.Int("count", len(edges)))
	return nil
}

// GetFindingsByScanID retrieves all findings associated with a specific scan ID.
func (s *Store) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	query := `
		SELECT id, task_id, timestamp, target, module, vulnerability, severity, description, evidence, recommendation, cwe
		FROM findings
		WHERE scan_id = $1
		ORDER BY severity DESC, timestamp ASC
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings for scan %s: %w", scanID, err)
	}
	defer rows.Close()

	var findings []schemas.Finding
	for rows.Next() {
		var f schemas.Finding
		if err := rows.Scan(&f.ID, &f.TaskID, &f.Timestamp, &f.Target, &f.Module, &f.Vulnerability, &f.Severity, &f.Description, &f.Evidence, &f.Recommendation, &f.CWE); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.ScanID = scanID
		findings = append(findings, f)
	}

	return findings, nil
}
