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

// Repository defines the interface for the persistence layer.
// This decouples consumers from the specific PostgreSQL implementation, improving testability.
type Repository interface {
	PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error
	GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error)
	Close()
}

// Store provides a PostgreSQL implementation of the Repository interface.
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// Compile-time check to ensure Store implements the Repository interface.
var _ Repository = (*Store)(nil)


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

// Define columns centrally for consistency.
var findingsColumns = []string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"}

// findingsCopySource implements the pgx.CopyFromSource interface for findings,
// allowing for efficient, streaming data transfer without large intermediate allocations.
type findingsCopySource struct {
	findings []schemas.Finding
	scanID   string
	idx      int
}

func (fcs *findingsCopySource) Next() bool {
	return fcs.idx < len(fcs.findings)
}

func (fcs *findingsCopySource) Values() ([]interface{}, error) {
	f := fcs.findings[fcs.idx]
	fcs.idx++
	// Order must match findingsColumns.
	return []interface{}{f.ID, fcs.scanID, f.TaskID, f.Timestamp, f.Target, f.Module, f.Vulnerability, f.Severity, f.Description, f.Evidence, f.Recommendation, f.CWE}, nil
}

func (fcs *findingsCopySource) Err() error {
	return nil // No errors are expected during value generation.
}

// persistFindings bulk inserts findings using the high-performance pgx CopyFrom protocol.
func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	// Use the custom CopyFromSource implementation to stream data directly to the driver.
	source := &findingsCopySource{findings: findings, scanID: scanID}

	copyCount, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		findingsColumns,
		source,
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
// Public entry point for the sanitization logic.
func sanitizeValue(v interface{}) interface{} {
    if v == nil {
        return nil
    }
    // Start the reflection-based recursion.
    return sanitizeReflectValue(reflect.ValueOf(v))
}

// sanitizeReflectValue handles the recursion using reflect.Value directly to optimize performance
// by avoiding repeated allocations from the .Interface() method.
func sanitizeReflectValue(rv reflect.Value) interface{} {
    if !rv.IsValid() {
        return nil
    }

    // Dereference pointers and interfaces to get to the concrete value.
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
            // Pass reflect.Value directly to the recursive call, avoiding .Interface() allocation.
            sanitizedMap[iter.Key().String()] = sanitizeReflectValue(iter.Value())
        }
        return sanitizedMap

    case reflect.Slice, reflect.Array:
        sanitizedSlice := make([]interface{}, rv.Len())
        for i := 0; i < rv.Len(); i++ {
            // Pass reflect.Value directly.
            sanitizedSlice[i] = sanitizeReflectValue(rv.Index(i))
        }
        return sanitizedSlice

    default:
        // For primitive types that are safe to serialize.
        if rv.CanInterface() {
            return rv.Interface()
        }
        return fmt.Sprintf("[unreadable value: %s]", rv.Type().String())
    }
}


// persistNodes bulk upserts knowledge graph nodes using a highly performant temporary table strategy.
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.KGNode) error {
	if len(nodes) == 0 {
		return nil
	}
	// 1. Data Preparation
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

	// 2. Create Temporary Table for this transaction.
	// ON COMMIT DROP ensures the table is cleaned up automatically.
	_, err := tx.Exec(ctx, `
		CREATE TEMPORARY TABLE temp_kg_nodes_ingest (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			properties JSONB
		) ON COMMIT DROP;
	`)
	if err != nil {
		return fmt.Errorf("failed to create temporary table for nodes: %w", err)
	}

	// 3. Use high-speed COPY protocol to load data into the temporary table.
	_, err = tx.CopyFrom(
		ctx,
		pgx.Identifier{"temp_kg_nodes_ingest"},
		[]string{"id", "type", "properties"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("failed to bulk copy nodes to temporary table: %w", err)
	}

	// 4. Execute a single, efficient UPSERT from the temporary table into the main table.
	_, err = tx.Exec(ctx, `
		INSERT INTO kg_nodes (id, type, properties)
		SELECT id, type, properties FROM temp_kg_nodes_ingest
		ON CONFLICT (id) DO UPDATE SET
			properties = kg_nodes.properties || EXCLUDED.properties,
			updated_at = NOW();
	`)
	if err != nil {
		return fmt.Errorf("failed to upsert nodes from temporary table: %w", err)
	}

	s.log.Debug("Successfully upserted nodes", zap.Int("count", len(nodes)))
	return nil
}

// persistEdges bulk upserts knowledge graph edges using the temporary table strategy.
func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.KGEdge) error {
    if len(edges) == 0 {
		return nil
	}
	// 1. Data Preparation
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

    // 2. Create Temporary Table
    _, err := tx.Exec(ctx, `
        CREATE TEMPORARY TABLE temp_kg_edges_ingest (
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relationship TEXT NOT NULL,
            properties JSONB,
            timestamp TIMESTAMPTZ,
            PRIMARY KEY (source_id, target_id, relationship)
        ) ON COMMIT DROP;
    `)
    if err != nil {
        return fmt.Errorf("failed to create temporary table for edges: %w", err)
    }

    // 3. Bulk Copy into Temporary Table
    _, err = tx.CopyFrom(
        ctx,
        pgx.Identifier{"temp_kg_edges_ingest"},
        []string{"source_id", "target_id", "relationship", "properties", "timestamp"},
        pgx.CopyFromRows(rows),
    )
    if err != nil {
        return fmt.Errorf("failed to bulk copy edges to temporary table: %w", err)
    }

	// 4. Execute a single, efficient UPSERT from the temporary table.
	_, err = tx.Exec(ctx, `
		INSERT INTO kg_edges (source_id, target_id, relationship, properties, timestamp)
		SELECT source_id, target_id, relationship, properties, timestamp FROM temp_kg_edges_ingest
		ON CONFLICT (source_id, target_id, relationship) DO UPDATE SET
			properties = kg_edges.properties || EXCLUDED.properties,
			timestamp = NOW();
	`)
    if err != nil {
        return fmt.Errorf("failed to upsert edges from temporary table: %w", err)
    }

	s.log.Debug("Successfully upserted edges", zap.Int("count", len(edges)))
	return nil
}

// GetFindingsByScanID retrieves all findings associated with a specific scan ID using an idiomatic and robust method.
func (s *Store) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	// Include scan_id in the SELECT list so the struct is fully populated automatically.
	query := `
		SELECT id, scan_id, task_id, timestamp, target, module, vulnerability, severity, description, evidence, recommendation, cwe
		FROM findings
		WHERE scan_id = $1
		ORDER BY severity DESC, timestamp ASC
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings for scan %s: %w", scanID, err)
	}

	// Use pgx.CollectRows with RowToStructByName for automatic, safe, and efficient row collection.
	// This helper handles iteration, scanning, closing rows, and checking rows.Err() automatically.
	// The schemas.Finding struct's json tags must match the column names for this to work.
	findings, err := pgx.CollectRows(rows, pgx.RowToStructByName[schemas.Finding])
	if err != nil {
		return nil, fmt.Errorf("failed to collect findings rows for scan %s: %w", scanID, err)
	}

	return findings, nil
}