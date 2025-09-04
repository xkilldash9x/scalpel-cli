package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Store provides a PostgreSQL implementation of the Repository interface.
type Store struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// New creates a new store instance and verifies the connection.
func New(ctx context.Context, pool *pgxpool.Pool, logger *zap.Logger) (*Store, error) {
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
	defer tx.Rollback(ctx)

	if len(envelope.Findings) > 0 {
		if err := s.persistFindings(ctx, tx, envelope.ScanID, envelope.Findings); err != nil {
			return err
		}
	}

	if envelope.KGUpdates != nil {
		if len(envelope.KGUpdates.Nodes) > 0 {
			nodeInputs := make([]schemas.NodeInput, len(envelope.KGUpdates.Nodes))
			for i, n := range envelope.KGUpdates.Nodes {
				nodeInputs[i] = schemas.NodeInput{
					ID:         n.ID,
					Type:       schemas.NodeType(n.Type),
					Properties: n.Properties,
				}
			}
			if err := s.persistNodes(ctx, tx, nodeInputs); err != nil {
				return err
			}
		}
		if len(envelope.KGUpdates.Edges) > 0 {
			edgeInputs := make([]schemas.EdgeInput, len(envelope.KGUpdates.Edges))
			for i, e := range envelope.KGUpdates.Edges {
				edgeInputs[i] = schemas.EdgeInput{
					SourceID:     e.From,
					TargetID:     e.To,
					Relationship: schemas.RelationshipType(e.Type),
					Properties:   e.Properties,
				}
			}
			if err := s.persistEdges(ctx, tx, edgeInputs); err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

// persistFindings bulk inserts findings using the high-performance pgx CopyFrom protocol.
func (s *Store) persistFindings(ctx context.Context, tx pgx.Tx, scanID string, findings []schemas.Finding) error {
	rows := make([][]interface{}, len(findings))
	for i, f := range findings {
		rows[i] = []interface{}{
			f.ID, scanID, f.TaskID, f.Timestamp, f.Target, f.Module,
			f.Vulnerability, f.Severity, f.Description, f.Evidence,
			f.Recommendation, f.CWE,
		}
	}

	_, err := tx.CopyFrom(
		ctx,
		pgconn.Identifier{"findings"},
		[]string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"},
		pgx.CopyFromRows(rows),
	)
	return err
}


// persistNodes bulk upserts knowledge graph nodes.
func (s *Store) persistNodes(ctx context.Context, tx pgx.Tx, nodes []schemas.NodeInput) error {
	rows := make([][]interface{}, len(nodes))
	for i, n := range nodes {
		propertiesJSON, err := json.Marshal(n.Properties)
		if err != nil {
			return fmt.Errorf("failed to marshal node properties for id %s: %w", n.ID, err)
		}
		rows[i] = []interface{}{n.ID, string(n.Type), propertiesJSON}
	}
	_, err := tx.CopyFrom(ctx, pgconn.Identifier{"kg_nodes"}, []string{"id", "type", "properties"}, pgx.CopyFromRows(rows))
	return err
}

// persistEdges bulk upserts knowledge graph edges.
func (s *Store) persistEdges(ctx context.Context, tx pgx.Tx, edges []schemas.EdgeInput) error {
	rows := make([][]interface{}, len(edges))
	for i, e := range edges {
		propertiesJSON, err := json.Marshal(e.Properties)
		if err != nil {
			return fmt.Errorf("failed to marshal edge properties: %w", err)
		}
		rows[i] = []interface{}{e.SourceID, e.TargetID, string(e.Relationship), propertiesJSON}
	}
	_, err := tx.CopyFrom(ctx, pgconn.Identifier{"kg_edges"}, []string{"source_id", "target_id", "relationship", "properties"}, pgx.CopyFromRows(rows))
	return err
}