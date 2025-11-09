// File: internal/knowledgegraph/postgres_kg.go
package knowledgegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// DBPool defines an interface for pgxpool.Pool methods, enabling easy mocking for tests.
type DBPool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Close()
}

// Ensures *pgxpool.Pool satisfies the DBPool interface at compile time.
var _ DBPool = (*pgxpool.Pool)(nil)

// PostgresKG provides a persistent implementation of the KnowledgeGraphClient using PostgreSQL.
type PostgresKG struct {
	pool DBPool
	log  *zap.Logger
}

// Ensures PostgresKG implements the KnowledgeGraphClient interface at compile time.
var _ schemas.KnowledgeGraphClient = (*PostgresKG)(nil)

// NewPostgresKG initializes a new connection wrapper for the PostgreSQL database.
func NewPostgresKG(pool DBPool, logger *zap.Logger) *PostgresKG {
	// This check ensures that in a production environment, we are using the real pgxpool.Pool.
	// During testing, a mock will be used, and this warning will be logged, which is expected.
	if _, ok := pool.(*pgxpool.Pool); !ok {
		logger.Warn("PostgresKG initialized with a non-production DBPool implementation. This is expected for tests.")
	}

	return &PostgresKG{
		pool: pool,
		// naming the logger gives us more context in the logs
		log: logger.Named("PostgresKG"),
	}
}

// AddNode inserts a new node or updates an existing one using an "upsert" operation.
func (p *PostgresKG) AddNode(ctx context.Context, node schemas.Node) error {
	// Assumes node.Properties is json.RawMessage; ensures it's a valid, non null JSON object.
	props := node.Properties
	if len(props) == 0 || string(props) == "null" {
		props = json.RawMessage("{}")
	}

	// CORRECTED: Changed table name from 'nodes' to 'kg_nodes'
	_, err := p.pool.Exec(ctx, `
        INSERT INTO kg_nodes (id, type, label, status, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE SET
            type = EXCLUDED.type,
            label = EXCLUDED.label,
            status = EXCLUDED.status,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `, node.ID, node.Type, node.Label, node.Status, props, node.CreatedAt, time.Now())

	if err != nil {
		p.log.Error("Failed to add or update node", zap.String("node_id", node.ID), zap.Error(err))
		return fmt.Errorf("failed to exec add node: %w", err)
	}

	p.log.Debug("Node added or updated successfully", zap.String("node_id", node.ID))
	return nil
}

// AddEdge inserts a new edge or updates an existing one based on its logical uniqueness.
func (p *PostgresKG) AddEdge(ctx context.Context, edge schemas.Edge) error {
	props := edge.Properties
	if len(props) == 0 || string(props) == "null" {
		props = json.RawMessage("{}")
	}

	// CORRECTED: Changed table name from 'edges' to 'kg_edges'.
	// This assumes a UNIQUE constraint exists on these three columns in the 'kg_edges' table.
	_, err := p.pool.Exec(ctx, `
        INSERT INTO kg_edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (from_node, to_node, type) DO UPDATE SET
            label = EXCLUDED.label,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `, edge.ID, edge.From, edge.To, edge.Type, edge.Label, props, edge.CreatedAt, time.Now())

	if err != nil {
		p.log.Error(
			"Failed to add or update edge",
			zap.String("from_node", edge.From),
			zap.String("to_node", edge.To),
			zap.String("edge_type", string(edge.Type)),
			zap.Error(err),
		)
		return fmt.Errorf("failed to exec add edge: %w", err)
	}

	p.log.Debug(
		"Edge added or updated successfully",
		zap.String("from_node", edge.From),
		zap.String("to_node", edge.To),
		zap.String("edge_type", string(edge.Type)),
	)
	return nil
}

// GetNode fetches a single node from the database by its ID.
func (p *PostgresKG) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	var node schemas.Node

	// CORRECTED: Changed table name from 'nodes' to 'kg_nodes'
	err := p.pool.QueryRow(ctx, `
        SELECT id, type, label, status, properties, created_at, last_seen
        FROM kg_nodes WHERE id = $1;
    `, id).Scan(&node.ID, &node.Type, &node.Label, &node.Status, &node.Properties, &node.CreatedAt, &node.LastSeen)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			p.log.Warn("Node not found", zap.String("node_id", id))
			return schemas.Node{}, fmt.Errorf("node with id '%s' not found: %w", id, err)
		}
		p.log.Error("Failed to get node", zap.String("node_id", id), zap.Error(err))
		return schemas.Node{}, fmt.Errorf("failed to scan node row: %w", err)
	}

	p.log.Debug("Retrieved node successfully", zap.String("node_id", id))
	return node, nil
}

// GetNeighbors retrieves all nodes directly connected from a given node.
func (p *PostgresKG) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	// CORRECTED: Changed table names from 'nodes' to 'kg_nodes' and 'edges' to 'kg_edges'
	rows, err := p.pool.Query(ctx, `
        SELECT n.id, n.type, n.label, n.status, n.properties, n.created_at, n.last_seen
        FROM kg_nodes n
        JOIN kg_edges e ON n.id = e.to_node
        WHERE e.from_node = $1;
    `, nodeID)
	if err != nil {
		p.log.Error("Failed to query for neighbors", zap.String("node_id", nodeID), zap.Error(err))
		return nil, fmt.Errorf("failed to query neighbors: %w", err)
	}
	defer rows.Close()

	var neighbors []schemas.Node
	for rows.Next() {
		var node schemas.Node
		if err := rows.Scan(&node.ID, &node.Type, &node.Label, &node.Status, &node.Properties, &node.CreatedAt, &node.LastSeen); err != nil {
			p.log.Error("Failed to scan neighbor node row", zap.Error(err))
			return nil, fmt.Errorf("failed to scan neighbor row: %w", err)
		}
		neighbors = append(neighbors, node)
	}

	if err := rows.Err(); err != nil {
		p.log.Error("Error during neighbor row iteration", zap.String("node_id", nodeID), zap.Error(err))
		return nil, fmt.Errorf("error iterating neighbor rows: %w", err)
	}

	p.log.Debug("Retrieved neighbors successfully", zap.String("node_id", nodeID), zap.Int("count", len(neighbors)))
	return neighbors, nil
}

// GetEdges finds all outgoing edges originating from a specific node.
func (p *PostgresKG) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	// CORRECTED: Changed table name from 'edges' to 'kg_edges'
	rows, err := p.pool.Query(ctx, `
        SELECT id, from_node, to_node, type, label, properties, created_at, last_seen
        FROM kg_edges WHERE from_node = $1;
    `, nodeID)
	if err != nil {
		p.log.Error("Failed to query for edges", zap.String("node_id", nodeID), zap.Error(err))
		return nil, fmt.Errorf("failed to query edges: %w", err)
	}
	defer rows.Close()

	var edges []schemas.Edge
	for rows.Next() {
		var edge schemas.Edge
		if err := rows.Scan(&edge.ID, &edge.From, &edge.To, &edge.Type, &edge.Label, &edge.Properties, &edge.CreatedAt, &edge.LastSeen); err != nil {
			p.log.Error("Failed to scan edge row", zap.Error(err))
			return nil, fmt.Errorf("failed to scan edge row: %w", err)
		}
		edges = append(edges, edge)
	}

	if err := rows.Err(); err != nil {
		p.log.Error("Error during edge row iteration", zap.String("node_id", nodeID), zap.Error(err))
		return nil, fmt.Errorf("error iterating edge rows: %w", err)
	}

	p.log.Debug("Retrieved edges successfully", zap.String("node_id", nodeID), zap.Int("count", len(edges)))
	return edges, nil
}

// QueryImprovementHistory retrieves past improvement attempts using efficient JSONB queries.
func (p *PostgresKG) QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]schemas.Node, error) {
	// Uses JSON path operator (->>) to efficiently query within the 'properties' JSONB column.
	// An index on (type, (properties->>'goal_objective')) is recommended for performance.
	// CORRECTED: Changed table name from 'nodes' to 'kg_nodes'
	query := `
        SELECT id, type, label, status, properties, created_at, last_seen
        FROM kg_nodes
        WHERE type = $1 AND properties->>'goal_objective' = $2
        ORDER BY created_at DESC
    `
	args := []any{schemas.NodeImprovementAttempt, goalObjective}

	if limit > 0 {
		query += " LIMIT $3"
		args = append(args, limit)
	}

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		p.log.Error("Failed to query improvement history", zap.String("objective", goalObjective), zap.Error(err))
		return nil, fmt.Errorf("failed to query improvement history: %w", err)
	}
	defer rows.Close()

	var history []schemas.Node
	for rows.Next() {
		var node schemas.Node
		if err := rows.Scan(&node.ID, &node.Type, &node.Label, &node.Status, &node.Properties, &node.CreatedAt, &node.LastSeen); err != nil {
			p.log.Error("Failed to scan history node row", zap.Error(err))
			return nil, fmt.Errorf("failed to scan history node: %w", err)
		}
		history = append(history, node)
	}

	if err := rows.Err(); err != nil {
		p.log.Error("Error during history row iteration", zap.Error(err))
		return nil, fmt.Errorf("error iterating history rows: %w", err)
	}

	p.log.Debug("Queried improvement history successfully", zap.String("objective", goalObjective), zap.Int("found", len(history)))
	return history, nil
}
