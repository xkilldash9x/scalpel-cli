package knowledgegraph

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// PostgresKG provides a robust, persistent implementation of the KnowledgeGraph interface
// using a PostgreSQL backend. This is suitable for production or larger scans.
type PostgresKG struct {
	db *sql.DB
}

// NewPostgresKG initializes a new connection wrapper for the PostgreSQL database.
func NewPostgresKG(db *sql.DB) *PostgresKG {
	return &PostgresKG{db: db}
}

// AddNode inserts or updates a node in the database. It uses ON CONFLICT to handle
// existing nodes, ensuring the graph data remains consistent and up-to-date.
func (p *PostgresKG) AddNode(node *schemas.Node) error {
	props, err := json.Marshal(node.Properties)
	if err != nil {
		return err
	}
	_, err = p.db.Exec(`
		INSERT INTO nodes (id, type, label, status, properties, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			label = EXCLUDED.label,
			status = EXCLUDED.status,
			properties = EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen;
	`, node.ID, node.Type, node.Label, node.Status, props, node.CreatedAt, time.Now())
	return err
}

// AddEdge inserts or updates an edge, linking two nodes in the database.
func (p *PostgresKG) AddEdge(edge *schemas.Edge) error {
	props, err := json.Marshal(edge.Properties)
	if err != nil {
		return err
	}
	_, err = p.db.Exec(`
		INSERT INTO edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			from_node = EXCLUDED.from_node,
			to_node = EXCLUDED.to_node,
			type = EXCLUDED.type,
			label = EXCLUDED.label,
			properties = EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen;
	`, edge.ID, edge.From, edge.To, edge.Type, edge.Label, props, edge.CreatedAt, time.Now())
	return err
}

// GetNode retrieves a single node by its unique ID.
func (p *PostgresKG) GetNode(id string) (*schemas.Node, error) {
	var node schemas.Node
	var props []byte
	err := p.db.QueryRow(`
		SELECT id, type, label, status, properties, created_at, last_seen
		FROM nodes WHERE id = $1;
	`, id).Scan(&node.ID, &node.Type, &node.Label, &node.Status, &props, &node.CreatedAt, &node.LastSeen)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(props, &node.Properties); err != nil {
		return nil, err
	}
	return &node, nil
}

// GetEdge retrieves a single edge by its unique ID.
func (p *PostgresKG) GetEdge(id string) (*schemas.Edge, error) {
	var edge schemas.Edge
	var props []byte
	err := p.db.QueryRow(`
		SELECT id, from_node, to_node, type, label, properties, created_at, last_seen
		FROM edges WHERE id = $1;
	`, id).Scan(&edge.ID, &edge.From, &edge.To, &edge.Type, &edge.Label, &props, &edge.CreatedAt, &edge.LastSeen)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(props, &edge.Properties); err != nil {
		return nil, err
	}
	return &edge, nil
}

// GetNeighbors finds all nodes directly connected to the given node via outgoing edges.
func (p *PostgresKG) GetNeighbors(nodeID string) ([]*schemas.Node, error) {
	rows, err := p.db.Query(`
		SELECT n.id, n.type, n.label, n.status, n.properties, n.created_at, n.last_seen
		FROM nodes n
		JOIN edges e ON n.id = e.to_node
		WHERE e.from_node = $1;
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var neighbors []*schemas.Node
	for rows.Next() {
		var node schemas.Node
		var props []byte
		if err := rows.Scan(&node.ID, &node.Type, &node.Label, &node.Status, &props, &node.CreatedAt, &node.LastSeen); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(props, &node.Properties); err != nil {
			return nil, err
		}
		neighbors = append(neighbors, &node)
	}
	return neighbors, nil
}

// GetEdges retrieves all outgoing edges from a specific node.
func (p *PostgresKG) GetEdges(nodeID string) ([]*schemas.Edge, error) {
	rows, err := p.db.Query(`
		SELECT id, from_node, to_node, type, label, properties, created_at, last_seen
		FROM edges WHERE from_node = $1;
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []*schemas.Edge
	for rows.Next() {
		var edge schemas.Edge
		var props []byte
		if err := rows.Scan(&edge.ID, &edge.From, &edge.To, &edge.Type, &edge.Label, &props, &edge.CreatedAt, &edge.LastSeen); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(props, &edge.Properties); err != nil {
			return nil, err
		}
		edges = append(edges, &edge)
	}
	return edges, nil
}
