// pkg/knowledgegraph/postgres_kg.go
package knowledgegraph

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/graphmodel"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
)

// PostgresKG is a persistent, thread safe KG implementation using PostgreSQL.
// It implements the GraphStore interface.
type PostgresKG struct {
	pool   *pgxpool.Pool
	logger *zap.Logger
}

// Ensure PostgresKG implements the GraphStore interface.
var _ GraphStore = (*PostgresKG)(nil)

// NewPostgresKG creates a new knowledge graph backed by a PostgreSQL database.
func NewPostgresKG(ctx context.Context, pool *pgxpool.Pool) (*PostgresKG, error) {
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("cannot ping postgres for KG: %w", err)
	}
	return &PostgresKG{pool: pool, logger: observability.GetLogger().Named("postgres_kg")}, nil
}

// AddNode uses an UPSERT (ON CONFLICT) query to be idempotent, merging properties.
func (kg *PostgresKG) AddNode(input graphmodel.NodeInput) (*graphmodel.Node, error) {
	propsJSON, err := json.Marshal(input.Properties)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node properties: %w", err)
	}

	// If type is not provided, infer it.
	nodeType := input.Type
	if nodeType == "" {
		nodeType = InferAssetType(input.ID)
	}

	query := `
		INSERT INTO kg_nodes (id, type, properties, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			properties = kg_nodes.properties || $3, -- Merge new properties into existing
			updated_at = NOW()
		RETURNING id, type, properties, created_at, updated_at;
	`
	row := kg.pool.QueryRow(context.Background(), query, input.ID, nodeType, propsJSON)

	var node graphmodel.Node
	var propsBytes []byte
	if err := row.Scan(&node.ID, &node.Type, &propsBytes, &node.CreatedAt, &node.UpdatedAt); err != nil {
		return nil, fmt.Errorf("failed to execute AddNode query and scan result: %w", err)
	}

	if err := json.Unmarshal(propsBytes, &node.Properties); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node properties from DB: %w", err)
	}

	return &node, nil
}

// AddEdge also uses an UPSERT to be idempotent, merging properties.
func (kg *PostgresKG) AddEdge(input graphmodel.EdgeInput) (*graphmodel.Edge, error) {
	propsJSON, err := json.Marshal(input.Properties)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal edge properties: %w", err)
	}

	query := `
		INSERT INTO kg_edges (source_id, target_id, relationship, properties, timestamp)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (source_id, target_id, relationship) DO UPDATE SET
			properties = kg_edges.properties || $4, -- Merge new properties
			timestamp = NOW()
		RETURNING source_id, target_id, relationship, properties, timestamp;
	`
	row := kg.pool.QueryRow(context.Background(), query, input.SourceID, input.TargetID, input.Relationship, propsJSON)

	var edge graphmodel.Edge
	var propsBytes []byte
	if err := row.Scan(&edge.SourceID, &edge.TargetID, &edge.Relationship, &propsBytes, &edge.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to execute AddEdge query and scan result: %w", err)
	}

	if err := json.Unmarshal(propsBytes, &edge.Properties); err != nil {
		return nil, fmt.Errorf("failed to unmarshal edge properties from DB: %w", err)
	}

	return &edge, nil
}

// GetNodeByID retrieves a single node by its ID.
func (kg *PostgresKG) GetNodeByID(id string) (*graphmodel.Node, error) {
	query := `SELECT id, type, properties, created_at, updated_at FROM kg_nodes WHERE id = $1`
	row := kg.pool.QueryRow(context.Background(), query, id)

	var node graphmodel.Node
	var propsBytes []byte
	err := row.Scan(&node.ID, &node.Type, &propsBytes, &node.CreatedAt, &node.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("node not found: %s", id)
		}
		return nil, fmt.Errorf("failed to query node by ID: %w", err)
	}

	if err := json.Unmarshal(propsBytes, &node.Properties); err != nil {
		return nil, fmt.Errorf("failed to unmarshal properties for node %s: %w", id, err)
	}

	return &node, nil
}

// FindNodes searches for nodes based on type and properties using JSONB operators.
func (kg *PostgresKG) FindNodes(query graphmodel.Query) ([]*graphmodel.Node, error) {
	var conditions []string
	var args []interface{}
	argCount := 1

	if query.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argCount))
		args = append(args, query.Type)
		argCount++
	}

	if len(query.Properties) > 0 {
		propsJSON, err := json.Marshal(query.Properties)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query properties: %w", err)
		}
		conditions = append(conditions, fmt.Sprintf("properties @> $%d", argCount))
		args = append(args, propsJSON)
	}

	sqlQuery := "SELECT id, type, properties, created_at, updated_at FROM kg_nodes"
	if len(conditions) > 0 {
		sqlQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := kg.pool.Query(context.Background(), sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute FindNodes query: %w", err)
	}
	defer rows.Close()

	var nodes []*graphmodel.Node
	for rows.Next() {
		var node graphmodel.Node
		var propsBytes []byte
		if err := rows.Scan(&node.ID, &node.Type, &propsBytes, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		if err := json.Unmarshal(propsBytes, &node.Properties); err != nil {
			return nil, fmt.Errorf("failed to unmarshal node properties: %w", err)
		}
		nodes = append(nodes, &node)
	}

	return nodes, nil
}

// GetNeighbors retrieves all directly connected nodes.
func (kg *PostgresKG) GetNeighbors(nodeId string) (graphmodel.NeighborsResult, error) {
	result := graphmodel.NeighborsResult{
		Outbound: make(map[graphmodel.RelationshipType][]*graphmodel.Node),
		Inbound:  make(map[graphmodel.RelationshipType][]*graphmodel.Node),
	}

	// Outbound query
	outboundQuery := `
		SELECT n.id, n.type, n.properties, n.created_at, n.updated_at, e.relationship
		FROM kg_nodes n JOIN kg_edges e ON n.id = e.target_id
		WHERE e.source_id = $1
	`
	rowsOut, err := kg.pool.Query(context.Background(), outboundQuery, nodeId)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, fmt.Errorf("failed to query outbound neighbors: %w", err)
	}
	defer rowsOut.Close()

	for rowsOut.Next() {
		var node graphmodel.Node
		var propsBytes []byte
		var rel graphmodel.RelationshipType
		if err := rowsOut.Scan(&node.ID, &node.Type, &propsBytes, &node.CreatedAt, &node.UpdatedAt, &rel); err != nil {
			return result, fmt.Errorf("failed to scan outbound neighbor: %w", err)
		}
		if err := json.Unmarshal(propsBytes, &node.Properties); err != nil {
			return result, fmt.Errorf("failed to unmarshal outbound neighbor properties: %w", err)
		}
		result.Outbound[rel] = append(result.Outbound[rel], &node)
	}

	// Inbound query
	inboundQuery := `
		SELECT n.id, n.type, n.properties, n.created_at, n.updated_at, e.relationship
		FROM kg_nodes n JOIN kg_edges e ON n.id = e.source_id
		WHERE e.target_id = $1
	`
	rowsIn, err := kg.pool.Query(context.Background(), inboundQuery, nodeId)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, fmt.Errorf("failed to query inbound neighbors: %w", err)
	}
	defer rowsIn.Close()

	for rowsIn.Next() {
		var node graphmodel.Node
		var propsBytes []byte
		var rel graphmodel.RelationshipType
		if err := rowsIn.Scan(&node.ID, &node.Type, &propsBytes, &node.CreatedAt, &node.UpdatedAt, &rel); err != nil {
			return result, fmt.Errorf("failed to scan inbound neighbor: %w", err)
		}
		if err := json.Unmarshal(propsBytes, &node.Properties); err != nil {
			return result, fmt.Errorf("failed to unmarshal inbound neighbor properties: %w", err)
		}
		result.Inbound[rel] = append(result.Inbound[rel], &node)
	}

	return result, nil
}

// ExportGraph retrieves all nodes and edges from the database.
func (kg *PostgresKG) ExportGraph() graphmodel.GraphExport {
	export := graphmodel.GraphExport{}
	var wg sync.WaitGroup
	var nodesErr, edgesErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		nodes, err := kg.FindNodes(graphmodel.Query{})
		if err != nil {
			nodesErr = err
			return
		}
		export.Nodes = nodes
	}()

	go func() {
		defer wg.Done()
		query := `SELECT source_id, target_id, relationship, properties, timestamp FROM kg_edges`
		rows, err := kg.pool.Query(context.Background(), query)
		if err != nil {
			edgesErr = err
			return
		}
		defer rows.Close()

		for rows.Next() {
			var edge graphmodel.Edge
			var propsBytes []byte
			if err := rows.Scan(&edge.SourceID, &edge.TargetID, &edge.Relationship, &propsBytes, &edge.Timestamp); err != nil {
				edgesErr = fmt.Errorf("failed to scan edge row: %w", err)
				return
			}
			if err := json.Unmarshal(propsBytes, &edge.Properties); err != nil {
				edgesErr = fmt.Errorf("failed to unmarshal edge properties: %w", err)
				return
			}
			export.Edges = append(export.Edges, &edge)
		}
	}()

	wg.Wait()
	if nodesErr != nil {
		kg.logger.Error("Failed to export nodes", zap.Error(nodesErr))
	}
	if edgesErr != nil {
		kg.logger.Error("Failed to export edges", zap.Error(edgesErr))
	}
	return export
}

// RecordTechnology is a transactional operation for recording technology usage.
func (kg *PostgresKG) RecordTechnology(assetId, techName, version, source string, confidence float64, assetType graphmodel.NodeType) error {
	tx, err := kg.pool.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin transaction for RecordTechnology: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Upsert asset node
	nodeType := assetType
	if nodeType == "" {
		nodeType = InferAssetType(assetId)
	}
	assetInput := graphmodel.NodeInput{ID: assetId, Type: nodeType}
	if _, err := kg.addNodeTx(tx, assetInput); err != nil {
		return err
	}

	// Upsert technology node
	safeVersion := version
	if safeVersion == "" {
		safeVersion = "unknown"
	}
	techId := fmt.Sprintf("TECH:%s:%s", techName, safeVersion)
	techInput := graphmodel.NodeInput{
		ID:         techId,
		Type:       graphmodel.NodeTypeTechnology,
		Properties: graphmodel.Properties{"name": techName, "version": safeVersion},
	}
	if _, err := kg.addNodeTx(tx, techInput); err != nil {
		return err
	}

	// Upsert edge
	edgeInput := graphmodel.EdgeInput{
		SourceID:     assetId,
		TargetID:     techId,
		Relationship: graphmodel.RelationshipTypeUsesTechnology,
		Properties:   graphmodel.Properties{"source": source, "confidence": confidence},
	}
	if _, err := kg.addEdgeTx(tx, edgeInput); err != nil {
		return err
	}

	return tx.Commit(context.Background())
}

// RecordLink is a transactional operation for recording a link between two assets.
func (kg *PostgresKG) RecordLink(sourceUrl, targetUrl, method string, depth int) error {
	tx, err := kg.pool.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin transaction for RecordLink: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Normalize source
	sourceId := sourceUrl
	if sourceId == "" {
		sourceId = graphmodel.RootNodeID
	}
	if method == "" {
		method = "GET"
	}

	// Upsert source node (if not a system node)
	if sourceId != graphmodel.RootNodeID && sourceId != graphmodel.OSINTNodeID {
		sourceDepth := 0
		if depth > 0 {
			sourceDepth = depth - 1
		}
		sourceInput := graphmodel.NodeInput{
			ID:         sourceId,
			Type:       InferAssetType(sourceId),
			Properties: graphmodel.Properties{"depth": sourceDepth},
		}
		if _, err := kg.addNodeTx(tx, sourceInput); err != nil {
			return err
		}
	}

	// Upsert target node
	targetInput := graphmodel.NodeInput{
		ID:         targetUrl,
		Type:       InferAssetType(targetUrl),
		Properties: graphmodel.Properties{"depth": depth},
	}
	if _, err := kg.addNodeTx(tx, targetInput); err != nil {
		return err
	}

	// Upsert edge
	edgeInput := graphmodel.EdgeInput{
		SourceID:     sourceId,
		TargetID:     targetUrl,
		Relationship: graphmodel.RelationshipTypeLinksTo,
		Properties:   graphmodel.Properties{"method": strings.ToUpper(method)},
	}
	if _, err := kg.addEdgeTx(tx, edgeInput); err != nil {
		return err
	}

	return tx.Commit(context.Background())
}

// ExtractMissionSubgraph uses a Common Table Expression (CTE) to traverse the graph.
func (kg *PostgresKG) ExtractMissionSubgraph(ctx context.Context, missionID string, lookbackSteps int) (graphmodel.GraphExport, error) {
	query := `
	WITH RECURSIVE mission_actions AS (
		-- 1. Get the most recent 'lookbackSteps' actions for the mission
		SELECT e.target_id as action_id, n.created_at
		FROM kg_edges e
		JOIN kg_nodes n ON e.target_id = n.id
		WHERE e.source_id = $1 AND e.relationship = 'EXECUTES_ACTION'
		ORDER BY n.created_at DESC
		LIMIT $2
	),
	relevant_nodes AS (
		-- 2. Base set of nodes: mission, recent actions, and directly affected assets
		(SELECT id FROM kg_nodes WHERE id = $1) -- Mission node
		UNION
		(SELECT action_id FROM mission_actions) -- Recent action nodes
		UNION
		(SELECT target_id FROM kg_edges WHERE source_id = $1 AND relationship = 'AFFECTS') -- Directly affected assets
		UNION
		-- 3. Observations and artifacts generated by recent actions
		(SELECT target_id FROM kg_edges WHERE source_id IN (SELECT action_id FROM mission_actions)
			AND relationship IN ('GENERATES_OBSERVATION', 'GENERATES_ARTIFACT'))
	),
	-- 4. One level of contextual neighbors for assets (e.g., technologies)
	final_node_ids AS (
		(SELECT id FROM relevant_nodes)
		UNION
		(SELECT e.target_id FROM kg_edges e JOIN relevant_nodes rn ON e.source_id = rn.id
			WHERE e.relationship IN ('USES_TECHNOLOGY', 'LINKS_TO', 'HAS_PARAMETER'))
	)
	-- 5. Select all nodes and edges that are part of this subgraph
	SELECT
		(SELECT jsonb_agg(nodes) FROM (SELECT * FROM kg_nodes WHERE id IN (SELECT id FROM final_node_ids)) AS nodes) AS nodes_json,
		(SELECT jsonb_agg(edges) FROM (SELECT * FROM kg_edges WHERE source_id IN (SELECT id FROM final_node_ids) AND target_id IN (SELECT id FROM final_node_ids)) AS edges) AS edges_json;
	`

	var nodesJSON, edgesJSON sql.NullString
	err := kg.pool.QueryRow(ctx, query, missionID, lookbackSteps).Scan(&nodesJSON, &edgesJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return graphmodel.GraphExport{}, nil // Return empty if no data found
		}
		return graphmodel.GraphExport{}, fmt.Errorf("failed to execute subgraph query: %w", err)
	}

	export := graphmodel.GraphExport{}
	if nodesJSON.Valid {
		if err := json.Unmarshal([]byte(nodesJSON.String), &export.Nodes); err != nil {
			return export, fmt.Errorf("failed to unmarshal subgraph nodes: %w", err)
		}
	}
	if edgesJSON.Valid {
		if err := json.Unmarshal([]byte(edgesJSON.String), &export.Edges); err != nil {
			return export, fmt.Errorf("failed to unmarshal subgraph edges: %w", err)
		}
	}

	return export, nil
}

// InferAssetType uses the package level utility function as it doesn't depend on DB state.
func (kg *PostgresKG) InferAssetType(assetId string) graphmodel.NodeType {
	return InferAssetType(assetId)
}

// -- Transactional Helpers --

// addNodeTx is a helper to run AddNode logic within an existing transaction.
func (kg *PostgresKG) addNodeTx(tx pgx.Tx, input graphmodel.NodeInput) (*graphmodel.Node, error) {
	propsJSON, err := json.Marshal(input.Properties)
	if err != nil {
		return nil, err
	}
	nodeType := input.Type
	if nodeType == "" {
		nodeType = InferAssetType(input.ID)
	}
	query := `INSERT INTO kg_nodes (id, type, properties) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET properties = kg_nodes.properties || $3, updated_at = NOW()`
	_, err = tx.Exec(context.Background(), query, input.ID, nodeType, propsJSON)
	if err != nil {
		return nil, err
	}
	// Note: We don't return the full node data here for performance in transactions.
	return &graphmodel.Node{ID: input.ID, Type: nodeType, Properties: input.Properties}, nil
}

// addEdgeTx is a helper to run AddEdge logic within an existing transaction.
func (kg *PostgresKG) addEdgeTx(tx pgx.Tx, input graphmodel.EdgeInput) (*graphmodel.Edge, error) {
	propsJSON, err := json.Marshal(input.Properties)
	if err != nil {
		return nil, err
	}
	query := `INSERT INTO kg_edges (source_id, target_id, relationship, properties, timestamp) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT (source_id, target_id, relationship) DO UPDATE SET properties = kg_edges.properties || $4, timestamp = NOW()`
	_, err = tx.Exec(context.Background(), query, input.SourceID, input.TargetID, input.Relationship, propsJSON)
	if err != nil {
		return nil, err
	}
	return &graphmodel.Edge{SourceID: input.SourceID, TargetID: input.TargetID, Relationship: input.Relationship, Properties: input.Properties}, nil
}
