package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// flexibleSQLMatcher creates a regex that is insensitive to whitespace for more robust SQL mock testing.
func flexibleSQLMatcher(sql string) string {
	// Trim leading/trailing space
	trimmed := strings.TrimSpace(sql)
	// Replace all sequences of whitespace characters (spaces, tabs, newlines) with the regex `\s+`
	// and quote the rest of the meta characters.
	return regexp.MustCompile(`\s+`).ReplaceAllString(regexp.QuoteMeta(trimmed), `\s+`)
}

// -- Test Cases --

func TestNewStore(t *testing.T) {
	t.Run("should return error if ping fails", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool(pgxmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer mockPool.Close()

		pingErr := errors.New("database unavailable")
		mockPool.ExpectPing().WillReturnError(pingErr)

		_, err = New(context.Background(), mockPool, zap.NewNop())
		require.Error(t, err)
		assert.ErrorIs(t, err, pingErr, "Error from ping should be propagated")
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestPersistData(t *testing.T) {
	ctx := context.Background()

	t.Run("should persist a full envelope successfully", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool(pgxmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		scanID := uuid.NewString()
		// REFACTOR: Use flattened struct and json.RawMessage
		finding := schemas.Finding{
			ID:                "finding-1",
			VulnerabilityName: "XSS",
			Evidence:          json.RawMessage("{}"),
		}
		// REFACTOR: Use NodeInput fields from knowledge_graph.go
		node := schemas.NodeInput{
			ID:     "node-1",
			Type:   schemas.NodeURL,
			Label:  "node-1-label",
			Status: schemas.StatusNew,
		}
		// REFACTOR: Use EdgeInput fields from knowledge_graph.go
		edge := schemas.EdgeInput{
			ID:    "edge-1",
			From:  "node-1",
			To:    "node-2",
			Type:  "LINKS_TO",
			Label: "edge-1-label",
		}

		envelope := &schemas.ResultEnvelope{
			ScanID:   scanID,
			Findings: []schemas.Finding{finding},
			KGUpdates: &schemas.KnowledgeGraphUpdate{
				NodesToAdd: []schemas.NodeInput{node},
				EdgesToAdd: []schemas.EdgeInput{edge},
			},
		}

		mockPool.ExpectBegin()

		// -- findings (Uses CopyFrom) --
		findingColumns := []string{"id", "scan_id", "task_id", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"}
		mockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, findingColumns).WillReturnResult(1)

		// -- nodes (Uses Exec loop) --
		// REFACTOR: Match SQL from postgres_kg.go
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
		mockPool.ExpectExec(flexibleSQLMatcher(sqlNodes)).
			WithArgs(node.ID, string(node.Type), node.Label, node.Status, json.RawMessage("{}"), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// -- edges (Uses Exec loop) --
		// REFACTOR: Match SQL from postgres_kg.go
		sqlEdges := `
		INSERT INTO kg_edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (from_node, to_node, type) DO UPDATE SET
			id = EXCLUDED.id,
			label = EXCLUDED.label,
			properties = EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen;
	`
		mockPool.ExpectExec(flexibleSQLMatcher(sqlEdges)).
			WithArgs(edge.ID, edge.From, edge.To, string(edge.Type), edge.Label, json.RawMessage("{}"), pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mockPool.ExpectCommit()

		if err := store.PersistData(ctx, envelope); err != nil {
			t.Fatalf("PersistData failed: %v", err)
		}
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("should handle transaction begin failure", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool(pgxmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		beginErr := errors.New("cannot begin tx")
		mockPool.ExpectBegin().WillReturnError(beginErr)

		err = store.PersistData(ctx, &schemas.ResultEnvelope{})
		require.Error(t, err)
		assert.ErrorIs(t, err, beginErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("should rollback if persisting findings fails", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool(pgxmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		copyErr := errors.New("copy from failed")
		// REFACTOR: Use flattened struct and json.RawMessage
		envelope := &schemas.ResultEnvelope{
			Findings: []schemas.Finding{
				{
					ID:                "f-1",
					VulnerabilityName: "Test",
					Evidence:          json.RawMessage("{}"),
				},
			},
		}

		mockPool.ExpectBegin()
		findingColumns := []string{"id", "scan_id", "task_id", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"}
		mockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, findingColumns).
			WillReturnError(copyErr)
		mockPool.ExpectRollback()

		err = store.PersistData(ctx, envelope)
		require.Error(t, err)
		assert.ErrorIs(t, err, copyErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestGetFindingsByScanID(t *testing.T) {
	ctx := context.Background()

	t.Run("should retrieve findings successfully", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool(pgxmock.MonitorPingsOption(true))
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		sqlGetFindings := `
		SELECT id, task_id, observed_at, target, module, vulnerability_name, severity, description, evidence, recommendation, cwe
		FROM findings
		WHERE scan_id = $1
		ORDER BY observed_at ASC;
		`
		scanID := uuid.NewString()
		now := time.Now()
		evidenceJSON := `{"detail": "some evidence"}`

		columns := []string{"id", "task_id", "observed_at", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe"}
		rows := pgxmock.NewRows(columns).
			AddRow("finding-123", "task-abc", now, "https://example.com", "SQLAnalyzer", "SQLi", "High", "desc", evidenceJSON, "reco", []string{"CWE-89"})

		// Use the flexible SQL matcher for a robust test.
		mockPool.ExpectQuery(flexibleSQLMatcher(sqlGetFindings)).
			WithArgs(scanID).
			WillReturnRows(rows)

		findings, err := store.GetFindingsByScanID(ctx, scanID)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		// Assertions for the retrieved finding.
		assert.Equal(t, "finding-123", findings[0].ID)
		// REFACTOR: Use VulnerabilityName
		assert.Equal(t, "SQLi", findings[0].VulnerabilityName)
		assert.JSONEq(t, evidenceJSON, string(findings[0].Evidence)) // Compare string to json.RawMessage (as string)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}
