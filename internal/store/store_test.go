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
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// flexibleSQLMatcher creates a regex that is insensitive to whitespace for more robust SQL mock testing.
func flexibleSQLMatcher(sql string) string {
	trimmed := strings.TrimSpace(sql)
	return regexp.MustCompile(`\s+`).ReplaceAllString(regexp.QuoteMeta(trimmed), `\s+`)
}

// ArgumentMatcherFunc is a helper to create inline mock matchers.
type ArgumentMatcherFunc func(interface{}) bool

func (f ArgumentMatcherFunc) Match(v interface{}) bool {
	return f(v)
}

// anyTime is a matcher that accepts any value (used for timestamps we can't predict exactly)
var anyTime = ArgumentMatcherFunc(func(v interface{}) bool {
	return true
})

const (
	sqlInsertNode = `
        INSERT INTO kg_nodes (id, type, label, status, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO UPDATE SET
            type = EXCLUDED.type,
            label = EXCLUDED.label,
            status = EXCLUDED.status,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
	sqlInsertEdge = `
        INSERT INTO kg_edges (id, from_node, to_node, type, label, properties, created_at, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (from_node, to_node, type) DO UPDATE SET
            id = EXCLUDED.id,
            label = EXCLUDED.label,
            properties = EXCLUDED.properties,
            last_seen = EXCLUDED.last_seen;
    `
)

// -- Test Cases --

func TestNewStore(t *testing.T) {
	t.Run("should return error if ping fails", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
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

	t.Run("should persist a full envelope successfully without rollback errors", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mockPool.Close()

		observedZapCore, observedLogs := observer.New(zapcore.ErrorLevel)
		observedLogger := zap.New(observedZapCore)

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, observedLogger)
		require.NoError(t, err)

		scanID := uuid.NewString()
		finding := schemas.Finding{
			ID:                "finding-1",
			VulnerabilityName: "XSS",
			Evidence:          json.RawMessage("{}"),
			ObservedAt:        time.Now(),
		}
		node := schemas.NodeInput{
			ID:     "node-1",
			Type:   schemas.NodeURL,
			Label:  "node-1-label",
			Status: schemas.StatusNew,
		}
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

		// -- Findings (Uses CopyFrom) --
		findingColumns := []string{"id", "scan_id", "task_id", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"}
		mockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, findingColumns).
			WillReturnResult(1)

		// -- Graph Updates (Uses SendBatch) --
		batchExp := mockPool.ExpectBatch()

		// 1. Expect Node Insert
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertNode)).
			WithArgs(
				node.ID,
				string(node.Type),
				node.Label,
				node.Status,
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// 2. Expect Edge Insert
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertEdge)).
			WithArgs(
				edge.ID,
				edge.From,
				edge.To,
				string(edge.Type),
				edge.Label,
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// Expect Commit AND the subsequent Rollback (which returns ErrTxClosed)
		mockPool.ExpectCommit()
		mockPool.ExpectRollback().WillReturnError(pgx.ErrTxClosed)

		if err := store.PersistData(ctx, envelope); err != nil {
			t.Fatalf("PersistData failed: %v", err)
		}
		assert.NoError(t, mockPool.ExpectationsWereMet())
		assert.Empty(t, observedLogs.All(), "Expected no errors logged on successful commit")
	})

	t.Run("should convert timestamps to UTC before persisting", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		loc, err := time.LoadLocation("America/New_York")
		require.NoError(t, err)
		observedTimeLocal := time.Date(2025, 11, 20, 10, 0, 0, 0, loc)

		scanID := uuid.NewString()
		finding := schemas.Finding{
			ID:                "finding-tz",
			VulnerabilityName: "TZ-Test",
			Evidence:          json.RawMessage("{}"),
			ObservedAt:        observedTimeLocal,
		}
		node := schemas.NodeInput{ID: "node-tz", Type: schemas.NodeHost}

		envelope := &schemas.ResultEnvelope{
			ScanID:   scanID,
			Findings: []schemas.Finding{finding},
			KGUpdates: &schemas.KnowledgeGraphUpdate{
				NodesToAdd: []schemas.NodeInput{node},
			},
		}

		mockPool.ExpectBegin()

		findingColumns := []string{"id", "scan_id", "task_id", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"}
		mockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, findingColumns).
			WillReturnResult(1)

		// -- Graph Updates --
		batchExp := mockPool.ExpectBatch()
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertNode)).
			WithArgs(
				node.ID,
				string(node.Type),
				node.Label,
				node.Status,
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mockPool.ExpectCommit()
		mockPool.ExpectRollback().WillReturnError(pgx.ErrTxClosed)

		if err := store.PersistData(ctx, envelope); err != nil {
			t.Fatalf("PersistData failed: %v", err)
		}
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("should convert JSON 'null' properties to empty object '{}'", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		scanID := uuid.NewString()

		node := schemas.NodeInput{
			ID:         "node-null-props",
			Type:       schemas.NodeURL,
			Status:     schemas.StatusNew,
			Properties: json.RawMessage("null"),
		}
		edge := schemas.EdgeInput{
			ID:         "edge-null-props",
			From:       "n1",
			To:         "n2",
			Type:       "LINKS_TO",
			Properties: json.RawMessage("null"),
		}

		envelope := &schemas.ResultEnvelope{
			ScanID: scanID,
			KGUpdates: &schemas.KnowledgeGraphUpdate{
				NodesToAdd: []schemas.NodeInput{node},
				EdgesToAdd: []schemas.EdgeInput{edge},
			},
		}

		mockPool.ExpectBegin()

		// -- Graph Updates --
		batchExp := mockPool.ExpectBatch()

		// 1. Expect Node Insert
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertNode)).
			WithArgs(
				node.ID,
				string(node.Type),
				node.Label,
				node.Status,
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		// 2. Expect Edge Insert
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertEdge)).
			WithArgs(
				edge.ID,
				edge.From,
				edge.To,
				string(edge.Type),
				edge.Label,
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		mockPool.ExpectCommit()
		mockPool.ExpectRollback().WillReturnError(pgx.ErrTxClosed)

		if err := store.PersistData(ctx, envelope); err != nil {
			t.Fatalf("PersistData failed: %v", err)
		}
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("should handle transaction begin failure", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
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
		mockPool, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		copyErr := errors.New("copy from failed")
		envelope := &schemas.ResultEnvelope{
			Findings: []schemas.Finding{
				{
					ID:                "f-1",
					VulnerabilityName: "Test",
					Evidence:          json.RawMessage("{}"),
					ObservedAt:        time.Now(),
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

	t.Run("should rollback if persisting graph updates (batch) fails", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mockPool.Close()

		mockPool.ExpectPing().WillReturnError(nil)
		store, err := New(context.Background(), mockPool, zap.NewNop())
		require.NoError(t, err)

		batchErr := errors.New("batch execution failed")
		envelope := &schemas.ResultEnvelope{
			KGUpdates: &schemas.KnowledgeGraphUpdate{
				NodesToAdd: []schemas.NodeInput{{ID: "n-fail"}},
			},
		}

		mockPool.ExpectBegin()

		batchExp := mockPool.ExpectBatch()
		batchExp.ExpectExec(flexibleSQLMatcher(sqlInsertNode)).
			WithArgs(
				"n-fail",
				"",                     // empty string(Type)
				"",                     // empty Label
				schemas.NodeStatus(""), // cast to schemas.NodeStatus
				json.RawMessage("{}"),
				anyTime,
				anyTime,
			).
			WillReturnError(batchErr)

		mockPool.ExpectRollback()

		err = store.PersistData(ctx, envelope)
		require.Error(t, err)
		assert.ErrorIs(t, err, batchErr)
		assert.Contains(t, err.Error(), "failed to execute batch insert for node n-fail")
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestGetFindingsByScanID(t *testing.T) {
	ctx := context.Background()

	t.Run("should retrieve findings successfully", func(t *testing.T) {
		mockPool, err := pgxmock.NewPool()
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
		now := time.Now().UTC()
		evidenceJSON := `{"detail": "some evidence"}`

		columns := []string{"id", "task_id", "observed_at", "target", "module", "vulnerability_name", "severity", "description", "evidence", "recommendation", "cwe"}
		rows := pgxmock.NewRows(columns).
			AddRow("finding-123", "task-abc", now, "https://example.com", "SQLAnalyzer", "SQLi", "High", "desc", []byte(evidenceJSON), "reco", []string{"CWE-89"})

		mockPool.ExpectQuery(flexibleSQLMatcher(sqlGetFindings)).
			WithArgs(scanID).
			WillReturnRows(rows)

		findings, err := store.GetFindingsByScanID(ctx, scanID)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		assert.Equal(t, "finding-123", findings[0].ID)
		assert.Equal(t, "SQLi", findings[0].VulnerabilityName)
		assert.JSONEq(t, evidenceJSON, string(findings[0].Evidence))
		assert.True(t, findings[0].ObservedAt.Equal(now))
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}
