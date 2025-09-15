// internal/store/store_test.go
package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
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

// -- Test Fixture Setup --

type storeTestFixture struct {
	MockPool pgxmock.PgxPoolIface
	Store    *Store
	Logger   *zap.Logger
}

// setupTest initializes a new fixture with a mock pool for each test.
func setupTest(t *testing.T) *storeTestFixture {
	t.Helper()

	mock, err := pgxmock.NewPool()
	require.NoError(t, err, "Failed to create mock pool")

	logger := zap.NewNop()
	store, err := New(context.Background(), mock, logger)
	// We expect New to ping the database
	mock.ExpectPing().WillReturnError(nil)
	require.NoError(t, err, "Failed to create store")

	return &storeTestFixture{
		MockPool: mock,
		Store:    store,
		Logger:   logger,
	}
}

// -- Test Cases --

func TestNewStore(t *testing.T) {
	t.Parallel()

	t.Run("should return error if ping fails", func(t *testing.T) {
		t.Parallel()
		mock, err := pgxmock.NewPool()
		require.NoError(t, err)
		defer mock.Close()

		pingErr := errors.New("database unavailable")
		mock.ExpectPing().WillReturnError(pingErr)

		_, err = New(context.Background(), mock, zap.NewNop())
		require.Error(t, err)
		assert.ErrorIs(t, err, pingErr, "Error from ping should be propagated")
	})
}

func TestPersistData(t *testing.T) {
	ctx := context.Background()

	t.Run("should persist a full envelope successfully", func(t *testing.T) {
		fixture := setupTest(t)
		defer fixture.MockPool.Close()

		scanID := uuid.NewString()
		finding := schemas.Finding{ID: "finding-1", Vulnerability: schemas.Vulnerability{Name: "XSS"}}
		node := schemas.Node{ID: "node-1", Type: "URL"}
		edge := schemas.Edge{ID: "edge-1", From: "node-1", To: "node-2"}

		envelope := &schemas.ResultEnvelope{
			ScanID:   scanID,
			Findings: []schemas.Finding{finding},
			KGUpdates: &schemas.KnowledgeGraphUpdate{
				NodesToAdd: []schemas.Node{node},
				EdgesToAdd: []schemas.Edge{edge},
			},
		}

		// -- set up our mock expectations --
		fixture.MockPool.ExpectBegin()
		// -- findings --
		fixture.MockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, []string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"}).
			WillReturnResult(1)
		// -- nodes --
		fixture.MockPool.ExpectExec(regexp.QuoteMeta(`INSERT INTO kg_nodes`)).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		// -- edges --
		fixture.MockPool.ExpectExec(regexp.QuoteMeta(`INSERT INTO kg_edges`)).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		fixture.MockPool.ExpectCommit()

		err := fixture.Store.PersistData(ctx, envelope)
		require.NoError(t, err)
		// -- ensure all expectations were met --
		assert.NoError(t, fixture.MockPool.ExpectationsWereMet())
	})

	t.Run("should handle transaction begin failure", func(t *testing.T) {
		fixture := setupTest(t)
		defer fixture.MockPool.Close()

		beginErr := errors.New("cannot begin tx")
		fixture.MockPool.ExpectBegin().WillReturnError(beginErr)

		err := fixture.Store.PersistData(ctx, &schemas.ResultEnvelope{})
		require.Error(t, err)
		assert.ErrorIs(t, err, beginErr)
		assert.NoError(t, fixture.MockPool.ExpectationsWereMet())
	})

	t.Run("should rollback if persisting findings fails", func(t *testing.T) {
		fixture := setupTest(t)
		defer fixture.MockPool.Close()

		copyErr := errors.New("copy from failed")
		envelope := &schemas.ResultEnvelope{Findings: []schemas.Finding{{ID: "f-1"}}}

		fixture.MockPool.ExpectBegin()
		fixture.MockPool.ExpectCopyFrom(pgx.Identifier{"findings"}, []string{"id", "scan_id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"}).
			WillReturnError(copyErr)
		fixture.MockPool.ExpectRollback()

		err := fixture.Store.PersistData(ctx, envelope)
		require.Error(t, err)
		assert.ErrorIs(t, err, copyErr)
		assert.NoError(t, fixture.MockPool.ExpectationsWereMet())
	})
}

func TestGetFindingsByScanID(t *testing.T) {
	ctx := context.Background()

	t.Run("should retrieve findings successfully", func(t *testing.T) {
		fixture := setupTest(t)
		defer fixture.MockPool.Close()

		scanID := uuid.NewString()
		now := time.Now()
		vulnJSON, _ := json.Marshal(schemas.Vulnerability{Name: "SQLi"})

		// -- columns must match the SELECT query in the function --
		columns := []string{"id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"}
		rows := pgxmock.NewRows(columns).
			AddRow("finding-123", "task-abc", now, "https://example.com", "SQLAnalyzer", vulnJSON, "High", "desc", "evid", "reco", []string{"CWE-89"})

		fixture.MockPool.ExpectQuery(regexp.QuoteMeta(`SELECT id, task_id, timestamp, target, module, vulnerability, severity, description, evidence, recommendation, cwe FROM findings`)).
			WithArgs(scanID).
			WillReturnRows(rows)

		findings, err := fixture.Store.GetFindingsByScanID(ctx, scanID)
		require.NoError(t, err)
		require.Len(t, findings, 1)

		assert.Equal(t, "finding-123", findings[0].ID)
		assert.Equal(t, "SQLi", findings[0].Vulnerability.Name)
		assert.NoError(t, fixture.MockPool.ExpectationsWereMet())
	})

	t.Run("should return empty slice when no findings are found", func(t *testing.T) {
		fixture := setupTest(t)
		defer fixture.MockPool.Close()

		scanID := "empty-scan"
		columns := []string{"id", "task_id", "timestamp", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe"}
		rows := pgxmock.NewRows(columns) // -- No rows added --

		fixture.MockPool.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
			WithArgs(scanID).
			WillReturnRows(rows)

		findings, err := fixture.Store.GetFindingsByScanID(ctx, scanID)
		require.NoError(t, err)
		assert.Empty(t, findings)
		assert.NoError(t, fixture.MockPool.ExpectationsWereMet())
	})
}

