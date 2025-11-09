// File: internal/analysis/core/core_test.go
package core

import (
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"

	// "time" // Removed unused import.

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// -- Mock Implementations for Testing --

// mockReporter is a thread safe mock for the Reporter interface.
type mockReporter struct {
	mu        sync.Mutex
	envelopes []*schemas.ResultEnvelope
}

// Write captures the result envelope for later inspection.
func (m *mockReporter) Write(envelope *schemas.ResultEnvelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if envelope == nil {
		return fmt.Errorf("cannot write a nil envelope")
	}
	m.envelopes = append(m.envelopes, envelope)
	return nil
}

// GetEnvelopes returns a copy of the captured envelopes.
func (m *mockReporter) GetEnvelopes() []*schemas.ResultEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	envelopesCopy := make([]*schemas.ResultEnvelope, len(m.envelopes))
	copy(envelopesCopy, m.envelopes)
	return envelopesCopy
}

// Reset clears the captured envelopes.
func (m *mockReporter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.envelopes = nil
}

// -- Test Fixture Setup --

type coreTestFixture struct {
	Logger   *zap.Logger
	Reporter *mockReporter
}

var globalFixture *coreTestFixture

// TestMain sets up the global test fixture.
func TestMain(m *testing.M) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Printf("Failed to create logger for tests: %v\n", err)
		os.Exit(1)
	}

	globalFixture = &coreTestFixture{
		Logger:   logger,
		Reporter: &mockReporter{},
	}

	exitCode := m.Run()

	_ = globalFixture.Logger.Sync()
	os.Exit(exitCode)
}

// -- Test Cases --

// TestBaseAnalyzer tests the BaseAnalyzer functionality.
func TestBaseAnalyzer(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	analyzerName := "Testola"
	analyzerDesc := "A test analyzer for demonstration."

	t.Run("NewBaseAnalyzer should create ACTIVE analyzer", func(t *testing.T) {
		t.Parallel()
		analyzer := NewBaseAnalyzer(analyzerName, analyzerDesc, TypeActive, fixture.Logger)
		require.NotNil(t, analyzer)

		assert.Equal(t, analyzerName, analyzer.Name())
		assert.Equal(t, analyzerDesc, analyzer.Description())
		assert.Equal(t, TypeActive, analyzer.Type())
		require.NotNil(t, analyzer.Logger)
	})

	t.Run("NewBaseAnalyzer should create PASSIVE analyzer", func(t *testing.T) {
		t.Parallel()
		analyzer := NewBaseAnalyzer(analyzerName, analyzerDesc, TypePassive, fixture.Logger)
		require.NotNil(t, analyzer)
		assert.Equal(t, TypePassive, analyzer.Type())
	})
}

// TestAnalysisContext covers the functionality of the AnalysisContext.
func TestAnalysisContext(t *testing.T) {
	t.Parallel()

	baseAc := &AnalysisContext{
		Global: &GlobalContext{
			Logger: globalFixture.Logger,
		},
		Task: schemas.Task{
			ScanID: uuid.NewString(),
			// FIX: Timeout field removed as it's no longer in schemas.Task.
		},
		TargetURL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/test",
		},
		Logger: globalFixture.Logger,
	}

	t.Run("AddFinding should correctly add findings", func(t *testing.T) {
		t.Parallel()
		ac := *baseAc
		ac.Findings = nil

		// FIX: Updated to use VulnerabilityName, as the Vulnerability struct was flattened.
		finding1 := schemas.Finding{
			VulnerabilityName: "First Test Finding",
		}
		ac.AddFinding(finding1)

		require.Len(t, ac.Findings, 1)
		// FIX: Updated assertion to check VulnerabilityName.
		assert.Equal(t, "First Test Finding", ac.Findings[0].VulnerabilityName)

		finding2 := schemas.Finding{
			VulnerabilityName: "Second Test Finding",
		}
		ac.AddFinding(finding2)

		require.Len(t, ac.Findings, 2)
		assert.Equal(t, "Second Test Finding", ac.Findings[1].VulnerabilityName)
	})

	t.Run("AddFinding should populate ScanID from task if missing", func(t *testing.T) {
		t.Parallel()
		ac := *baseAc
		ac.Findings = nil

		finding := schemas.Finding{
			VulnerabilityName: "Finding without ScanID",
		}
		ac.AddFinding(finding)

		require.Len(t, ac.Findings, 1)
		assert.Equal(t, ac.Task.ScanID, ac.Findings[0].ScanID)
	})

	t.Run("AddFinding should not overwrite existing ScanID", func(t *testing.T) {
		t.Parallel()
		ac := *baseAc
		ac.Findings = nil

		customScanID := "custom-" + uuid.NewString()
		finding := schemas.Finding{
			VulnerabilityName: "Finding with custom ScanID",
			ScanID:            customScanID,
		}
		ac.AddFinding(finding)

		require.Len(t, ac.Findings, 1)
		assert.Equal(t, customScanID, ac.Findings[0].ScanID)
	})
}

// TestIdentifierConstants ensures that the identifier constants have the expected string values.
func TestIdentifierConstants(t *testing.T) {
	t.Parallel()

	t.Run("IdentifierType constants", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "Unknown", string(TypeUnknown))
		assert.Equal(t, "NumericID", string(TypeNumericID))
		assert.Equal(t, "UUID", string(TypeUUID))
		assert.Equal(t, "ObjectID", string(TypeObjectID))
		assert.Equal(t, "Base64", string(TypeBase64))
	})

	t.Run("IdentifierLocation constants", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "URLPath", string(LocationURLPath))
		assert.Equal(t, "QueryParam", string(LocationQueryParam))
		assert.Equal(t, "JSONBody", string(LocationJSONBody))
		assert.Equal(t, "Header", string(LocationHeader))
	})
}
