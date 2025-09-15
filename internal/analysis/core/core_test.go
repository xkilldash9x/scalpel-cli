// core/core_test.go
package core

import (
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// -- Mock Implementations for Testing --

// mockReporter is a thread safe mock for the Reporter interface.
// It's used to capture the output of analyzers in a test environment.
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
	// returning a copy to prevent race conditions
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

// coreTestFixture holds the shared resources for all tests in this package.
type coreTestFixture struct {
	Logger   *zap.Logger
	Reporter *mockReporter
}

// globalFixture is the single, shared instance of our test fixture.
var globalFixture *coreTestFixture

// TestMain sets up the global test fixture before any tests are run
// and handles teardown after all tests have completed.
func TestMain(m *testing.M) {
	// -- setting up our global fixture --
	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Printf("Failed to create logger for tests: %v\n", err)
		os.Exit(1)
	}

	globalFixture = &coreTestFixture{
		Logger:   logger,
		Reporter: &mockReporter{},
	}

	// -- run all the tests --
	exitCode := m.Run()

	// -- a spot of cleanup --
	_ = globalFixture.Logger.Sync() // flushes any buffered log entries

	os.Exit(exitCode)
}

// -- Test Cases --

// TestBaseAnalyzer thoroughly tests the BaseAnalyzer functionality.
func TestBaseAnalyzer(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	analyzerName := "Testola"
	analyzerDesc := "A test analyzer for demonstration."

	t.Run("NewBaseAnalyzer should create ACTIVE analyzer", func(t *testing.T) {
		t.Parallel()
		analyzer := NewBaseAnalyzer(analyzerName, analyzerDesc, TypeActive, fixture.Logger)
		require.NotNil(t, analyzer, "NewBaseAnalyzer should not return nil")

		assert.Equal(t, analyzerName, analyzer.Name(), "Name() should return the correct name")
		assert.Equal(t, analyzerDesc, analyzer.Description(), "Description() should return the correct description")
		assert.Equal(t, TypeActive, analyzer.Type(), "Type() should return ACTIVE")
		require.NotNil(t, analyzer.Logger, "Logger should not be nil")
	})

	t.Run("NewBaseAnalyzer should create PASSIVE analyzer", func(t *testing.T) {
		t.Parallel()
		analyzer := NewBaseAnalyzer(analyzerName, analyzerDesc, TypePassive, fixture.Logger)
		require.NotNil(t, analyzer, "NewBaseAnalyzer should not return nil")

		assert.Equal(t, TypePassive, analyzer.Type(), "Type() should return PASSIVE")
	})
}

// TestAnalysisContext covers the functionality of the AnalysisContext.
func TestAnalysisContext(t *testing.T) {
	t.Parallel()

	// -- creating a base context for the tests in this function --
	baseAc := &AnalysisContext{
		Global: &GlobalContext{
			Logger: globalFixture.Logger,
		},
		Task: schemas.Task{
			ScanID:  uuid.NewString(),
			Timeout: 60,
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
		// creating a copy of the base context to ensure test isolation
		ac := *baseAc
		ac.Findings = nil // Ensure we start with a clean slate

		// first finding to add
		finding1 := schemas.Finding{Title: "First Test Finding"}
		ac.AddFinding(finding1)

		require.Len(t, ac.Findings, 1, "Should have one finding after the first addition")
		assert.Equal(t, "First Test Finding", ac.Findings[0].Title)

		// second finding to add
		finding2 := schemas.Finding{Title: "Second Test Finding"}
		ac.AddFinding(finding2)

		require.Len(t, ac.Findings, 2, "Should have two findings after the second addition")
		assert.Equal(t, "Second Test Finding", ac.Findings[1].Title)
	})

	t.Run("AddFinding should populate ScanID from task if missing", func(t *testing.T) {
		t.Parallel()
		ac := *baseAc
		ac.Findings = nil

		finding := schemas.Finding{Title: "Finding without ScanID"}
		ac.AddFinding(finding)

		require.Len(t, ac.Findings, 1)
		assert.Equal(t, ac.Task.ScanID, ac.Findings[0].ScanID, "ScanID should be populated from the task context")
	})

	t.Run("AddFinding should not overwrite existing ScanID", func(t *testing.T) {
		t.Parallel()
		ac := *baseAc
		ac.Findings = nil

		customScanID := "custom-" + uuid.NewString()
		finding := schemas.Finding{
			Title:  "Finding with custom ScanID",
			ScanID: customScanID,
		}
		ac.AddFinding(finding)

		require.Len(t, ac.Findings, 1)
		assert.Equal(t, customScanID, ac.Findings[0].ScanID, "Existing ScanID should be preserved")
	})
}

// TestIdentifierConstants ensures that the identifier constants have the expected string values.
func TestIdentifierConstants(t *testing.T) {
	t.Parallel()

	// -- makes sure our types are what they say they are --
	t.Run("IdentifierType constants", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "Unknown", string(TypeUnknown))
		assert.Equal(t, "NumericID", string(TypeNumericID))
		assert.Equal(t, "UUID", string(TypeUUID))
		assert.Equal(t, "ObjectID", string(TypeObjectID))
		assert.Equal(t, "Base64", string(TypeBase64))
	})

	// -- makes sure our locations are where we think they are --
	t.Run("IdentifierLocation constants", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "URLPath", string(LocationURLPath))
		assert.Equal(t, "QueryParam", string(LocationQueryParam))
		assert.Equal(t, "JSONBody", string(LocationJSONBody))
		assert.Equal(t, "Header", string(LocationHeader))
	})
}
