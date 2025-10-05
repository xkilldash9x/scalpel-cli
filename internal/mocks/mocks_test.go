// internal/worker/mocks_test.go
package mocks_test

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// MockAnalyzer is a mock implementation of the core.Analyzer interface for isolated testing.
// It allows us to simulate the behavior of any analysis adapter, including successes and failures,
// without executing the actual analysis logic. This is crucial for unit testing the worker's
// dispatch and error handling capabilities.
type MockAnalyzer struct {
	mock.Mock
}

// Analyze is the mock's implementation of the Analyze method.
// It records that the method was called and returns whatever values were configured in the test setup.
func (m *MockAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	args := m.Called(ctx, analysisCtx)
	return args.Error(0)
}

// Name is the mock's implementation of the Name method.
// It records that the method was called and returns the configured mock name.
func (m *MockAnalyzer) Name() string {
	args := m.Called()
	return args.String(0)
}

// Description is the mock's implementation of the Description method.
// It records that the method was called and returns the configured mock description,
// satisfying the core.Analyzer interface.
func (m *MockAnalyzer) Description() string {
	args := m.Called()
	return args.String(0)
}


