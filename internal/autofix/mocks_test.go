// internal/autofix/mock.go
package autofix_test

import (
	"context"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/internal/autofix"
)

// MockWatcher is a mock implementation of WatcherInterface.
type MockWatcher struct {
	mock.Mock
}

func (m *MockWatcher) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockAnalyzer is a mock implementation of AnalyzerInterface.
type MockAnalyzer struct {
	mock.Mock
}

func (m *MockAnalyzer) GeneratePatch(ctx context.Context, report autofix.PostMortem) (*autofix.AnalysisResult, error) {
	args := m.Called(ctx, report)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*autofix.AnalysisResult), args.Error(1)
}

// MockDeveloper is a mock implementation of DeveloperInterface.
type MockDeveloper struct {
	mock.Mock
}

func (m *MockDeveloper) ValidateAndCommit(ctx context.Context, report autofix.PostMortem, analysis *autofix.AnalysisResult) error {
	args := m.Called(ctx, report, analysis)
	return args.Error(0)
}
