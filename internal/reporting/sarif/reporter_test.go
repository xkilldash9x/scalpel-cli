// internal/reporting/reporter_test.go
package reporting_test

import (
	"testing"
    "errors"

	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
    // Removed import of github.com/xkilldash9x/scalpel-cli/internal/reporting/sarif
)

// MockReporter implements the Reporter interface for testing purposes.
type MockReporter struct {
	name          string
	GenerateFunc func(findings []schemas.Finding) ([]byte, error)
}

func (m *MockReporter) Name() string {
	return m.name
}

func (m *MockReporter) GenerateReport(findings []schemas.Finding) ([]byte, error) {
	if m.GenerateFunc != nil {
		return m.GenerateFunc(findings)
	}
	return nil, errors.New("MockReporter GenerateFunc not configured")
}

// TestRegisterAndGetReporter tests the registry functionality without relying on concrete implementations.
func TestRegisterAndGetReporter(t *testing.T) {
	// Assuming this tests a global or package-level registry.

	mockName := "mock_test_format"
	mock := &MockReporter{name: mockName}
	reporting.RegisterReporter(mock)

	reporter, err := reporting.GetReporter(mockName)
	assert.NoError(t, err)
	assert.Equal(t, mock, reporter)

	_, err = reporting.GetReporter("nonexistent_format")
	assert.Error(t, err)
}