
// internal/mocks/self_heal_orchestrator_mock.go
package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockSelfHealOrchestrator is a mock implementation of SelfHealOrchestrator.
type MockSelfHealOrchestrator struct {
	mock.Mock
}

func (m *MockSelfHealOrchestrator) Start(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockSelfHealOrchestrator) WaitForShutdown() {
	m.Called()
}
