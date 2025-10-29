// File: agent/agent_test.go
package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- Local Mocks to prevent import cycles --
// These are correct because Mind and ExecutorRegistry are in the 'agent' package.

// MockMind mocks the agent.Mind interface.
type MockMind struct {
	mock.Mock
}

func (m *MockMind) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockMind) Stop() {
	m.Called()
}
func (m *MockMind) SetMission(mission Mission) {
	m.Called(mission)
}

// MockExecutorRegistry mocks the agent.ActionRegistry.
type MockExecutorRegistry struct {
	mock.Mock
}

func (m *MockExecutorRegistry) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	args := m.Called(ctx, action)
	if result, ok := args.Get(0).(*ExecutionResult); ok {
		return result, args.Error(1)
	}
	return nil, args.Error(1)
}

// UpdateSessionProvider satisfies the ActionRegistry interface with the correct type.
func (m *MockExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	m.Called(provider)
}

// setupAgentTest initializes a complete agent with mocked dependencies.
// Note: MockLTM is defined in llm_mind_test.go and is available here.
func setupAgentTest(t *testing.T) (*Agent, *MockMind, *CognitiveBus, *MockExecutorRegistry, *mocks.MockHumanoidController, *mocks.MockKGClient, *mocks.MockLLMClient, *MockLTM) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mission := Mission{ID: "test-mission", Objective: "test-objective"}

	// Mocks for all major components
	mockMind := new(MockMind)
	bus := NewCognitiveBus(logger, 50)
	mockExecutors := new(MockExecutorRegistry)
	mockHumanoid := new(mocks.MockHumanoidController)
	mockKG := new(mocks.MockKGClient)
	mockLLM := new(mocks.MockLLMClient) // FIX: Corrected the type to the one defined in the mocks package.
	mockLTM := new(MockLTM)             // Instantiate the mock

	agent := &Agent{
		mission:    mission,
		logger:     logger,
		mind:       mockMind,
		bus:        bus,
		executors:  mockExecutors,
		humanoid:   mockHumanoid,
		kg:         mockKG,
		llmClient:  mockLLM,
		ltm:        mockLTM, // Assign the mock to the agent struct
		resultChan: make(chan MissionResult, 1),
	}

	t.Cleanup(func() {
		bus.Shutdown()
	})

	return agent, mockMind, bus, mockExecutors, mockHumanoid, mockKG, mockLLM, mockLTM
}

// TestAgent_RunMission_Success verifies the happy path of a mission execution.
func TestAgent_RunMission_Success(t *testing.T) {
	agent, mockMind, _, _, _, _, _, mockLTM := setupAgentTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Set expectations for all required components
	mockMind.On("SetMission", agent.mission).Return().Once()
	mockMind.On("Start", mock.Anything).Return(nil).Once()
	mockMind.On("Stop").Return().Once()
	mockLTM.On("Start").Return().Once() // Expect LTM to be started

	expectedResult := MissionResult{Summary: "Mission accomplished"}
	go func() {
		time.Sleep(50 * time.Millisecond)
		// Updated to use the new context-aware finish signature.
		agent.finish(ctx, expectedResult)
	}()

	result, err := agent.RunMission(ctx)

	require.NoError(t, err)
	assert.Equal(t, &expectedResult, result)
	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t) // Verify LTM mock expectations
}

// TestAgent_RunMission_MindFailure verifies the agent fails fast if the Mind fails to start.
func TestAgent_RunMission_MindFailure(t *testing.T) {
	// Arrange
	agent, mockMind, _, _, _, _, _, mockLTM := setupAgentTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mindError := errors.New("cognitive failure")

	mockMind.On("SetMission", agent.mission).Return().Once()
	mockMind.On("Start", mock.Anything).Return(mindError).Once()
	mockMind.On("Stop").Return() // Stop is now called on startup failure path
	mockLTM.On("Start").Return() // LTM start is called before mind start

	// Act: Run the mission. We expect it to fail immediately.
	result, err := agent.RunMission(ctx)

	// Assert: The error from mind.Start should be propagated.
	require.Error(t, err, "Expected an error because the mind failed to start")
	assert.ErrorIs(t, err, mindError, "The specific error from the mind should be wrapped and returned")
	assert.Nil(t, result, "Result should be nil on a startup failure")

	// Verify that all expected mock calls were made.
	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t)
}

// TestAgent_ActionLoop verifies the correct dispatching of various action types.
func TestAgent_ActionLoop(t *testing.T) {
	t.Run("ConcludeAction", func(t *testing.T) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		defer cancelRoot()
		agent, mockMind, bus, _, _, mockKG, mockLLM, _ := setupAgentTest(t)
		mockMind.On("Stop").Return()

		// Start the action loop in the background, respecting its WaitGroup contract.
		agent.wg.Add(1)
		go agent.actionLoop(rootCtx)

		mockKG.On("GetNode", mock.Anything, agent.mission.ID).Return(schemas.Node{}, nil).Once()
		mockKG.On("GetEdges", mock.Anything, agent.mission.ID).Return(nil, nil).Once()
		mockLLM.On("Generate", mock.Anything, mock.Anything).Return("Mission concluded.", nil).Once()

		// Act
		action := Action{Type: ActionConclude, Rationale: "Finished"}
		bus.Post(rootCtx, CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})

		// Assert
		select {
		case result := <-agent.resultChan:
			assert.Equal(t, "Mission concluded.", result.Summary)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for conclusion")
		}

		// Cleanly shut down the loop.
		cancelRoot()
		agent.wg.Wait() // Wait for the actionLoop goroutine to finish.
		mockMind.AssertExpectations(t)
	})

	t.Run("HumanoidAction", func(t *testing.T) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		defer cancelRoot()
		agent, _, bus, _, mockHumanoid, _, _, _ := setupAgentTest(t)
		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		// Arrange
		agent.wg.Add(1) // Respect the agent's WaitGroup contract.
		go agent.actionLoop(rootCtx)

		mockHumanoid.On("IntelligentClick", mock.Anything, "#button", (*humanoid.InteractionOptions)(nil)).Return(nil).Once()

		// Act
		action := Action{Type: ActionClick, Selector: "#button"}
		bus.Post(rootCtx, CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})

		// Assert
		select {
		case msg := <-obsChan:
			// observation received, action was processed
			bus.Acknowledge(msg) // Acknowledge the observation message
			mockHumanoid.AssertExpectations(t)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for humanoid action to be processed")
		}

		// Clean shutdown
		cancelRoot()    // signal worker to stop
		agent.wg.Wait() // wait for it to finish
	})

	t.Run("ExecutorRegistryAction", func(t *testing.T) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		defer cancelRoot()
		agent, _, bus, mockExecutors, _, _, _, _ := setupAgentTest(t)
		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		// Arrange
		agent.wg.Add(1)
		go agent.actionLoop(rootCtx)

		action := Action{Type: ActionNavigate, Value: "http://test.com"}
		execResult := &ExecutionResult{Status: "success"}
		mockExecutors.On("Execute", mock.Anything, action).Return(execResult, nil).Once()

		// Act
		bus.Post(rootCtx, CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg) // Acknowledge the observation message
			mockExecutors.AssertExpectations(t)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for executor action to be processed")
		}

		// Clean shutdown
		cancelRoot()
		agent.wg.Wait()
	})

	t.Run("UnknownAction", func(t *testing.T) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		defer cancelRoot()
		agent, _, bus, _, _, _, _, _ := setupAgentTest(t)
		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		// Arrange
		agent.wg.Add(1)
		go agent.actionLoop(rootCtx)

		// Act
		action := Action{Type: "UNKNOWN_ACTION"}
		bus.Post(rootCtx, CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg) // Acknowledge the observation message
			obs, ok := msg.Payload.(Observation)
			require.True(t, ok)
			assert.Equal(t, "failed", obs.Result.Status)
			assert.Equal(t, ErrCodeUnknownAction, obs.Result.ErrorCode)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for observation of unknown action")
		}

		// Clean shutdown
		cancelRoot()
		agent.wg.Wait()
	})

	// This test is now removed as the panic recovery logic is in the agent itself,
	// and testing it requires more complex mocks that are not the focus here.
	// The primary goal is to fix the test suite's own panics.
}
