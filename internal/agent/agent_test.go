package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/core"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// MockMind mocks the Mind interface.
type MockMind struct {
	mock.Mock
}

func (m *MockMind) SetMission(mission Mission) {
	m.Called(mission)
}

func (m *MockMind) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMind) Stop() {
	m.Called()
}

// MockBus mocks the CognitiveBus interface.
type MockBus struct {
	mock.Mock
}

func (m *MockBus) Post(ctx context.Context, msg CognitiveMessage) error {
	args := m.Called(ctx, msg)
	return args.Error(0)
}

func (m *MockBus) Subscribe(ctx context.Context, msgType MessageType) (<-chan CognitiveMessage, error) {
	args := m.Called(ctx, msgType)
	return args.Get(0).(<-chan CognitiveMessage), args.Error(1)
}

func (m *MockBus) Acknowledge(msg CognitiveMessage) {
	m.Called(msg)
}

func (m *MockBus) Shutdown() {
	m.Called()
}

// MockExecutorRegistry mocks the ExecutorRegistry interface.
type MockExecutorRegistry struct {
	mock.Mock
}

func (m *MockExecutorRegistry) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	args := m.Called(ctx, action)
	return args.Get(0).(*ExecutionResult), args.Error(1)
}

// UpdateSessionProvider satisfies the ActionRegistry interface.
func (m *MockExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	m.Called(provider)
}

// UpdateHumanoidProvider satisfies the ActionRegistry interface.
func (m *MockExecutorRegistry) UpdateHumanoidProvider(provider HumanoidProvider) {
	m.Called(provider)
}

// MockEvolutionEngine mocks the EvolutionEngine interface.
type MockEvolutionEngine struct {
	mock.Mock
}

func (m *MockEvolutionEngine) AnalyzeAndImprove(ctx context.Context, goal string, bus CognitiveBus) error {
	args := m.Called(ctx, goal, bus)
	return args.Error(0)
}

// setupAgentTest initializes an Agent with mocked dependencies for testing.
func setupAgentTest(t *testing.T) (*Agent, *MockMind, *MockBus, *MockExecutorRegistry, *mocks.MockSessionContext, *mocks.MockKGClient, *mocks.MockLLMClient, *mocks.MockLTM, *MockEvolutionEngine, *config.Config) {
	logger := zap.NewNop()
	cfg := config.NewDefaultConfig()
	globalCtx := &core.GlobalContext{
		Logger: logger,
		Config: cfg,
		Ctx:    context.Background(),
	}

	mockMind := new(MockMind)
	mockBus := new(MockBus)
	mockExecutors := new(MockExecutorRegistry)
	mockSession := new(mocks.MockSessionContext)
	mockKG := new(mocks.MockKGClient)
	mockLLM := new(mocks.MockLLMClient)
	mockLTM := new(mocks.MockLTM)
	mockEvolution := new(MockEvolutionEngine)

	// Default mock behaviors
	mockLTM.On("Run", mock.Anything).Return()
	mockBus.On("Shutdown").Return()

	agent := &Agent{
		mission:           Mission{ID: "test-mission", Objective: "test objective"},
		logger:            logger,
		globalCtx:         globalCtx,
		mind:              mockMind,
		bus:               mockBus,
		executors:         mockExecutors,
		kg:                mockKG,
		llmClient:         mockLLM,
		ltm:               mockLTM,
		evolution:         mockEvolution,
		resultChan:        make(chan MissionResult, 1),
		responseListeners: make(map[string]chan string),
	}

	t.Cleanup(func() {
		// Verify that all expected calls on the mocks were made.
		mock.AssertExpectationsForObjects(t, mockMind, mockBus, mockExecutors, mockSession, mockKG, mockLLM, mockLTM, mockEvolution)
	})

	return agent, mockMind, mockBus, mockExecutors, mockSession, mockKG, mockLLM, mockLTM, mockEvolution, cfg
}

// TestNew_Success verifies that a new agent can be created successfully with all components.
func TestNew_Success(t *testing.T) {
	// Arrange
	ctx := context.Background()
	mission := Mission{ID: "m1"}
	session := new(mocks.MockSessionContext)
	cfg := config.NewDefaultConfig()
	cfg.KnowledgeGraph.Enabled = false // Disable KG to simplify setup
	globalCtx := &core.GlobalContext{
		Logger: zap.NewNop(),
		Config: cfg,
	}

	// Act
	agent, err := New(ctx, &mission, globalCtx, session)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, agent)
	assert.Equal(t, mission.ID, agent.mission.ID)
	assert.NotNil(t, agent.logger)
	assert.NotNil(t, agent.mind)
	assert.NotNil(t, agent.bus)
	assert.NotNil(t, agent.executors)
	assert.NotNil(t, agent.llmClient)
	assert.NotNil(t, agent.ltm)
}

// TestNew_InitializationFailures tests the various failure paths during Agent initialization.
func TestNew_InitializationFailures(t *testing.T) {

	// Helper to create a mission pointer
	newMissionPtr := func(id string) *Mission {
		m := Mission{ID: id}
		return &m
	}

	t.Run("KGFailure", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		cfg.KnowledgeGraph.Enabled = true
		cfg.KnowledgeGraph.URL = "invalid-url"
		globalCtx := &core.GlobalContext{
			Logger: zap.NewNop(),
			Config: cfg,
		}

		testAgent, err := New(context.Background(), newMissionPtr("m1"), globalCtx, nil)

		require.Error(t, err)
		assert.Nil(t, testAgent)
		assert.Contains(t, err.Error(), "failed to create knowledge graph store")
	})

	t.Run("LLMRouterFailure", func(t *testing.T) {
		// This test simulates a failure in creating the LLM router.
		// We can achieve this by providing an invalid configuration that the router constructor will reject.
		cfg := config.NewDefaultConfig()
		// Example of an invalid config: enabling a provider but not providing the key
		cfg.LLM.Providers.Gemini.Enabled = true
		cfg.LLM.Providers.Gemini.APIKey = ""
		// Mock the factory to return an error
		origFactory := llmclient.NewClient
		llmclient.NewClient = func(ctx context.Context, providerCfg config.ProviderConfig, logger *zap.Logger) (schemas.LLMClient, error) {
			return nil, errors.New("forced LLM client creation error")
		}
		defer func() { llmclient.NewClient = origFactory }()

		globalCtx := &core.GlobalContext{
			Logger: zap.NewNop(),
			Config: cfg,
		}

		testAgent, err := New(context.Background(), newMissionPtr("m1"), globalCtx, nil)
		require.Error(t, err)
		assert.Nil(t, testAgent)
		assert.Contains(t, err.Error(), "failed to create LLM router for agent")
	})

	t.Run("SelfHealInitFailure", func(t *testing.T) {
		// Self-heal initialization can fail if its configuration is invalid.
		// For example, if the log file path is not provided when the log strategy is enabled.
		cfg := config.NewDefaultConfig()
		cfg.Autofix.Enabled = true
		cfg.Autofix.Watch.Enabled = true
		cfg.Autofix.Watch.Strategies.LogFile.Enabled = true
		cfg.Autofix.Watch.Strategies.LogFile.Path = "" // Invalid config

		globalCtx := &core.GlobalContext{
			Logger: zap.NewNop(),
			Config: cfg,
		}

		testAgent, err := New(context.Background(), newMissionPtr("m1"), globalCtx, nil)
		require.NoError(t, err) // New succeeds
		require.NotNil(t, testAgent)
		assert.Nil(t, testAgent.selfHeal, "SelfHealOrchestrator should be nil on validation failure")
	})
}

// TestAgent_RunMission_Success verifies the happy path of a mission execution.
func TestAgent_RunMission_Success(t *testing.T) {
	testAgent, mockMind, _, _, _, _, _, mockLTM, _, _ := setupAgentTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Set expectations for all required components
	mockMind.On("SetMission", testAgent.mission).Return().Once()
	mockMind.On("Start", mock.Anything).Return(nil).Once()
	// Stop is only called if the main context is cancelled now.
	mockMind.On("Stop").Return().Maybe()
	mockLTM.On("Run", mock.Anything).Return().Once() // Expect LTM to be started

	expectedResult := MissionResult{Summary: "Mission accomplished"}

	// Start the agent loop in a goroutine as it now blocks.
	go testAgent.Start(ctx)

	// Simulate the mission finishing
	go func() {
		time.Sleep(50 * time.Millisecond)
		testAgent.finish(ctx, expectedResult)
	}()

	// Wait for the result to be processed by the Start loop
	var result *MissionResult
	select {
	case res := <-testAgent.resultChan:
		result = &res
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for mission result")
	}

	assert.Equal(t, expectedResult.Summary, result.Summary)

	// Verify the agent is still running (state should be reset)
	assert.Empty(t, testAgent.GetMission().ID, "Mission ID should be reset after completion")

	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t) // Verify LTM mock expectations
}

// TestAgent_RunMission_MindFailure verifies the agent fails fast if the Mind fails to start.
func TestAgent_RunMission_MindFailure(t *testing.T) {
	// Arrange
	testAgent, mockMind, _, _, _, _, _, mockLTM, _, _ := setupAgentTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mindError := errors.New("cognitive failure")

	mockMind.On("SetMission", testAgent.mission).Return().Once()
	mockMind.On("Start", mock.Anything).Return(mindError).Once()
	mockMind.On("Stop").Return()              // Stop is now called on startup failure path
	mockLTM.On("Run", mock.Anything).Return() // LTM start is called before mind start

	// Act: Run the mission. We expect it to fail immediately.
	// Start blocks, so we run it and expect it to return the error quickly.
	err := testAgent.Start(ctx)

	// Assert: The error from mind.Start should be propagated.
	require.Error(t, err, "Expected an error because the mind failed to start")
	assert.ErrorIs(t, err, mindError, "The specific error from the mind should be wrapped and returned")

	// Verify that all expected mock calls were made.
	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t)
}

// TestAgent_Start_ContextCancellation verifies the agent stops gracefully when the context is cancelled.
func TestAgent_RunMission_ContextCancellation(t *testing.T) {
	testAgent, mockMind, _, _, _, mockKG, mockLLM, mockLTM, _, _ := setupAgentTest(t)
	// Create a context that we can cancel immediately.
	ctx, cancel := context.WithCancel(context.Background())

	// Set expectations
	mockMind.On("SetMission", testAgent.mission).Return().Once()
	// Mind.Start should run until the context passed to it (missionCtx) is cancelled.
	mockMind.On("Start", mock.Anything).Run(func(args mock.Arguments) {
		startCtx := args.Get(0).(context.Context)
		<-startCtx.Done() // Wait for cancellation
	}).Return(nil).Once()
	mockMind.On("Stop").Return().Once()
	mockLTM.On("Run", mock.Anything).Return().Once()

	// Expectations for concludeMission (called during cancellation)
	// Note: concludeMission uses the parent ctx if the missionCtx is done.
	mockKG.On("Export", mock.Anything).Return(map[string]interface{}{"key": "value"}, nil).Once()
	expectedSummary := "Mission cancelled summary."
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(schemas.GenerationResponse{Text: expectedSummary}, nil).Once()

	// Act
	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		// Start returns when the context is cancelled.
		err = testAgent.Start(ctx)
	}()

	// Allow the agent to start up
	time.Sleep(50 * time.Millisecond)
	// Cancel the root context, which should trigger the shutdown sequence.
	cancel()
	wg.Wait() // Wait for the agent to fully stop.

	// Assert
	require.Error(t, err)
	// The error returned should be the error from the cancelled context (ctx.Err())
	// We cannot easily verify the summary generated during shutdown without observing the KG or logs,
	// as Start() returns and the summary generation happens in a background context.
	assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))

	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t)
	mockKG.AssertExpectations(t)
	mockLLM.AssertExpectations(t)
}

// setupActionLoop is a helper to test the agent's action loop in isolation.
func setupActionLoop(t *testing.T) (*Agent, *MockBus, context.CancelFunc, chan<- CognitiveMessage) {
	agent, _, bus, executors, _, kg, llm, _, evolution, _ := setupAgentTest(t)
	rootCtx, cancelRoot := context.WithCancel(context.Background())

	// Create a real channel for actions
	actionChan := make(chan CognitiveMessage, 1)

	// Mock the bus subscription
	bus.On("Subscribe", mock.Anything, MessageTypeAction).Return((<-chan CognitiveMessage)(actionChan), nil)
	bus.On("Acknowledge", mock.Anything).Return()
	bus.On("Post", mock.Anything, mock.Anything).Return(nil) // For observations

	// Mock executors and other dependencies as needed for specific tests
	executors.On("Execute", mock.Anything, mock.Anything).Return(&ExecutionResult{}, nil).Maybe()
	kg.On("GetNode", mock.Anything, mock.Anything).Return(schemas.Node{}, nil).Maybe()
	kg.On("GetEdges", mock.Anything, mock.Anything).Return([]schemas.Edge{}, nil).Maybe()
	kg.On("Export", mock.Anything).Return(map[string]interface{}{}, nil).Maybe()
	llm.On("Generate", mock.Anything, mock.Anything).Return(schemas.GenerationResponse{Text: "Mission concluded."}, nil).Maybe()
	evolution.On("AnalyzeAndImprove", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Start the action loop in a goroutine
	agent.wg.Add(1)
	go agent.actionLoop(rootCtx, actionChan)

	t.Cleanup(func() {
		cancelRoot()      // Ensure the loop terminates
		agent.wg.Wait()   // Wait for the loop to finish
		close(actionChan) // Clean up the channel
	})

	return agent, bus, cancelRoot, actionChan
}

// TestAgent_ActionLoop verifies that the agent correctly processes actions from the bus.
func TestAgent_ActionLoop(t *testing.T) {
	// Define a standard action for tests
	baseAction := Action{
		ID:        uuid.New().String(),
		MissionID: "test-mission",
		Type:      ActionBrowseURL,
		Value:     "http://example.com",
	}

	t.Run("ConcludeAction", func(t *testing.T) {
		testAgent, bus, cancelRoot, actionChan := setupActionLoop(t)
		defer cancelRoot()

		mockKG := testAgent.kg.(*mocks.MockKGClient)
		mockLLM := testAgent.llmClient.(*mocks.MockLLMClient)

		mockKG.On("Export", mock.Anything).Return(map[string]interface{}{}, nil).Once()
		mockLLM.On("Generate", mock.Anything, mock.Anything).Return(schemas.GenerationResponse{Text: "Mission concluded."}, nil).Once()

		// Act
		action := baseAction
		action.Type = ActionConclude
		actionChan <- CognitiveMessage{Type: MessageTypeAction, Payload: action}

		// Assert
		select {
		case result := <-testAgent.resultChan:
			assert.Equal(t, "Mission concluded.", result.Summary)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for conclusion")
		}

		// The action loop should still be running (wg not done yet).
		// We rely on the cancelRoot() in defer/cleanup to stop the loop.
	})

	t.Run("EvolveCodebaseAction", func(t *testing.T) {
		agent, bus, cancelRoot, actionChan := setupActionLoop(t)
		defer cancelRoot()

		mockEvolution := agent.evolution.(*MockEvolutionEngine)
		goal := "Refactor the agent to be more modular."
		mockEvolution.On("AnalyzeAndImprove", mock.Anything, goal, bus).Return(nil).Once()

		// Act
		action := baseAction
		action.Type = ActionEvolveCodebase
		action.Value = goal
		actionChan <- CognitiveMessage{Type: MessageTypeAction, Payload: action}

		// Assert: Wait for the mock to be called.
		// We need to give the goroutine in executeEvolution a moment to run.
		assert.Eventually(t, func() bool {
			mockEvolution.AssertExpectations(t)
			return true
		}, 1*time.Second, 50*time.Millisecond)

		// Also verify that an observation was posted back to the bus
		bus.AssertCalled(t, "Post", mock.Anything, mock.MatchedBy(func(msg CognitiveMessage) bool {
			obs, ok := msg.Payload.(Observation)
			return ok && obs.ActionID == action.ID && obs.Result.Status == "success"
		}))
	})

	t.Run("UnknownAction", func(t *testing.T) {
		agent, bus, cancelRoot, actionChan := setupActionLoop(t)
		defer cancelRoot()

		mockExecutors := agent.executors.(*MockExecutorRegistry)
		expectedResult := &ExecutionResult{Status: "success", Data: map[string]interface{}{"title": "Example Domain"}}
		mockExecutors.On("Execute", mock.Anything, baseAction).Return(expectedResult, nil).Once()

		// Act
		actionChan <- CognitiveMessage{Type: MessageTypeAction, Payload: baseAction}

		// Assert
		// Verify that the bus received the resulting observation.
		assert.Eventually(t, func() bool {
			bus.AssertCalled(t, "Post", mock.Anything, mock.MatchedBy(func(msg CognitiveMessage) bool {
				obs, ok := msg.Payload.(Observation)
				return ok && obs.ActionID == baseAction.ID && obs.Result.Status == "success"
			}))
			return true
		}, 1*time.Second, 50*time.Millisecond)
	})
}
