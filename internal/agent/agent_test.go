// File: internal/agent/agent_test.go
package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- Local Mocks to prevent import cycles --

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
	// Handle the (nil, nil) case specifically for testing that scenario.
	if args.Get(0) == nil && args.Error(1) == nil {
		return nil, nil
	}
	if result, ok := args.Get(0).(*ExecutionResult); ok {
		return result, args.Error(1)
	}
	return nil, args.Error(1)
}

// UpdateSessionProvider satisfies the ActionRegistry interface.
func (m *MockExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	m.Called(provider)
}

// MockEvolutionEngine mocks the EvolutionEngine interface.
type MockEvolutionEngine struct {
	mock.Mock
}

func (m *MockEvolutionEngine) Run(ctx context.Context, objective string, targetFiles []string) error {
	args := m.Called(ctx, objective, targetFiles)
	return args.Error(0)
}

// setupAgentTest initializes a complete agent with mocked dependencies.
// Note: MockLTM is defined in llm_mind_test.go and is available here.
func setupAgentTest(t *testing.T) (*Agent, *MockMind, *CognitiveBus, *MockExecutorRegistry, *mocks.MockHumanoidController, *mocks.MockKGClient, *mocks.MockLLMClient, *MockLTM, *MockEvolutionEngine, chan schemas.Finding) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mission := Mission{ID: "test-mission", Objective: "test-objective", ScanID: "test-scan"}

	// Mocks for all major components
	mockMind := new(MockMind)
	bus := NewCognitiveBus(logger, 50)
	mockExecutors := new(MockExecutorRegistry)
	mockHumanoid := new(mocks.MockHumanoidController)
	mockKG := new(mocks.MockKGClient)
	mockLLM := new(mocks.MockLLMClient)
	mockLTM := new(MockLTM)
	mockEvolution := new(MockEvolutionEngine)

	// Create a bidirectional channel for the test to read from.
	bidirectionalFindingsChan := make(chan schemas.Finding, 10)
	// Initialize GlobalContext (required by postObservation)
	// Use NewDefaultConfig() for realistic configuration structure
	cfg := config.NewDefaultConfig()
	globalCtx := &core.GlobalContext{
		Logger:       logger,
		Config:       cfg,
		FindingsChan: bidirectionalFindingsChan, // The agent will treat it as send-only.
		DBPool:       nil,                       // Explicitly nil for tests not needing DB
	}

	agent := &Agent{
		mission:    mission,
		logger:     logger,
		globalCtx:  globalCtx,
		mind:       mockMind,
		bus:        bus,
		executors:  mockExecutors,
		humanoid:   mockHumanoid,
		kg:         mockKG,
		llmClient:  mockLLM,
		ltm:        mockLTM,
		evolution:  mockEvolution,
		resultChan: make(chan MissionResult, 1),
	}

	t.Cleanup(func() {
		// Create a context for shutdown to avoid hanging
		_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		bus.Shutdown()
		// Safely drain the channel
		go func() {
			for range bidirectionalFindingsChan {
				// consume and discard
			}
		}()
		time.Sleep(10 * time.Millisecond) // give the drain goroutine a moment to start
		close(bidirectionalFindingsChan)
	})

	return agent, mockMind, bus, mockExecutors, mockHumanoid, mockKG, mockLLM, mockLTM, mockEvolution, bidirectionalFindingsChan
}

// TestNewGraphStoreFromConfig tests the factory function for GraphStore.
func TestNewGraphStoreFromConfig(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("InMemorySuccess", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "in-memory"}
		store, err := NewGraphStoreFromConfig(ctx, cfg, nil, logger)
		require.NoError(t, err)
		assert.NotNil(t, store)
	})

	t.Run("PostgresRequiresPool", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "postgres"}
		store, err := NewGraphStoreFromConfig(ctx, cfg, nil, logger)
		require.Error(t, err)
		assert.Nil(t, store)
		assert.Contains(t, err.Error(), "requires a valid database connection pool")
	})

	// Note: Testing Postgres success requires a real pgxpool.Pool, which is complex to mock fully.

	t.Run("UnknownType", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "invalid-type"}
		store, err := NewGraphStoreFromConfig(ctx, cfg, nil, logger)
		require.Error(t, err)
		assert.Nil(t, store)
		assert.Contains(t, err.Error(), "unknown knowledge_graph type specified")
	})
}

// TestNew_InitializationFailures tests the various failure paths during Agent initialization.
func TestNew_InitializationFailures(t *testing.T) {
	ctx := context.Background()
	mission := Mission{ID: "m1"}
	session := new(mocks.MockSessionContext)

	t.Run("KGFailure", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		agentCfg := cfg.Agent()
		agentCfg.KnowledgeGraph.Type = "invalid-type"
		globalCtx := &core.GlobalContext{
			Logger: zaptest.NewLogger(t),
			Config: cfg,
		}

		agent, err := New(ctx, mission, globalCtx, session)

		require.Error(t, err)
		assert.Nil(t, agent)
		assert.Contains(t, err.Error(), "failed to create knowledge graph store")
	})

	t.Run("LLMFailure", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		// This isolates the test to only the LLM initialization failure.
		originalNewGraphStore := NewGraphStoreFromConfig
		NewGraphStoreFromConfig = func(ctx context.Context, cfg config.KnowledgeGraphConfig, pool *pgxpool.Pool, logger *zap.Logger) (GraphStore, error) {
			return new(mocks.MockKGClient), nil // Return a mock KG successfully
		}
		t.Cleanup(func() { NewGraphStoreFromConfig = originalNewGraphStore })

		// Configure LLM with an invalid setup (e.g., empty models map) to force failure in llmclient.NewClient
		agentCfg := cfg.Agent()
		agentCfg.LLM.Models = map[string]config.LLMModelConfig{}
		agentCfg.LLM.DefaultPowerfulModel = "non-existent"
		globalCtx := &core.GlobalContext{
			Logger: zaptest.NewLogger(t),
			Config: cfg,
		}

		agent, err := New(ctx, mission, globalCtx, session)
		require.Error(t, err)
		assert.Nil(t, agent)
		assert.Contains(t, err.Error(), "failed to create LLM router for agent")
	})

	// Testing Self-Heal and Evolution initialization failures (they log errors but don't return error from New)
	t.Run("SelfHealInitializationFailure_LogsErrorButContinues", func(t *testing.T) {
		cfg := config.NewDefaultConfig()
		originalNewGraphStore := NewGraphStoreFromConfig
		NewGraphStoreFromConfig = func(ctx context.Context, cfg config.KnowledgeGraphConfig, pool *pgxpool.Pool, logger *zap.Logger) (GraphStore, error) {
			return new(mocks.MockKGClient), nil // Return a mock KG successfully
		}
		t.Cleanup(func() { NewGraphStoreFromConfig = originalNewGraphStore })

		autofixCfg := cfg.Autofix()
		// FIX: Mock the LLM client creation as well to completely isolate this test
		// to the SelfHealOrchestrator initialization logic.
		originalNewLLMClient := NewLLMClient
		NewLLMClient = func(cfg config.AgentConfig, logger *zap.Logger) (schemas.LLMClient, error) {
			return new(mocks.MockLLMClient), nil
		}
		t.Cleanup(func() { NewLLMClient = originalNewLLMClient })

		autofixCfg.Enabled = true // Get the autofix config struct
		t.Logf("Testing with Autofix.Enabled = %v", autofixCfg.Enabled)
		// Invalid config: MinConfidenceThreshold > 1.0 fails validation
		autofixCfg.MinConfidenceThreshold = 1.5 // Modify it
		t.Logf("Testing with Autofix.MinConfidenceThreshold = %v", autofixCfg.MinConfidenceThreshold)
		globalCtx := &core.GlobalContext{
			Logger: zaptest.NewLogger(t),
			Config: cfg,
		}

		agent, err := New(ctx, mission, globalCtx, session)
		require.NoError(t, err) // New succeeds
		require.NotNil(t, agent)
		assert.Nil(t, agent.selfHeal, "SelfHealOrchestrator should be nil on validation failure")
	})
}

// TestAgent_RunMission_Success verifies the happy path of a mission execution.
func TestAgent_RunMission_Success(t *testing.T) {
	agent, mockMind, _, _, _, _, _, mockLTM, _, _ := setupAgentTest(t)
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
	agent, mockMind, _, _, _, _, _, mockLTM, _, _ := setupAgentTest(t)
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

// TestAgent_RunMission_ContextCancellation verifies the agent stops gracefully when the context is cancelled.
func TestAgent_RunMission_ContextCancellation(t *testing.T) {
	agent, mockMind, _, _, _, mockKG, mockLLM, mockLTM, _, _ := setupAgentTest(t)
	// Create a context that we can cancel immediately.
	ctx, cancel := context.WithCancel(context.Background())

	// Set expectations
	mockMind.On("SetMission", agent.mission).Return().Once()
	// Mind.Start should run until the context passed to it (missionCtx) is cancelled.
	mockMind.On("Start", mock.Anything).Run(func(args mock.Arguments) {
		startCtx := args.Get(0).(context.Context)
		<-startCtx.Done() // Block until cancelled
	}).Return(context.Canceled).Once()
	mockMind.On("Stop").Return().Once()
	mockLTM.On("Start").Return().Once()

	// Expectations for concludeMission (called during cancellation)
	// Note: concludeMission uses the parent ctx if the missionCtx is done.
	mockKG.On("GetNode", mock.Anything, agent.mission.ID).Return(schemas.Node{}, nil).Once()
	mockKG.On("GetEdges", mock.Anything, agent.mission.ID).Return([]schemas.Edge{}, nil).Once()
	expectedSummary := "Mission cancelled summary."
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(expectedSummary, nil).Once()

	// Act
	var wg sync.WaitGroup
	wg.Add(1)
	var result *MissionResult
	var err error
	go func() {
		defer wg.Done()
		result, err = agent.RunMission(ctx)
	}()

	// Allow the agent to start up
	time.Sleep(100 * time.Millisecond)
	cancel() // Cancel the parent context, which propagates to missionCtx

	// Wait for RunMission to return
	wg.Wait()

	// Assert
	require.Error(t, err)
	// The error returned should be the error from the cancelled context (ctx.Err())
	assert.True(t, errors.Is(err, context.Canceled))
	require.NotNil(t, result, "A summary should still be generated on cancellation")
	assert.Equal(t, expectedSummary, result.Summary)

	mockMind.AssertExpectations(t)
	mockLTM.AssertExpectations(t)
	mockKG.AssertExpectations(t)
	mockLLM.AssertExpectations(t)
}

// TestAgent_ActionLoop verifies the correct dispatching of various action types.
func TestAgent_ActionLoop(t *testing.T) {
	// Helper to setup and run the action loop in the background
	setupActionLoop := func(t *testing.T) (*Agent, *CognitiveBus, context.CancelFunc, chan schemas.Finding) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		agent, _, bus, _, _, _, _, _, _, findingsChan := setupAgentTest(t)

		actionChan, unsubscribeActions := bus.Subscribe(MessageTypeAction)
		t.Cleanup(unsubscribeActions)

		agent.wg.Add(1)
		go agent.actionLoop(rootCtx, actionChan)

		// Ensure cleanup waits for the loop to finish
		t.Cleanup(func() {
			cancelRoot()
			agent.wg.Wait()
		})

		return agent, bus, cancelRoot, findingsChan
	}

	t.Run("ConcludeAction", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here

		mockMind := agent.mind.(*MockMind)
		mockMind.On("Stop").Return()
		mockKG := agent.kg.(*mocks.MockKGClient)
		mockLLM := agent.llmClient.(*mocks.MockLLMClient)

		mockKG.On("GetNode", mock.Anything, agent.mission.ID).Return(schemas.Node{}, nil).Once()
		mockKG.On("GetEdges", mock.Anything, agent.mission.ID).Return([]schemas.Edge{}, nil).Once()
		mockLLM.On("Generate", mock.Anything, mock.Anything).Return("Mission concluded.", nil).Once()

		// Act
		action := Action{Type: ActionConclude, Rationale: "Finished"}
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert
		select {
		case result := <-agent.resultChan:
			assert.Equal(t, "Mission concluded.", result.Summary)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for conclusion")
		}

		// Wait for the actionLoop goroutine to finish (it returns after conclude).
		agent.wg.Wait()
		mockMind.AssertExpectations(t)
	})

	t.Run("EvolveCodebaseAction", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here
		mockEvolution := agent.evolution.(*MockEvolutionEngine)

		obsChan, unsubObs := bus.Subscribe(MessageTypeObservation)
		defer unsubObs()

		action := Action{Type: ActionEvolveCodebase, Value: "Improve error handling"}
		// Expect the evolution engine to be called.
		mockEvolution.On("Run", mock.Anything, action.Value, mock.AnythingOfType("[]string")).Return(nil).Once()

		// Act
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg-evo", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
			obs, ok := msg.Payload.(Observation)
			require.True(t, ok)
			assert.Equal(t, "success", obs.Result.Status)
			assert.Equal(t, ObservedEvolutionResult, obs.Result.ObservationType)
			mockEvolution.AssertExpectations(t)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for EVOLVE_CODEBASE action to be processed")
		}
	})

	t.Run("ExecutorRegistryAction", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here
		mockExecutors := agent.executors.(*MockExecutorRegistry)

		action := Action{Type: ActionNavigate, Value: "http://test.com"}
		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()
		execResult := &ExecutionResult{Status: "success"}
		mockExecutors.On("Execute", mock.Anything, action).Return(execResult, nil).Once()

		// Act
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg) // Acknowledge the observation message
			mockExecutors.AssertExpectations(t)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for executor action to be processed")
		}
	})

	t.Run("ExecutorRawError", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here
		mockExecutors := agent.executors.(*MockExecutorRegistry)

		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		action := Action{Type: ActionClick}
		expectedErr := errors.New("raw execution error")
		// Executor returns a raw error (not a structured ExecutionResult)
		mockExecutors.On("Execute", mock.Anything, action).Return(nil, expectedErr).Once()

		// Act
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg-err", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
			obs, ok := msg.Payload.(Observation)
			require.True(t, ok)
			assert.Equal(t, "failed", obs.Result.Status)
			assert.Equal(t, ErrCodeExecutionFailure, obs.Result.ErrorCode)
			assert.Contains(t, obs.Result.ErrorDetails["message"], expectedErr.Error())
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for observation of raw error")
		}
	})

	// NEW: Test for invalid payload type on the action channel
	t.Run("InvalidPayloadType", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here

		// The goal is to verify that the actionLoop acknowledges and discards
		// an invalid message, then proceeds to process the next valid one.
		// This avoids a data race on the bus's internal waitgroup.

		// 1. Mock the executor for the *valid* action we'll send later.
		mockExecutors := agent.executors.(*MockExecutorRegistry)
		validAction := Action{Type: ActionNavigate, Value: "http://valid.com"}
		execResult := &ExecutionResult{Status: "success"}
		mockExecutors.On("Execute", mock.Anything, validAction).Return(execResult, nil).Once()

		// 2. Subscribe to observations to see the result of the valid action.
		obsChan, unsubObs := bus.Subscribe(MessageTypeObservation)
		defer unsubObs()

		// 3. Post the invalid message first.
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg-invalid", Type: MessageTypeAction, Payload: "not an action"})
		require.NoError(t, err)

		// 4. Post the valid message immediately after.
		err = bus.Post(context.Background(), CognitiveMessage{ID: "test-msg-valid", Type: MessageTypeAction, Payload: validAction})
		require.NoError(t, err)

		// 5. Assert that we receive an observation for the valid action.
		// This proves the loop didn't get stuck on the invalid message.
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
			mockExecutors.AssertExpectations(t)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for observation from valid action; loop may be blocked by invalid payload.")
		}
	})

	// NEW: Test for Executor returning (nil, nil)
	t.Run("ExecutorReturnsNilNil", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot() // No need for findingsChan here
		mockExecutors := agent.executors.(*MockExecutorRegistry)

		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		action := Action{Type: ActionClick}
		// Simulate a buggy executor returning (nil, nil)
		mockExecutors.On("Execute", mock.Anything, action).Return(nil, nil).Once()

		// Act
		err := bus.Post(context.Background(), CognitiveMessage{ID: "test-msg-nil", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert: Should receive a fallback error observation
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
			obs, ok := msg.Payload.(Observation)
			require.True(t, ok)
			assert.Equal(t, "failed", obs.Result.Status)
			assert.Equal(t, ErrCodeExecutionFailure, obs.Result.ErrorCode)
			assert.Contains(t, obs.Result.ErrorDetails["message"], "Internal Error: Action handler returned nil result.")
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for observation of nil/nil result")
		}
	})

	// NEW: Test for PerformComplexTask being dispatched to the executor
	t.Run("PerformComplexTaskAction_DispatchedToExecutor", func(t *testing.T) {
		agent, bus, cancelRoot, _ := setupActionLoop(t)
		defer cancelRoot()
		mockExecutors := agent.executors.(*MockExecutorRegistry)

		action := Action{Type: ActionPerformComplexTask, Value: "some complex task"}
		obsChan, unsub := bus.Subscribe(MessageTypeObservation)
		defer unsub()

		execResult := &ExecutionResult{Status: "success", ObservationType: ObservedSystemState}
		mockExecutors.On("Execute", mock.Anything, action).Return(execResult, nil).Once()

		// Act
		err := bus.Post(context.Background(), CognitiveMessage{ID: "complex-task-msg", Type: MessageTypeAction, Payload: action})
		require.NoError(t, err)

		// Assert
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
			mockExecutors.AssertExpectations(t)
		case <-time.After(2 * time.Second):
			t.Fatal("Timeout waiting for PerformComplexTask action to be dispatched to executor")
		}
	})
}

// TestExecuteEvolution covers the logic within the agent's evolution handler.
func TestExecuteEvolution(t *testing.T) {
	ctx := context.Background() // No need for findingsChan here

	t.Run("Success", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, mockEvolution, _ := setupAgentTest(t)
		action := Action{Type: ActionEvolveCodebase, Value: "Refactor tests"}
		mockEvolution.On("Run", mock.Anything, action.Value, []string(nil)).Return(nil).Once()

		result := agent.executeEvolution(ctx, action)

		require.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
		assert.Equal(t, ObservedEvolutionResult, result.ObservationType)
		mockEvolution.AssertExpectations(t)
	})

	t.Run("Failure", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, mockEvolution, _ := setupAgentTest(t)
		action := Action{Type: ActionEvolveCodebase, Value: "Implement feature X"}
		expectedErr := errors.New("evolution analysis failed")
		mockEvolution.On("Run", mock.Anything, action.Value, []string(nil)).Return(expectedErr).Once()

		result := agent.executeEvolution(ctx, action)

		require.NotNil(t, result)
		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeEvolutionFailure, result.ErrorCode)
		assert.Contains(t, result.ErrorDetails["message"], expectedErr.Error())
	})

	t.Run("Timeout", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, mockEvolution, _ := setupAgentTest(t)
		action := Action{Type: ActionEvolveCodebase, Value: "Complex task"}

		// Simulate a timeout by having Run return context.DeadlineExceeded
		mockEvolution.On("Run", mock.Anything, action.Value, []string(nil)).Return(context.DeadlineExceeded).Once()

		result := agent.executeEvolution(ctx, action)

		require.NotNil(t, result)
		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeTimeoutError, result.ErrorCode)
	})

	t.Run("DisabledFeature", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, _, _ := setupAgentTest(t)
		agent.evolution = nil // Simulate feature disabled or failed initialization
		action := Action{Type: ActionEvolveCodebase, Value: "Test"}

		result := agent.executeEvolution(ctx, action)

		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeFeatureDisabled, result.ErrorCode)
	})

	t.Run("MissingObjective", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, _, _ := setupAgentTest(t)
		action := Action{Type: ActionEvolveCodebase, Value: "", Metadata: map[string]interface{}{}}

		result := agent.executeEvolution(ctx, action)

		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeInvalidParameters, result.ErrorCode)
	})

	t.Run("ObjectiveInMetadata", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, mockEvolution, _ := setupAgentTest(t)
		objective := "Objective from metadata"
		action := Action{Type: ActionEvolveCodebase, Value: "", Metadata: map[string]interface{}{"objective": objective}}
		mockEvolution.On("Run", mock.Anything, objective, []string(nil)).Return(nil).Once()

		result := agent.executeEvolution(ctx, action)
		assert.Equal(t, "success", result.Status)
	})

	t.Run("TargetFilesParsing", func(t *testing.T) {
		agent, _, _, _, _, _, _, _, mockEvolution, _ := setupAgentTest(t)
		objective := "Test parsing"
		targetFiles := []string{"file1.go", "file2.go"}

		// Test with []string
		action1 := Action{Type: ActionEvolveCodebase, Value: objective, Metadata: map[string]interface{}{"target_files": targetFiles}}
		mockEvolution.On("Run", mock.Anything, objective, targetFiles).Return(nil).Once()
		agent.executeEvolution(ctx, action1)

		// Test with []interface{} (common after JSON unmarshal)
		targetFilesInterface := []interface{}{"fileA.go", "fileB.go", 123} // Include an invalid type
		expectedFilesInterface := []string{"fileA.go", "fileB.go"}         // Should filter invalid types
		action2 := Action{Type: ActionEvolveCodebase, Value: objective, Metadata: map[string]interface{}{"target_files": targetFilesInterface}}
		mockEvolution.On("Run", mock.Anything, objective, expectedFilesInterface).Return(nil).Once()
		agent.executeEvolution(ctx, action2)

		mockEvolution.AssertExpectations(t)
	})
}

// TestPostObservation_FindingsHandling verifies that findings generated by executors are processed by the agent.
func TestPostObservation_FindingsHandling(t *testing.T) {
	// We need the original bidirectional channel to read from it.
	// The agent setup returns all necessary components.
	agent, _, bus, _, _, _, _, _, _, bidirectionalFindingsChan := setupAgentTest(t)
	ctx := context.Background()

	action := Action{ID: "action-1", ScanID: "scan-1", MissionID: "mission-1"}
	finding1 := schemas.Finding{ID: "f1", TaskID: "task-A"}
	finding2 := schemas.Finding{ID: "f2"} // Missing TaskID and ScanID

	result := &ExecutionResult{
		Status:   "success",
		Findings: []schemas.Finding{finding1, finding2},
	}

	// Ensure the observation posted to the bus is acknowledged
	obsChan, unsub := bus.Subscribe(MessageTypeObservation)
	defer unsub()
	go func() {
		select {
		case msg := <-obsChan:
			bus.Acknowledge(msg)
		case <-time.After(2 * time.Second):
			// Timeout
		}
	}()

	// Act
	agent.postObservation(ctx, action, result)

	var received1, received2 schemas.Finding
	select {
	// Assert: Check the findings channel
	// Wait for findings to arrive on the bidirectional channel.
	case received1 = <-bidirectionalFindingsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for finding 1")
	}
	select {
	case received2 = <-bidirectionalFindingsChan:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for finding 2")
	}

	// Ensure the order is correct for assertion (postObservation iterates in order)
	if received1.ID != "f1" {
		received1, received2 = received2, received1
	}

	assert.Equal(t, "f1", received1.ID)
	assert.Equal(t, "task-A", received1.TaskID)
	assert.Equal(t, "scan-1", received1.ScanID) // Should be populated from action

	assert.Equal(t, "f2", received2.ID)
	assert.Equal(t, "action-1", received2.TaskID) // Should default to Action ID
	assert.Equal(t, "scan-1", received2.ScanID)   // Should be populated from action
}

// TestConcludeMission_FailurePaths tests error handling during mission conclusion.
func TestConcludeMission_FailurePaths(t *testing.T) {
	ctx := context.Background()

	t.Run("ContextGatheringFails", func(t *testing.T) {
		// FIX (Group 4): gatherMissionContext is resilient and does not return an error if KG calls fail;
		// it returns an empty/partial subgraph. Therefore, concludeMission proceeds to the LLM generation step.
		// The test must mock the LLM client to prevent a panic from an unmocked call.
		agent, _, _, _, _, mockKG, mockLLM, _, _, _ := setupAgentTest(t)
		expectedErr := errors.New("KG connection lost")
		// Mock GetNode (the first step in gatherMissionContext) to fail
		mockKG.On("GetNode", mock.Anything, agent.mission.ID).Return(schemas.Node{}, expectedErr).Once()

		// Mock the LLM call that follows the context gathering.
		expectedSummary := "Summary based on empty context."
		mockLLM.On("Generate", mock.Anything, mock.Anything).Return(expectedSummary, nil).Once()

		result, err := agent.concludeMission(ctx)
		require.NoError(t, err, "concludeMission should not fail even if context gathering has internal errors")
		require.NotNil(t, result)
		assert.Equal(t, expectedSummary, result.Summary)
	})

	t.Run("LLMGenerationFails", func(t *testing.T) {
		agent, _, _, _, _, mockKG, mockLLM, _, _, _ := setupAgentTest(t)
		// Mock successful context gathering
		mockKG.On("GetNode", mock.Anything, agent.mission.ID).Return(schemas.Node{}, nil).Once()
		mockKG.On("GetEdges", mock.Anything, agent.mission.ID).Return([]schemas.Edge{}, nil).Once()

		// Mock LLM failure
		expectedErr := errors.New("LLM API error")
		mockLLM.On("Generate", mock.Anything, mock.Anything).Return("", expectedErr).Once()

		result, err := agent.concludeMission(ctx)
		// concludeMission handles the LLM error internally and returns a fallback summary
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Summary, "AI failed to generate a summary")
	})
}

// TestGatherMissionContext_KGErrors verifies robustness when the KG returns errors during traversal.
func TestGatherMissionContext_KGErrors(t *testing.T) {
	agent, _, _, _, _, mockKG, _, _, _, _ := setupAgentTest(t)
	ctx := context.Background()
	missionID := agent.mission.ID
	nodeA := schemas.Node{ID: "A"}

	// Setup: Mission -> A, but retrieval of neighbors/edges might fail.
	edgeM_A := schemas.Edge{ID: "E1", From: missionID, To: "A"}

	// Scenario 1: GetNode fails for neighbor
	mockKG.On("GetNode", ctx, missionID).Return(schemas.Node{ID: missionID}, nil).Once()
	mockKG.On("GetEdges", ctx, missionID).Return([]schemas.Edge{edgeM_A}, nil).Once()
	mockKG.On("GetNode", ctx, "A").Return(schemas.Node{}, errors.New("Node A missing")).Once() // This call is correct

	subgraph, err := agent.gatherMissionContext(ctx, missionID)
	require.NoError(t, err)
	// Should contain Mission node and the edge E1, but not Node A.
	assert.Len(t, subgraph.Nodes, 1)
	assert.Len(t, subgraph.Edges, 1)

	// Scenario 2: GetEdges fails for node
	mockKG.ExpectedCalls = nil // Reset mocks
	mockKG.On("GetNode", ctx, missionID).Return(schemas.Node{ID: missionID}, nil).Once()
	mockKG.On("GetEdges", ctx, missionID).Return([]schemas.Edge{edgeM_A}, nil).Once()
	mockKG.On("GetNode", ctx, "A").Return(nodeA, nil).Once()
	mockKG.On("GetEdges", ctx, "A").Return(nil, errors.New("Edges for A failed")).Once()

	subgraph, err = agent.gatherMissionContext(ctx, missionID)
	require.NoError(t, err)
	// Should contain Mission, Node A, and the edge E1.
	assert.Len(t, subgraph.Nodes, 2)
	assert.Len(t, subgraph.Edges, 1)

	mockKG.AssertExpectations(t)
}
