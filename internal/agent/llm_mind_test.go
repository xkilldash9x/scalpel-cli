// File: internal/agent/llm_mind_test.go
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// mockUUIDGenerator replaces the UUID generator with a function that returns
// a predictable sequence of IDs. This is crucial for making tests deterministic.
func mockUUIDGenerator(t *testing.T, ids ...string) {
	t.Helper()
	// Increased buffer for safety in complex tests
	idChan := make(chan string, len(ids)+10)
	for _, id := range ids {
		idChan <- id
	}
	// Closing the channel allows us to detect exhaustion reliably.
	close(idChan)

	// Store original function
	originalUUIDNewString := uuidNewString

	// Check if the channel is empty when called, prevents tests from hanging if not enough IDs are provided.
	uuidNewString = func() string {
		id, ok := <-idChan
		if !ok {
			// FIX: Fail the test if we run out of IDs. Using t.Fatalf in a goroutine causes issues.
			// We log the error and panic instead, which allows the Mind's recovery mechanisms (or the test runner) to handle it gracefully.
			t.Logf("CRITICAL: mockUUIDGenerator ran out of IDs. Stack:\n%s", debug.Stack())
			panic("mockUUIDGenerator ran out of IDs.")
		}
		return id
	}
	t.Cleanup(func() { uuidNewString = originalUUIDNewString })
}

// -- Test Setup Helper --
// -- LTM Mock --

// MockLTM mocks the long-term memory interface.
type MockLTM struct {
	mock.Mock
}

// ProcessAndFlagObservation mocks the processing of an observation.
func (m *MockLTM) ProcessAndFlagObservation(ctx context.Context, obs Observation) map[string]bool {
	args := m.Called(ctx, obs)

	// Safely get the return value, returning nil if not configured in the test.
	if val := args.Get(0); val != nil {
		if asMap, ok := val.(map[string]bool); ok {
			return asMap
		}
	}
	return nil
}

// Start mocks the startup process for the LTM.
func (m *MockLTM) Start() {
	m.Called()
}

// Stop mocks the cleanup/shutdown process.
func (m *MockLTM) Stop() {
	m.Called()
}

// setupLLMMind initializes the LLMMind and its dependencies for testing.
// Optionally accepts configuration modifier functions.
func setupLLMMind(t *testing.T, cfgModifiers ...func(*config.AgentConfig)) (*LLMMind, *mocks.MockLLMClient, *mocks.MockKGClient, *MockLTM, *CognitiveBus) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mockLLM := new(mocks.MockLLMClient)
	mockKG := new(mocks.MockKGClient)
	mockLTM := new(MockLTM)
	// Use a real CognitiveBus to properly test the integration of the OODA loop.
	bus := NewCognitiveBus(logger, 50)

	// A default configuration for our tests.
	cfg := config.AgentConfig{
		LLM: config.LLMRouterConfig{
			DefaultPowerfulModel: "test-model",
			Models:               map[string]config.LLMModelConfig{"test-model": {Model: "test-model"}},
		},
		Evolution: config.EvolutionConfig{
			Enabled: false, // Default to disabled for most tests
		},
	}

	// Apply configuration modifications if provided.
	for _, modifier := range cfgModifiers {
		modifier(&cfg)
	}

	// The Stop method is called during cleanup, so we'll set a standing expectation for it.
	mockLTM.On("Stop").Return().Maybe()

	mind := NewLLMMind(logger, mockLLM, cfg, mockKG, bus, mockLTM)

	// Make sure all our resources are cleaned up when the test is done.
	t.Cleanup(func() {
		mind.Stop()
		bus.Shutdown()
	})

	return mind, mockLLM, mockKG, mockLTM, bus
}

// -- Test Cases: Initialization and State Management (Coverage Increase) --

// TestLLMMind_UpdateState verifies the OODA state machine rules.
func TestLLMMind_UpdateState(t *testing.T) {
	mind, _, _, _, _ := setupLLMMind(t)

	// Initial state is INITIALIZING.
	assert.Equal(t, StateInitializing, mind.currentState)

	// Valid transition
	mind.updateState(StateObserving)
	assert.Equal(t, StateObserving, mind.currentState)

	// Idempotency check
	mind.updateState(StateObserving)
	assert.Equal(t, StateObserving, mind.currentState)

	// Transition to terminal state: COMPLETED
	mind.updateState(StateCompleted)
	assert.Equal(t, StateCompleted, mind.currentState)

	// Attempt to transition out of terminal state (should be ignored)
	mind.updateState(StateObserving)
	assert.Equal(t, StateCompleted, mind.currentState)

	// Reset for testing FAILED state
	mind2, _, _, _, _ := setupLLMMind(t)
	mind2.updateState(StateDeciding)
	assert.Equal(t, StateDeciding, mind2.currentState)

	mind2.updateState(StateFailed)
	assert.Equal(t, StateFailed, mind2.currentState)

	// Attempt to transition out of FAILED (should be ignored)
	mind2.updateState(StateObserving)
	assert.Equal(t, StateFailed, mind2.currentState)
}

// NEW: TestLLMMind_SetMission_KGFailure verifies failure path during mission setup.
func TestLLMMind_SetMission_KGFailure(t *testing.T) {
	mind, _, mockKG, _, _ := setupLLMMind(t)
	missionID := "mission-fail"

	// Mock GetNode to simulate node not existing
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{}, errors.New("not found")).Once()
	// Mock AddNode to fail
	expectedErr := errors.New("KG connection failed")
	mockKG.On("AddNode", mock.Anything, mock.Anything).Return(expectedErr).Once()

	// Act
	mind.SetMission(Mission{ID: missionID})

	// Assert
	assert.Equal(t, StateFailed, mind.currentState, "Mind should transition to FAILED if mission node cannot be created")
	mockKG.AssertExpectations(t)
}

// NEW TEST: TestLLMMind_Start_StateInitializationRace attempts to detect race conditions
// during the initialization phase when Start and SetMission are called concurrently.
func TestLLMMind_Start_StateInitializationRace(t *testing.T) {
	// This test is primarily useful when run with the race detector (go test -race).
	mind, _, mockKG, _, _ := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	missionID := "mission-race-init"

	// Mock KG calls needed for SetMission
	mockMissionInitialization(t, mockKG, missionID)

	// We want Start() and SetMission() to run concurrently.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Start will initialize and wait for the observer loop, then check/update the state.
		mind.Start(ctx)
	}()

	go func() {
		defer wg.Done()
		// SetMission will update the state and signal readiness.
		mind.SetMission(Mission{ID: missionID})
	}()

	// Wait for the observer loop to be ready (which happens during Start)
	select {
	case <-mind.observerReadyChan:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for observer loop to start")
	}

	// The state assertions are implicitly handled by the race detector and the fact that the loops proceed.
	cancel()
}

// -- Test Cases: Prompt Generation and Parsing (Coverage Increase) --

// TestGenerateSystemPrompt verifies the system prompt generation, including conditional logic.
func TestGenerateSystemPrompt(t *testing.T) {
	t.Run("Evolution Disabled", func(t *testing.T) {
		// Setup mind with default config (Evolution disabled).
		mind, _, _, _, _ := setupLLMMind(t)
		prompt := mind.generateSystemPrompt()

		assert.Contains(t, prompt, "HUMANOID_DRAG_AND_DROP")
		assert.Contains(t, prompt, "**Crucial Error Handling Instructions**:")
		// Crucially, it should NOT contain the Evolution section
		assert.NotContains(t, prompt, "EVOLVE_CODEBASE")
		assert.NotContains(t, prompt, "Proactive Self-Improvement (Evolution):")
	})

	t.Run("Evolution Enabled", func(t *testing.T) {
		// Setup mind with Evolution explicitly enabled.
		mind, _, _, _, _ := setupLLMMind(t, func(cfg *config.AgentConfig) {
			cfg.Evolution.Enabled = true
		})
		prompt := mind.generateSystemPrompt()

		assert.Contains(t, prompt, "EVOLVE_CODEBASE")
		assert.Contains(t, prompt, "Proactive Self-Improvement (Evolution):")
	})
}

// -- Test Cases: Context Gathering (Orient) (Coverage Increase) --

// TestGatherContext verifies the BFS traversal and depth limiting.
func TestGatherContext(t *testing.T) {
	mind, _, mockKG, _, _ := setupLLMMind(t)
	ctx := context.Background()
	missionID := "M1"

	// Setup a simple graph structure: M1 -> A1 -> O1 -> A2
	M1 := schemas.Node{ID: missionID}
	A1 := schemas.Node{ID: "A1"}
	O1 := schemas.Node{ID: "O1"}
	A2 := schemas.Node{ID: "A2"}

	// --- Run 1: Test with sufficient depth ---
	mind.contextLookbackSteps = 5

	// Mock the KG interactions for the BFS traversal.
	mockKG.On("GetNode", ctx, missionID).Return(M1, nil).Once()
	mockKG.On("GetNeighbors", ctx, missionID).Return([]schemas.Node{A1}, nil).Once()
	mockKG.On("GetNeighbors", ctx, "A1").Return([]schemas.Node{M1, O1}, nil).Once()
	mockKG.On("GetNeighbors", ctx, "O1").Return([]schemas.Node{A1, A2}, nil).Once()
	mockKG.On("GetNeighbors", ctx, "A2").Return([]schemas.Node{O1}, nil).Once()
	mockKG.On("GetEdges", ctx, mock.Anything).Return([]schemas.Edge{}, nil)

	subgraph, err := mind.gatherContext(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, subgraph.Nodes, 4, "Should find all 4 nodes with sufficient depth")

	// --- Run 2: Test with limited depth ---
	mockKG.ExpectedCalls = nil // Reset mocks for the second run.
	mind.contextLookbackSteps = 2

	mockKG.On("GetNode", ctx, missionID).Return(M1, nil).Once()
	mockKG.On("GetNeighbors", ctx, missionID).Return([]schemas.Node{A1}, nil).Once()
	mockKG.On("GetNeighbors", ctx, "A1").Return([]schemas.Node{M1, O1}, nil).Once()
	mockKG.On("GetEdges", ctx, mock.Anything).Return([]schemas.Edge{}, nil)

	subgraph, err = mind.gatherContext(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, subgraph.Nodes, 3, "Should find 3 nodes (M1, A1, O1) with depth limit 2")

	// --- Run 3: Test failure to get start node ---
	mockKG.ExpectedCalls = nil
	expectedErr := errors.New("KG connection failed")
	mockKG.On("GetNode", ctx, missionID).Return(schemas.Node{}, expectedErr).Once()

	subgraph, err = mind.gatherContext(ctx, missionID)
	require.Error(t, err)
	assert.Nil(t, subgraph)
	assert.Contains(t, err.Error(), "failed to get mission start node")

	mockKG.AssertExpectations(t)
}

// TestParseActionResponse verifies the robust parsing of LLM responses, including markdown formatting.
func TestParseActionResponse(t *testing.T) {
	mind, _, _, _, _ := setupLLMMind(t)

	// The action we expect to get back from a valid response.
	expectedAction := Action{
		Type:      ActionNavigate,
		Value:     "http://example.com/login",
		Rationale: "Start at login page.",
	}
	validJSON, _ := json.Marshal(expectedAction)

	tests := []struct {
		name        string
		response    string
		expectError bool
		expectType  ActionType
	}{
		{"Valid Plain JSON", string(validJSON), false, ActionNavigate},
		{"Valid Markdown JSON Block", "```json\n" + string(validJSON) + "\n```", false, ActionNavigate},
		{"Valid Markdown Block (no lang)", "```\n" + string(validJSON) + "\n```", false, ActionNavigate},
		{"Extra text and Markdown", "Here is the plan:\n```json\n" + string(validJSON) + "\n```\nProceed.", false, ActionNavigate},
		{"JSON embedded without markdown", "Plan: " + string(validJSON) + " End.", false, ActionNavigate},
		{"Invalid JSON", `{"type": "NAVIGATE", "value": "http://missing_quote.com}`, true, ""},
		{"Missing Type Field", `{"value": "http://example.com"}`, true, ""},
		{"Empty Response", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Testing the unexported method directly.
			action, err := mind.parseActionResponse(tt.response)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectType, action.Type)
			}
		})
	}
}

// -- Test Cases: OODA Loop Integration --

// mockMissionInitialization sets up the necessary mocks for when the mind
// initializes a new mission in the knowledge graph.
func mockMissionInitialization(t *testing.T, mockKG *mocks.MockKGClient, missionID string) {
	t.Helper()
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{}, errors.New("not found")).Once()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(node schemas.Node) bool {
		return node.Type == schemas.NodeMission && node.ID == missionID
	})).Return(nil).Once()
}

// mockDecisionCycle sets up the mocks for a full Orient -> Decide -> Act cycle.
func mockDecisionCycle(
	mockKG *mocks.MockKGClient,
	mockLLM *mocks.MockLLMClient,
	missionID string,
	contextNodes []schemas.Node, // Nodes returned for context gathering
	llmAction Action, // The action the LLM will decide on
	expectedActionID string, // The UUID that will be assigned to the action
	expectedEdgeID string, // The UUID that will be assigned to the mission->action edge
) {
	// Orient: Mocks for gatherContext
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{ID: missionID}, nil).Once()
	mockKG.On("GetNeighbors", mock.Anything, missionID).Return(contextNodes, nil).Once()
	mockKG.On("GetEdges", mock.Anything, missionID).Return([]schemas.Edge{}, nil).Once()
	for _, node := range contextNodes {
		mockKG.On("GetNeighbors", mock.Anything, node.ID).Return([]schemas.Node{}, nil).Maybe()
		mockKG.On("GetEdges", mock.Anything, node.ID).Return([]schemas.Edge{}, nil).Maybe()
	}

	// Decide: Mock for LLM call
	llmResponse, _ := json.Marshal(llmAction)
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(string(llmResponse), nil).Once()

	// Act: Mocks for recordActionKG
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(node schemas.Node) bool {
		return node.Type == schemas.NodeAction && node.ID == expectedActionID
	})).Return(nil).Once()
	// Validate the edge ID as well to ensure the UUID sequence is correct.
	mockKG.On("AddEdge", mock.Anything, mock.MatchedBy(func(edge schemas.Edge) bool {
		return edge.ID == expectedEdgeID && edge.Type == schemas.RelationshipExecuted && edge.From == missionID && edge.To == expectedActionID
	})).Return(nil).Once()
}

// mockObservationProcessing sets up the mocks for when the mind processes an observation.
func mockObservationProcessing(
	mockKG *mocks.MockKGClient,
	mockLTM *MockLTM,
	obs Observation,
	actionToUpdateID string,
	expectedEdgeID string,
) {
	mockLTM.On("ProcessAndFlagObservation", mock.Anything, obs).Return(nil).Once()

	// Mocks for recordObservationKG
	// Use mock.Anything for the context to avoid type mismatch panics
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeObservation && n.ID == obs.ID })).Return(nil).Once()
	// Validate the edge ID as well.
	mockKG.On("AddEdge", mock.Anything, mock.MatchedBy(func(e schemas.Edge) bool {
		return e.ID == expectedEdgeID && e.Type == schemas.RelationshipHasObservation && e.From == actionToUpdateID && e.To == obs.ID
	})).Return(nil).Once()

	// Mocks for updateActionStatusFromObservation
	originalActionNode := schemas.Node{ID: actionToUpdateID, Type: schemas.NodeAction, Properties: json.RawMessage(`{}`)}
	mockKG.On("GetNode", mock.Anything, actionToUpdateID).Return(originalActionNode, nil).Once()

	// Determine the expected status based on the observation result.
	expectedStatus := schemas.StatusAnalyzed
	if obs.Result.Status == "failed" {
		expectedStatus = schemas.StatusError
	}

	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(node schemas.Node) bool {
		props := make(map[string]interface{})
		if node.Properties != nil {
			json.Unmarshal(node.Properties, &props)
		}
		return node.ID == actionToUpdateID && props["status"] == string(expectedStatus)
	})).Return(nil).Once()
}

// TestOODALoop_HappyPath verifies the full cycle: SetMission -> Orient -> Decide -> Act -> Observe -> Orient...
func TestOODALoop_HappyPath(t *testing.T) {
	mind, mockLLM, mockKG, mockLTM, bus := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// --- Test Data and Configuration ---
	missionID := "mission-ooda-happy"
	obs1ID := "obs-1" // Observation IDs are provided externally.

	// Define UUIDs for all generated entities in the correct sequence.
	// Sequence: A1 ID, Edge M->A1 ID, Edge A1->O1 ID, A2 ID, Edge M->A2 ID
	action1ID, edgeM_A1_ID, edgeA1_O1_ID, action2ID, edgeM_A2_ID := "action-1", "edge-M-A1", "edge-A1-O1", "action-2", "edge-M-A2"
	mockUUIDGenerator(t, action1ID, edgeM_A1_ID, edgeA1_O1_ID, action2ID, edgeM_A2_ID)

	// --- Start Mind and Bus Subscription ---
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mind.Start(ctx)
	}()
	actionChan, unsubscribeActions := bus.Subscribe(MessageTypeAction)
	defer unsubscribeActions()

	// --- 1. Set up mocks for Mission Initialization AND First Decision Cycle ---
	mockMissionInitialization(t, mockKG, missionID)
	mockDecisionCycle(mockKG, mockLLM, missionID, []schemas.Node{}, Action{Type: ActionNavigate}, action1ID, edgeM_A1_ID)

	// --- 2. Trigger First Cycle by Setting Mission ---
	mind.SetMission(Mission{ID: missionID, Objective: "Test OODA Happy Path"})
	assertActionReceived(t, bus, actionChan, action1ID, "Timeout waiting for Cycle 1 Action")

	// --- 3. Set up mocks for Observation Processing AND Second Decision Cycle ---
	observation := Observation{ID: obs1ID, SourceActionID: action1ID, Data: "success data", Result: ExecutionResult{Status: "success"}}
	mockObservationProcessing(mockKG, mockLTM, observation, action1ID, edgeA1_O1_ID)
	action1Node := schemas.Node{ID: action1ID, Type: schemas.NodeAction}
	mockDecisionCycle(mockKG, mockLLM, missionID, []schemas.Node{action1Node}, Action{Type: ActionConclude}, action2ID, edgeM_A2_ID)

	// --- 4. Trigger Second Cycle by Posting Observation ---
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: observation}))
	assertActionReceived(t, bus, actionChan, action2ID, "Timeout waiting for Cycle 2 Action")

	// --- 5. Final Assertions ---
	select {
	case msg := <-actionChan:
		t.Fatalf("Received unexpected extra action on the bus: %+v", msg.Payload)
	default:
		// No extra actions, as expected.
	}
	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateCompleted
	}, 5*time.Second, 50*time.Millisecond)

	mockKG.AssertExpectations(t)
	mockLLM.AssertExpectations(t)
	mockLTM.AssertExpectations(t)

	cancel() // Signal mind to stop.
	wg.Wait()
}

// assertActionReceived is a helper to wait for and validate an action on the bus.
func assertActionReceived(t *testing.T, bus *CognitiveBus, actionChan <-chan CognitiveMessage, expectedID, timeoutMsg string) {
	t.Helper()
	select {
	case msg := <-actionChan:
		bus.Acknowledge(msg)
		postedAction, ok := msg.Payload.(Action)
		require.True(t, ok, "Received non-Action payload on action channel")
		assert.Equal(t, expectedID, postedAction.ID, "Action ID mismatch for: %s", timeoutMsg)
	case <-time.After(5 * time.Second):
		t.Fatal(timeoutMsg)
	}
}

// -- Test Cases: Robustness and Error Handling --

// Verifies the Mind transitions to StateFailed if observation processing fails.
func TestOODALoop_ObservationKGFailure(t *testing.T) {
	mind, mockLLM, mockKG, mockLTM, bus := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missionID := "mission-fail-obs"
	actionID := "action-fail-obs"
	mockUUIDGenerator(t, actionID, "edge-1", "edge-2") // Provide enough UUIDs

	// -- Mocks for the initial, unrelated decision cycle triggered by SetMission --
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{}, errors.New("not found")).Once()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeMission })).Return(nil).Once()
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{ID: missionID}, nil).Maybe() // For decision cycle
	mockKG.On("GetNeighbors", mock.Anything, missionID).Return([]schemas.Node{}, nil).Maybe()
	mockKG.On("GetEdges", mock.Anything, missionID).Return([]schemas.Edge{}, nil).Maybe()
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(`{"type": "NAVIGATE", "value": "http://init.com", "rationale": "initial action"}`, nil).Maybe()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeAction })).Return(nil).Maybe()
	mockKG.On("AddEdge", mock.Anything, mock.Anything).Return(nil).Maybe()

	// -- Mocks for the actual test scenario --
	expectedError := errors.New("KG critical failure")
	// The LTM processes the observation before it's recorded in the KG.
	mockLTM.On("ProcessAndFlagObservation", mock.Anything, mock.AnythingOfType("Observation")).Return(nil).Once()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeObservation })).Return(expectedError).Once()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mind.Start(ctx)
	}()

	mind.SetMission(Mission{ID: missionID, Objective: "test"})
	time.Sleep(100 * time.Millisecond) // Allow first cycle to run
	observation := Observation{ID: "obs-fail", Data: "some data"}
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: observation})
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateFailed
	}, 2*time.Second, 50*time.Millisecond)

	cancel()
	wg.Wait()
}

// NEW: Verifies the Mind handles panics during observation processing and transitions to StateFailed.
func TestOODALoop_ObservationPanic(t *testing.T) {
	mind, _, mockKG, mockLTM, bus := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missionID := "mission-panic-obs"
	mockUUIDGenerator(t)

	// Minimal mock setup just to get the mind running
	mockKG.On("GetNode", mock.Anything, mock.Anything).Return(schemas.Node{}, errors.New("not found")).Maybe()
	mockKG.On("AddNode", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Configure the LTM mock to panic when processing the observation.
	mockLTM.On("ProcessAndFlagObservation", mock.Anything, mock.AnythingOfType("Observation")).Run(func(args mock.Arguments) {
		panic("LTM cognitive failure simulation")
	}).Return(nil).Once()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mind.Start(ctx)
	}()

	mind.SetMission(Mission{ID: missionID, Objective: "test"})
	time.Sleep(100 * time.Millisecond) // Allow mind to start

	// Act: Post the observation that triggers the panic
	observation := Observation{ID: "obs-panic", Data: "trigger"}
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: observation})
	require.NoError(t, err)

	// Assert: The mind should catch the panic and transition to StateFailed
	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateFailed
	}, 2*time.Second, 50*time.Millisecond)

	cancel()
	wg.Wait()
}

// Verifies the Mind handles LLM API failures gracefully.
func TestOODALoop_DecisionLLMFailure(t *testing.T) {
	mind, mockLLM, mockKG, _, _ := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	missionID := "mission-llm-fail"
	missionNode := schemas.Node{ID: missionID, Type: schemas.NodeMission}
	mockUUIDGenerator(t) // No UUIDs needed as we fail before action generation

	cycleCompleteWg := sync.WaitGroup{}
	cycleCompleteWg.Add(1)

	// -- Mock Setup in strict execution order --
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{}, errors.New("not found")).Once()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeMission })).Return(nil).Once()
	mockKG.On("GetNode", mock.Anything, missionID).Return(missionNode, nil).Once()
	mockKG.On("GetNeighbors", mock.Anything, missionID).Return([]schemas.Node{}, nil).Once()
	mockKG.On("GetEdges", mock.Anything, missionID).Return([]schemas.Edge{}, nil).Once()
	expectedError := errors.New("LLM API timeout")
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return("", expectedError).Once().Run(func(args mock.Arguments) {
		cycleCompleteWg.Done()
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mind.Start(ctx)
	}()
	mind.SetMission(Mission{ID: missionID, Objective: "test"})

	if !waitTimeout(&cycleCompleteWg, 5*time.Second) {
		t.Fatal("Timeout waiting for the OODA loop (LLM Generate call) to execute.")
	}

	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		currentState := mind.currentState
		mind.mu.RUnlock()
		return currentState == StateObserving
	}, 1*time.Second, 50*time.Millisecond, "Mind should return to OBSERVING after LLM failure")

	mockLLM.AssertExpectations(t)
	mockKG.AssertExpectations(t)

	cancel()
	wg.Wait()
}

// Verifies the Mind fails if it cannot record its decided action.
func TestOODALoop_ActionKGFailure(t *testing.T) {
	mind, mockLLM, mockKG, _, _ := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missionID := "mission-action-kg-fail"
	missionNode := schemas.Node{ID: missionID, Type: schemas.NodeMission}
	actionID := "action-kg-fail-id"
	mockUUIDGenerator(t, actionID) // Provide UUID for the action that will fail to be recorded

	// -- Mock Setup in strict execution order --
	mockKG.On("GetNode", mock.Anything, missionID).Return(schemas.Node{}, errors.New("not found")).Once()
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeMission })).Return(nil).Once()
	mockKG.On("GetNode", mock.Anything, missionID).Return(missionNode, nil).Once()
	mockKG.On("GetNeighbors", mock.Anything, missionID).Return([]schemas.Node{}, nil).Once()
	mockKG.On("GetEdges", mock.Anything, missionID).Return([]schemas.Edge{}, nil).Once()
	llmResponse, _ := json.Marshal(Action{Type: ActionClick})
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(string(llmResponse), nil).Once()
	expectedError := errors.New("KG write failure")
	mockKG.On("AddNode", mock.Anything, mock.MatchedBy(func(n schemas.Node) bool { return n.Type == schemas.NodeAction })).Return(expectedError).Once()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mind.Start(ctx)
	}()
	mind.SetMission(Mission{ID: missionID, Objective: "test"})

	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateFailed
	}, 2*time.Second, 50*time.Millisecond)

	cancel()
	wg.Wait()
}

// NEW: TestLLMMind_RecordActionKG_ValueTruncation verifies long action values are truncated for storage.
func TestLLMMind_RecordActionKG_ValueTruncation(t *testing.T) {
	mind, _, mockKG, _, _ := setupLLMMind(t)
	ctx := context.Background()

	longValue := strings.Repeat("A", 300)
	expectedTruncated := longValue[:256] + "..."

	action := Action{
		ID:        "action-long",
		MissionID: "mission-1",
		Type:      ActionInputText,
		Value:     longValue,
	}

	mockUUIDGenerator(t, "edge-id")

	// Expect AddNode with truncated value in properties
	mockKG.On("AddNode", ctx, mock.MatchedBy(func(n schemas.Node) bool {
		if n.ID != action.ID {
			return false
		}
		props := make(map[string]interface{})
		json.Unmarshal(n.Properties, &props)
		return props["value"] == expectedTruncated
	})).Return(nil).Once()

	mockKG.On("AddEdge", ctx, mock.Anything).Return(nil).Once()

	// Act
	err := mind.recordActionKG(ctx, action)

	// Assert
	require.NoError(t, err)
	mockKG.AssertExpectations(t)
}
