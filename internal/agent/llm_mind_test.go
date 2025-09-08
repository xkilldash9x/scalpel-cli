// agent/llm_mind_test.go
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	// Assuming these imports based on the provided context.
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph/graphmodel"
)


// Test Setup Helper


// setupLLMMind initializes the LLMMind and its dependencies for testing.
func setupLLMMind(t *testing.T) (*LLMMind, *MockLLMClient, *MockGraphStore, *CognitiveBus) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	mockLLM := new(MockLLMClient)
	// Use the thread-safe MockGraphStore defined in mocks_test.go.
	mockKG := new(MockGraphStore)
	// Use a real CognitiveBus for integration testing of the OODA loop.
	bus := NewCognitiveBus(logger, 50)

	// Default configuration
	cfg := config.AgentConfig{
		LLM: config.LLMConfig{Model: "test-model"},
	}

	mind := NewLLMMind(logger, mockLLM, cfg, mockKG, bus)

	// Ensure resources are cleaned up after the test.
	t.Cleanup(func() {
		mind.Stop()
		bus.Shutdown()
	})

	return mind, mockLLM, mockKG, bus
}


// Test Cases: Initialization and State Management


// TestNewLLMMind_Initialization verifies the initial state and configuration (White-box).
func TestNewLLMMind_Initialization(t *testing.T) {
	mind, _, _, _ := setupLLMMind(t)

	// White-box verification of initial state
	assert.Equal(t, StateInitializing, mind.currentState)
	assert.Equal(t, 10, mind.contextLookbackSteps, "Default context lookback should be set")
	assert.NotNil(t, mind.stateReadyChan)
}

// TestLLMMind_SetMission verifies the transition when a new mission is assigned.
func TestLLMMind_SetMission(t *testing.T) {
	mind, _, _, _ := setupLLMMind(t)

	mission := Mission{ID: "M1", Objective: "Test Objective"}

	// Execute SetMission
	mind.SetMission(mission)

	// Verify State Change (White-box access with lock)
	mind.mu.RLock()
	assert.Equal(t, StateObserving, mind.currentState)
	assert.Equal(t, "M1", mind.currentMission.ID)
	mind.mu.RUnlock()

	// Verify that the decision loop was signaled (stateReadyChan)
	select {
	case <-mind.stateReadyChan:
		// Expected behavior: Signal received
	default:
		t.Fatal("SetMission did not signal the stateReadyChan")
	}
}


// Test Cases: Prompt Generation and Parsing (Unit Tests)


// TestParseActionResponse verifies the robust parsing of LLM responses, including markdown formatting.
func TestParseActionResponse(t *testing.T) {
	mind, _, _, _ := setupLLMMind(t)

	// Expected Action structure
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
		{"Invalid JSON", `{"type": "NAVIGATE", "value": "http://missing_quote.com}`, true, ""},
		{"Missing Type Field", `{"value": "http://example.com"}`, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Testing the unexported method (white-box)
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


// Test Cases: Knowledge Graph Interactions (Unit Tests)


// TestRecordActionKG_Truncation verifies long values are truncated before KG persistence.
func TestRecordActionKG_Truncation(t *testing.T) {
	mind, _, mockKG, _ := setupLLMMind(t)

	// Create a string longer than the 256 rune limit.
	longValue := strings.Repeat("X", 300)
	action := Action{
		ID:    "A-TRUNC",
		MissionID: "M1",
		Value: longValue,
	}

	// Expected truncation: 256 chars + "..."
	expectedValue := strings.Repeat("X", 256) + "..."

	// Expect the value property to be truncated (White-box check of input properties)
	mockKG.On("AddNode", mock.MatchedBy(func(input graphmodel.NodeInput) bool {
		val, ok := input.Properties["value"].(string)
		return ok && val == expectedValue
	})).Return("A-TRUNC", nil).Once()

	mockKG.On("AddEdge", mock.Anything).Return("E-TRUNC", nil).Once()

	// Execute (unexported method)
	err := mind.recordActionKG(action)
	assert.NoError(t, err)
	mockKG.AssertExpectations(t)
}

// TestProcessObservation_Integration verifies the sequence of KG calls when processing an observation.
func TestProcessObservation_Integration(t *testing.T) {
	mind, _, mockKG, _ := setupLLMMind(t)

	// Use the strongly typed ExecutionResult for the observation data.
	execResult := ExecutionResult{
		Status: "failed",
		Error:  "Timeout occurred",
	}
	obs := Observation{
		ID:             "O1",
		MissionID:      "M1",
		SourceActionID: "A1",
		Type:           ObservedDOMChange,
		Data:           &execResult, // Pass as pointer as expected by implementation
	}

	// Expect calls for recording the observation AND updating the action status.

	// 1. Record Observation Node
	mockKG.On("AddNode", mock.MatchedBy(func(i graphmodel.NodeInput) bool {
		return i.ID == "O1" && i.Type == graphmodel.NodeTypeObservation
	})).Return("O1", nil).Once()

	// 2. Record Edges (Action->Obs, Obs->Mission)
	mockKG.On("AddEdge", mock.Anything).Return("E1", nil).Twice()

	// 3. Update Action Status (including error message)
	mockKG.On("AddNode", mock.MatchedBy(func(input graphmodel.NodeInput) bool {
		return input.ID == "A1" && input.Properties["status"] == "failed" && input.Properties["error"] == "Timeout occurred"
	})).Return("A1", nil).Once()

	// Execute (unexported method)
	err := mind.processObservation(obs)
	assert.NoError(t, err)
	mockKG.AssertExpectations(t)
}


// Test Cases: OODA Loop Integration (Event Driven)


// TestOODALoop_HappyPath verifies the full cycle: SetMission -> Orient -> Decide -> Act -> Observe -> Orient...
// This is an end-to-end test of the LLMMind's asynchronous processing via the Start method.
func TestOODALoop_HappyPath(t *testing.T) {
	mind, mockLLM, mockKG, bus := setupLLMMind(t)
	// Use a context with timeout to prevent the test from hanging indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	missionID := "mission-ooda"
	action1ID := "" // Will capture the ID generated by the Mind

	// --- Expectations for Cycle 1 (Mission Start -> Act) ---

	// 1. Orient
	mockKG.On("ExtractMissionSubgraph", mock.Anything, missionID, 10).Return(graphmodel.GraphExport{}, nil).Once()

	// 2. Decide
	llmAction1 := Action{Type: ActionNavigate, Value: "http://start.com"}
	llmResponse1, _ := json.Marshal(llmAction1)
	mockLLM.On("GenerateResponse", mock.Anything, mock.Anything).Return(string(llmResponse1), nil).Once()

	// 3. Act (Record Action in KG)
	// We use MatchedBy to capture the dynamically generated Action ID.
	mockKG.On("AddNode", mock.MatchedBy(func(input graphmodel.NodeInput) bool {
		// White-box check of the input properties.
		if input.Type == graphmodel.NodeTypeAction && input.Properties["status"] == "planned" {
			action1ID = input.ID // Capture the ID
			return true
		}
		return false
	})).Return("dyn-action-1", nil).Once()
	mockKG.On("AddEdge", mock.MatchedBy(func(input graphmodel.EdgeInput) bool {
		return input.Relationship == graphmodel.RelationshipTypeExecutesAction
	})).Return("edge-m-a1", nil).Once()

	// Start the Mind's processing loops (Observer and Decision)
	go func() {
		// We expect Start to run until the context is cancelled.
		if err := mind.Start(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("LLMMind Start returned unexpected error: %v", err)
		}
	}()

	// Subscribe to the bus to monitor Actions posted by the Mind
	actionChan, unsubscribeActions := bus.Subscribe(MessageTypeAction)
	defer unsubscribeActions()

	// Trigger the OODA loop by setting the mission (sends signal to stateReadyChan)
	mind.SetMission(Mission{ID: missionID, Objective: "Test OODA"})

	// Wait for the Action to be posted on the bus
	var postedAction1 Action
	select {
	case msg := <-actionChan:
		bus.Acknowledge(msg)
		postedAction1 = msg.Payload.(Action)
	case <-ctx.Done():
		t.Fatal("Timeout waiting for Cycle 1 Action on the bus")
	}

	// Verify Cycle 1 results
	require.NotEmpty(t, action1ID, "Action ID should have been captured during KG mock")
	assert.Equal(t, action1ID, postedAction1.ID)

	// --- Expectations for Cycle 2 (Observe -> Act) ---

	// 4. Observe (Process Observation and Update KG - Observer Loop)
	mockKG.On("AddNode", mock.MatchedBy(func(i graphmodel.NodeInput) bool { return i.Type == graphmodel.NodeTypeObservation })).Return("obs-1", nil).Once()
	mockKG.On("AddEdge", mock.Anything).Return("edge-obs", nil).Twice()
	// Update Action 1 status
	mockKG.On("AddNode", mock.MatchedBy(func(i graphmodel.NodeInput) bool {
		return i.ID == action1ID && i.Properties["status"] == "success"
	})).Return(action1ID, nil).Once()

	// 5. Orient (Gather Context again - Decision Loop)
	mockKG.On("ExtractMissionSubgraph", mock.Anything, missionID, 10).Return(graphmodel.GraphExport{}, nil).Once()

	// 6. Decide (LLM Call again)
	llmAction2 := Action{Type: ActionConclude}
	llmResponse2, _ := json.Marshal(llmAction2)
	mockLLM.On("GenerateResponse", mock.Anything, mock.Anything).Return(string(llmResponse2), nil).Once()

	// 7. Act (Record Action 2 in KG)
	mockKG.On("AddNode", mock.MatchedBy(func(i graphmodel.NodeInput) bool { return i.Type == graphmodel.NodeTypeAction })).Return("dyn-action-2", nil).Once()
	mockKG.On("AddEdge", mock.Anything).Return("edge-m-a2", nil).Once()

	// Trigger Cycle 2 by posting an Observation (simulating the Executor)
	observation := Observation{
		SourceActionID: action1ID,
		Data:           &ExecutionResult{Status: "success"},
	}
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: observation})
	require.NoError(t, err)

	// Wait for the second Action (Conclude) to be posted
	select {
	case msg := <-actionChan:
		bus.Acknowledge(msg)
		postedAction2 := msg.Payload.(Action)
		assert.Equal(t, ActionConclude, postedAction2.Type)
	case <-ctx.Done():
		t.Fatal("Timeout waiting for Cycle 2 Action on the bus")
	}

	// Final Verification
	mockKG.AssertExpectations(t)
	mockLLM.AssertExpectations(t)
}


// Test Cases: Robustness and Error Handling (Integration)


// TestOODALoop_ObservationKGFailure verifies the Mind transitions to StateFailed if observation processing fails critically.
func TestOODALoop_ObservationKGFailure(t *testing.T) {
	mind, _, mockKG, bus := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start the Mind
	go mind.Start(ctx)
	mind.SetMission(Mission{ID: "mission-fail"})

	// Simulate KG failure during observation processing (Observer Loop)
	expectedError := errors.New("KG critical failure")
	// The first AddNode call in the observer loop is for the observation itself.
	mockKG.On("AddNode", mock.Anything).Return("", expectedError).Once()

	// Post observation
	observation := Observation{ID: "obs-fail", Data: "data"}
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: observation})
	require.NoError(t, err)

	// Verify the Mind transitions to StateFailed (White-box check)
	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateFailed
	}, 2*time.Second, 50*time.Millisecond)
}

// TestOODALoop_DecisionLLMFailure verifies the Mind handles LLM API failures gracefully and returns to Observing.
func TestOODALoop_DecisionLLMFailure(t *testing.T) {
	mind, mockLLM, mockKG, _ := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missionID := "mission-llm-fail"

	// Setup expectations: Orient succeeds, Decide fails.
	mockKG.On("ExtractMissionSubgraph", mock.Anything, missionID, 10).Return(graphmodel.GraphExport{}, nil).Once()

	expectedError := errors.New("LLM API timeout")
	mockLLM.On("GenerateResponse", mock.Anything, mock.Anything).Return("", expectedError).Once()

	// Start the Mind and trigger the cycle
	go mind.Start(ctx)
	mind.SetMission(Mission{ID: missionID})

	// Verify the Mind returns to StateObserving (allowing for potential retries later).
	// It transitions through Orienting, Deciding, and back to Observing.
	assert.Eventually(t, func() bool {
		// We check if the mocks have been called as a proxy for the cycle completing.
		mocksMet := mockLLM.AssertExpectations(t) && mockKG.AssertExpectations(t)

		mind.mu.RLock()
		currentState := mind.currentState
		mind.mu.RUnlock()

		return mocksMet && currentState == StateObserving
	}, 2*time.Second, 50*time.Millisecond)
}

// TestOODALoop_ActionKGFailure verifies the Mind transitions to StateFailed if it cannot record its decided action.
func TestOODALoop_ActionKGFailure(t *testing.T) {
	mind, mockLLM, mockKG, _ := setupLLMMind(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	missionID := "mission-action-kg-fail"

	// Setup expectations: Orient succeeds, Decide succeeds, Act (KG recording) fails.
	mockKG.On("ExtractMissionSubgraph", mock.Anything, missionID, 10).Return(graphmodel.GraphExport{}, nil).Once()

	llmResponse, _ := json.Marshal(Action{Type: ActionClick})
	mockLLM.On("GenerateResponse", mock.Anything, mock.Anything).Return(string(llmResponse), nil).Once()

	expectedError := errors.New("KG write failure")
	// The AddNode call during the Act phase fails.
	mockKG.On("AddNode", mock.Anything).Return("", expectedError).Once()

	// Start the Mind and trigger the cycle
	go mind.Start(ctx)
	mind.SetMission(Mission{ID: missionID})

	// Verify the Mind transitions to StateFailed (White-box check)
	assert.Eventually(t, func() bool {
		mind.mu.RLock()
		defer mind.mu.RUnlock()
		return mind.currentState == StateFailed
	}, 2*time.Second, 50*time.Millisecond)
}