// internal/evolution/models/models.go
package models

import (
	"time"
)

// MessageType defines the categories of messages on the evolution bus.
type MessageType string

const (
	// --- OODA Loop Stages ---
	TypeGoal        MessageType = "EVO_GOAL"        // Initial objective
	TypeObservation MessageType = "EVO_OBSERVATION" // Data gathered during Observe phase
	TypeSynthesis   MessageType = "EVO_SYNTHESIS"   // Result of the Orient phase (Strategies)
	TypeAction      MessageType = "EVO_ACTION"      // Result of the Decide phase (Action Plan)
	TypeResult      MessageType = "EVO_RESULT"      // Outcome of the Act phase

	// --- Observation Types ---
	ObsSourceCode     string = "SOURCE_CODE"
	ObsUnitTest       string = "UNIT_TEST"
	ObsBuildStatus    string = "BUILD_STATUS"
	ObsTestStatus     string = "TEST_STATUS"
	ObsDependencies   string = "DEPENDENCY_GRAPH"
	ObsGitBlame       string = "GIT_BLAME"
	ObsStaticAnalysis string = "STATIC_ANALYSIS"
	ObsActionResult   string = "ACTION_RESULT" // Feedback from the previous ACT phase
)

// Goal represents the high-level objective for the improvement process.
type Goal struct {
	ID          string
	Objective   string   // e.g., "Refactor the JWT scanner to support JWE"
	TargetFiles []string // Initial files identified as relevant
	Timestamp   time.Time
}

// Observation represents a single piece of information gathered during the Observe phase.
type Observation struct {
	ID        string
	GoalID    string
	Type      string      // e.g., ObsSourceCode, ObsBuildStatus
	Source    string      // The component/file path that generated the observation
	Data      interface{} // The actual content
	Timestamp time.Time
	IsError   bool // Indicates if this observation represents a failure state
}

// Strategy represents a proposed approach generated during the Orient phase.
type Strategy struct {
	ID                  string
	Description         string  `json:"description"`
	Rationale           string  `json:"rationale"`
	EstimatedComplexity float64 `json:"complexity"` // 0.0 (easy) to 1.0 (complex)
	PotentialImpact     float64 `json:"impact"`     // 0.0 (low risk) to 1.0 (high risk)
	Rank                int     `json:"rank"`
}

// Synthesis represents the output of the Orient phase.
type Synthesis struct {
	ID         string
	GoalID     string
	Strategies []Strategy
	Timestamp  time.Time
}

// ActionType defines the specific operations the Executor can perform.
type ActionType string

const (
	ActionApplyPatch   ActionType = "APPLY_PATCH"
	ActionRunCommand   ActionType = "RUN_COMMAND"
	ActionCreateFile   ActionType = "CREATE_FILE"
	ActionConcludeGoal ActionType = "CONCLUDE_GOAL"
)

// Action represents a concrete step decided during the Decide phase.
type Action struct {
	ID     string
	GoalID string
	// Phase 2: StrategyID is crucial for linking the action back to the strategy that proposed it.
	StrategyID  string
	Type        ActionType
	Description string
	Payload     map[string]interface{} // e.g., {"patch": "..."} or {"command": "..."}
	Timestamp   time.Time
}

// Result represents the outcome of the Act phase.
type Result struct {
	ID       string
	GoalID   string
	ActionID string
	// Phase 2: StrategyID must be propagated here so the Chronicler can record the full lineage.
	StrategyID string
	Success    bool
	Output     string // Captured stdout/stderr or error message
	Timestamp  time.Time
}
