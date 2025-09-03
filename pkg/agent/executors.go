// -- pkg/agent/executors.go --
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/graphmodel"
	"github.com/xkilldash9x/scalpel-cli/pkg/knowledgegraph"
)

// ActionExecutor defines the interface for components that execute actions decided by the Mind.
type ActionExecutor interface {
	// Execute performs the action and returns the results (observations) and an error if it failed.
	// CORRECTED: The return type is now a strongly-typed struct instead of a generic map.
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
}

// SessionProvider is a function type that returns the current active browser session.
type SessionProvider func() browser.SessionContext

// MissionContextProvider is a function type that returns the current mission details.
type MissionContextProvider func() Mission

// --- Browser Executor ---

// BrowserExecutor implements the ActionExecutor interface for browser interaction actions.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
}

// NewBrowserExecutor creates a new BrowserExecutor.
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	return &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
		sessionProvider: provider,
	}
}

// Execute handles actions that require the browser environment.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// If there's no active session, the mission cannot proceed with browser actions.
		return nil, fmt.Errorf("cannot execute browser action (%s): No active browser session", action.Type)
	}

	var err error
	switch action.Type {
	case ActionNavigate:
		err = session.Navigate(action.Value)

	case ActionClick:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionClick requires a 'selector'")
		}
		err = session.Click(action.Selector)

	case ActionInputText:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionInputText requires a 'selector'")
		}
		err = session.Type(action.Selector, action.Value)

	case ActionSubmitForm:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionSubmitForm requires a 'selector' for the form or a submit button")
		}
		err = session.Submit(action.Selector)

	case ActionScroll:
		direction := "down"
		if action.Value == "up" {
			direction = "up"
		}
		err = session.ScrollPage(direction)

	case ActionWaitForAsync:
		durationMs := 1000 // Default wait time
		// Handle different numeric types that might come from JSON decoding (float64) or direct initialization (int).
		if dur, ok := action.Metadata["duration_ms"].(float64); ok {
			durationMs = int(dur)
		} else if dur, ok := action.Metadata["duration_ms"].(int); ok {
			durationMs = dur
		}
		err = session.WaitForAsync(durationMs)

	default:
		// This should ideally not happen if the Agent's executor registration is correct.
		return nil, fmt.Errorf("BrowserExecutor cannot handle action type: %s", action.Type)
	}

	// Browser actions primarily result in environmental changes observed by instrumentation.
	// The primary observation here is simply the success or failure of the execution itself.
	result := &ExecutionResult{
		Status: "success",
		ObservationType: ObservedDOMChange, // A browser action always results in a potential DOM change
	}
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	}
	return result, err
}

// --- TAO Executor ---

// Define placeholder interfaces for external dependencies if they are not available in the context.
// These should match the actual interfaces used in the GlobalContext.
type PolicyEngine interface {
	GeneratePolicy(ctx context.Context, kg knowledgegraph.GraphStore, target string) (interface{}, error)
}

type RemoteInteractor interface {
	UploadFile(ctx context.Context, host, path string, data []byte) error
	ExecuteCommand(ctx context.Context, host, command string) (RemoteResult, error)
}

type RemoteResult struct {
	ExitCode int
	StdOut   string
	StdErr   string
}

// TAOExecutor implements the ActionExecutor interface for Taint-Aware Obfuscation actions.
type TAOExecutor struct {
	logger           *zap.Logger
	policyEngine     PolicyEngine
	remoteInteractor RemoteInteractor
	kg               knowledgegraph.GraphStore
	missionProvider  MissionContextProvider
}

// NewTAOExecutor creates a new TAOExecutor.
func NewTAOExecutor(logger *zap.Logger, engine PolicyEngine, interactor RemoteInteractor, kg knowledgegraph.GraphStore, missionProvider MissionContextProvider) *TAOExecutor {
	return &TAOExecutor{
		logger:           logger.Named("tao_executor"),
		policyEngine:     engine,
		remoteInteractor: interactor,
		kg:               kg,
		missionProvider:  missionProvider,
	}
}

// Execute handles TAO related actions (GeneratePolicy, TriggerBuild).
func (e *TAOExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	switch action.Type {
	case ActionGeneratePolicy:
		return e.executeGeneratePolicy(ctx, action)
	case ActionTriggerBuild:
		return e.executeTriggerBuild(ctx, action)
	default:
		return nil, fmt.Errorf("TAOExecutor cannot handle action type: %s", action.Type)
	}
}

// executeGeneratePolicy handles the TAO policy generation action.
func (e *TAOExecutor) executeGeneratePolicy(ctx context.Context, action Action) (*ExecutionResult, error) {
	if e.policyEngine == nil {
		return nil, fmt.Errorf("TAO Policy Engine is not initialized")
	}

	// Determine the target binary/asset.
	targetBinary, ok := action.Metadata["target_binary"].(string)
	if !ok || targetBinary == "" {
		// Fallback to the mission target if not specified in metadata.
		currentMission := e.missionProvider()
		if currentMission.TargetURL != "" {
			targetBinary = currentMission.TargetURL
		} else {
			return nil, fmt.Errorf("ActionGeneratePolicy requires 'target_binary' in metadata or a mission target")
		}
	}

	// Generate the policy using the engine.
	generatedPolicy, err := e.policyEngine.GeneratePolicy(ctx, e.kg, targetBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TAO policy: %w", err)
	}

	// Store the generated policy artifact in the Knowledge Graph.
	policyNodeID, err := e.storePolicyArtifact(targetBinary, generatedPolicy, action.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to store policy artifact: %w", err)
	}

	// Return the results for the observation.
	results := &ExecutionResult{
		Status:          "success",
		Event:           "policy_generated",
		PolicyNodeID:    policyNodeID,
		TargetBinary:    targetBinary,
		ObservationType: ObservedPolicyGenerated,
	}
	return results, nil
}

// storePolicyArtifact saves the policy data into the KG as a new node.
func (e *TAOExecutor) storePolicyArtifact(targetBinary string, policyData interface{}, sourceActionID string) (string, error) {
	policyJSON, err := json.Marshal(policyData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal generated policy: %w", err)
	}

	policyNodeID := fmt.Sprintf("policy-%s", uuid.New().String())

	// Add the Policy Artifact Node.
	_, err = e.kg.AddNode(graphmodel.NodeInput{
		ID:   policyNodeID,
		Type: graphmodel.NodeTypeTAOPolicyArtifact,
		Properties: graphmodel.Properties{
			"target_binary": targetBinary,
			"policy_data":   string(policyJSON),
			"generated_at":  time.Now().UTC(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to add policy node to KG: %w", err)
	}

	// Link Action -> Artifact.
	_, err = e.kg.AddEdge(graphmodel.EdgeInput{
		SourceID:     sourceActionID,
		TargetID:     policyNodeID,
		Relationship: graphmodel.RelationshipTypeGeneratesArtifact,
	})
	if err != nil {
		e.logger.Warn("Failed to link action to policy artifact", zap.Error(err))
	}

	// Link Artifact -> Target Asset.
	_, err = e.kg.AddEdge(graphmodel.EdgeInput{
		SourceID:     policyNodeID,
		TargetID:     targetBinary,
		Relationship: graphmodel.RelationshipTypeAppliesTo,
	})
	if err != nil {
		// Non-fatal, but worth logging.
		e.logger.Warn("Failed to link policy artifact to target asset", zap.Error(err))
	}

	return policyNodeID, nil
}

// executeTriggerBuild handles the remote build execution action.
func (e *TAOExecutor) executeTriggerBuild(ctx context.Context, action Action) (*ExecutionResult, error) {
	if e.remoteInteractor == nil {
		return nil, fmt.Errorf("RemoteInteractor is not initialized")
	}

	// Extract and validate parameters.
	params, err := extractBuildParams(action)
	if err != nil {
		return nil, err
	}

	// Retrieve the policy data from the KG.
	policyData, err := e.retrievePolicyDataFromKG(params.PolicyNodeID)
	if err != nil {
		return nil, err
	}

	// Upload the policy file to the remote host.
	err = e.remoteInteractor.UploadFile(ctx, params.Host, params.RemotePolicyPath, []byte(policyData))
	if err != nil {
		return nil, fmt.Errorf("failed to upload policy file to %s:%s: %w", params.Host, params.RemotePolicyPath, err)
	}
	e.logger.Info("Successfully uploaded TAO policy", zap.String("host", params.Host), zap.String("path", params.RemotePolicyPath))

	// Execute the build command remotely.
	result, err := e.remoteInteractor.ExecuteCommand(ctx, params.Host, params.BuildCommand)

	// Prepare the observation results regardless of execution error.
	observationData := &ExecutionResult{
		Status:          "success",
		Host:            params.Host,
		Command:         params.BuildCommand,
		ExitCode:        result.ExitCode,
		StdOut:          result.StdOut,
		StdErr:          result.StdErr,
		ObservationType: ObservedBuildResult,
	}


	if err != nil {
		observationData.Status = "failed"
		observationData.Error = err.Error()
		e.logger.Error("Remote build command failed", zap.Error(err), zap.Int("exit_code", result.ExitCode), zap.String("stderr", result.StdErr))
		// Return the observation data along with the error.
		return observationData, fmt.Errorf("remote build failed: %w", err)
	}

	e.logger.Info("Remote build command executed successfully")
	return observationData, nil
}

// Helper struct for build parameters.
type buildParams struct {
	Host             string
	RemotePolicyPath string
	BuildCommand     string
	PolicyNodeID     string
}

// extractBuildParams validates and extracts parameters from the action metadata.
func extractBuildParams(action Action) (buildParams, error) {
	params := buildParams{}
	var ok bool
	// Standardize metadata key names for consistency.
	if params.Host, ok = action.Metadata["build_server_host"].(string); !ok || params.Host == "" {
		return params, fmt.Errorf("ActionTriggerBuild requires 'build_server_host' in metadata")
	}
	if params.RemotePolicyPath, ok = action.Metadata["remote_policy_path"].(string); !ok || params.RemotePolicyPath == "" {
		return params, fmt.Errorf("ActionTriggerBuild requires 'remote_policy_path' in metadata")
	}
	if params.BuildCommand, ok = action.Metadata["build_command"].(string); !ok || params.BuildCommand == "" {
		return params, fmt.Errorf("ActionTriggerBuild requires 'build_command' in metadata")
	}
	if params.PolicyNodeID, ok = action.Metadata["policy_node_id"].(string); !ok || params.PolicyNodeID == "" {
		return params, fmt.Errorf("ActionTriggerBuild requires 'policy_node_id' in metadata")
	}
	return params, nil
}

// retrievePolicyDataFromKG finds the policy node and extracts the data.
func (e *TAOExecutor) retrievePolicyDataFromKG(policyNodeID string) (string, error) {
	node, err := e.kg.GetNodeByID(policyNodeID)
	if err != nil {
		return "", fmt.Errorf("policy node %s not found in Knowledge Graph: %w", policyNodeID, err)
	}
	// Ensure the node is actually a policy artifact.
	if node.Type != graphmodel.NodeTypeTAOPolicyArtifact {
		return "", fmt.Errorf("node %s is not a TAO_PolicyArtifact (found %s)", policyNodeID, node.Type)
	}

	policyData, ok := node.Properties["policy_data"].(string)
	if !ok {
		return "", fmt.Errorf("policy node %s is missing 'policy_data' or it is not a string", policyNodeID)
	}
	return policyData, nil
}