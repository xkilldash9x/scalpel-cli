package agent

import (
	"context"
	_ "embed" // Import the embed package for JS assets
	"encoding/json"
	"fmt"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// LoginExecutor is responsible for autonomously handling the login process.
// It uses heuristics to identify login forms and attempts to authenticate
// using provided credentials.
type LoginExecutor struct {
	logger           *zap.Logger
	humanoidProvider HumanoidProvider
	sessionProvider  SessionProvider
	kg               GraphStore
}

var _ ActionExecutor = (*LoginExecutor)(nil) // Verify interface compliance.

// NewLoginExecutor creates a new LoginExecutor.
func NewLoginExecutor(humanoidProvider HumanoidProvider, sessionProvider SessionProvider, kg GraphStore) *LoginExecutor {
	return &LoginExecutor{
		logger:           observability.GetLogger().Named("login_executor"),
		humanoidProvider: humanoidProvider,
		sessionProvider:  sessionProvider,
		kg:               kg,
	}
}

// Execute performs the login action.
func (e *LoginExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	e.logger.Info("Executing login sequence...")

	h := e.humanoidProvider()
	session := e.sessionProvider()

	if h == nil || session == nil {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": "Humanoid or Session provider not available"},
		}, nil
	}

	// 1. Extract Credentials
	username := ""
	password := ""

	if val, ok := action.Metadata["username"].(string); ok {
		username = val
	}
	if val, ok := action.Metadata["password"].(string); ok {
		password = val
	}

	// 1a. If credentials missing, query KG for accounts linked to this mission.
	if username == "" || password == "" {
		if e.kg != nil && action.MissionID != "" {
			e.logger.Debug("Credentials missing in metadata, querying KG for accounts linked to mission.", zap.String("mission_id", action.MissionID))
			edges, err := e.kg.GetEdges(ctx, action.MissionID)
			if err != nil {
				e.logger.Warn("Failed to query KG edges for mission", zap.Error(err))
			} else {
				// Iterate in reverse to prioritize more recently created accounts if standard iteration order allows,
				// or just iterate and pick the last one.
				for _, edge := range edges {
					if edge.Type == schemas.RelationshipHas {
						node, err := e.kg.GetNode(ctx, edge.To)
						if err == nil && node.Type == schemas.NodeAccount {
							var props map[string]interface{}
							if json.Unmarshal(node.Properties, &props) == nil {
								if u, ok := props["username"].(string); ok {
									username = u
								}
								// WARNING: Password retrieval from KG is for autonomous testing context only.
								if p, ok := props["password"].(string); ok {
									password = p
								}
								e.logger.Info("Found account credentials in KG", zap.String("username", username))
								// Use the first valid one found (or could add logic to find 'latest')
								if username != "" && password != "" {
									break
								}
							}
						}
					}
				}
			}
		}
	}

	if username == "" || password == "" {
		// If credentials are not provided, we can't proceed with a specific login.
		// However, for testing purposes, or if the agent wants to test for
		// "guest" access or similar, we might proceed.
		// For now, fail if no credentials.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeInvalidParameters,
			ErrorDetails:    map[string]interface{}{"message": "Username and password are required in metadata or linked in KG for EXECUTE_LOGIN_SEQUENCE"},
		}, nil
	}

	// 2. Identify Login Form
	// We'll reuse the form analysis script logic from SignUpExecutor if possible,
	// or implement a simplified version here. Since SignUpExecutor has a complex
	// analysis script embedded, we might want to use a simpler heuristic here or
	// duplicating the script is not ideal.
	// Let's implement a basic heuristic search for username/email and password fields.

	// Helper to find element by multiple selectors
	findElement := func(selectors []string) string {
		for _, sel := range selectors {
			// Check if exists and visible
			// We can use a script to check existence efficiently
			ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			// Basic check if selector exists
			script := fmt.Sprintf(`document.querySelector('%s') !== null`, sel)
			rawResult, err := session.ExecuteScript(ctxWithTimeout, script, nil)
			if err != nil {
				continue
			}

			var exists bool
			if err := json.Unmarshal(rawResult, &exists); err == nil && exists {
				return sel
			}
		}
		return ""
	}

	usernameSelectors := []string{
		"input[name='username']", "input[id='username']", "input[type='text'][name*='user']",
		"input[name='email']", "input[id='email']", "input[type='email']",
	}
	passwordSelectors := []string{
		"input[name='password']", "input[id='password']", "input[type='password']",
	}
	submitSelectors := []string{
		"button[type='submit']", "input[type='submit']", "button:contains('Login')", "button:contains('Sign In')",
		"form button", // fallback
	}

	userSel := findElement(usernameSelectors)
	passSel := findElement(passwordSelectors)
	submitSel := findElement(submitSelectors)

	if userSel == "" || passSel == "" {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedDOMChange,
			ErrorCode:       ErrCodeElementNotFound,
			ErrorDetails:    map[string]interface{}{"message": "Could not identify login form fields (username/password)"},
		}, nil
	}

	// 3. Fill Form
	ensureVisible := true
	opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

	e.logger.Debug("Filling login form", zap.String("username_selector", userSel), zap.String("password_selector", passSel))

	if err := h.Type(ctx, userSel, username, opts); err != nil {
		return e.handleError(err, action)
	}

	if err := h.Type(ctx, passSel, password, opts); err != nil {
		return e.handleError(err, action)
	}

	// 4. Submit
	if submitSel != "" {
		e.logger.Debug("Clicking submit button", zap.String("selector", submitSel))
		if err := h.IntelligentClick(ctx, submitSel, opts); err != nil {
			e.logger.Warn("Failed to click submit button, trying Enter on password field", zap.Error(err))
			// Fallback: Press Enter on password field
			if err := h.Type(ctx, passSel, "\n", opts); err != nil {
				return e.handleError(err, action)
			}
		}
	} else {
		// Fallback: Press Enter on password field
		e.logger.Debug("No submit button found, pressing Enter on password field")
		if err := h.Type(ctx, passSel, "\n", opts); err != nil {
			return e.handleError(err, action)
		}
	}

	// 5. Wait for Navigation or Update
	time.Sleep(2 * time.Second) // Basic wait, ideally usage of WaitForAsync
	_ = session.WaitForAsync(ctx, 5000)

	// 6. Verify Login (Basic)
	// Check if we are redirected or if login form is gone
	// For now, return success with observation
	// Ideally we check for auth cookies or URL change, similar to SignUpExecutor.

	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedAuthResult,
		Data: map[string]interface{}{
			"message":  "Login sequence executed",
			"username": username,
		},
	}, nil
}

func (e *LoginExecutor) handleError(err error, action Action) (*ExecutionResult, error) {
	code, details := ParseBrowserError(err, action)
	return &ExecutionResult{
		Status:          "failed",
		ObservationType: ObservedSystemState,
		ErrorCode:       code,
		ErrorDetails:    details,
	}, nil
}
