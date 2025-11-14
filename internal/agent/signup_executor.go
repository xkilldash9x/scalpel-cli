// internal/agent/signup_executor.go
package agent

import (
	"bufio"
	"context"
	_ "embed" // Import the embed package
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	json "github.com/json-iterator/go" // Use json-iterator for consistency and performance

	"github.com/mitchellh/go-homedir"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// Increased max retries as form analysis and submission can be flaky on dynamic pages.
const maxSignUpRetries = 2

// --- Embedded JavaScript Assets ---

//go:embed js_scripts/form_analysis.js
var formAnalysisScript string

//go:embed js_scripts/verification_success.js
var verificationSuccessScript string

//go:embed js_scripts/verification_error.js
var verificationErrorScript string

// SignUpExecutor is responsible for autonomously handling the sign-up process
// by analyzing the DOM, identifying the registration form, filling it with generated data,
// and verifying the outcome via auth state changes, network traffic, and DOM inspection.
type SignUpExecutor struct {
	logger           *zap.Logger
	humanoidProvider HumanoidProvider
	sessionProvider  SessionProvider
	seclists         *seclistsData
	cfg              config.Interface
}

// seclistsData holds the data loaded from SecLists.
type seclistsData struct {
	Usernames  []string
	Passwords  []string
	FirstNames []string
	LastNames  []string
}

// generatedUserData holds the randomly generated data for a sign-up attempt.
type generatedUserData struct {
	Username  string
	Password  string
	Email     string
	FirstName string
	LastName  string
}

// formAnalysisResult holds the output of the JavaScript-based form analysis.
type formAnalysisResult struct {
	Fields          map[string]string `json:"fields"` // Map of fieldType (e.g., "email") -> CSS selector
	SubmitSelector  string            `json:"submitSelector"`
	ContextSelector string            `json:"contextSelector"` // Selector for the form element itself
}

// NewSignUpExecutor creates a new SignUpExecutor.
func NewSignUpExecutor(humanoidProvider HumanoidProvider, sessionProvider SessionProvider, cfg config.Interface) (*SignUpExecutor, error) {
	logger := observability.GetLogger()
	// Check if the feature is enabled in the config first.
	if cfg == nil {
		logger.Error("SignUpExecutor received a nil config.")
		return nil, fmt.Errorf("config is nil")
	}
	if cfg.Scanners().Active.Auth.SignUp == nil {
		logger.Error("SignUpExecutor config is missing 'signup' section.")
		return nil, fmt.Errorf("signup config section is nil")
	}
	if !cfg.Scanners().Active.Auth.SignUp.Enabled {
		// Return nil, nil if disabled, allowing the registry to skip registration cleanly.
		logger.Info("SignUpExecutor is disabled by configuration.")
		return nil, nil
	}

	// Verify that the embedded JS assets loaded correctly (non-empty).
	if formAnalysisScript == "" || verificationSuccessScript == "" || verificationErrorScript == "" {
		return nil, fmt.Errorf("failed to load embedded JavaScript assets. Ensure js_scripts/*.js files are present during build")
	}

	seclists, err := loadSecListsData(cfg)
	if err != nil {
		// If SecLists loading fails, the feature cannot function. Return the error.
		return nil, fmt.Errorf("failed to load SecLists data: %w", err)
	}
	return &SignUpExecutor{
		logger:           observability.GetLogger().Named("signup_executor"),
		humanoidProvider: humanoidProvider,
		sessionProvider:  sessionProvider,
		seclists:         seclists,
		cfg:              cfg,
	}, nil
}

// Execute performs the sign-up action with a retry mechanism.
func (e *SignUpExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	var lastResult *ExecutionResult

	// Set a timeout for the entire execution, including retries.
	execCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	for i := 0; i <= maxSignUpRetries; i++ {
		if execCtx.Err() != nil {
			return e.fail(ErrCodeTimeoutError, "Sign-up execution timed out.", nil), nil
		}

		if i > 0 {
			e.logger.Info("Retrying sign-up process", zap.Int("attempt", i+1))
			// Add a stabilization wait before retrying.
			if session := e.sessionProvider(); session != nil {
				_ = session.WaitForAsync(execCtx, 2000)
			}
		}

		result := e.attemptSignUp(execCtx, action)

		// Handle successful execution
		if result.Status == "success" {
			return result, nil
		}

		// Handle structured failure
		e.logger.Warn("Sign-up attempt failed", zap.String("error_code", string(result.ErrorCode)), zap.Int("attempt", i+1))
		lastResult = result

		// Decide if retry is warranted based on the error code.
		if !e.isRetryableError(result.ErrorCode) {
			e.logger.Warn("Sign-up failed with non-retryable error.", zap.String("error_code", string(result.ErrorCode)))
			return result, nil
		}
	}

	e.logger.Error("Sign-up process failed after all retries")
	// Return the last structured result.
	return lastResult, nil
}

// isRetryableError determines if an error warrants a retry.
func (e *SignUpExecutor) isRetryableError(code ErrorCode) bool {
	switch code {
	// Transient errors, interaction failures, or inconclusive results that might succeed on retry.
	case ErrCodeTimeoutError, ErrCodeElementNotFound, ErrCodeHumanoidInteractionFailed, ErrCodeAuthWorkflowFailed, ErrCodeHumanoidTargetNotVisible:
		return true
	// Issues that will likely fail again immediately (e.g., server validation, CAPTCHA, configuration).
	case ErrCodeAuthCaptchaDetected, ErrCodeAuthValidationFailed, ErrCodeFeatureDisabled, ErrCodeInvalidParameters:
		return false
	default:
		return false
	}
}

// attemptSignUp contains the logic for a single sign-up attempt.
func (e *SignUpExecutor) attemptSignUp(ctx context.Context, action Action) *ExecutionResult {
	h := e.humanoidProvider()
	session := e.sessionProvider()
	if h == nil || session == nil {
		return e.fail(ErrCodeExecutionFailure, "Humanoid or Session provider not available", nil)
	}

	// 0. Pre-checks (CAPTCHA)
	if captchaDetected, details := e.detectCaptcha(ctx, session); captchaDetected {
		return e.fail(ErrCodeAuthCaptchaDetected, "CAPTCHA detected on the page, aborting sign-up.", details)
	}

	// 1. Capture Initial State (Auth State and URL)
	initialAuthState := e.getAuthState(ctx, session)
	initialURL, _ := e.getCurrentURL(ctx, session) // Best effort URL capture

	// 2. Analyze the form structure using intelligent JavaScript execution.
	analysisResult, err := e.analyzeSignUpForm(ctx, session)
	if err != nil {
		e.logger.Error("Form analysis failed", zap.Error(err))
		// Use ELEMENT_NOT_FOUND as the primary error if analysis fails to identify the form.
		return e.fail(ErrCodeElementNotFound, "Failed to analyze and identify the sign-up form.", map[string]interface{}{"error": err.Error()})
	}

	e.logger.Info("Successfully analyzed sign-up form", zap.Int("fields_found", len(analysisResult.Fields)))

	// 3. Generate User Data
	userData := e.generateUserData()
	e.logger.Info("Generated user data for sign-up attempt",
		zap.String("username", userData.Username),
		zap.String("email", userData.Email),
	)

	// 4. Fill form fields using the analyzed selectors and generated data.
	if err := e.fillForm(ctx, h, analysisResult, userData, action); err != nil {
		// The fillForm function returns a structured ExecutionResult on failure.
		return err
	}

	// 5. Handle Checkboxes (ToS/Privacy)
	// This is best effort; failure doesn't abort the attempt.
	e.handleCheckboxes(ctx, h, analysisResult.ContextSelector)

	// 6. Submit the form (Multi-strategy)
	if err := e.submitForm(ctx, h, session, analysisResult); err != nil {
		e.logger.Warn("Failed to submit the form.", zap.Error(err))
		// If submission fails, categorize it as a workflow failure unless ParseBrowserError finds something more specific.
		code, details := ParseBrowserError(err, action)
		if code == ErrCodeExecutionFailure || code == ErrCodeElementNotFound {
			code = ErrCodeAuthWorkflowFailed
		}
		return e.fail(code, fmt.Sprintf("Failed to submit form: %v", err), details)
	}

	// 7. Wait for stabilization
	// Wait dynamically for the application state to stabilize (network idle, DOM settled).
	e.logger.Info("Waiting for application stabilization after submission (WaitForAsync)...")
	if err := session.WaitForAsync(ctx, 5000); err != nil { // Wait up to 5 seconds
		// Timeout doesn't guarantee failure, the page might just be slow.
		e.logger.Debug("WaitForAsync completed (potentially timed out), proceeding to verification.", zap.Error(err))
	}

	// 8. Verify the result (Auth State + Network analysis + DOM checks)
	return e.verifySignUp(ctx, session, userData, initialAuthState, initialURL)
}

// fillForm handles the logic of mapping generated data to the analyzed fields and interacting with them.
func (e *SignUpExecutor) fillForm(ctx context.Context, h humanoid.Controller, analysis *formAnalysisResult, userData *generatedUserData, action Action) *ExecutionResult {
	dataMap := map[string]string{
		"firstName": userData.FirstName,
		"lastName":  userData.LastName,
		"email":     userData.Email,
		"username":  userData.Username,
		"password":  userData.Password,
		// Handle password confirmation fields identically to the main password field.
		"passwordConfirm": userData.Password,
	}

	// Use InteractionOptions to ensure the element is visible before typing.
	ensureVisible := true
	opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

	for fieldType, selector := range analysis.Fields {
		value, exists := dataMap[fieldType]
		if !exists || selector == "" {
			continue // Skip if we don't have data for this field type or the selector is missing
		}

		e.logger.Debug("Filling field", zap.String("type", fieldType), zap.String("selector", selector))
		// Use humanoid typing for realistic interaction
		if err := h.Type(ctx, selector, value, opts); err != nil {
			e.logger.Warn("Failed to fill identified field", zap.String("type", fieldType), zap.String("selector", selector), zap.Error(err))

			// If we fail to fill an essential field (as determined by the analysis), abort the attempt.
			// We rely on the analysis script's identification of these core fields.
			if fieldType == "email" || fieldType == "username" || fieldType == "password" {
				details := map[string]interface{}{
					"field_type": fieldType,
					"selector":   selector,
				}
				// Use ParseBrowserError to get structured error codes (e.g., visibility issues)
				errorCode, errorDetails := ParseBrowserError(err, action)
				errorDetails["field_details"] = details
				return e.fail(errorCode, fmt.Sprintf("Failed to fill essential field: %s", fieldType), errorDetails)
			}
			// Continue for non-essential fields.
		}
	}
	return nil // Success
}

// handleCheckboxes attempts to find and check common checkboxes like ToS agreements within the form context.
func (e *SignUpExecutor) handleCheckboxes(ctx context.Context, h humanoid.Controller, contextSelector string) {
	keywords := []string{"terms", "privacy", "agree", "accept", "consent", "policy"}
	// Use InteractionOptions to ensure visibility before clicking.
	ensureVisible := true
	opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

	// If the context selector is empty or body, use the global context.
	if contextSelector == "" || contextSelector == "body" {
		contextSelector = ""
	} else {
		contextSelector += " " // Add space for descendant selection
	}

	for _, keyword := range keywords {
		// Look for checkboxes associated with these keywords via attributes within the context.
		// Using case-insensitive attribute selectors [attr*="value" i].
		selectors := []string{
			fmt.Sprintf(`%sinput[type="checkbox"][id*="%s" i]`, contextSelector, keyword),
			fmt.Sprintf(`%sinput[type="checkbox"][name*="%s" i]`, contextSelector, keyword),
			fmt.Sprintf(`%sinput[type="checkbox"][aria-label*="%s" i]`, contextSelector, keyword),
		}

		for _, selector := range selectors {
			// Relying on IntelligentClick to handle the interaction. It handles visibility and checks if already checked.
			err := h.IntelligentClick(ctx, selector, opts)
			if err == nil {
				e.logger.Info("Successfully interacted with checkbox", zap.String("keyword", keyword), zap.String("selector", selector))
				// If successful, break to the next keyword group to handle multiple distinct checkboxes (e.g., ToS AND Privacy).
				break
			}
		}
	}
}

// submitForm implements the multi-strategy submission logic.
func (e *SignUpExecutor) submitForm(ctx context.Context, h humanoid.Controller, session schemas.SessionContext, analysis *formAnalysisResult) error {

	// Strategy 1: Click the identified submit button.
	if analysis.SubmitSelector != "" {
		e.logger.Debug("Attempting Strategy 1: Clicking analyzed submit button", zap.String("selector", analysis.SubmitSelector))
		// Use InteractionOptions to ensure the element is visible before clicking.
		ensureVisible := true
		opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

		if err := h.IntelligentClick(ctx, analysis.SubmitSelector, opts); err == nil {
			e.logger.Info("Form submission initiated using Strategy 1 (Button Click).")
			return nil
		} else {
			e.logger.Warn("Strategy 1 (Button Click) failed.", zap.Error(err))
		}
	}

	// Strategy 2: Direct JavaScript form submission using the analyzed context selector.
	if analysis.ContextSelector != "" && analysis.ContextSelector != "body" {
		e.logger.Debug("Attempting Strategy 2: JS Form Submit using context selector", zap.String("selector", analysis.ContextSelector))

		// Note: Using fmt.Sprintf for the selector is generally discouraged if the selector isn't sanitized,
		// but here it's generated by our own trusted analysis script.
		script := fmt.Sprintf(`
			const form = document.querySelector('%s');
			if (form && typeof form.submit === 'function') {
				// Trigger submit event first to activate client-side hooks/validation.
				const event = new Event('submit', { bubbles: true, cancelable: true });
				form.dispatchEvent(event);
				if (!event.defaultPrevented) {
					// Use requestSubmit if available (triggers validation constraints), otherwise submit().
					if (typeof form.requestSubmit === 'function') {
						form.requestSubmit();
					} else {
						form.submit();
					}
				}
				return true;
			}
			return false;
		`, analysis.ContextSelector)

		rawSubmitted, err := session.ExecuteScript(ctx, script, nil)
		if err == nil {
			var submitted bool
			if json.Unmarshal(rawSubmitted, &submitted) == nil && submitted {
				e.logger.Info("Form submission initiated using Strategy 2 (JS Form Submit).")
				return nil
			}
		}
		e.logger.Warn("Strategy 2 (JS Form Submit) failed or context not a form.", zap.Error(err))
	}

	// Strategy 3: Press Enter on the password field (implicit submission).
	passwordSelector := analysis.Fields["password"]
	if passwordSelector != "" {
		e.logger.Debug("Attempting Strategy 3: Enter Key Press on password field", zap.String("selector", passwordSelector))
		// Use Humanoid Type to send the Enter key (represented by newline character).
		if err := h.Type(ctx, passwordSelector, "\n", nil); err == nil {
			e.logger.Info("Form submission initiated using Strategy 3 (Enter Key Press).")
			return nil
		} else {
			e.logger.Warn("Strategy 3 (Enter Key Press) failed.", zap.Error(err))
		}
	}

	return fmt.Errorf("all form submission strategies failed")
}

// analyzeSignUpForm executes the embedded formAnalysisScript in the browser context.
func (e *SignUpExecutor) analyzeSignUpForm(ctx context.Context, session schemas.SessionContext) (*formAnalysisResult, error) {

	// Allow a reasonable timeout for the script execution.
	scriptCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// Execute the embedded script and explicitly call the function.
	scriptWithCall := formAnalysisScript + "; analyzeSignUpForm();"
	rawResult, err := session.ExecuteScript(scriptCtx, scriptWithCall, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute form analysis script: %w", err)
	}

	var result formAnalysisResult
	// Use json-iterator for unmarshaling the result from ExecuteScript.
	if err := json.Unmarshal(rawResult, &result); err != nil {
		e.logger.Error("Failed to unmarshal form analysis result", zap.ByteString("raw_result", rawResult), zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal form analysis result: %w", err)
	}

	// Validate the results to ensure essential components were identified.
	if result.SubmitSelector == "" {
		return nil, fmt.Errorf("analysis completed but could not identify the submit button")
	}

	// Check for essential fields (username/email AND password) based on the returned selectors.
	hasIdentifier := result.Fields["email"] != "" || result.Fields["username"] != ""
	hasPassword := result.Fields["password"] != ""

	if !hasIdentifier || !hasPassword {
		e.logger.Warn("Form analysis missed essential fields", zap.Bool("hasIdentifier", hasIdentifier), zap.Bool("hasPassword", hasPassword), zap.Any("fields", result.Fields))
		return nil, fmt.Errorf("form analysis missed essential fields (identifier or password)")
	}

	return &result, nil
}

// verifySignUp checks if the sign-up was successful by prioritizing auth state changes,
// then network activity, and finally falling back to DOM inspection.
func (e *SignUpExecutor) verifySignUp(ctx context.Context, session schemas.SessionContext, userData *generatedUserData, initialAuthState map[string]interface{}, initialURL string) *ExecutionResult {

	// 1. Check for Authentication State Change (Strongest Indicator)
	currentAuthState := e.getAuthState(ctx, session)
	if e.compareAuthStates(initialAuthState, currentAuthState) {
		e.logger.Info("Sign-up successful: Authentication state changed (new cookies/storage).")
		return e.success(userData, map[string]interface{}{"verification_method": "auth_state_change"})
	}

	// 2. Check for URL Change (Strong indicator if auth state didn't change, common in redirects)
	currentURL, _ := e.getCurrentURL(ctx, session)
	if initialURL != "" && currentURL != "" && initialURL != currentURL {
		// Ensure the new URL doesn't obviously contain error indicators
		if !strings.Contains(strings.ToLower(currentURL), "error") && !strings.Contains(strings.ToLower(currentURL), "fail") {
			e.logger.Info("Sign-up likely successful: URL changed.", zap.String("from", initialURL), zap.String("to", currentURL))
			return e.success(userData, map[string]interface{}{"verification_method": "url_change", "new_url": currentURL})
		}
	}

	// 3. Analyze Network Traffic (HAR) for the submission request.
	// This provides insight into the server's response code.
	if result := e.verifyNetworkTraffic(ctx, session, userData); result != nil {
		return result
	}

	// 4. Fallback: Check DOM for success/error indicators
	e.logger.Info("Auth state, URL change, and Network verification inconclusive. Falling back to DOM analysis.")
	return e.verifySignUpDOM(ctx, session, userData)
}

// verifyNetworkTraffic analyzes recent HAR data for submission status codes.
func (e *SignUpExecutor) verifyNetworkTraffic(ctx context.Context, session schemas.SessionContext, userData *generatedUserData) *ExecutionResult {
	artifactCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	artifacts, err := session.CollectArtifacts(artifactCtx)

	if err == nil && artifacts != nil && artifacts.HAR != nil {
		var harData schemas.HAR
		if err := json.Unmarshal(*artifacts.HAR, &harData); err != nil {
			e.logger.Warn("Failed to unmarshal HAR data during verification", zap.Error(err))
			return nil // Inconclusive
		}

		// Look at requests that occurred in the last 15 seconds (since submission).
		lookbackDuration := 15 * time.Second
		now := time.Now()

		for _, entry := range harData.Log.Entries {
			if now.Sub(entry.StartedDateTime) > lookbackDuration {
				continue
			}

			// Check for submission methods (POST/PUT)
			method := entry.Request.Method
			if method == "POST" || method == "PUT" {
				statusCode := entry.Response.Status
				e.logger.Debug("Analyzing network request during verification", zap.String("method", method), zap.Int("status", statusCode), zap.String("url", entry.Request.URL))

				// Success codes (200-202, 3xx)
				if (statusCode >= 200 && statusCode <= 202) || (statusCode >= 300 && statusCode < 400) {
					e.logger.Info("Sign-up likely successful: Network request indicated success.", zap.Int("status", statusCode))
					return e.success(userData, map[string]interface{}{"verification_method": "network", "status_code": statusCode})
				}

				// Failure codes (400 Bad Request, 409 Conflict, 422 Unprocessable Entity, 403 Forbidden)
				if statusCode == 400 || statusCode == 409 || statusCode == 422 || statusCode == 403 {
					e.logger.Warn("Sign-up failed: Network request indicated failure (likely validation).", zap.Int("status", statusCode))
					return e.fail(ErrCodeAuthValidationFailed, "Sign-up API request failed (validation or conflict).", map[string]interface{}{"status_code": statusCode})
				}

				// Server errors (5xx)
				if statusCode >= 500 {
					e.logger.Warn("Sign-up failed: Network request indicated server error.", zap.Int("status", statusCode))
					return e.fail(ErrCodeAuthWorkflowFailed, "Sign-up API request failed (server error).", map[string]interface{}{"status_code": statusCode})
				}
			}
		}
	}
	return nil // Inconclusive
}

// verifySignUpDOM performs DOM-based verification checks using the embedded JS scripts.
func (e *SignUpExecutor) verifySignUpDOM(ctx context.Context, session schemas.SessionContext, userData *generatedUserData) *ExecutionResult {

	// Check DOM for success indicators using the embedded script
	rawSuccessResult, err := session.ExecuteScript(ctx, verificationSuccessScript, nil)
	if err == nil {
		var successIndicator *string
		// Use json-iterator for unmarshaling results from ExecuteScript.
		if err := json.Unmarshal(rawSuccessResult, &successIndicator); err == nil && successIndicator != nil {
			e.logger.Info("Sign-up successful: Found success indicator in DOM.", zap.String("indicator", *successIndicator))
			return e.success(userData, map[string]interface{}{"verification_method": "dom", "indicator": *successIndicator})
		}
	} else {
		e.logger.Warn("Failed to execute success verification script.", zap.Error(err))
	}

	// Check DOM for error indicators using the embedded script
	rawErrorResult, err := session.ExecuteScript(ctx, verificationErrorScript, nil)
	if err == nil {
		var errorIndicator *string
		if err := json.Unmarshal(rawErrorResult, &errorIndicator); err == nil && errorIndicator != nil {
			e.logger.Warn("Sign-up failed: Found error indicator in DOM.", zap.String("indicator", *errorIndicator))

			// Attempt to classify the error (Validation vs Workflow)
			indicatorText := strings.ToLower(*errorIndicator)
			validationKeywords := []string{"taken", "exists", "weak", "mismatch", "invalid", "required"}
			isValidation := false
			for _, kw := range validationKeywords {
				if strings.Contains(indicatorText, kw) {
					isValidation = true
					break
				}
			}

			errorCode := ErrCodeAuthWorkflowFailed
			if isValidation {
				errorCode = ErrCodeAuthValidationFailed
			}

			return e.fail(errorCode, "Found error indicator in DOM.", map[string]interface{}{"indicator": *errorIndicator})
		}
	} else {
		e.logger.Warn("Failed to execute error verification script.", zap.Error(err))
	}

	// Inconclusive
	e.logger.Warn("Sign-up verification inconclusive (Auth State, Network, and DOM). Assuming failure.")
	return e.fail(ErrCodeAuthWorkflowFailed, "Sign-up status could not be determined by any verification method.", nil)
}

// --- Helper Functions for Verification and State Management ---

// getAuthState collects indicators of the user's authentication state (cookies, local/session storage keys).
func (e *SignUpExecutor) getAuthState(ctx context.Context, session schemas.SessionContext) map[string]interface{} {
	state := make(map[string]interface{})

	// Use a short timeout for state collection operations.
	stateCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Collect storage keys. The JS script handles sorting (Object.keys().sort()).
	script := `({
		localStorageKeys: Object.keys(window.localStorage || {}).sort(),
		sessionStorageKeys: Object.keys(window.sessionStorage || {}).sort()
	})`

	rawStorage, err := session.ExecuteScript(stateCtx, script, nil)
	if err == nil {
		var storageState map[string][]string
		// Use json-iterator for unmarshaling results from ExecuteScript.
		if json.Unmarshal(rawStorage, &storageState) == nil {
			state["storage"] = storageState
		}
	}

	// Collect cookies. We rely on CollectArtifacts to get the current snapshot.
	artifacts, err := session.CollectArtifacts(stateCtx)
	if err == nil && artifacts != nil && artifacts.Storage.Cookies != nil {
		// We capture the names of the cookies as the primary indicator.
		var cookieNames []string
		for _, cookie := range artifacts.Storage.Cookies {
			cookieNames = append(cookieNames, cookie.Name)
		}
		// CRITICAL: Sort the cookie names for deterministic comparison.
		sort.Strings(cookieNames)
		state["cookies"] = cookieNames
	}

	return state
}

// compareAuthStates checks if the current auth state is different from the initial state using JSON serialization.
// Relies on the keys being sorted in getAuthState.
func (e *SignUpExecutor) compareAuthStates(initial, current map[string]interface{}) bool {
	// Serialize both states to JSON for a simple, deep comparison.
	initialJSON, _ := json.Marshal(initial)
	currentJSON, _ := json.Marshal(current)
	// If the serialized states differ, it means a new cookie or storage key was added (or removed).
	return string(initialJSON) != string(currentJSON)
}

// getCurrentURL retrieves the current browser URL.
func (e *SignUpExecutor) getCurrentURL(ctx context.Context, session schemas.SessionContext) (string, error) {
	rawURL, err := session.ExecuteScript(ctx, "window.location.href", nil)
	if err != nil {
		return "", err
	}
	var url string
	// Use json-iterator for unmarshaling results from ExecuteScript.
	if err := json.Unmarshal(rawURL, &url); err != nil {
		return "", err
	}
	return url, nil
}

// detectCaptcha checks the page for common CAPTCHA indicators using JS execution.
func (e *SignUpExecutor) detectCaptcha(ctx context.Context, session schemas.SessionContext) (bool, map[string]interface{}) {
	// Check for common iframes, elements, and attributes used by major CAPTCHA providers.
	// Use a single JS execution for efficiency.
	script := `
        const captchaSelectors = [
            'iframe[src*="recaptcha/api"]', // Google reCAPTCHA v2/v3
            'iframe[src*="hcaptcha.com"]',  // hCaptcha
            '.g-recaptcha',                 // reCAPTCHA class
            '.h-captcha',                   // hCaptcha class
            '#cf-challenge-wrapper',        // Cloudflare Turnstile/Challenge
            'iframe[src*="challenges.cloudflare.com"]',
			'[data-sitekey]'                // Common attribute, checked last as it's generic
        ];

        for (const selector of captchaSelectors) {
            try {
                if (document.querySelector(selector)) {
                    return selector;
                }
            } catch (e) {}
        }
        return null;
    `

	rawResult, err := session.ExecuteScript(ctx, script, nil)
	if err != nil {
		e.logger.Warn("Failed to execute CAPTCHA detection script.", zap.Error(err))
		return false, nil
	}

	var foundSelector *string
	if err := json.Unmarshal(rawResult, &foundSelector); err == nil && foundSelector != nil {
		e.logger.Warn("CAPTCHA mechanism detected.", zap.String("selector", *foundSelector))
		return true, map[string]interface{}{"provider_hint": *foundSelector}
	}

	return false, nil
}

// ... (Data Generation and Loading functions defined later) ...

// --- Result Helpers ---

// fail is a helper function to generate a standardized failed ExecutionResult.
func (e *SignUpExecutor) fail(code ErrorCode, message string, details map[string]interface{}) *ExecutionResult {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["message"] = message

	// Include summary data for the observation.
	data := map[string]interface{}{
		"action": "SIGN_UP",
		"status": "FAILED",
		"reason": code,
	}

	return &ExecutionResult{
		Status: "failed",
		// Use ObservedAuthResult so the Mind understands the auth attempt outcome.
		ObservationType: ObservedAuthResult,
		ErrorCode:       code,
		ErrorDetails:    details,
		Data:            data,
	}
}

// success is a helper function to generate a standardized successful ExecutionResult,
// including the generated credentials and knowledge graph updates for the new user account.
func (e *SignUpExecutor) success(userData *generatedUserData, data map[string]interface{}) *ExecutionResult {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["action"] = "SIGN_UP"
	data["status"] = "SUCCESS"
	data["username"] = userData.Username
	data["email"] = userData.Email
	// We do NOT store the password in the observation data for security reasons.

	// Create a Knowledge Graph update to record the successful creation of the account.
	accountID := fmt.Sprintf("account:%s:%s", userData.Email, userData.Username)

	propsMap := map[string]interface{}{
		"username":   userData.Username,
		"email":      userData.Email,
		"first_name": userData.FirstName,
		"last_name":  userData.LastName,
		"source":     "AutonomousSignUp",
		// We store the password securely in the KG properties for potential later use (e.g., login testing).
		"password": userData.Password,
	}
	propsBytes, _ := json.Marshal(propsMap)

	kgUpdate := &schemas.KnowledgeGraphUpdate{
		NodesToAdd: []schemas.NodeInput{
			{
				ID:         accountID,
				Type:       schemas.NodeAccount,
				Label:      fmt.Sprintf("Account: %s (%s)", userData.Username, userData.Email),
				Status:     schemas.StatusNew,
				Properties: propsBytes,
			},
		},
	}

	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedAuthResult,
		Data:            data,
		KGUpdates:       kgUpdate,
	}
}

// --- Data Generation and Loading ---

// generateUserData creates a new set of realistic and compliant user data using the loaded SecLists.
func (e *SignUpExecutor) generateUserData() *generatedUserData {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

    // Robustness check: ensure lists are not empty before accessing indices.
    if len(e.seclists.Usernames) == 0 || len(e.seclists.FirstNames) == 0 || len(e.seclists.LastNames) == 0 {
        // This should ideally be caught during initialization, but serves as a runtime safety check.
        e.logger.Error("SecLists data is unexpectedly empty during data generation.")
        return e.generateFallbackUserData(r)
    }

	// Select random entries from the loaded lists.
	usernameBase := e.seclists.Usernames[r.Intn(len(e.seclists.Usernames))]
	firstName := e.seclists.FirstNames[r.Intn(len(e.seclists.FirstNames))]
	lastName := e.seclists.LastNames[r.Intn(len(e.seclists.LastNames))]

	// Generate a compliant password (Best Practice: Ensure complexity)
	password := e.generateCompliantPassword()

	// Create unique email and username to avoid collisions during parallel testing or retries.
	// Use a configurable domain if provided, otherwise fallback to a common test domain.
	domain := "example.com" // Default safe domain
	if e.cfg.Scanners().Active.Auth.SignUp != nil && e.cfg.Scanners().Active.Auth.SignUp.EmailDomain != "" {
		domain = e.cfg.Scanners().Active.Auth.SignUp.EmailDomain
	}

	uniqueSuffix := fmt.Sprintf("%d", r.Intn(100000))
	email := fmt.Sprintf("%s.%s.%s@%s", strings.ToLower(firstName), strings.ToLower(lastName), uniqueSuffix, domain)
	username := fmt.Sprintf("%s_%s", usernameBase, uniqueSuffix)

	return &generatedUserData{
		Username:  username,
		Password:  password,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
	}
}

// generateFallbackUserData provides data if SecLists are unavailable.
func (e *SignUpExecutor) generateFallbackUserData(r *rand.Rand) *generatedUserData {
    uniqueSuffix := fmt.Sprintf("%d", r.Intn(10000000))
    domain := "example.com"
	if e.cfg.Scanners().Active.Auth.SignUp != nil && e.cfg.Scanners().Active.Auth.SignUp.EmailDomain != "" {
		domain = e.cfg.Scanners().Active.Auth.SignUp.EmailDomain
	}
    return &generatedUserData{
		Username:  fmt.Sprintf("fallbackuser_%s", uniqueSuffix),
		Password:  e.generateCompliantPassword(),
		Email:     fmt.Sprintf("fallback.user.%s@%s", uniqueSuffix, domain),
		FirstName: "Fallback",
		LastName:  "User",
	}
}

// generateCompliantPassword creates a password that adheres to common complexity rules (length, mixed case, number, symbol).
func (e *SignUpExecutor) generateCompliantPassword() string {
	const lowerChars = "abcdefghijklmnopqrstuvwxyz"
	const upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const numberChars = "0123456789"
	const symbolChars = "!@#$%^&*()_+-="
	const minLength = 14 // Increased minimum length for better compliance

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var password []byte
	var availableChars = lowerChars + upperChars + numberChars + symbolChars

	// Ensure mandatory character types are present
	password = append(password, upperChars[r.Intn(len(upperChars))])
	password = append(password, numberChars[r.Intn(len(numberChars))])
	password = append(password, symbolChars[r.Intn(len(symbolChars))])
	password = append(password, lowerChars[r.Intn(len(lowerChars))])

	// Fill the rest of the password up to MinLength
	for len(password) < minLength {
		password = append(password, availableChars[r.Intn(len(availableChars))])
	}

	// Shuffle the password to ensure the mandatory characters aren't predictably located
	r.Shuffle(len(password), func(i, j int) {
		password[i], password[j] = password[j], password[i]
	})

	return string(password)
}

// loadSecListsData loads all the necessary data from the SecLists repository paths defined in the configuration.
func loadSecListsData(cfg config.Interface) (*seclistsData, error) {
	// We use the path configuration from the ATO scanner settings as the standard location for SecLists.
	atoCfg := cfg.Scanners().Active.Auth.ATO
	if atoCfg.SecListsPath == "" {
		return nil, fmt.Errorf("SecLists path (scanners.active.auth.ato.seclists_path) is not configured")
	}

	secListsDir, err := homedir.Expand(atoCfg.SecListsPath)
	if err != nil {
		return nil, fmt.Errorf("could not expand SecLists path '%s': %w", atoCfg.SecListsPath, err)
	}

	if _, err := os.Stat(secListsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("SecLists directory not found at '%s'. Please ensure the path is correct.", secListsDir)
	}

	// Define the specific files required for sign-up data generation.
	paths := map[string]string{
		"Usernames": filepath.Join("Usernames", "top-usernames-shortlist.txt"),
		// Passwords list is loaded but primarily we generate compliant ones.
		"Passwords": filepath.Join("Passwords", "Common-Credentials", "10-million-password-list-top-100.txt"),
		// Using specific name lists for better realism.
		"FirstNames": filepath.Join("Usernames", "Names", "givennames-usa-top1000.txt"),
		"LastNames":  filepath.Join("Usernames", "Names", "familynames-usa-top1000.txt"),
	}

	data := &seclistsData{}
	var loadErr error

	// Load each required wordlist.
	data.Usernames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["Usernames"]))
	if loadErr != nil {
		return nil, loadErr
	}
	// Load passwords list, but don't fail if missing as we generate them.
	data.Passwords, _ = loadWordlist(filepath.Join(secListsDir, paths["Passwords"]))

	data.FirstNames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["FirstNames"]))
	if loadErr != nil {
		// If the specific first names file fails, try the generic names.txt.
		observability.GetLogger().Warn("Failed to load primary first names wordlist, trying fallback.", zap.Error(loadErr))
		data.FirstNames, loadErr = loadWordlist(filepath.Join(secListsDir, "Usernames", "Names", "names.txt"))
		if loadErr != nil {
			// If that fails too, fallback to the usernames list.
			observability.GetLogger().Warn("Failed to load fallback names wordlist, falling back to usernames list.", zap.Error(loadErr))
			data.FirstNames = data.Usernames
		}
	}

	data.LastNames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["LastNames"]))
	if loadErr != nil {
		observability.GetLogger().Warn("Failed to load last names wordlist, falling back to usernames list.", zap.Error(loadErr))
		data.LastNames = data.Usernames
	}

	// Ensure essential lists are not empty.
	if len(data.Usernames) == 0 || len(data.FirstNames) == 0 || len(data.LastNames) == 0 {
		return nil, fmt.Errorf("one or more essential SecLists files (Usernames or Names) are empty or failed to load")
	}

	return data, nil
}

// loadWordlist reads a wordlist file and returns a slice of strings, ignoring comments and empty lines.
func loadWordlist(path string) ([]string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found at '%s'", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist file '%s': %w", path, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore empty lines and comments (starting with #)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist file '%s': %w", path, err)
	}

	return lines, nil
}
