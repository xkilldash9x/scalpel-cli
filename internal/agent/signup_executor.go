// internal/agent/signup_executor.go
package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed" // Import the embed package for JS assets
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand" // Alias math/rand for non-security sensitive randomization
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	json "github.com/json-iterator/go" // Use json-iterator for consistency and performance

	"github.com/mitchellh/go-homedir" // Corrected import path
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// Increased max retries as form analysis and submission can be flaky on dynamic pages.
const maxSignUpRetries = 2

// Timeouts and waits for various stages.
const (
	executionTimeout    = 5 * time.Minute
	scriptTimeout       = 20 * time.Second
	stateTimeout        = 5 * time.Second
	stabilizationWaitMs = 5000 // Wait time after submission for the page to settle.
	retryWaitMs         = 2000 // Wait time before retrying after a failure.
)

// Define standard errors.
var (
	ErrConfigIsNil            = errors.New("config must not be nil")
	ErrProvidersNil           = errors.New("providers must not be nil")
	ErrEmbeddedAssetsMissing  = errors.New("failed to load embedded JavaScript assets")
	ErrEssentialSecListsEmpty = errors.New("one or more essential SecLists files are empty or failed to load")
)

// --- Embedded JavaScript Assets ---

//go:embed js_scripts/form_analysis.js
var formAnalysisScript string

//go:embed js_scripts/verification_success.js
var verificationSuccessScript string

//go:embed js_scripts/verification_error.js
var verificationErrorScript string

//go:embed js_scripts/captcha_detection.js
var captchaDetectionScript string

// --- Data Structures ---

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
	Fields          map[string]string `json:"fields"`
	SubmitSelector  string            `json:"submitSelector"`
	ContextSelector string            `json:"contextSelector"`
}

// --- SecLists Loader Interface (Dependency Injection) ---

// SecListsLoader defines the interface for loading SecLists data.
type SecListsLoader interface {
	Load(cfg config.Interface) (*seclistsData, error)
}

// FileSystemSecListsLoader implements SecListsLoader by reading from the local filesystem.
type FileSystemSecListsLoader struct{}

// NewFileSystemSecListsLoader creates a new loader instance.
func NewFileSystemSecListsLoader() *FileSystemSecListsLoader {
	return &FileSystemSecListsLoader{}
}

// Load reads and parses the necessary SecLists files based on the configuration.
func (l *FileSystemSecListsLoader) Load(cfg config.Interface) (*seclistsData, error) {
	logger := observability.GetLogger().Named("seclists_loader")

	// We use the path configuration from the ATO scanner settings.
	atoCfg := cfg.Scanners().Active.Auth.ATO
	if atoCfg.SecListsPath == "" {
		return nil, fmt.Errorf("configuration error: SecLists path (scanners.active.auth.ato.seclists_path) is not configured")
	}

	// Safely expand potential home directory references (~).
	secListsDir, err := homedir.Expand(atoCfg.SecListsPath)
	if err != nil {
		return nil, fmt.Errorf("could not resolve SecLists path '%s': %w", atoCfg.SecListsPath, err)
	}

	// Verify the directory exists and is actually a directory.
	if info, err := os.Stat(secListsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("SecLists directory not found at '%s'. Please ensure the path is correct", secListsDir)
	} else if err != nil {
		return nil, fmt.Errorf("error accessing SecLists directory '%s': %w", secListsDir, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("SecLists path '%s' is not a directory", secListsDir)
	}

	// Define the specific files required.
	paths := map[string]string{
		"Usernames":  filepath.Join("Usernames", "top-usernames-shortlist.txt"),
		"Passwords":  filepath.Join("Passwords", "Common-Credentials", "10-million-password-list-top-100.txt"),
		"FirstNames": filepath.Join("Usernames", "Names", "givennames-usa-top1000.txt"),
		"LastNames":  filepath.Join("Usernames", "Names", "familynames-usa-top1000.txt"),
	}

	data := &seclistsData{}
	var loadErr error

	// Load essential lists with fallbacks.
	data.Usernames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["Usernames"]))
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load usernames wordlist: %w", loadErr)
	}

	// Load passwords list (optional).
	data.Passwords, _ = loadWordlist(filepath.Join(secListsDir, paths["Passwords"]))

	data.FirstNames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["FirstNames"]))
	if loadErr != nil {
		// Implement fallback strategy.
		logger.Warn("Failed to load primary first names wordlist, trying generic names.txt fallback.", zap.Error(loadErr))
		data.FirstNames, loadErr = loadWordlist(filepath.Join(secListsDir, "Usernames", "Names", "names.txt"))
		if loadErr != nil {
			// Final fallback.
			logger.Warn("Failed to load fallback names wordlist, falling back to usernames list.", zap.Error(loadErr))
			data.FirstNames = data.Usernames
		}
	}

	data.LastNames, loadErr = loadWordlist(filepath.Join(secListsDir, paths["LastNames"]))
	if loadErr != nil {
		logger.Warn("Failed to load last names wordlist, falling back to usernames list.", zap.Error(loadErr))
		data.LastNames = data.Usernames
	}

	// Final validation: Ensure essential lists are not empty.
	if len(data.Usernames) == 0 || len(data.FirstNames) == 0 || len(data.LastNames) == 0 {
		return nil, ErrEssentialSecListsEmpty
	}

	return data, nil
}

// loadWordlist reads a wordlist file efficiently, ignoring comments and empty lines.
func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		// Handles "not found" and permission errors.
		return nil, fmt.Errorf("failed to open wordlist file '%s': %w", path, err)
	}
	defer file.Close()

	var lines []string
	// Use bufio.Scanner for efficient line-by-line reading.
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore empty lines and comments (starting with #).
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	// Check for errors encountered during scanning.
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist file '%s': %w", path, err)
	}

	return lines, nil
}

// --- SignUpExecutor Implementation ---

// SignUpExecutor is responsible for autonomously handling the sign-up process.
type SignUpExecutor struct {
	logger           *zap.Logger
	humanoidProvider HumanoidProvider
	sessionProvider  SessionProvider
	seclists         *seclistsData
	cfg              config.Interface
	signUpCfg        *config.SignUpConfig
}

// NewSignUpExecutor creates a new SignUpExecutor.
// It accepts a SecListsLoader for dependency injection. If loader is nil, it defaults to FileSystemSecListsLoader.
func NewSignUpExecutor(humanoidProvider HumanoidProvider, sessionProvider SessionProvider, cfg config.Interface, loader SecListsLoader) (*SignUpExecutor, error) {
	logger := observability.GetLogger().Named("signup_executor")

	// 1. Defense in Depth: Validate input parameters rigorously.
	if cfg == nil {
		logger.Error("Configuration is nil.")
		return nil, ErrConfigIsNil
	}
	if humanoidProvider == nil || sessionProvider == nil {
		logger.Error("Providers are nil.")
		return nil, ErrProvidersNil
	}

	// 2. Retrieve and validate configuration section.
	signUpCfg := cfg.Scanners().Active.Auth.SignUp

	if signUpCfg == nil {
		// Treat missing config block as disabled.
		logger.Debug("SignUpExecutor config section ('scanners.active.auth.signup') is missing. Disabling executor.")
		return nil, nil
	}

	if !signUpCfg.Enabled {
		// Return nil, nil if disabled, allowing clean registry skip.
		logger.Info("SignUpExecutor is disabled by configuration.")
		return nil, nil
	}

	// 3. Verify embedded assets (Build integrity check).
	if formAnalysisScript == "" || verificationSuccessScript == "" || verificationErrorScript == "" || captchaDetectionScript == "" {
		logger.Error("Embedded JS assets missing.")
		return nil, ErrEmbeddedAssetsMissing
	}

	// 4. Load necessary external data (SecLists) using the injected loader.
	if loader == nil {
		loader = NewFileSystemSecListsLoader()
	}

	seclists, err := loader.Load(cfg)
	if err != nil {
		// If SecLists loading fails, the feature cannot function.
		logger.Error("Failed to load SecLists data.", zap.Error(err))
		return nil, fmt.Errorf("dependency error: failed to load SecLists data: %w", err)
	}

	return &SignUpExecutor{
		logger:           logger,
		humanoidProvider: humanoidProvider,
		sessionProvider:  sessionProvider,
		seclists:         seclists,
		cfg:              cfg,
		signUpCfg:        signUpCfg,
	}, nil
}

// Execute performs the sign-up action with a retry mechanism.
func (e *SignUpExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	// Defense in Depth: Handle nil receiver gracefully if Execute is called on an uninitialized executor.
	if e == nil {
		// Cannot use e.logger or e.fail() as e is nil.
		observability.GetLogger().Error("Execute called on nil SignUpExecutor.")
		// Use a temporary executor just to utilize the fail helper method consistently.
		tempExecutor := &SignUpExecutor{logger: observability.GetLogger()}
		return tempExecutor.fail(ErrCodeExecutionFailure, "Internal Error: SignUpExecutor is nil during Execute.", nil), nil
	}

	e.logger.Debug("Execute: Started")
	var lastResult *ExecutionResult

	// Set a timeout for the entire execution, including retries.
	execCtx, cancel := context.WithTimeout(ctx, executionTimeout)
	defer cancel()

	for i := 0; i <= maxSignUpRetries; i++ {
		e.logger.Debug("Execute: Starting loop", zap.Int("attempt", i+1), zap.Int("max_retries", maxSignUpRetries))
		// Check context cancellation between retries.
		if execCtx.Err() != nil {
			e.logger.Warn("Execute: Context timed out or cancelled before attempt.", zap.Error(execCtx.Err()))
			return e.fail(ErrCodeTimeoutError, "Sign-up execution timed out.", nil), nil
		}

		if i > 0 {
			e.logger.Info("Retrying sign-up process", zap.Int("attempt", i+1))
			e.logger.Debug("Execute: Waiting before retry", zap.Int("wait_ms", retryWaitMs))
			// Add a stabilization wait before retrying.
			if session := e.sessionProvider(); session != nil {
				// This is the retry wait.
				_ = session.WaitForAsync(execCtx, retryWaitMs)
			}
			e.logger.Debug("Execute: Wait complete, proceeding with retry.")
		}

		// Perform the attempt.
		result := e.attemptSignUp(execCtx, action)

		// Log the attempt's outcome.
		e.logger.Debug("Execute: Attempt completed",
			zap.Int("attempt", i+1),
			zap.String("status", result.Status),
			zap.String("error_code", string(result.ErrorCode)),
		)

		// Handle successful execution
		if result.Status == "success" {
			e.logger.Info("Sign-up process completed successfully.")
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
	// Return the last structured result if all retries failed.
	return lastResult, nil
}

// isRetryableError determines if an error warrants a retry.
func (e *SignUpExecutor) isRetryableError(code ErrorCode) bool {
	switch code {
	// Transient errors, interaction failures, or inconclusive results.
	case ErrCodeTimeoutError, ErrCodeElementNotFound, ErrCodeHumanoidInteractionFailed, ErrCodeAuthWorkflowFailed, ErrCodeHumanoidTargetNotVisible:
		return true
	// Deterministic failures (e.g., validation, CAPTCHA, configuration, critical system failure).
	case ErrCodeAuthCaptchaDetected, ErrCodeAuthValidationFailed, ErrCodeFeatureDisabled, ErrCodeInvalidParameters, ErrCodeExecutionFailure:
		return false
	default:
		// Default to false for unknown errors.
		return false
	}
}

// attemptSignUp contains the logic for a single sign-up attempt.
func (e *SignUpExecutor) attemptSignUp(ctx context.Context, action Action) *ExecutionResult {
	e.logger.Debug("attemptSignUp: Started")
	h := e.humanoidProvider()
	session := e.sessionProvider()
	// Defense in depth: Check providers availability at runtime.
	if h == nil || session == nil {
		e.logger.Error("Humanoid or Session provider returned nil during attempt.")
		return e.fail(ErrCodeExecutionFailure, "Internal error: Humanoid or Session provider not available", nil)
	}

	// 0. Pre-checks (CAPTCHA)
	e.logger.Debug("attemptSignUp: Step 0 - Checking CAPTCHA")
	if captchaDetected, details := e.detectCaptcha(ctx, session); captchaDetected {
		e.logger.Debug("attemptSignUp: CAPTCHA detected.")
		return e.fail(ErrCodeAuthCaptchaDetected, "CAPTCHA detected on the page, aborting sign-up.", details)
	}

	// 1. Capture Initial State (Auth State and URL)
	e.logger.Debug("attemptSignUp: Step 1 - Capturing Initial State")
	initialAuthState := e.getAuthState(ctx, session)
	initialURL, _ := e.getCurrentURL(ctx, session) // Best effort URL capture
	e.logger.Debug("attemptSignUp: Initial state captured", zap.Any("auth_state", initialAuthState), zap.String("url", initialURL))

	// 2. Analyze the form structure.
	e.logger.Debug("attemptSignUp: Step 2 - Analyzing Form")
	analysisResult, err := e.analyzeSignUpForm(ctx, session)
	if err != nil {
		// Logging handled within analyzeSignUpForm.
		e.logger.Warn("attemptSignUp: Form analysis failed.", zap.Error(err))
		return e.fail(ErrCodeElementNotFound, "Failed to analyze and identify the sign-up form.", map[string]interface{}{"error": err.Error()})
	}

	e.logger.Info("Successfully analyzed sign-up form", zap.Int("fields_found", len(analysisResult.Fields)))
	e.logger.Debug("attemptSignUp: Form analysis result", zap.Any("result", analysisResult))

	// 3. Generate User Data
	e.logger.Debug("attemptSignUp: Step 3 - Generating User Data")
	userData, err := e.generateUserData()
	if err != nil {
		// This occurs if secure password generation fails (crypto/rand error). This is non-retryable.
		e.logger.Error("attemptSignUp: Failed to generate user data", zap.Error(err))
		return e.fail(ErrCodeExecutionFailure, "Failed to generate secure user data.", map[string]interface{}{"error": err.Error()})
	}
	e.logger.Info("Generated user data for sign-up attempt",
		zap.String("username", userData.Username),
		zap.String("email", userData.Email),
		// Security Best Practice: Do not log passwords.
	)

	// 4. Fill form fields.
	e.logger.Debug("attemptSignUp: Step 4 - Filling Form")
	if errResult := e.fillForm(ctx, h, analysisResult, userData, action); errResult != nil {
		e.logger.Warn("attemptSignUp: Failed to fill form.", zap.String("error_code", string(errResult.ErrorCode)))
		return errResult
	}

	// 5. Handle Checkboxes (ToS/Privacy) - Best effort.
	e.logger.Debug("attemptSignUp: Step 5 - Handling Checkboxes")
	e.handleCheckboxes(ctx, h, analysisResult.ContextSelector)

	// 6. Submit the form (Multi-strategy).
	e.logger.Debug("attemptSignUp: Step 6 - Submitting Form")
	if err := e.submitForm(ctx, h, session, analysisResult); err != nil {
		e.logger.Warn("Failed to submit the form.", zap.Error(err))
		// Categorize the submission failure.
		code, details := ParseBrowserError(err, action)
		if code == ErrCodeExecutionFailure || code == ErrCodeElementNotFound {
			code = ErrCodeAuthWorkflowFailed
		}
		return e.fail(code, fmt.Sprintf("Failed to submit form: %v", err), details)
	}

	// 7. Wait for stabilization.
	e.logger.Info("Waiting for application stabilization after submission (WaitForAsync)...")
	e.logger.Debug("attemptSignUp: Step 7 - Stabilization Wait", zap.Int("wait_ms", stabilizationWaitMs))
	if err := session.WaitForAsync(ctx, stabilizationWaitMs); err != nil {
		// Timeout doesn't guarantee failure, proceed to verification.
		e.logger.Debug("WaitForAsync completed (potentially timed out), proceeding to verification.", zap.Error(err))
	}

	// 8. Verify the result.
	e.logger.Debug("attemptSignUp: Step 8 - Verifying Result")
	return e.verifySignUp(ctx, session, userData, initialAuthState, initialURL)
}

// analyzeSignUpForm executes the embedded formAnalysisScript in the browser context.
func (e *SignUpExecutor) analyzeSignUpForm(ctx context.Context, session schemas.SessionContext) (*formAnalysisResult, error) {

	// Allow a reasonable timeout for the script execution.
	scriptCtx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()

	// Downgraded logging level as this is an implementation detail.
	e.logger.Debug("Executing form analysis script",
		zap.Int("script_len", len(formAnalysisScript)),
	)
	// Execute the embedded script directly.
	// The script itself (form_analysis.js) is self-executing and returns the result as the last expression.
	// We previously wrapped this in an IIFE (e.g., fmt.Sprintf("(function() { %s })()", ...)),
	// but this is redundant as the JS structure handles execution context.

	e.logger.Debug("analyzeSignUpForm: Calling session.ExecuteScript with formAnalysisScript")
	// Use the raw formAnalysisScript directly.
	rawResult, err := session.ExecuteScript(scriptCtx, formAnalysisScript, []interface{}{})
	// Log the result from the mock/browser for diagnostics.
	e.logger.Debug("analyzeSignUpForm: session.ExecuteScript returned", zap.ByteString("rawResult", rawResult), zap.Error(err))

	if err != nil {
		e.logger.Error("Form analysis script execution failed.", zap.Error(err))
		return nil, fmt.Errorf("failed to execute form analysis script: %w", err)
	}

	// REFACTOR: Removed brittle check for `null` primitive.
	// The JS script returns a structured object, so we rely on Unmarshal and
	// subsequent validation to determine success or failure.
	if len(rawResult) == 0 {
		e.logger.Warn("Form analysis script returned empty response.")
		return nil, fmt.Errorf("analysis script returned no data")
	}

	var result formAnalysisResult
	// Robust unmarshaling.
	if err := json.Unmarshal(rawResult, &result); err != nil {
		e.logger.Error("Failed to unmarshal form analysis result", zap.ByteString("raw_result", rawResult), zap.Error(err))
		return nil, fmt.Errorf("failed to unmarshal form analysis result: %w", err)
	}

	// Validate the results to ensure essential components were identified.
	// This block now correctly catches failures where the script runs but
	// finds no suitable form, returning an "empty" result object.
	if result.SubmitSelector == "" && (result.ContextSelector == "" || result.ContextSelector == "body") {
		e.logger.Warn("Form analysis failed to identify submit button or form context.", zap.Any("analysis_result", result))
		return nil, fmt.Errorf("analysis completed but could not identify the submit button or form context")
	}

	// Check for essential fields (identifier AND password).
	hasIdentifier := result.Fields["email"] != "" || result.Fields["username"] != ""
	hasPassword := result.Fields["password"] != ""

	if !hasIdentifier || !hasPassword {
		// **FIX**: Corrected `hasAdditional` to `hasPassword`
		e.logger.Warn("Form analysis missed essential fields", zap.Bool("hasIdentifier", hasIdentifier), zap.Bool("hasPassword", hasPassword), zap.Any("fields", result.Fields))
		return nil, fmt.Errorf("form analysis missed essential fields (identifier or password)")
	}

	e.logger.Debug("analyzeSignUpForm: Analysis successful", zap.Any("result", result))
	return &result, nil
}

// getAuthState collects indicators of the user's authentication state (cookies, local/session storage keys).
func (e *SignUpExecutor) getAuthState(ctx context.Context, session schemas.SessionContext) map[string]interface{} {
	state := make(map[string]interface{})

	// Use a short timeout for state collection operations.
	stateCtx, cancel := context.WithTimeout(ctx, stateTimeout)
	defer cancel()

	// Collect storage keys. The JS script ensures sorting for deterministic comparison.
	// NOTE: Ensure the indentation and structure match exactly for reliable testing.
	script := `({
		localStorageKeys: Object.keys(window.localStorage || {}).sort(),
		sessionStorageKeys: Object.keys(window.sessionStorage || {}).sort()
	})`

	rawStorage, err := session.ExecuteScript(stateCtx, script, []interface{}{})
	if err == nil {
		var storageState map[string][]string
		if json.Unmarshal(rawStorage, &storageState) == nil {
			state["storage"] = storageState
		}
	} else {
		e.logger.Debug("Failed to collect storage state.", zap.Error(err))
	}

	// Collect cookies via CollectArtifacts.
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
	} else {
		e.logger.Debug("Failed to collect cookie state.", zap.Error(err))
	}

	return state
}

// detectCaptcha checks the page for common CAPTCHA indicators using JS execution.
func (e *SignUpExecutor) detectCaptcha(ctx context.Context, session schemas.SessionContext) (bool, map[string]interface{}) {
	detectCtx, cancel := context.WithTimeout(ctx, stateTimeout)
	defer cancel()

	// REFACTOR: Use the embedded script variable instead of hardcoded string.
	e.logger.Debug("detectCaptcha: Executing script")
	rawResult, err := session.ExecuteScript(detectCtx, captchaDetectionScript, []interface{}{})
	e.logger.Debug("detectCaptcha: Script returned", zap.ByteString("rawResult", rawResult), zap.Error(err))

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

// generateUserData creates a new set of realistic and compliant user data.
// It returns an error if secure data generation (password) fails.
func (e *SignUpExecutor) generateUserData() (*generatedUserData, error) {
	// Use math/rand for non-security sensitive randomization (usernames, emails).
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	// Robustness check: ensure lists are available.
	if e.seclists == nil || len(e.seclists.Usernames) == 0 || len(e.seclists.FirstNames) == 0 || len(e.seclists.LastNames) == 0 {
		e.logger.Error("SecLists data is unexpectedly empty during data generation. Using fallback.")
		return e.generateFallbackUserData(r)
	}

	// Select random entries.
	usernameBase := e.seclists.Usernames[r.Intn(len(e.seclists.Usernames))]
	firstName := e.seclists.FirstNames[r.Intn(len(e.seclists.FirstNames))]
	lastName := e.seclists.LastNames[r.Intn(len(e.seclists.LastNames))]

	// Generate a secure, compliant password.
	password, err := e.generateCompliantPassword()
	if err != nil {
		return nil, err
	}

	// Determine email domain.
	domain := e.getEmailDomain()

	// Create unique identifiers.
	uniqueSuffix := fmt.Sprintf("%d", r.Intn(1000000))
	email := fmt.Sprintf("%s.%s.%s@%s", strings.ToLower(firstName), strings.ToLower(lastName), uniqueSuffix, domain)
	username := fmt.Sprintf("%s_%s", strings.ToLower(usernameBase), uniqueSuffix)

	return &generatedUserData{
		Username:  username,
		Password:  password,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
	}, nil
}

// getEmailDomain retrieves the configured domain or a safe default.
func (e *SignUpExecutor) getEmailDomain() string {
	if e.signUpCfg != nil && e.signUpCfg.EmailDomain != "" {
		return e.signUpCfg.EmailDomain
	}
	return "example.com" // RFC 2606 reserved testing domain.
}

// generateFallbackUserData provides data if SecLists are unavailable.
func (e *SignUpExecutor) generateFallbackUserData(r *mrand.Rand) (*generatedUserData, error) {
	uniqueSuffix := fmt.Sprintf("%d", r.Intn(10000000))
	domain := e.getEmailDomain()

	password, err := e.generateCompliantPassword()
	if err != nil {
		return nil, err
	}

	return &generatedUserData{
		Username:  fmt.Sprintf("scalpel_fallback_%s", uniqueSuffix),
		Password:  password,
		Email:     fmt.Sprintf("scalpel.fallback.%s@%s", uniqueSuffix, domain),
		FirstName: "Scalpel",
		LastName:  "Fallback",
	}, nil
}

// generateCompliantPassword creates a password adhering to common complexity rules using cryptographically secure RNG (crypto/rand).
func (e *SignUpExecutor) generateCompliantPassword() (string, error) {
	// Define character sets, removing ambiguous characters for better usability.
	const lowerChars = "abcdefghijkmnopqrstuvwxyz"
	const upperChars = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const numberChars = "23456789"
	const symbolChars = "!@#$%^&*()_+-="
	const minLength = 16 // Strong minimum length (NIST recommendation)

	var password []byte
	var availableChars = lowerChars + upperChars + numberChars + symbolChars

	// Helper function to get a cryptographically secure random character from a charset.
	cryptoRandChar := func(charset string) (byte, error) {
		if len(charset) == 0 {
			return 0, fmt.Errorf("internal error: empty charset for password generation")
		}
		max := big.NewInt(int64(len(charset)))
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			// Failure in the underlying OS entropy source.
			return 0, fmt.Errorf("crypto/rand failure: %w", err)
		}
		return charset[n.Int64()], nil
	}

	// Ensure mandatory character types are present.
	mandatorySets := []string{upperChars, numberChars, symbolChars, lowerChars}
	for _, charset := range mandatorySets {
		char, err := cryptoRandChar(charset)
		if err != nil {
			return "", err
		}
		password = append(password, char)
	}

	// Fill the rest of the password up to MinLength.
	for len(password) < minLength {
		char, err := cryptoRandChar(availableChars)
		if err != nil {
			return "", err
		}
		password = append(password, char)
	}

	// Secure shuffle (Fisher-Yates) to ensure mandatory characters aren't predictably located.
	for i := len(password) - 1; i > 0; i-- {
		max := big.NewInt(int64(i + 1))
		jBig, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("crypto/rand failure during shuffle: %w", err)
		}
		j := jBig.Int64()
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

// fillForm handles the logic of mapping generated data to the analyzed fields and interacting with them.
func (e *SignUpExecutor) fillForm(ctx context.Context, h humanoid.Controller, analysis *formAnalysisResult, userData *generatedUserData, action Action) *ExecutionResult {
	dataMap := map[string]string{
		"firstName":       userData.FirstName,
		"lastName":        userData.LastName,
		"email":           userData.Email,
		"username":        userData.Username,
		"password":        userData.Password,
		"passwordConfirm": userData.Password, // Handle confirmation fields identically
	}

	// Use InteractionOptions to ensure the element is visible before typing.
	ensureVisible := true
	opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

	for fieldType, selector := range analysis.Fields {
		value, exists := dataMap[fieldType]
		if !exists || selector == "" {
			continue // Skip optional fields or those we couldn't identify.
		}

		e.logger.Debug("Filling field", zap.String("type", fieldType), zap.String("selector", selector))
		// Use humanoid typing for realistic interaction.
		if err := h.Type(ctx, selector, value, opts); err != nil {
			e.logger.Warn("Failed to fill identified field", zap.String("type", fieldType), zap.String("selector", selector), zap.Error(err))

			// Abort if an essential field fails.
			if fieldType == "email" || fieldType == "username" || fieldType == "password" {
				// Use ParseBrowserError to get structured error codes.
				errorCode, errorDetails := ParseBrowserError(err, action)
				if errorDetails == nil {
					errorDetails = make(map[string]interface{})
				}
				errorDetails["field_details"] = map[string]string{"type": fieldType, "selector": selector}
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
	// Ensure visibility before clicking.
	ensureVisible := true
	opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

	// Determine the search context.
	baseSelector := ""
	if contextSelector != "" && contextSelector != "body" {
		baseSelector = contextSelector + " " // Add space for descendant selection
	}

	for _, keyword := range keywords {
		// Look for checkboxes associated with these keywords via attributes (case-insensitive).
		selectors := []string{
			fmt.Sprintf(`%sinput[type="checkbox"][id*="%s" i]`, baseSelector, keyword),
			fmt.Sprintf(`%sinput[type="checkbox"][name*="%s" i]`, baseSelector, keyword),
			fmt.Sprintf(`%sinput[type="checkbox"][aria-label*="%s" i]`, baseSelector, keyword),
		}

		for _, selector := range selectors {
			// IntelligentClick handles visibility and checks if already checked.
			err := h.IntelligentClick(ctx, selector, opts)
			if err == nil {
				e.logger.Info("Successfully interacted with checkbox", zap.String("keyword", keyword), zap.String("selector", selector))
				// If successful, break to the next keyword group.
				break
			}
			// Log failure at debug level as this is best effort.
			e.logger.Debug("Failed to interact with potential checkbox selector", zap.String("selector", selector), zap.Error(err))
		}
	}
}

// submitForm implements the multi-strategy submission logic for robustness.
func (e *SignUpExecutor) submitForm(ctx context.Context, h humanoid.Controller, session schemas.SessionContext, analysis *formAnalysisResult) error {

	// Strategy 1: Click the identified submit button (Most realistic).
	if analysis.SubmitSelector != "" {
		e.logger.Debug("Attempting Strategy 1: Clicking analyzed submit button", zap.String("selector", analysis.SubmitSelector))
		ensureVisible := true
		opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}

		if err := h.IntelligentClick(ctx, analysis.SubmitSelector, opts); err == nil {
			e.logger.Info("Form submission initiated using Strategy 1 (Button Click).")
			return nil
		} else {
			e.logger.Warn("Strategy 1 (Button Click) failed. Proceeding to fallback strategies.", zap.Error(err))
		}
	}

	// Strategy 2: Direct JavaScript form submission.
	if analysis.ContextSelector != "" && analysis.ContextSelector != "body" {
		e.logger.Debug("Attempting Strategy 2: JS Form Submit using context selector", zap.String("selector", analysis.ContextSelector))

		// Robust JS snippet to trigger submission while respecting client-side validation.
		// Escape single quotes in the selector to prevent JS syntax errors.
		escapedSelector := strings.ReplaceAll(analysis.ContextSelector, "'", "\\'")
		script := fmt.Sprintf(`
			(function() {
				const form = document.querySelector('%s');
				if (form && (form instanceof HTMLFormElement)) {
					// Trigger 'submit' event first to activate client-side hooks (e.g., React/Angular).
					const event = new Event('submit', { bubbles: true, cancelable: true });
					form.dispatchEvent(event);
					
					// Proceed if not prevented by client-side validation.
					if (!event.defaultPrevented) {
						// Use requestSubmit if available (triggers HTML5 validation), otherwise submit().
						if (typeof form.requestSubmit === 'function') {
							form.requestSubmit();
						} else {
							form.submit();
						}
					}
					return true;
				}
				return false;
			})();
		`, escapedSelector)

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

	// Strategy 3: Press Enter on the password field (Implicit submission).
	passwordSelector := analysis.Fields["password"]
	if passwordSelector != "" {
		e.logger.Debug("Attempting Strategy 3: Enter Key Press on password field", zap.String("selector", passwordSelector))
		// Send the Enter key (newline character).
		ensureVisible := true
		opts := &humanoid.InteractionOptions{EnsureVisible: &ensureVisible}
		if err := h.Type(ctx, passwordSelector, "\n", opts); err == nil {
			e.logger.Info("Form submission initiated using Strategy 3 (Enter Key Press).")
			return nil
		} else {
			e.logger.Warn("Strategy 3 (Enter Key Press) failed.", zap.Error(err))
		}
	}

	return fmt.Errorf("all form submission strategies failed")
}

// verifySignUp checks if the sign-up was successful using a prioritized verification strategy.
func (e *SignUpExecutor) verifySignUp(ctx context.Context, session schemas.SessionContext, userData *generatedUserData, initialAuthState map[string]interface{}, initialURL string) *ExecutionResult {
	e.logger.Debug("verifySignUp: Started")

	// 1. Check for Authentication State Change (Strongest Indicator)
	e.logger.Debug("verifySignUp: Checking Auth State Change")
	currentAuthState := e.getAuthState(ctx, session)
	if e.compareAuthStates(initialAuthState, currentAuthState) {
		e.logger.Info("Sign-up successful: Authentication state changed (new cookies/storage).")
		return e.success(userData, map[string]interface{}{"verification_method": "auth_state_change"})
	}

	// 2. Check for URL Change (Strong indicator)
	e.logger.Debug("verifySignUp: Checking URL Change")
	currentURL, _ := e.getCurrentURL(ctx, session)
	if initialURL != "" && currentURL != "" && initialURL != currentURL {
		// Heuristic check for error indicators in the new URL.
		lowerURL := strings.ToLower(currentURL)
		if !strings.Contains(lowerURL, "error") && !strings.Contains(lowerURL, "fail") && !strings.Contains(lowerURL, "denied") {
			e.logger.Info("Sign-up likely successful: URL changed.", zap.String("from", initialURL), zap.String("to", currentURL))
			return e.success(userData, map[string]interface{}{"verification_method": "url_change", "new_url": currentURL})
		}
	}

	// 3. Analyze Network Traffic (HAR) for the submission request.
	e.logger.Debug("verifySignUp: Checking Network Traffic")
	if result := e.verifyNetworkTraffic(ctx, session, userData); result != nil {
		e.logger.Debug("verifySignUp: Network verification conclusive.", zap.String("status", result.Status))
		return result
	}

	// 4. Fallback: Check DOM for success/error indicators.
	e.logger.Info("Auth state, URL change, and Network verification inconclusive. Falling back to DOM analysis.")
	e.logger.Debug("verifySignUp: Checking DOM")
	return e.verifySignUpDOM(ctx, session, userData)
}

// verifyNetworkTraffic analyzes recent HAR data for submission status codes.
func (e *SignUpExecutor) verifyNetworkTraffic(ctx context.Context, session schemas.SessionContext, userData *generatedUserData) *ExecutionResult {
	artifactCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	artifacts, err := session.CollectArtifacts(artifactCtx)

	if err != nil || artifacts == nil || artifacts.HAR == nil {
		e.logger.Warn("Failed to collect HAR artifacts for network verification.", zap.Error(err))
		return nil // Inconclusive
	}

	var harData schemas.HAR
	if err := json.Unmarshal(*artifacts.HAR, &harData); err != nil {
		e.logger.Warn("Failed to unmarshal HAR data during verification", zap.Error(err))
		return nil // Inconclusive
	}

	// Look at requests that occurred recently (since submission).
	lookbackDuration := 15 * time.Second
	now := time.Now()

	// Iterate backwards (most recent first).
	for i := len(harData.Log.Entries) - 1; i >= 0; i-- {
		entry := harData.Log.Entries[i]

		if now.Sub(entry.StartedDateTime) > lookbackDuration {
			break
		}

		// Check for submission methods (POST/PUT).
		method := entry.Request.Method
		if method == "POST" || method == "PUT" {
			statusCode := entry.Response.Status
			e.logger.Debug("Analyzing network request during verification", zap.String("method", method), zap.Int("status", statusCode), zap.String("url", entry.Request.URL))

			// Success codes (200-202, 3xx)
			if (statusCode >= 200 && statusCode <= 202) || (statusCode >= 300 && statusCode < 400) {
				e.logger.Info("Sign-up likely successful: Network request indicated success.", zap.Int("status", statusCode))
				return e.success(userData, map[string]interface{}{"verification_method": "network", "status_code": statusCode})
			}

			// Failure codes (Validation/Conflict)
			if statusCode == 400 || statusCode == 409 || statusCode == 422 || statusCode == 403 {
				e.logger.Warn("Sign-up failed: Network request indicated failure (validation or conflict).", zap.Int("status", statusCode))
				return e.fail(ErrCodeAuthValidationFailed, "Sign-up API request failed (validation or conflict).", map[string]interface{}{"status_code": statusCode})
			}

			// Server errors (5xx)
			if statusCode >= 500 {
				e.logger.Warn("Sign-up failed: Network request indicated server error.", zap.Int("status", statusCode))
				return e.fail(ErrCodeAuthWorkflowFailed, "Sign-up API request failed (server error).", map[string]interface{}{"status_code": statusCode})
			}
		}
	}

	return nil // Inconclusive
}

// verifySignUpDOM performs DOM-based verification checks using the embedded JS scripts.
func (e *SignUpExecutor) verifySignUpDOM(ctx context.Context, session schemas.SessionContext, userData *generatedUserData) *ExecutionResult {

	// Check DOM for success indicators. Execute script directly (it is self-executing).
	// Removed redundant IIFE wrapper.
	e.logger.Debug("verifySignUpDOM: Executing success script")
	rawSuccessResult, err := session.ExecuteScript(ctx, verificationSuccessScript, nil)
	e.logger.Debug("verifySignUpDOM: Success script returned", zap.ByteString("rawResult", rawSuccessResult), zap.Error(err))

	if err == nil {
		var successIndicator *string
		if err := json.Unmarshal(rawSuccessResult, &successIndicator); err == nil && successIndicator != nil {
			e.logger.Info("Sign-up successful: Found success indicator in DOM.", zap.String("indicator", *successIndicator))
			return e.success(userData, map[string]interface{}{"verification_method": "dom", "indicator": *successIndicator})
		}
	} else {
		e.logger.Warn("Failed to execute success verification script.", zap.Error(err))
	}

	// Check DOM for error indicators. Execute script directly (it is self-executing).
	// Removed redundant IIFE wrapper.
	e.logger.Debug("verifySignUpDOM: Executing error script")
	rawErrorResult, err := session.ExecuteScript(ctx, verificationErrorScript, nil)
	e.logger.Debug("verifySignUpDOM: Error script returned", zap.ByteString("rawResult", rawErrorResult), zap.Error(err))

	if err == nil {
		var errorIndicator *string
		if err := json.Unmarshal(rawErrorResult, &errorIndicator); err == nil && errorIndicator != nil {
			e.logger.Warn("Sign-up failed: Found error indicator in DOM.", zap.String("indicator", *errorIndicator))

			// Attempt to classify the error (Validation vs Workflow).
			indicatorText := strings.ToLower(*errorIndicator)
			validationKeywords := []string{"taken", "exists", "already in use", "weak", "mismatch", "invalid", "required"}
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

// compareAuthStates checks if the current auth state is different from the initial state using JSON serialization.
func (e *SignUpExecutor) compareAuthStates(initial, current map[string]interface{}) bool {
	// Serialize both states to JSON for a simple, deep comparison.
	initialJSON, err1 := json.Marshal(initial)
	currentJSON, err2 := json.Marshal(current)

	if err1 != nil || err2 != nil {
		e.logger.Error("Failed to marshal auth states for comparison.", zap.Error(err1), zap.Error(err2))
		return false
	}

	// If the serialized states differ, it indicates a change in the session fingerprint.
	return string(initialJSON) != string(currentJSON)
}

// getCurrentURL retrieves the current browser URL.
func (e *SignUpExecutor) getCurrentURL(ctx context.Context, session schemas.SessionContext) (string, error) {
	urlCtx, cancel := context.WithTimeout(ctx, stateTimeout)
	defer cancel()

	rawURL, err := session.ExecuteScript(urlCtx, "window.location.href", []interface{}{})
	if err != nil {
		e.logger.Debug("Failed to get current URL.", zap.Error(err))
		return "", err
	}
	var url string
	if err := json.Unmarshal(rawURL, &url); err != nil {
		return "", err
	}
	return url, nil
}

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
		Status:          "failed",
		ObservationType: ObservedAuthResult,
		ErrorCode:       code,
		ErrorDetails:    details,
		Data:            data,
	}
}

// success is a helper function to generate a standardized successful ExecutionResult,
// including KG updates for the new user account.
func (e *SignUpExecutor) success(userData *generatedUserData, data map[string]interface{}) *ExecutionResult {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["action"] = "SIGN_UP"
	data["status"] = "SUCCESS"
	data["username"] = userData.Username
	data["email"] = userData.Email
	// Security Best Practice: Do NOT store the password in the observation data.

	// Create a Knowledge Graph update to record the successful creation of the account.
	accountID := fmt.Sprintf("account:email:%s", userData.Email)

	propsMap := map[string]interface{}{
		"username":   userData.Username,
		"email":      userData.Email,
		"first_name": userData.FirstName,
		"last_name":  userData.LastName,
		"source":     "AutonomousSignUp",
		// Store the password securely in the KG properties for potential later use.
		"password": userData.Password,
	}
	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		e.logger.Error("Failed to marshal KG properties for new account.", zap.Error(err))
	}

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
