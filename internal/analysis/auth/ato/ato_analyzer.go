// internal/analysis/auth/ato/analyzer.go
package ato

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// loginResult represents the semantic outcome of a single login attempt.
type loginResult int

const (
	loginUnknown loginResult = iota
	loginSuccess
	loginMFAChallenge   // Indicates primary credentials are valid, but MFA is required.
	loginFailureUser    // Indicates the username was likely invalid (via keyword).
	loginFailurePass    // Indicates the username was valid, but the password was not (via keyword).
	loginFailureGeneric // A generic failure message that doesn't leak information.
	loginFailureLockout
	loginFailureDifferential // A failure response that differs from the baseline (content/structure).
	loginFailureTiming       // A failure response with significantly different timing, indicating enumeration.
)

// Constants for analysis tuning
const (
	maxResponseSize       = 2 * 1024 * 1024 // 2MB limit for responses read in the browser
	baselineSamples       = 3               // Number of samples to establish baseline
	timingThresholdFactor = 2.0             // How much slower a response must be (relative) to flag timing enumeration
	timingMinDifferenceMs = 100.0           // Minimum absolute difference (ms) required to flag timing enumeration
)

// loginAttempt holds all necessary, parsed information to replay a login request.
type loginAttempt struct {
	URL          string
	Method       string
	ContentType  string
	UserField    string
	PassField    string
	IsEmailBased bool // Helps generate format-aware baseline credentials
	BodyParams   map[string]interface{}
	Headers      map[string]string
}

// baselineFailure captures the signature of a known-invalid login response.
type baselineFailure struct {
	Status           int
	LengthNormalized int
	BodyHash         [32]byte // Hash of the normalized body
	AvgResponseTime  float64  // Average response time for baseline requests
}

// csrfToken holds the name and value for an anti-forgery token.
// Added JSON tags for unmarshaling from ExecuteScript results.
type csrfToken struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// endpointIdentifier creates a unique string for a given method and URL to track tested endpoints.
func (la *loginAttempt) endpointIdentifier() string {
	return fmt.Sprintf("%s-%s", la.Method, la.URL)
}

// credentialFieldHeuristics maps common parameter names to the credential type.
var credentialFieldHeuristics = map[string]string{
	"username": "user", "user": "user", "email": "user", "login": "user", "user_id": "user", "uid": "user",
	"password": "pass", "pass": "pass", "secret": "pass", "credential": "pass", "pwd": "pass",
}

// csrfFieldHeuristics provides CSS selectors and meta tag names to find common CSRF tokens.
// Enhanced to include meta tags.
var csrfFieldHeuristics = []string{
	`input[type=hidden][name*=csrf]`,
	`input[type=hidden][name*=token]`,
	`input[type=hidden][name*=_token]`,
	`input[type=hidden][name*=nonce]`,
	`meta[name*=csrf]`,
	`meta[name*=token]`,
}

// dynamicContentRegex is used to normalize response bodies by replacing dynamic elements.
var dynamicContentRegex = regexp.MustCompile(
	// UUIDs
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|` +
		// CSRF/Request Tokens (heuristic: long hex/base64 strings)
		`[A-Za-z0-9+/=_-]{32,}|` +
		// Timestamps (Unix epoch/milliseconds)
		`\b\d{10,13}\b`,
)

// HumanoidProvider defines a simple interface used to check if a SessionContext
// can provide access to a `humanoid.Humanoid` controller. This allows for
// optional, graceful integration with the humanoid module for more realistic pauses.
type HumanoidProvider interface {
	GetHumanoid() *humanoid.Humanoid
}

// ATOAnalyzer is a specialized active analyzer that tests login endpoints for
// account takeover vulnerabilities, such as credential stuffing and username
// enumeration. It operates by discovering login forms in captured HTTP traffic
// and replaying them with a list of common credentials.
type ATOAnalyzer struct {
	*core.BaseAnalyzer
	cfg           *config.ATOConfig
	rng           *rand.Rand
	credentialSet []schemas.Credential
}

// NewATOAnalyzer creates a new instance of the ATOAnalyzer, loading its
// configuration and the credential set it will use for testing.
func NewATOAnalyzer(cfg config.Interface, logger *zap.Logger) (*ATOAnalyzer, error) {
	// Use the public Scanners() getter method instead of direct field access.
	atoCfg := cfg.Scanners().Active.Auth.ATO
	creds, err := loadCredentialSet(atoCfg.CredentialFile, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ATO analyzer: %w", err)
	}

	return &ATOAnalyzer{
		BaseAnalyzer: core.NewBaseAnalyzer(
			"Account Takeover",
			"Actively tests login endpoints for credential stuffing and enumeration vulnerabilities.",
			core.TypeActive,
			logger,
		),
		cfg:           &atoCfg,
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
		credentialSet: creds,
	}, nil
}

// loadCredentialSet loads the list of username/password pairs to be tested from
// a specified file or falls back to a small, internal default list if no file
// is provided.
func loadCredentialSet(filePath string, logger *zap.Logger) ([]schemas.Credential, error) {
	if filePath == "" {
		logger.Warn("No credential file specified in config, using internal default list for ATO analysis.")
		return []schemas.Credential{
			{Username: "admin", Password: "password"},
			{Username: "admin", Password: "password123"},
			{Username: "admin", Password: "admin"},
			{Username: "root", Password: "root"},
			{Username: "test", Password: "test"},
			{Username: "guest", Password: "guest"},
		}, nil
	}
	// Production logic to read and parse a credential file would go here.
	return nil, fmt.Errorf("credential file loading not yet implemented for path: %s", filePath)
}

// Analyze is the main entry point for the ATO analysis.
func (a *ATOAnalyzer) Analyze(ctx context.Context, analysisCtx schemas.SessionContext) error {
	if !a.cfg.Enabled {
		a.Logger.Info("ATO analysis is disabled by configuration.")
		return nil
	}

	// CollectArtifacts now requires the context.
	artifacts, err := analysisCtx.CollectArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("ATO analyzer failed to collect artifacts: %w", err)
	}

	// Handle HAR data unmarshaling as it's defined as *json.RawMessage in schemas.
	if artifacts.HAR == nil {
		a.Logger.Info("No HAR data collected, cannot discover login endpoints.")
		return nil
	}

	var harData schemas.HAR
	if err := json.Unmarshal(*artifacts.HAR, &harData); err != nil {
		return fmt.Errorf("failed to unmarshal HAR data: %w", err)
	}

	loginAttempts := a.discoverLoginEndpoints(&harData)
	if len(loginAttempts) == 0 {
		a.Logger.Info("No potential login endpoints were found to test.")
		return nil
	}

	var wg sync.WaitGroup
	jobs := make(chan *loginAttempt, len(loginAttempts))
	results := make(chan schemas.Finding, len(loginAttempts)*2)

	numWorkers := a.cfg.Concurrency
	if numWorkers <= 0 {
		numWorkers = 4 // A sensible default.
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go a.worker(ctx, &wg, analysisCtx, jobs, results)
	}

	for _, attempt := range loginAttempts {
		jobs <- attempt
	}
	close(jobs)

	wg.Wait()
	close(results)

	for finding := range results {
		// Handle potential error returned by AddFinding.
		if err := analysisCtx.AddFinding(ctx, finding); err != nil {
			a.Logger.Error("Failed to report finding via SessionContext", zap.Error(err))
		}
	}

	return nil
}

// parses HAR artifacts to find unique login requests.
func (a *ATOAnalyzer) discoverLoginEndpoints(harData *schemas.HAR) map[string]*loginAttempt {
	loginAttempts := make(map[string]*loginAttempt)
	if harData == nil {
		return loginAttempts
	}

	for _, entry := range harData.Log.Entries {
		if attempt, err := a.identifyLoginRequest(entry.Request); err == nil {
			id := attempt.endpointIdentifier()
			if _, exists := loginAttempts[id]; !exists {
				loginAttempts[id] = attempt
				a.Logger.Info("Potential login endpoint identified.", zap.String("url", attempt.URL))
			}
		}
	}
	return loginAttempts
}

// worker is a concurrent routine that pulls login attempts from the jobs channel and tests them.
func (a *ATOAnalyzer) worker(ctx context.Context, wg *sync.WaitGroup, analysisCtx schemas.SessionContext, jobs <-chan *loginAttempt, results chan<- schemas.Finding) {
	defer wg.Done()
	for attempt := range jobs {
		// Basic SSRF Protection: Validate URL before processing (CWE-918 mitigation).
		if !a.isValidTargetURL(attempt.URL) {
			a.Logger.Warn("Skipping potentially unsafe URL identified in HAR data.", zap.String("url", attempt.URL))
			continue
		}

		findings := a.testEndpoint(ctx, analysisCtx, attempt)
		for _, finding := range findings {
			select {
			case results <- finding:
			case <-ctx.Done():
				return
			}
		}
	}
}

// isValidTargetURL performs basic checks to mitigate SSRF risks.
// In a production environment, this should be more robust, integrating with network policies and scope configuration.
func (a *ATOAnalyzer) isValidTargetURL(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// Ensure it's HTTP/HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Basic check against localhost/loopback.
	if u.Hostname() == "localhost" || strings.HasPrefix(u.Hostname(), "127.") || u.Hostname() == "[::1]" {
		// Logged for visibility, allowed for flexibility (e.g., testing local apps).
		a.Logger.Debug("Processing request to loopback address.", zap.String("host", u.Hostname()))
	}

	return true
}

// identifyLoginRequest parses a request to determine if it's a login attempt.
func (a *ATOAnalyzer) identifyLoginRequest(req schemas.Request) (*loginAttempt, error) {
	if req.Method != http.MethodPost || req.PostData == nil {
		return nil, fmt.Errorf("not a POST request with data")
	}

	contentType := req.PostData.MimeType
	bodyParams := make(map[string]interface{})
	var userField, passField string
	isEmailBased := false

	switch {
	case strings.Contains(contentType, "application/json"):
		if err := json.Unmarshal([]byte(req.PostData.Text), &bodyParams); err != nil {
			return nil, fmt.Errorf("could not parse JSON body: %w", err)
		}
		for key := range bodyParams {
			keyLower := strings.ToLower(key)
			if fieldType, ok := credentialFieldHeuristics[keyLower]; ok {
				if fieldType == "user" && userField == "" {
					userField = key
					if keyLower == "email" {
						isEmailBased = true
					}
				} else if fieldType == "pass" && passField == "" {
					passField = key
				}
			}
		}
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		for _, p := range req.PostData.Params {
			bodyParams[p.Name] = p.Value
			keyLower := strings.ToLower(p.Name)
			if fieldType, ok := credentialFieldHeuristics[keyLower]; ok {
				if fieldType == "user" && userField == "" {
					userField = p.Name
					if keyLower == "email" {
						isEmailBased = true
					}
				} else if fieldType == "pass" && passField == "" {
					passField = p.Name
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}

	if userField != "" && passField != "" {
		headers := make(map[string]string)
		for _, h := range req.Headers {
			// Exclude headers managed by the browser (like Content-Length, Host).
			// Keep cookies derived from the HAR file initially, as they might be necessary (e.g., device fingerprints).
			// The browser fetch call ('include' mode) will handle session management.
			if !strings.EqualFold(h.Name, "Content-Length") && !strings.EqualFold(h.Name, "Host") {
				headers[h.Name] = h.Value
			}
		}
		// Ensure Content-Type is set correctly if not already present in headers map.
		// Check case-insensitively.
		hasContentType := false
		for k := range headers {
			if strings.EqualFold(k, "Content-Type") {
				hasContentType = true
				break
			}
		}
		if !hasContentType && contentType != "" {
			headers["Content-Type"] = contentType
		}

		return &loginAttempt{
			URL:          req.URL,
			Method:       req.Method,
			ContentType:  contentType,
			UserField:    userField,
			PassField:    passField,
			IsEmailBased: isEmailBased,
			BodyParams:   bodyParams,
			Headers:      headers,
		}, nil
	}

	return nil, fmt.Errorf("did not find distinct user and password fields")
}

// testEndpoint executes the credential stuffing and enumeration attack against a single endpoint.
func (a *ATOAnalyzer) testEndpoint(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt) []schemas.Finding {
	var findings []schemas.Finding
	userEnumerationDetected := false
	var enumerationEvidence string

	// --- Humanoid Integration: Retrieve Controller ---
	var h *humanoid.Humanoid
	if provider, ok := analysisCtx.(HumanoidProvider); ok {
		h = provider.GetHumanoid()
	}

	if h == nil {
		a.Logger.Debug("Humanoid controller not available in SessionContext, using legacy pauses.")
	}
	// ---------------------------------------------------

	a.Logger.Debug("Establishing baseline failure response", zap.String("url", attempt.URL))
	// Enhanced baseline establishment (multi-sample, format-aware)
	baseline, err := a.establishBaseline(ctx, analysisCtx, attempt)
	if err != nil {
		a.Logger.Error("Could not establish a reliable baseline for login endpoint, enumeration checks are disabled for this target.",
			zap.String("url", attempt.URL), zap.Error(err))
		// If baseline fails, set it to nil to disable differential/timing analysis.
		baseline = nil
	}

	for _, creds := range a.credentialSet {
		if ctx.Err() != nil {
			a.Logger.Warn("ATO analysis cancelled during testing.", zap.Error(ctx.Err()))
			return findings
		}

		// Pass only the context and the humanoid controller to executePause.
		if err := a.executePause(ctx, h); err != nil {
			// Check if the error was due to context cancellation.
			if ctx.Err() != nil {
				a.Logger.Warn("ATO analysis cancelled during pause.", zap.Error(ctx.Err()))
				return findings
			}
			// Log other potential errors during the pause execution, but continue.
			a.Logger.Warn("Error during execution pause, proceeding.", zap.Error(err))
		}

		token, err := a.getFreshCSRFToken(ctx, analysisCtx, attempt.URL)
		if err != nil {
			// Only warn if the context wasn't cancelled.
			if ctx.Err() == nil {
				a.Logger.Warn("Failed to fetch fresh CSRF token, continuing without it.", zap.Error(err))
			}
		}

		a.Logger.Debug("Attempting login", zap.String("username", creds.Username), zap.String("url", attempt.URL))
		// Use 'include' credentials mode to allow session-bound CSRF tokens to work.
		response, err := a.executeLoginAttempt(ctx, analysisCtx, attempt, creds, token, "include")
		if err != nil {
			if ctx.Err() == nil {
				a.Logger.Error("Failed to execute login attempt", zap.Error(err), zap.String("url", attempt.URL))
			}
			continue
		}

		result := a.analyzeLoginResponse(response, baseline)

		// Handle Success or MFA
		if result == loginSuccess || result == loginMFAChallenge {
			// VULN FIX: CWE-312 - Redact the password from the evidence string.
			evidence := fmt.Sprintf("Successfully authenticated primary credentials for %s with username '%s' (password redacted).", attempt.URL, creds.Username)
			if result == loginMFAChallenge {
				evidence += " An MFA challenge was detected."
			}
			findings = append(findings, a.createCredentialStuffingFinding(attempt, evidence, userEnumerationDetected, result == loginMFAChallenge))
			// Stop testing this endpoint after finding valid credentials.
			return findings
		}

		// Handle Enumeration Detection
		if !userEnumerationDetected {
			switch result {
			case loginFailurePass:
				userEnumerationDetected = true
				enumerationEvidence = fmt.Sprintf("Detected via keyword analysis: The response indicated an incorrect password for user '%s', confirming the username is valid.", creds.Username)
			case loginFailureDifferential:
				userEnumerationDetected = true
				enumerationEvidence = fmt.Sprintf("Detected via differential analysis: The response for user '%s' differed structurally from the baseline 'invalid user' response.", creds.Username)
			case loginFailureTiming:
				userEnumerationDetected = true
				enumerationEvidence = fmt.Sprintf("Detected via timing analysis: The response time for user '%s' (%.2fms) was significantly longer than the baseline (%.2fms).", creds.Username, response.TimeMs, baseline.AvgResponseTime)
			}
		}
	}

	if userEnumerationDetected {
		evidence := fmt.Sprintf("The login mechanism at %s allows for username enumeration. %s", attempt.URL, enumerationEvidence)
		findings = append(findings, a.createUserEnumerationFinding(attempt, evidence))
	}
	return findings
}

// normalizeBody applies normalization rules to remove dynamic content, making differential analysis more robust.
func normalizeBody(body string) string {
	// Replace known dynamic patterns with placeholders.
	normalized := dynamicContentRegex.ReplaceAllString(body, "DYNAMIC_VALUE")
	return normalized
}

// establishBaseline sends multiple requests with random credentials to establish a reliable baseline of a failed login.
// It incorporates format awareness and consistency checks.
func (a *ATOAnalyzer) establishBaseline(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt) (*baselineFailure, error) {
	var samples []*fetchResponse
	var normalizedBodies []string
	var totalTime float64

	for i := 0; i < baselineSamples; i++ {
		// Generate format-aware random credentials
		randomUser := uuid.NewString()
		if attempt.IsEmailBased {
			randomUser = fmt.Sprintf("%s@example.com", randomUser)
		}
		randomCreds := schemas.Credential{
			Username: randomUser,
			Password: uuid.NewString(),
		}

		token, err := a.getFreshCSRFToken(ctx, analysisCtx, attempt.URL)
		if err != nil {
			if ctx.Err() == nil {
				a.Logger.Warn("Failed to get CSRF token for baseline request.", zap.Error(err))
			}
			// Continue without token if fetching fails, might affect baseline quality.
		}

		// Use 'include' credentials mode for baseline requests as well, for consistency.
		res, err := a.executeLoginAttempt(ctx, analysisCtx, attempt, randomCreds, token, "include")
		if err != nil {
			return nil, fmt.Errorf("baseline attempt %d failed: %w", i+1, err)
		}
		samples = append(samples, res)
		normalized := normalizeBody(res.Body)
		normalizedBodies = append(normalizedBodies, normalized)
		totalTime += res.TimeMs

		// Small pause between baseline samples
		time.Sleep(50 * time.Millisecond)
	}

	// Analyze consistency. All samples should ideally have the same status code and normalized body.
	firstStatus := samples[0].Status
	firstNormalizedBody := normalizedBodies[0]
	firstHash := sha256.Sum256([]byte(firstNormalizedBody))

	for i := 1; i < baselineSamples; i++ {
		if samples[i].Status != firstStatus {
			return nil, fmt.Errorf("baseline inconsistent: status codes differ (%d vs %d)", firstStatus, samples[i].Status)
		}
		if normalizedBodies[i] != firstNormalizedBody {
			// If normalization fails to stabilize the content, the endpoint is too dynamic.
			return nil, fmt.Errorf("baseline inconsistent: normalized bodies differ (sample 0 vs %d). Endpoint might be too dynamic.", i)
		}
	}

	return &baselineFailure{
		Status:           firstStatus,
		LengthNormalized: len(firstNormalizedBody),
		BodyHash:         firstHash,
		AvgResponseTime:  totalTime / float64(baselineSamples),
	}, nil
}

// getFreshCSRFToken navigates to the login page and attempts to scrape a CSRF token value using the SessionContext.
// Enhanced to look in meta tags and potentially JS variables.
func (a *ATOAnalyzer) getFreshCSRFToken(ctx context.Context, analysisCtx schemas.SessionContext, pageURL string) (*csrfToken, error) {

	// --- Humanoid Integration: Retrieve Controller ---
	var h *humanoid.Humanoid
	if provider, ok := analysisCtx.(HumanoidProvider); ok {
		h = provider.GetHumanoid()
	}
	// ---------------------------------------------------

	// 1. Pre-navigation pause (Cognitive planning)
	if h != nil {
		// Call CognitivePause directly using the operation context 'ctx'.
		if err := h.CognitivePause(ctx, 300, 100); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("context cancelled during pre-navigation pause: %w", err)
			}
			a.Logger.Debug("Humanoid cognitive pause failed before navigation", zap.Error(err))
		}
	}

	// 2. Navigate using the SessionContext interface
	if err := analysisCtx.Navigate(ctx, pageURL); err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	// 3. Wait for the page to stabilize
	// WaitForAsync(0) waits for network idle and stabilization.
	if err := analysisCtx.WaitForAsync(ctx, 0); err != nil {
		// Log this error, but we might still be able to scrape if the DOM is partially ready.
		a.Logger.Warn("Waiting for page stabilization failed, proceeding with scraping attempt.", zap.Error(err), zap.String("url", pageURL))
	}

	// 4. Post-navigation pause (Visual scanning of the page)
	if h != nil {
		if err := h.CognitivePause(ctx, 500, 200); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("context cancelled during post-navigation pause: %w", err)
			}
			a.Logger.Debug("Humanoid cognitive pause failed after navigation", zap.Error(err))
		}
	}

	// 5. Scrape CSRF token using JavaScript execution.
	// The script iterates over the provided selectors (passed as arguments) and returns the first match.
	// Enhanced script to handle input fields and meta tags.
	script := `
		(function(selectors) {
			for (const selector of selectors) {
				const el = document.querySelector(selector);
				if (el) {
					let name = el.getAttribute('name');
					let value = '';

					if (el.tagName.toLowerCase() === 'meta') {
						// For meta tags, the value is in the 'content' attribute.
						value = el.getAttribute('content');
					} else if (el.tagName.toLowerCase() === 'input') {
						// For input fields, the value is in the 'value' attribute.
						value = el.getAttribute('value');
					}

					if (name && value) {
						// Return the object directly, matching JSON tags in csrfToken struct.
						return { name: name, value: value };
					}
				}
			}

			// Optional Enhancement: Check common JS variables if DOM scraping fails
			const jsVars = ['csrfToken', 'REQUEST_TOKEN', 'NONCE'];
			for (const varName of jsVars) {
				if (typeof window[varName] === 'string' && window[varName].length > 0) {
					return { name: varName, value: window[varName] };
				}
			}

			return null; // No token found
		})(arguments[0]);
	`

	// Prepare arguments for ExecuteScript
	args := []interface{}{csrfFieldHeuristics}

	// Brief hesitation during scraping (simulating visual search)
	if h != nil {
		// Call Hesitate directly.
		if err := h.Hesitate(ctx, 50*time.Millisecond); err != nil {
			a.Logger.Debug("Humanoid hesitation failed during CSRF scraping", zap.Error(err))
		}
	}

	resultRaw, err := analysisCtx.ExecuteScript(ctx, script, args)
	if err != nil {
		return nil, fmt.Errorf("failed to execute CSRF scraping script: %w", err)
	}

	// Check if the result is null (no token found)
	if resultRaw == nil || string(resultRaw) == "null" {
		a.Logger.Debug("No CSRF token found on page.", zap.String("url", pageURL))
		return nil, nil // No token found, but not an error
	}

	// Unmarshal the result into the csrfToken struct
	var token csrfToken
	if err := json.Unmarshal(resultRaw, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CSRF token data from script result: %w", err)
	}

	if token.Name != "" && token.Value != "" {
		a.Logger.Debug("Found CSRF token", zap.String("name", token.Name), zap.String("value", "REDACTED"))
		return &token, nil
	}

	return nil, nil
}

// fetchResponse is a struct to unmarshal the structured JSON response from the browser fetch call.
type fetchResponse struct {
	Body       string  `json:"body"`
	Status     int     `json:"status"`
	StatusText string  `json:"statusText"`
	Error      string  `json:"error"`
	TimeMs     float64 `json:"timeMs"` // Added response time measurement
}

// executeLoginAttempt safely replays a modified login request using the browser's fetch API via the SessionContext.
// credentialsMode controls how the browser handles cookies ('omit', 'include', 'same-origin').
func (a *ATOAnalyzer) executeLoginAttempt(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt, creds schemas.Credential, token *csrfToken, credentialsMode string) (*fetchResponse, error) {
	// 1. Prepare the request body
	bodyParams := make(map[string]interface{})
	for k, v := range attempt.BodyParams {
		bodyParams[k] = v
	}
	bodyParams[attempt.UserField] = creds.Username
	bodyParams[attempt.PassField] = creds.Password
	if token != nil && token.Name != "" {
		bodyParams[token.Name] = token.Value
	}

	var bodyString string
	if strings.Contains(attempt.ContentType, "application/json") {
		bodyBytes, err := json.Marshal(bodyParams)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal new JSON body: %w", err)
		}
		bodyString = string(bodyBytes)
	} else { // Assume form-urlencoded
		values := url.Values{}
		for k, v := range bodyParams {
			// Ensure values are strings when encoding form data.
			values.Add(k, fmt.Sprintf("%v", v))
		}
		bodyString = values.Encode()
	}

	// 2. Define the script (using arguments instead of fmt.Sprintf for safety and clarity)
	// The script executes an async fetch, measures time, and implements a response size limit.
	script := `
		(async (url, method, headers, body, credentialsMode, maxSize) => {
			const startTime = performance.now();
			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

				const response = await fetch(url, {
					method: method,
					headers: headers,
					body: body,
					credentials: credentialsMode,
					redirect: 'manual',  // Handle redirects manually
					signal: controller.signal,
				});

				clearTimeout(timeoutId);

				// Read response body with size limit (CWE-400 mitigation)
				let responseBody = '';
				const reader = response.body.getReader();
				const decoder = new TextDecoder();
				let receivedLength = 0;
				let truncated = false;

				while(true) {
					const {done, value} = await reader.read();
					if (done) break;

					const chunk = decoder.decode(value, {stream: true});
                    receivedLength += chunk.length;

					if (receivedLength > maxSize) {
						// Append only the part of the chunk that fits within the limit
						responseBody += chunk.substring(0, maxSize - (receivedLength - chunk.length));
						truncated = true;
						// Abort the reading process
						reader.cancel();
						break;
					}
					responseBody += chunk;
				}

				if (truncated) {
					responseBody += "... [TRUNCATED]";
				}

				const endTime = performance.now();
				// Return the structured object directly.
				return {
					body: responseBody,
					status: response.status,
					statusText: response.statusText,
					error: '',
					timeMs: endTime - startTime
				};
			} catch (e) {
				const endTime = performance.now();
				// Handle network errors (CORS, connection refused, timeout, etc.)
				return { body: '', status: 0, statusText: '', error: e.message, timeMs: endTime - startTime };
			}
		})(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
	`

	// 3. Prepare arguments for ExecuteScript
	args := []interface{}{
		attempt.URL,
		attempt.Method,
		attempt.Headers,
		bodyString,
		credentialsMode,
		maxResponseSize,
	}

	// 4. Execute the script using the SessionContext interface
	responseRaw, err := analysisCtx.ExecuteScript(ctx, script, args)
	if err != nil {
		return nil, fmt.Errorf("ExecuteScript failed for login attempt: %w", err)
	}

	// 5. Unmarshal the result
	var response fetchResponse
	if err := json.Unmarshal(responseRaw, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fetch response from browser: %w", err)
	}

	if response.Error != "" {
		// Ignore errors if context was cancelled during the fetch.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("in-page fetch failed: %s", response.Error)
	}
	return &response, nil
}

// analyzeLoginResponse inspects the response for keywords and compares it against the baseline using differential and timing analysis.
func (a *ATOAnalyzer) analyzeLoginResponse(res *fetchResponse, baseline *baselineFailure) loginResult {
	// 1. Keyword-based analysis (High confidence indicators).
	bodyLower := strings.ToLower(res.Body)

	// Check for MFA keywords first if configured, as they might overlap with success indicators.
	if len(a.cfg.MFAKeywords) > 0 {
		for _, kw := range a.cfg.MFAKeywords {
			if strings.Contains(bodyLower, strings.ToLower(kw)) {
				return loginMFAChallenge
			}
		}
	}

	if res.Status >= 200 && res.Status < 400 {
		isSuccess := res.Status >= 300 && res.Status < 400 // Assume redirect is success (unless MFA detected).
		if !isSuccess {
			for _, kw := range a.cfg.SuccessKeywords {
				// Keywords should be compared in lowercase.
				if strings.Contains(bodyLower, strings.ToLower(kw)) {
					isSuccess = true
					break
				}
			}
			// Enhanced check: Look for JWT tokens if standard keywords fail.
			if !isSuccess && jwtRegex.MatchString(res.Body) {
				isSuccess = true
			}
		}
		if isSuccess {
			return loginSuccess
		}
	}

	for _, kw := range a.cfg.LockoutKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			return loginFailureLockout
		}
	}
	// Keywords indicating valid user, invalid password.
	for _, kw := range a.cfg.PassFailureKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			return loginFailurePass
		}
	}
	// Keywords indicating invalid user.
	for _, kw := range a.cfg.UserFailureKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			return loginFailureUser
		}
	}
	for _, kw := range a.cfg.GenericFailureKeywords {
		if strings.Contains(bodyLower, strings.ToLower(kw)) {
			return loginFailureGeneric
		}
	}

	// 2. Differential Analysis (Compares against baseline if available).
	if baseline != nil {
		normalizedBody := normalizeBody(res.Body)
		currentBodyHash := sha256.Sum256([]byte(normalizedBody))

		// Check if the response matches the baseline (known invalid user/pass).
		if res.Status == baseline.Status && len(normalizedBody) == baseline.LengthNormalized && currentBodyHash == baseline.BodyHash {
			// It matches the baseline structurally, proceed to timing analysis or return failure.
		} else {
			// If we reached here, the response differed from the baseline but didn't match any specific keywords.
			// This indicates potential enumeration (or success if keywords missed it).
			return loginFailureDifferential
		}
	}

	// 3. Timing Analysis (Compares response time against baseline if available).
	if baseline != nil && baseline.AvgResponseTime > 0 {
		// Check if the response time is significantly longer than the baseline.
		// This often indicates password hashing occurred (valid user) even if the response body is generic.
		if res.TimeMs > baseline.AvgResponseTime*timingThresholdFactor {
			// Ensure the difference is meaningful (absolute minimum difference) to avoid noise.
			if math.Abs(res.TimeMs-baseline.AvgResponseTime) > timingMinDifferenceMs {
				return loginFailureTiming
			}
		}
	}

	// If differential analysis matched the baseline and timing analysis was inconclusive.
	if baseline != nil {
		return loginFailureUser
	}

	return loginUnknown
}

// executePause handles the pacing between requests using Humanoid if available, or falling back to legacy sleep.
func (a *ATOAnalyzer) executePause(ctx context.Context, h *humanoid.Humanoid) error {
	minDelayMs := a.cfg.MinRequestDelayMs
	jitterMs := a.cfg.RequestDelayJitterMs

	if minDelayMs <= 0 && jitterMs <= 0 {
		return nil
	}

	if h != nil {
		// Use Humanoid's CognitivePause for realistic behavior.
		// Calculate Mean and StdDev based on Min + Jitter configuration.

		mean := float64(minDelayMs)
		stdDev := 0.0

		if jitterMs > 0 {
			mean += float64(jitterMs) / 2.0
			stdDev = float64(jitterMs) / 2.0
		}

		// If the configuration results in a very small delay, apply a reasonable cognitive pause if Humanoid is enabled.
		if mean < 50.0 {
			mean = 500.0 // Default to 500ms if config is tiny.
			if stdDev < 100.0 {
				stdDev = 100.0
			}
		}

		// Execute the action using the operation context 'ctx'.
		return h.CognitivePause(ctx, mean, stdDev)

	} else {
		// Fallback: Use the legacy randomized sleep using the operation context.
		// Propagate the error from legacyPause (e.g., context.Canceled).
		return a.legacyPause(ctx)
	}
}

// legacyPause introduces a variable delay. This is used as a fallback when the Humanoid module is unavailable.
func (a *ATOAnalyzer) legacyPause(ctx context.Context) error {
	// Check if any delay is configured.
	if a.cfg.MinRequestDelayMs <= 0 && a.cfg.RequestDelayJitterMs <= 0 {
		return nil
	}

	baseDelayMs := a.cfg.MinRequestDelayMs
	// Ensure a base delay if MinDelayMs is zero but JitterMs is positive.
	if baseDelayMs <= 0 {
		baseDelayMs = 1
	}

	jitter := 0
	// Ensure the argument to Intn is positive.
	if a.cfg.RequestDelayJitterMs > 0 {
		jitter = a.rng.Intn(a.cfg.RequestDelayJitterMs)
	}

	// FIX: CWE-190 Integer Overflow mitigation. Cast to int64 before addition.
	delay := time.Duration(int64(baseDelayMs)+int64(jitter)) * time.Millisecond
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// createCredentialStuffingFinding creates a finding for a successful ATO.
func (a *ATOAnalyzer) createCredentialStuffingFinding(attempt *loginAttempt, evidence string, enumerated bool, mfaDetected bool) schemas.Finding {
	id := fmt.Sprintf("ato-stuffing-%s", attempt.endpointIdentifier())
	hash := sha256.Sum256([]byte(id))

	severity := schemas.SeverityCritical
	desc := "The login endpoint is vulnerable to credential stuffing attacks. It was possible to successfully authenticate using a common credential, indicating a lack of robust anti-automation controls (e.g., rate-limiting, CAPTCHA)."

	if mfaDetected {
		severity = schemas.SeverityHigh // Still severe as primary credentials are weak, but mitigated by MFA.
		desc = "Weak primary credentials accepted, but login protected by Multi-Factor Authentication (MFA). While MFA mitigates immediate takeover, the acceptance of weak credentials remains a risk and allows attackers to target the MFA mechanism."
	}

	if enumerated {
		desc += " Additionally, the endpoint leaks information about valid usernames, making targeted attacks more effective."
	}

	// Create a structured object for the evidence
	evidencePayload := map[string]string{"details": evidence}
	evidenceJSON, err := json.Marshal(evidencePayload)
	if err != nil {
		// This should realistically never fail for this map
		a.Logger.Error("Failed to marshal finding evidence", zap.String("id", id), zap.Error(err))
		evidenceJSON = json.RawMessage(`{"details":"failed to marshal evidence"}`)
	}

	vulnName := "Account Takeover (Credential Stuffing)"
	if mfaDetected {
		vulnName = "Weak Credentials Accepted (MFA Present)"
	}

	return schemas.Finding{
		ID:                hex.EncodeToString(hash[:]),
		ObservedAt:        time.Now().UTC(),
		Target:            attempt.URL,
		Module:            a.Name(),
		Description:       desc,
		Severity:          severity,
		Evidence:          evidenceJSON,
		Recommendation:    "Implement multi-layered anti-automation controls: strict rate-limiting per IP/username, CAPTCHA challenges after several failed attempts, and an anomaly detection system. Enforce strong password policies. Ensure MFA implementation is robust against bypass techniques.",
		VulnerabilityName: vulnName,
		CWE:               []string{"CWE-307", "CWE-521"},
	}
}

// createUserEnumerationFinding creates a finding for an information leak.
func (a *ATOAnalyzer) createUserEnumerationFinding(attempt *loginAttempt, evidence string) schemas.Finding {
	id := fmt.Sprintf("ato-enumeration-%s", attempt.endpointIdentifier())
	hash := sha256.Sum256([]byte(id))

	// Create a structured object for the evidence
	evidencePayload := map[string]string{"details": evidence}
	evidenceJSON, err := json.Marshal(evidencePayload)
	if err != nil {
		// This should realistically never fail for this map
		a.Logger.Error("Failed to marshal finding evidence", zap.String("id", id), zap.Error(err))
		evidenceJSON = json.RawMessage(`{"details":"failed to marshal evidence"}`)
	}

	return schemas.Finding{
		ID:                hex.EncodeToString(hash[:]),
		ObservedAt:        time.Now().UTC(),
		Target:            attempt.URL,
		Module:            a.Name(),
		Description:       "The login endpoint's responses allow for username enumeration. The server provides a distinct response (either in content, structure, or timing) when a username exists versus when it does not. This allows an attacker to build a list of valid usernames.",
		Severity:          schemas.SeverityMedium,
		Evidence:          evidenceJSON,
		Recommendation:    "Modify the login failure logic to return a single, generic error message (e.g., 'Invalid username or password') regardless of the reason for failure. Ensure the HTTP status code, response body, and response time are consistent across all failure cases.",
		VulnerabilityName: "Username Enumeration",
		CWE:               []string{"CWE-203", "CWE-208"}, // Added CWE-208 for timing analysis
	}
}
