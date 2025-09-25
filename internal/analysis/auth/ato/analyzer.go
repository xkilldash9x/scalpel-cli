// internal/analysis/auth/ato/analyzer.go
package ato

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// loginResult represents the semantic outcome of a single login attempt.
type loginResult int

const (
	loginUnknown loginResult = iota
	loginSuccess
	loginFailureUser         // Indicates the username was likely invalid (via keyword).
	loginFailurePass         // Indicates the username was valid, but the password was not (via keyword).
	loginFailureGeneric      // A generic failure message that doesn't leak information.
	loginFailureLockout
	loginFailureDifferential // A failure response that differs from the baseline, indicating enumeration.
)

// loginAttempt holds all necessary, parsed information to replay a login request.
type loginAttempt struct {
	URL         string
	Method      string
	ContentType string
	UserField   string
	PassField   string
	BodyParams  map[string]interface{}
	Headers     map[string]string
}

// baselineFailure captures the signature of a known-invalid login response.
type baselineFailure struct {
	Status   int
	Length   int
	BodyHash [32]byte
}

// csrfToken holds the name and value for an anti-forgery token.
type csrfToken struct {
	Name  string
	Value string
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

// csrfFieldHeuristics provides CSS selectors to find common CSRF tokens.
var csrfFieldHeuristics = []string{
	`input[type=hidden][name*=csrf]`,
	`input[type=hidden][name*=token]`,
	`input[type=hidden][name*=_token]`,
	`input[type=hidden][name*=nonce]`,
}

// HumanoidProvider defines an interface for duck-typing the SessionContext
// to check if it provides access to the Humanoid controller.
type HumanoidProvider interface {
	GetHumanoid() *humanoid.Humanoid
}

// ATOAnalyzer actively and concurrently tests login mechanisms for vulnerabilities.
type ATOAnalyzer struct {
	*core.BaseAnalyzer
	cfg           *config.ATOConfig
	rng           *rand.Rand
	credentialSet []schemas.Credential
}

// NewATOAnalyzer creates a new, production-ready instance of the ATO analyzer.
func NewATOAnalyzer(cfg *config.Config, logger *zap.Logger) (*ATOAnalyzer, error) {
	atoCfg := cfg.Scanners.Active.Auth.ATO
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

// loads credentials from an external file or falls back to a default list.
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

// Analyze is the main entry point for the ATO analysis, using a concurrent worker pool.
func (a *ATOAnalyzer) Analyze(ctx context.Context, analysisCtx schemas.SessionContext) error {
	if !a.cfg.Enabled {
		a.Logger.Info("ATO analysis is disabled by configuration.")
		return nil
	}

	artifacts, err := analysisCtx.CollectArtifacts()
	if err != nil {
		return fmt.Errorf("ATO analyzer failed to collect artifacts: %w", err)
	}

	loginAttempts := a.discoverLoginEndpoints(artifacts)
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
		analysisCtx.AddFinding(finding)
	}

	return nil
}

// parses HAR artifacts to find unique login requests.
func (a *ATOAnalyzer) discoverLoginEndpoints(artifacts *schemas.Artifacts) map[string]*loginAttempt {
	loginAttempts := make(map[string]*loginAttempt)
	for _, entry := range artifacts.HAR.Log.Entries {
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

// identifyLoginRequest parses a request to determine if it's a login attempt.
func (a *ATOAnalyzer) identifyLoginRequest(req schemas.Request) (*loginAttempt, error) {
	if req.Method != http.MethodPost || req.PostData == nil {
		return nil, fmt.Errorf("not a POST request with data")
	}

	contentType := req.PostData.MimeType
	bodyParams := make(map[string]interface{})
	var userField, passField string

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
			if !strings.EqualFold(h.Name, "Content-Length") {
				headers[h.Name] = h.Value
			}
		}
		return &loginAttempt{
			URL:         req.URL,
			Method:      req.Method,
			ContentType: contentType,
			UserField:   userField,
			PassField:   passField,
			BodyParams:  bodyParams,
			Headers:     headers,
		}, nil
	}

	return nil, fmt.Errorf("did not find distinct user and password fields")
}

// testEndpoint executes the credential stuffing and enumeration attack against a single endpoint.
func (a *ATOAnalyzer) testEndpoint(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt) []schemas.Finding {
	var findings []schemas.Finding
	userEnumerationDetected := false

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
	baseline, err := a.establishBaseline(ctx, analysisCtx, attempt)
	if err != nil {
		a.Logger.Error("Could not establish a baseline for login endpoint, enumeration checks will be less reliable.",
			zap.String("url", attempt.URL), zap.Error(err))
	}

	for _, creds := range a.credentialSet {
		if ctx.Err() != nil {
			a.Logger.Warn("ATO analysis cancelled during testing.", zap.Error(ctx.Err()))
			return findings
		}

		if err := a.executePause(ctx, analysisCtx, h); err != nil {
			// Check if the error was due to context cancellation (either operation ctx or browser ctx).
			if ctx.Err() != nil || (analysisCtx.GetContext() != nil && analysisCtx.GetContext().Err() != nil) {
				a.Logger.Warn("ATO analysis cancelled during pause.", zap.Error(err))
				return findings
			}
			// Log other potential errors during the pause execution, but continue.
			a.Logger.Warn("Error during execution pause, proceeding.", zap.Error(err))
		}

		token, err := a.getFreshCSRFToken(ctx, analysisCtx, attempt.URL)
		if err != nil {
			a.Logger.Warn("Failed to fetch fresh CSRF token, continuing without it.", zap.Error(err))
		}

		a.Logger.Debug("Attempting login", zap.String("username", creds.Username), zap.String("url", attempt.URL))
		response, err := a.executeLoginAttempt(ctx, analysisCtx, attempt, creds, token)
		if err != nil {
			a.Logger.Error("Failed to execute login attempt", zap.Error(err), zap.String("url", attempt.URL))
			continue
		}

		result := a.analyzeLoginResponse(response, baseline)
		if result == loginSuccess {
			evidence := fmt.Sprintf("Successfully logged in to %s with username '%s' and password '%s'.", attempt.URL, creds.Username, creds.Password)
			findings = append(findings, a.createCredentialStuffingFinding(attempt, evidence, userEnumerationDetected))
			return findings
		}

		if result == loginFailurePass || result == loginFailureDifferential {
			userEnumerationDetected = true
		}
	}

	if userEnumerationDetected {
		evidence := fmt.Sprintf("The login mechanism at %s provides distinct responses for invalid passwords versus invalid usernames. This was detected by observing a response that differed from the baseline 'invalid user' response, allowing an attacker to confirm valid usernames.", attempt.URL)
		findings = append(findings, a.createUserEnumerationFinding(attempt, evidence))
	}
	return findings
}

// establishBaseline sends a request with random credentials to establish a baseline of a failed login.
func (a *ATOAnalyzer) establishBaseline(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt) (*baselineFailure, error) {
	randomCreds := schemas.Credential{
		Username: uuid.NewString(),
		Password: uuid.NewString(),
	}

	token, err := a.getFreshCSRFToken(ctx, analysisCtx, attempt.URL)
	if err != nil {
		a.Logger.Warn("Failed to get CSRF token for baseline request.", zap.Error(err))
	}

	res, err := a.executeLoginAttempt(ctx, analysisCtx, attempt, randomCreds, token)
	if err != nil {
		return nil, fmt.Errorf("baseline attempt failed: %w", err)
	}

	return &baselineFailure{
		Status:   res.Status,
		Length:   len(res.Body),
		BodyHash: sha256.Sum256([]byte(res.Body)),
	}, nil
}

// getFreshCSRFToken navigates to the login page and attempts to scrape a CSRF token value.
func (a *ATOAnalyzer) getFreshCSRFToken(ctx context.Context, analysisCtx schemas.SessionContext, pageURL string) (*csrfToken, error) {
	var tokenName, tokenValue string
	var nodes []*cdp.Node

	// --- Humanoid Integration: Retrieve Controller ---
	var h *humanoid.Humanoid
	if provider, ok := analysisCtx.(HumanoidProvider); ok {
		h = provider.GetHumanoid()
	}
	// ---------------------------------------------------

	tasks := chromedp.Tasks{}

	// Pre-navigation pause (Cognitive planning)
	if h != nil {
		tasks = append(tasks, h.CognitivePause(300, 100))
	}

	tasks = append(tasks, chromedp.Navigate(pageURL))
	// Wait for the page to be ready before proceeding.
	tasks = append(tasks, chromedp.WaitReady("body"))

	// Post-navigation pause (Visual scanning of the page)
	if h != nil {
		tasks = append(tasks, h.CognitivePause(500, 200))
	}

	for _, selector := range csrfFieldHeuristics {
		tasks = append(tasks, chromedp.ActionFunc(func(c context.Context) error {
			// If we already found a token, no need to keep searching.
			if tokenName != "" {
				return nil
			}
			err := chromedp.Nodes(selector, &nodes, chromedp.AtLeast(0)).Do(c)
			if err != nil || len(nodes) == 0 {
				return nil // Continue to next selector
			}

			// Brief hesitation during scraping
			if h != nil {
				// 'c' is the browser context provided by chromedp.Run.
				if err := h.Hesitate(50 * time.Millisecond).Do(c); err != nil {
					// Log error but don't fail the whole process if hesitation fails.
					a.Logger.Debug("Humanoid hesitation failed during CSRF scraping", zap.Error(err))
				}
			}

			var attrs map[string]string
			if err := chromedp.Attributes(selector, &attrs, chromedp.FromNode(nodes[0])).Do(c); err != nil {
				return err
			}
			if name, ok := attrs["name"]; ok {
				if val, ok := attrs["value"]; ok {
					tokenName = name
					tokenValue = val
					a.Logger.Debug("Found CSRF token", zap.String("name", name), zap.String("value", "REDACTED"))
				}
			}
			return nil
		}))
	}

	if err := chromedp.Run(analysisCtx.GetContext(), tasks); err != nil {
		return nil, fmt.Errorf("could not navigate to page or scrape CSRF token: %w", err)
	}

	if tokenName != "" {
		return &csrfToken{Name: tokenName, Value: tokenValue}, nil
	}

	return nil, nil // No token found, but not an error
}

// fetchResponse is a struct to unmarshal the structured JSON response from the browser fetch call.
type fetchResponse struct {
	Body       string `json:"body"`
	Status     int    `json:"status"`
	StatusText string `json:"statusText"`
	Error      string `json:"error"`
}

// executeLoginAttempt safely replays a modified login request using the browser's fetch API.
func (a *ATOAnalyzer) executeLoginAttempt(ctx context.Context, analysisCtx schemas.SessionContext, attempt *loginAttempt, creds schemas.Credential, token *csrfToken) (*fetchResponse, error) {
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
			values.Add(k, fmt.Sprintf("%v", v))
		}
		bodyString = values.Encode()
	}

	headersJSON, err := json.Marshal(attempt.Headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal headers to JSON: %w", err)
	}
	bodyJSON, err := json.Marshal(bodyString)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body to JSON: %w", err)
	}

	script := fmt.Sprintf(`
		(async (url, method, headers, body) => {
			try {
				const response = await fetch(url, {
					method: method, headers: headers, body: body,
					credentials: 'omit', redirect: 'manual',
				});
				const responseBody = await response.text();
				return JSON.stringify({
					body: responseBody, status: response.status,
					statusText: response.statusText, error: ''
				});
			} catch (e) {
				return JSON.stringify({ body: '', status: 0, error: e.message });
			}
		})(%q, %q, %s, %s);
	`, attempt.URL, attempt.Method, string(headersJSON), string(bodyJSON))

	var responseJSON string
	if err := chromedp.Run(analysisCtx.GetContext(),
		chromedp.Evaluate(script, &responseJSON),
	); err != nil {
		return nil, fmt.Errorf("chromedp.Evaluate failed: %w", err)
	}

	var response fetchResponse
	if err := json.Unmarshal([]byte(responseJSON), &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fetch response from browser: %w", err)
	}
	if response.Error != "" {
		return nil, fmt.Errorf("in-page fetch failed: %s", response.Error)
	}
	return &response, nil
}

// analyzeLoginResponse inspects the response for keywords indicating the login outcome.
func (a *ATOAnalyzer) analyzeLoginResponse(res *fetchResponse, baseline *baselineFailure) loginResult {
	// 1. Perform differential analysis first for the highest reliability.
	if baseline != nil {
		currentBodyHash := sha256.Sum256([]byte(res.Body))
		if res.Status != baseline.Status || len(res.Body) != baseline.Length || currentBodyHash != baseline.BodyHash {
			return loginFailureDifferential
		}
	}

	// 2. Fallback to keyword-based analysis.
	bodyLower := strings.ToLower(res.Body)
	if res.Status >= 200 && res.Status < 400 {
		isSuccess := res.Status >= 300 && res.Status < 400
		if !isSuccess {
			for _, kw := range a.cfg.SuccessKeywords {
				if strings.Contains(bodyLower, kw) {
					isSuccess = true
					break
				}
			}
		}
		if isSuccess {
			return loginSuccess
		}
	}

	for _, kw := range a.cfg.LockoutKeywords {
		if strings.Contains(bodyLower, kw) {
			return loginFailureLockout
		}
	}
	for _, kw := range a.cfg.UserFailureKeywords {
		if strings.Contains(bodyLower, kw) {
			return loginFailureUser
		}
	}
	for _, kw := range a.cfg.PassFailureKeywords {
		if strings.Contains(bodyLower, kw) {
			return loginFailurePass
		}
	}
	for _, kw := range a.cfg.GenericFailureKeywords {
		if strings.Contains(bodyLower, kw) {
			return loginFailureGeneric
		}
	}
	return loginUnknown
}

// executePause handles the pacing between requests using Humanoid if available, or falling back to legacy sleep.
func (a *ATOAnalyzer) executePause(ctx context.Context, analysisCtx schemas.SessionContext, h *humanoid.Humanoid) error {
	minDelayMs := a.cfg.MinRequestDelayMs
	jitterMs := a.cfg.RequestDelayJitterMs

	if minDelayMs <= 0 && jitterMs <= 0 {
		return nil
	}

	if h != nil {
		// Use Humanoid's CognitivePause for realistic behavior (idling, micro-movements, fatigue awareness).
		// Calculate Mean and StdDev based on Min + Jitter configuration.
		// Mean = MinDelay + Jitter/2; StdDev = Jitter/2 (approx)

		mean := float64(minDelayMs)
		stdDev := 0.0

		if jitterMs > 0 {
			mean += float64(jitterMs) / 2.0
			stdDev = float64(jitterMs) / 2.0
		}

		// If the configuration results in a very small delay, we still apply a reasonable cognitive pause if Humanoid is enabled.
		if mean < 50.0 {
			mean = 500.0 // Default to 500ms if config is tiny.
			if stdDev < 100.0 {
				stdDev = 100.0
			}
		}

		// Execute the action using the session's browser context, required for Humanoid actions.
		browserCtx := analysisCtx.GetContext()
		if browserCtx == nil {
			// Handle gracefully if browser context is somehow unavailable.
			a.Logger.Error("Browser context is nil, falling back to legacy pause.")
			a.legacyPause(ctx)
			return nil
		}

		// Execute the action. Errors (including context cancellation of browserCtx) will be returned.
		return chromedp.Run(browserCtx, h.CognitivePause(mean, stdDev))

	} else {
		// Fallback: Use the legacy randomized sleep using the operation context.
		a.legacyPause(ctx)
		return nil
	}
}

// legacyPause introduces a variable delay. This is used as a fallback when the Humanoid module is unavailable.
func (a *ATOAnalyzer) legacyPause(ctx context.Context) {
	// Check if any delay is configured.
	if a.cfg.MinRequestDelayMs <= 0 && a.cfg.RequestDelayJitterMs <= 0 {
		return
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

	delay := time.Duration(baseDelayMs+jitter) * time.Millisecond
	select {
	case <-time.After(delay):
	case <-ctx.Done():
	}
}

// createCredentialStuffingFinding creates a finding for a successful ATO.
func (a *ATOAnalyzer) createCredentialStuffingFinding(attempt *loginAttempt, evidence string, enumerated bool) schemas.Finding {
	id := fmt.Sprintf("ato-stuffing-%s", attempt.endpointIdentifier())
	hash := sha256.Sum256([]byte(id))
	desc := "The login endpoint is vulnerable to credential stuffing attacks. It was possible to successfully authenticate using a common credential, indicating a lack of robust anti-automation controls (e.g., rate-limiting, CAPTCHA)."
	if enumerated {
		desc += " The endpoint also leaks information about valid usernames, making targeted attacks more effective."
	}
	return schemas.Finding{
		ID:             hex.EncodeToString(hash[:]),
		Timestamp:      time.Now().UTC(),
		Target:         attempt.URL,
		Module:         a.Name(),
		Description:    desc,
		Severity:       schemas.SeverityCritical,
		Evidence:       evidence,
		Recommendation: "Implement multi-layered anti-automation controls: strict rate-limiting per IP/username, CAPTCHA challenges after several failed attempts, and an anomaly detection system to block suspicious login patterns.",
		Vulnerability:  schemas.Vulnerability{Name: "Account Takeover (Credential Stuffing)"},
		CWE:            []string{"CWE-307"},
	}
}

// createUserEnumerationFinding creates a finding for an information leak.
func (a *ATOAnalyzer) createUserEnumerationFinding(attempt *loginAttempt, evidence string) schemas.Finding {
	id := fmt.Sprintf("ato-enumeration-%s", attempt.endpointIdentifier())
	hash := sha256.Sum256([]byte(id))
	return schemas.Finding{
		ID:             hex.EncodeToString(hash[:]),
		Timestamp:      time.Now().UTC(),
		Target:         attempt.URL,
		Module:         a.Name(),
		Description:    "The login endpoint's responses allow for username enumeration. The server provides a distinct response when a username exists but the password is incorrect versus when the username does not exist. This allows an attacker to build a list of valid usernames.",
		Severity:       schemas.SeverityMedium,
		Evidence:       evidence,
		Recommendation: "Modify the login failure logic to return a single, generic error message (e.g., 'Invalid username or password') regardless of the reason for failure. Ensure the HTTP status code and response body are identical in all failure cases.",
		Vulnerability:  schemas.Vulnerability{Name: "Username Enumeration"},
		CWE:            []string{"CWE-203"},
	}
}
