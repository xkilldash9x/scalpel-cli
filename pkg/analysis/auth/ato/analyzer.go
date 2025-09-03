// pkg/analysis/auth/ato/analyzer.go
package ato

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
	
	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
)

// Config holds the configuration for the ATO analyzer.
type Config struct {
	ScanID            uuid.UUID
	LoginURL          string
	ContentType       string // e.g., "application/json"
	UserField         string
	PassField         string
	CSRFField         string // REVISION: Optional CSRF field name if known
	KnownUsers        []string
	MaxGlobalAttempts int
	DelayBetween      time.Duration
}

// Analyzer is the brains of the operation for trying to steal passwords.
type Analyzer struct {
	config   Config
	client   *http.Client
	logger   *zap.Logger
	reporter core.Reporter
}

// Regex for finding CSRF tokens in HTML input fields.
var csrfTokenRegex = regexp.MustCompile(`(?i)<input[^>]*?name=["']?(?:csrf|token|_csrf|authenticity_token|__RequestVerificationToken)["']?[^>]*?value=["']?([a-zA-Z0-9+/=_-]{16,})["']?`)


// NewAnalyzer initializes the ATO analyzer.
func NewAnalyzer(cfg Config, logger *zap.Logger, reporter core.Reporter) *Analyzer {
	if cfg.ContentType == "" {
		cfg.ContentType = "application/x-www-form-urlencoded"
	}

	// REVISION: Initialize a cookie jar to handle session cookies required for CSRF tokens.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logger.Error("Failed to initialize cookie jar", zap.Error(err))
		// Proceed without a jar if initialization fails, but CSRF handling might be impaired.
	}
	
	return &Analyzer{
		config: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
			// super important: we need to see the initial auth response, not follow redirects.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Jar: jar,
		},
		logger:   logger.Named("ato_analyzer"),
		reporter: reporter,
	}
}

// Run executes the full ATO testing workflow.
func (a *Analyzer) Run(ctx context.Context) error {
	a.logger.Info("Starting ATO analysis", zap.String("target", a.config.LoginURL))

	// REVISION: 1. Check for CSRF protection and fetch initial token.
	initialCSRFToken, requiresCSRF, err := a.fetchCSRFToken(ctx)
	if err != nil {
		a.logger.Warn("Failed to fetch initial page for CSRF check. Proceeding without CSRF handling.", zap.Error(err))
		requiresCSRF = false
	}

	// 2. Check for user enumeration.
	if err := a.checkUserEnumeration(ctx, initialCSRFToken, requiresCSRF); err != nil {
		a.logger.Warn("User enumeration check failed or encountered errors", zap.Error(err))
	}

	// 3. Execute password spraying.
	if err := a.executePasswordSpraying(ctx, initialCSRFToken, requiresCSRF); err != nil {
		return fmt.Errorf("password spraying attack failed: %w", err)
	}

	return nil
}

// REVISION: Implemented CSRF token fetching.
// fetchCSRFToken makes a GET request to the login URL to extract a CSRF token.
func (a *Analyzer) fetchCSRFToken(ctx context.Context) (string, bool, error) {
	a.logger.Debug("Fetching login page to check for CSRF tokens.")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.LoginURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")

	// The client (with its cookie jar) handles session cookies automatically.
	resp, err := a.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}
	body := string(bodyBytes)

	// Attempt to find the token using regex.
	matches := csrfTokenRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		token := matches[1]
		a.logger.Info("Found potential CSRF token in HTML input.")
		return token, true, nil
	}

	a.logger.Debug("No CSRF token found in HTML inputs.")
	return "", false, nil
}

// checkUserEnumeration actively probes the login page for info leaks.
func (a *Analyzer) checkUserEnumeration(ctx context.Context, csrfToken string, requiresCSRF bool) error {
	// Attempt 1: Baseline (known valid user with a bogus password).
	var baselineResponse *LoginResponse
	if len(a.config.KnownUsers) > 0 {
		attempt := LoginAttempt{
			Username: a.config.KnownUsers[0], 
			Password: "InvalidPassword!Scalpel_Enum",
			CSRFToken: csrfToken,
		}
		resp, err := a.sendLoginRequest(ctx, attempt, requiresCSRF)
		if err != nil {
			a.logger.Warn("Failed to establish baseline response with known user", zap.Error(err))
			// Continue without baseline if it fails.
		} else {
			baselineResponse = resp
		}
	}

	// Attempt 2: Invalid user.
	invalidUsername := fmt.Sprintf("scalpel_enum_test_%d", time.Now().UnixNano())
	attemptInvalid := LoginAttempt{
		Username: invalidUsername, 
		Password: "InvalidPassword!Scalpel_Enum",
		CSRFToken: csrfToken,
	}
	respInvalid, err := a.sendLoginRequest(ctx, attemptInvalid, requiresCSRF)
	if err != nil {
		return fmt.Errorf("request for invalid user failed: %w", err)
	}

	// Check 1: Verbose Error Messages
	if respInvalid.IsUserEnumeration || (baselineResponse != nil && baselineResponse.IsUserEnumeration) {
		detail := respInvalid.EnumerationDetail
		if detail == "" && baselineResponse != nil {
			detail = baselineResponse.EnumerationDetail
		}
		a.reportFinding(
			"User Enumeration via Verbose Error Messages",
			detail,
			core.SeverityMedium,
			respInvalid.Evidence,
		)
		return nil
	}

	// If no verbose messages, compare responses (if baseline exists).
	if baselineResponse != nil {
		// Check 2: Status Code Differentiation
		if baselineResponse.StatusCode != respInvalid.StatusCode {
			detail := fmt.Sprintf("Valid user resulted in status %d, invalid user resulted in status %d.", baselineResponse.StatusCode, respInvalid.StatusCode)
			a.reportFinding(
				"User Enumeration via Status Code Differentiation",
				detail,
				core.SeverityMedium,
				respInvalid.Evidence,
			)
		} 
		
		// Check 3: Content Length Differentiation
		// Allow tolerance for dynamic content.
		if (abs(len(baselineResponse.ResponseBody)-len(respInvalid.ResponseBody)) > 100) { 
			detail := fmt.Sprintf("Valid user resulted in length %d, invalid user resulted in length %d.", len(baselineResponse.ResponseBody), len(respInvalid.ResponseBody))
			a.reportFinding(
				"User Enumeration via Content Length Differentiation",
				detail,
				core.SeverityMedium,
				respInvalid.Evidence,
			)
		}

		// Check 4: Timing Analysis (REVISION)
		timeDiff := baselineResponse.ResponseTimeMs - respInvalid.ResponseTimeMs
		// If the valid user takes significantly longer (e.g., > 200ms), it suggests conditional processing (like password hashing).
		if timeDiff > 200 {
			detail := fmt.Sprintf("The application takes significantly longer to respond to valid users. Valid user: %dms, Invalid user: %dms.", baselineResponse.ResponseTimeMs, respInvalid.ResponseTimeMs)
			a.reportFinding(
				"User Enumeration via Timing Analysis",
				detail,
				core.SeverityMedium,
				respInvalid.Evidence,
			)
		}
	}

	return nil
}

// executePasswordSpraying runs the low and slow attack.
func (a *Analyzer) executePasswordSpraying(ctx context.Context, initialCSRFToken string, requiresCSRF bool) error {
	if len(a.config.KnownUsers) == 0 {
		return nil
	}

	payloads := GenerateSprayingPayloads(a.config.KnownUsers)
	attempts := 0
	lockoutDetected := false
	currentCSRFToken := initialCSRFToken

	for _, attempt := range payloads {
		if attempts >= a.config.MaxGlobalAttempts {
			a.logger.Info("Max global attempts reached. Stopping attack.")
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// REVISION: Handle CSRF token refresh if necessary (simplified approach assuming per-session tokens might expire).
		// A more robust implementation would detect specific CSRF failure responses.
		if requiresCSRF && currentCSRFToken == "" {
			// If we need a token and don't have one, try fetching a new one.
			newToken, _, err := a.fetchCSRFToken(ctx)
			if err != nil || newToken == "" {
				a.logger.Warn("CSRF required but failed to refresh token. Halting attack.", zap.Error(err))
				break
			}
			currentCSRFToken = newToken
		}

		attempt.CSRFToken = currentCSRFToken

		resp, err := a.sendLoginRequest(ctx, attempt, requiresCSRF)
		if err != nil {
			continue
		}
		attempts++

		if resp.Success {
			// jackpot!
			detail := fmt.Sprintf("Successful authentication with Username: '%s' and Password: '%s' via Password Spraying.", attempt.Username, attempt.Password)
			a.reportFinding(
				"Account Takeover Successful (Password Spraying)",
				detail,
				core.SeverityCritical,
				resp.Evidence,
			)
		}

		if resp.IsLockout {
			a.logger.Info("Account lockout mechanism detected. Halting attack.")
			lockoutDetected = true
			break
		}
		
		// If assuming per-request tokens, clear it. Assuming per-session here.
		// currentCSRFToken = "" 

		time.Sleep(a.config.DelayBetween)
	}

	// Report weak lockout policy if applicable.
	if !lockoutDetected && attempts > 15 {
		detail := fmt.Sprintf("The application allowed %d failed login attempts without enforcing an effective account lockout policy.", attempts)
		a.reportFinding(
			"Weak or Non-Existent Account Lockout Policy",
			detail,
			core.SeverityHigh,
			nil,
		)
	}

	return nil
}

// sendLoginRequest handles JSON or form data, including CSRF tokens.
func (a *Analyzer) sendLoginRequest(ctx context.Context, attempt LoginAttempt, includeCSRF bool) (*LoginResponse, error) {
	var bodyReader io.Reader
	var serializedReqBody string
	contentType := a.config.ContentType

	// Determine the CSRF field name.
	csrfFieldName := a.config.CSRFField
	if csrfFieldName == "" {
		csrfFieldName = "csrf_token" // Default fallback
	}

	// build the request body based on the content type.
	if strings.Contains(contentType, "application/json") {
		payload := map[string]string{
			a.config.UserField: attempt.Username,
			a.config.PassField: attempt.Password,
		}
		if includeCSRF && attempt.CSRFToken != "" {
			payload[csrfFieldName] = attempt.CSRFToken
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		serializedReqBody = string(jsonPayload)
		bodyReader = bytes.NewReader(jsonPayload)
	} else {
		// default to form-urlencoded
		data := url.Values{}
		data.Set(a.config.UserField, attempt.Username)
		data.Set(a.config.PassField, attempt.Password)

		if includeCSRF && attempt.CSRFToken != "" {
			data.Set(csrfFieldName, attempt.CSRFToken)
		}

		serializedReqBody = data.Encode()
		bodyReader = bytes.NewBufferString(serializedReqBody)
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.LoginURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")
	// Set Origin/Referer headers, often required by CSRF checks.
	req.Header.Set("Origin", req.URL.Scheme + "://" + req.URL.Host)
	req.Header.Set("Referer", a.config.LoginURL)

	startTime := time.Now()
	resp, err := a.client.Do(req) // Client handles cookies automatically.
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseTimeMs := time.Since(startTime).Milliseconds()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// REVISION: Pass response time to analysis.
	analyzedResponse := AnalyzeResponse(attempt, resp.StatusCode, string(respBody), responseTimeMs)
	
	// attach the raw request/response as evidence.
	analyzedResponse.Evidence = &core.Evidence{
		Summary: fmt.Sprintf("Attempt with user: %s", attempt.Username),
		Request: &core.SerializedRequest{
			Method:  req.Method,
			URL:     a.config.LoginURL,
			Headers: req.Header,
			Body:    serializedReqBody,
		},
		Response: &core.SerializedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       string(respBody),
		},
	}
	
	return &analyzedResponse, nil
}

// reportFinding publishes the finding.
func (a *Analyzer) reportFinding(title, description string, severity core.SeverityLevel, evidence *core.Evidence) {
	finding := core.AnalysisResult{
		ScanID:            a.config.ScanID,
		AnalyzerName:      "ATOAnalyzer (Active)",
		Timestamp:         time.Now().UTC(),
		VulnerabilityType: "AuthenticationFlaw",
		Title:             title,
		Description:       description,
		Severity:          severity,
		Status:            core.StatusOpen,
		Confidence:        0.9, // high confidence, we actively did this.
		TargetURL:         a.config.LoginURL,
		Evidence:          evidence,
	}
	if err := a.reporter.Publish(finding); err != nil {
		a.logger.Error("Failed to publish finding", zap.Error(err), zap.String("title", title))
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
