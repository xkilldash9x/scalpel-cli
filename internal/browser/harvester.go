package browser

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

const networkIdleCheckFrequency = 250 * time.Millisecond

// requestState holds the information for a single network request throughout its lifecycle.
type requestState struct {
	request   playwright.Request
	response  playwright.Response
	body      []byte
	err       error
	finished  bool
	isDataURL bool
	startTime time.Time
}

// Harvester listens to browser network events and console logs to build a HAR file and monitor activity.
type Harvester struct {
	ctx             context.Context // Session lifecycle context.
	logger          *zap.Logger
	captureBodies   bool
	page            playwright.Page // Store page to manage listeners.

	mu              sync.RWMutex
	requests        map[playwright.Request]*requestState // Keyed by Request object pointer.
	consoleLogs     []schemas.ConsoleLog
	pageTitle       string
	pageStartTime time.Time
	pageTimings     schemas.PageTimings

	activeReqs int64 // Counter for active requests, including body fetching time.

	stopOnce sync.Once

	// Store remover functions returned by page.On() instead of handler references.
	eventRemovers []func()
}

// NewHarvester creates a new network harvester instance.
func NewHarvester(ctx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	h := &Harvester{
		ctx:             ctx,
		logger:          logger.Named("harvester"),
		captureBodies: captureBodies,
		requests:        make(map[playwright.Request]*requestState),
		consoleLogs:     make([]schemas.ConsoleLog, 0),
		pageStartTime: time.Now(),
		eventRemovers: make([]func(), 0),
	}
	// Handlers are implemented as methods (handleRequest, etc.)
	return h
}

// Start begins listening to network and console events from the Playwright Page.
func (h *Harvester) Start(page playwright.Page) {
	h.logger.Debug("Starting harvester event listeners.")
	h.page = page

	// Helper to register listener and store the remover function.
	register := func(event string, handler interface{}) {
		// Note: If you encounter a compilation error here regarding "no value used as value",
		// it means your playwright-go version does not support the (func(), error) return
		// signature for page.On/page.Once. You will need to upgrade your playwright-go dependency.
		remover, err := page.On(event, handler)
		if err != nil {
			h.logger.Error("Failed to register event listener.", zap.String("event", event), zap.Error(err))
			return
		}
		h.eventRemovers = append(h.eventRemovers, remover)
	}

	// -- Network Events --
	register("request", h.handleRequest)
	register("response", h.handleResponse)
	register("requestfinished", h.handleRequestFinished)
	register("requestfailed", h.handleRequestFailed)

	// -- Console Events --
	register("console", h.handleConsoleMessage)

	// -- Page Lifecycle Events --
	register("load", h.handlePageLoad)
	register("domcontentloaded", h.handleDOMContentLoaded)

	// Capture the accurate start time upon the first main frame navigation.
	// Use Once which also returns a remover.
	remover, err := page.Once("framenavigated", func(frame playwright.Frame) {
		if frame == page.MainFrame() {
			h.mu.Lock()
			h.pageStartTime = time.Now()
			h.mu.Unlock()
		}
	})
	if err == nil {
		h.eventRemovers = append(h.eventRemovers, remover)
	} else {
		h.logger.Error("Failed to register framenavigated listener.", zap.Error(err))
	}
}

// Stop halts the event listeners by calling all stored remover functions.
func (h *Harvester) Stop() {
	h.stopOnce.Do(func() {
		h.logger.Debug("Stopping harvester event listeners.")
		// Call the stored remover functions.
		if h.page != nil && !h.page.IsClosed() {
			for _, remover := range h.eventRemovers {
				remover()
			}
		}
		h.eventRemovers = nil // Clear the slice
	})
}

// GetConsoleLogs returns a copy of the collected console logs.
func (h *Harvester) GetConsoleLogs() []schemas.ConsoleLog {
	h.mu.RLock()
	defer h.mu.RUnlock()
	logs := make([]schemas.ConsoleLog, len(h.consoleLogs))
	copy(logs, h.consoleLogs)
	return logs
}

// WaitNetworkIdle blocks until the network has been quiet for a specified duration.
// It relies on the activeReqs counter which is incremented on request and decremented
// only after the response body has been fully processed or the request has failed.
func (h *Harvester) WaitNetworkIdle(ctx context.Context, quietPeriod time.Duration) error {
	h.logger.Debug("Waiting for network to become idle.", zap.Duration("quiet_period", quietPeriod))

	ticker := time.NewTicker(networkIdleCheckFrequency)
	defer ticker.Stop()

	lastActiveTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			// The operation context (e.g., the specific interaction) was cancelled.
			return ctx.Err()
		case <-h.ctx.Done():
			// The overall session context was cancelled.
			return h.ctx.Err()
		case now := <-ticker.C:
			h.mu.RLock()
			active := h.activeReqs
			h.mu.RUnlock()

			if active == 0 {
				// If network is currently idle, check if the quiet period has passed.
				if now.Sub(lastActiveTime) >= quietPeriod {
					h.logger.Debug("Network is idle.")
					return nil
				}
			} else {
				// Network is active (requests pending or bodies fetching), reset the last active time.
				lastActiveTime = now
			}
		}
	}
}

// -- Event Handlers --

// handleRequest tracks the start of a network request.
func (h *Harvester) handleRequest(req playwright.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.activeReqs++

	h.requests[req] = &requestState{
		request:   req,
		isDataURL: strings.HasPrefix(req.URL(), "data:"),
		startTime: time.Now(),
	}
}

// handleResponse captures the response object when it arrives.
func (h *Harvester) handleResponse(resp playwright.Response) {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := resp.Request()
	if reqState, ok := h.requests[req]; ok {
		reqState.response = resp
	}
}

// handleRequestFinished is called when a request successfully completes.
func (h *Harvester) handleRequestFinished(req playwright.Request) {
	h.processRequestCompletion(req, nil)
}

// handleRequestFailed is called when a request fails for any reason (e.g., DNS, timeout).
func (h *Harvester) handleRequestFailed(req playwright.Request) {
	// Retrieves the driver-specific failure reason.
	// FIX: req.Failure() returns only the string reason in this API version, not a string and an error.
	failureText := req.Failure()

	var failureErr error
	// If failureText is non-empty, it contains the reason.
	if failureText != "" {
		failureErr = fmt.Errorf("request failed: %s", failureText)
	} else {
		// Defensive: The event fired but the reason was empty.
		failureErr = fmt.Errorf("request failed (unknown reason)")
	}
	h.processRequestCompletion(req, failureErr)
}

// processRequestCompletion handles the final state update, including fetching the body.
// This function ensures the body is fetched (if required) before the active request counter is decremented.
func (h *Harvester) processRequestCompletion(req playwright.Request, failureErr error) {
	h.mu.RLock()
	reqState, ok := h.requests[req]
	// Determine if body capture is necessary.
	shouldFetchBody := h.captureBodies && ok && !reqState.isDataURL && reqState.response != nil
	h.mu.RUnlock()

	var body []byte
	var fetchErr error

	if shouldFetchBody {
		// Fetch the body content synchronously.
		body, fetchErr = reqState.response.Body()
		if fetchErr != nil {
			// Log the error if it's not due to the context being cancelled (session shutdown).
			if h.ctx.Err() == nil {
				h.logger.Debug("Failed to fetch response body.", zap.String("url", req.URL()), zap.Error(fetchErr))
			}
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Update state after fetching body.
	if reqState, ok := h.requests[req]; ok {
		reqState.finished = true
		reqState.body = body
		// Prioritize failure error over body fetch error.
		if failureErr != nil {
			reqState.err = failureErr
		} else if fetchErr != nil {
			reqState.err = fetchErr
		}
	}

	// Decrement activeReqs only after all processing (including body fetch) is done.
	h.activeReqs--
}

// handleConsoleMessage captures a console log event and converts it to the project schema.
func (h *Harvester) handleConsoleMessage(msg playwright.ConsoleMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()

	location := msg.Location()
	h.consoleLogs = append(h.consoleLogs, schemas.ConsoleLog{
		Type:      msg.Type(),
		Timestamp: time.Now(), // Approximate timestamp.
		Text:      msg.Text(),
		Source:    "console-api",
		URL:       location.URL,
		Line:      int64(location.LineNumber),
	})
}

// handlePageLoad records the page load event timing.
func (h *Harvester) handlePageLoad(page playwright.Page) {
	if page.MainFrame() != page.MainFrame() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pageTitle, _ = page.Title()
	// Calculate time since the navigation started.
	h.pageTimings.OnLoad = float64(time.Since(h.pageStartTime).Milliseconds())
}

// handleDOMContentLoaded records the DOM content loaded event timing.
func (h *Harvester) handleDOMContentLoaded(page playwright.Page) {
	if page.MainFrame() != page.MainFrame() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Calculate time since the navigation started.
	h.pageTimings.OnContentLoad = float64(time.Since(h.pageStartTime).Milliseconds())
}

// -- HAR Generation --

// GenerateHAR constructs the HAR structure from the collected network events.
func (h *Harvester) GenerateHAR() *schemas.HAR {
	h.mu.RLock()
	defer h.mu.RUnlock()

	har := schemas.NewHAR()
	pageID := "page_1"

	har.Log.Pages = append(har.Log.Pages, schemas.Page{
		StartedDateTime: h.pageStartTime,
		ID:              pageID,
		Title:           h.pageTitle,
		PageTimings:     h.pageTimings,
	})

	for _, reqState := range h.requests {
		// Skip incomplete entries (not finished, or finished without response and without error).
		if !reqState.finished || (reqState.response == nil && reqState.err == nil) {
			continue
		}

		// FIX: reqState.request.Timing() returns only the struct, not a struct and an error.
		// Retrieves detailed network timing information.
		timing := reqState.request.Timing()

		// Calculate total duration. If ResponseEnd is available, use precise duration; otherwise, approximate.
		totalTime := float64(-1)
		if timing.ResponseEnd > 0 && timing.RequestStart > 0 {
			totalTime = timing.ResponseEnd - timing.RequestStart
		} else {
			// Approximate total time if precise timing is unavailable (e.g., failure).
			totalTime = time.Since(reqState.startTime).Seconds() * 1000
		}

		entry := schemas.Entry{
			Pageref:         pageID,
			StartedDateTime: reqState.startTime, // Use the recorded request start time.
			Time:            totalTime,
			Request:         h.buildHARRequest(reqState.request),
			Response:        h.buildHARResponse(reqState.response, reqState.body, reqState.err),
			Cache:           struct{}{},
			Timings:         convertPWTImings(timing),
		}
		har.Log.Entries = append(har.Log.Entries, entry)
	}
	return har
}

// buildHARRequest converts a Playwright Request object into the HAR Request schema.
func (h *Harvester) buildHARRequest(req playwright.Request) schemas.Request {
	// Use AllHeaders for reliability.
	headers, _ := req.AllHeaders()
	headersSize := calculateHeaderSize(headers)
	nvHeaders := convertPWHeaders(headers)

	postData, _ := req.PostData()
	bodySize := int64(len(postData))

	harReq := schemas.Request{
		Method:      req.Method(),
		URL:         req.URL(),
		HTTPVersion: "HTTP/1.1", // Approximation
		// Updated to use HARCookie conversion.
		Cookies:     extractCookiesFromHeaders(headers),
		Headers:     nvHeaders,
		QueryString: extractQueryString(req.URL()),
		HeadersSize: headersSize,
		BodySize:    bodySize,
	}

	if bodySize > 0 {
		contentType, _ := req.HeaderValue("content-type")
		harReq.PostData = &schemas.PostData{
			MimeType: contentType,
			Text:     postData,
		}
	}

	return harReq
}

// buildHARResponse converts a Playwright Response object and collected body into the HAR Response schema.
func (h *Harvester) buildHARResponse(resp playwright.Response, body []byte, reqErr error) schemas.Response {
	if resp == nil {
		// Handle failed requests where no response object exists.
		return schemas.Response{
			Status:      0,
			StatusText:  "Failed",
			HTTPVersion: "unknown",
			Content: schemas.Content{
				Size:     0,
				MimeType: "text/plain",
				Text:     fmt.Sprintf("Request failed: %v", reqErr),
			},
			HeadersSize: -1,
			BodySize:    -1,
		}
	}

	// Use AllHeaders for reliability.
	headers, _ := resp.AllHeaders()
	headersSize := calculateHeaderSize(headers)
	nvHeaders := convertPWHeaders(headers)

	contentType, _ := resp.HeaderValue("content-type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	content := schemas.Content{
		Size:     int64(len(body)),
		MimeType: contentType,
	}

	// Only store the body as text if the MIME type suggests it's human readable text.
	if isTextMime(contentType) {
		content.Text = string(body)
	} else if len(body) > 0 {
		// For binary content, encode to base64 for HAR format compatibility.
		content.Encoding = "base64"
		content.Text = base64.StdEncoding.EncodeToString(body)
	}

	bodySize := int64(len(body)) // Approximation of transferred size.

	// Determine protocol, falling back to HTTP/1.1.
	protocol := "HTTP/1.1"
	sd, err := resp.SecurityDetails()
	// FIX: sd.Protocol is a *string and must be checked for nil and dereferenced.
	if err == nil && sd != nil && sd.Protocol != nil && *sd.Protocol != "" {
		protocol = *sd.Protocol
	}

	redirectURL, _ := resp.HeaderValue("location")
	return schemas.Response{
		Status:      resp.Status(),
		StatusText:  resp.StatusText(),
		HTTPVersion: protocol,
		// Updated to use HARCookie conversion.
		Cookies:     extractCookiesFromHeaders(headers), // Handles Set Cookie
		Headers:     nvHeaders,
		Content:     content,
		RedirectURL: redirectURL,
		HeadersSize: headersSize,
		BodySize:    bodySize,
	}
}

// -- Helpers --

// convertPWTImings converts Playwright RequestTiming to HAR Timings format.
// Playwright timings are relative durations in milliseconds.
func convertPWTImings(t playwright.RequestTiming) schemas.Timings {
	// Calculates the duration between two timing points. Returns -1 if the timing data is invalid.
	duration := func(start, end float64) float64 {
		if start <= 0 || end <= 0 || start > end {
			return -1
		}
		return end - start
	}

	dnsTime := duration(t.DomainLookupStart, t.DomainLookupEnd)
	connectTime := duration(t.ConnectStart, t.ConnectEnd)
	// SSL time is the duration of the secure connection handshake.
	sslTime := duration(t.SecureConnectionStart, t.ConnectEnd)

	// FIX: RequestEnd is undefined in this playwright-go version.
	// We approximate by setting send time to -1 (unavailable per HAR spec) and
	// calculating wait as the total time from request start to response start.
	sendTime := float64(-1)
	waitTime := duration(t.RequestStart, t.ResponseStart)
	
	// FIX: ResponseEnd is likely unavailable if RequestEnd is missing, but if it exists, use it for receive.
	receiveTime := duration(t.ResponseStart, t.ResponseEnd)


	return schemas.Timings{
		Blocked: -1, // Not accurately available in Playwright RequestTiming structure.
		DNS:     dnsTime,
		Connect: connectTime,
		Send:    sendTime,
		Wait:    waitTime,
		Receive: receiveTime,
		SSL:     sslTime,
	}
}

// convertPWHeaders converts a map of Playwright headers into a slice of HAR NVPair.
func convertPWHeaders(headers map[string]string) []schemas.NVPair {
	pairs := make([]schemas.NVPair, 0, len(headers))
	for k, v := range headers {
		pairs = append(pairs, schemas.NVPair{Name: k, Value: v})
	}
	return pairs
}

// calculateHeaderSize estimates the size of the headers in bytes.
// It includes key, value, ": ", and "\r\n" (4 bytes) for each entry.
func calculateHeaderSize(headers map[string]string) int64 {
	var size int64
	for k, v := range headers {
		size += int64(len(k) + len(v) + 4)
	}
	return size
}

// extractQueryString parses the query parameters from a URL string into NVPair slice.
func extractQueryString(urlString string) []schemas.NVPair {
	u, err := url.Parse(urlString)
	if err != nil {
		return []schemas.NVPair{}
	}
	qs := u.Query()
	pairs := make([]schemas.NVPair, 0, len(qs))
	for k, values := range qs {
		for _, v := range values {
			pairs = append(pairs, schemas.NVPair{Name: k, Value: v})
		}
	}
	return pairs
}

// extractCookiesFromHeaders robustly parses cookies from "Cookie" or "Set-Cookie" headers into HAR format.
func extractCookiesFromHeaders(headers map[string]string) []schemas.HARCookie {
	// Playwright sometimes combines multiple 'set-cookie' headers into a single string separated by newlines.
	if setCookieHeader, ok := headers["set-cookie"]; ok {
		header := http.Header{}
		// Split the combined header back into individual lines for net/http parser.
		for _, line := range strings.Split(setCookieHeader, "\n") {
			if line != "" {
				header.Add("Set-Cookie", line)
			}
		}
		resp := http.Response{Header: header}
		return convertHttpCookiesToHARSchema(resp.Cookies())
	}

	// Check for "Cookie" header (Requests).
	if cookieHeader, ok := headers["cookie"]; ok {
		header := http.Header{}
		header.Add("Cookie", cookieHeader)
		// Use a dummy request to parse the cookies.
		req := http.Request{Header: header}
		return convertHttpCookiesToHARSchema(req.Cookies())
	}

	return []schemas.HARCookie{}
}

// convertHttpCookiesToHARSchema converts net/http cookies to the HAR schema format (ISO 8601 timestamps).
func convertHttpCookiesToHARSchema(cookies []*http.Cookie) []schemas.HARCookie {
	schemaCookies := make([]schemas.HARCookie, len(cookies))
	for i, c := range cookies {
		expiresStr := ""
		// Check if the expiration time is set and format as ISO 8601 (RFC3339Nano) for HAR compliance.
		if !c.Expires.IsZero() {
			expiresStr = c.Expires.UTC().Format(time.RFC3339Nano)
		}

		schemaCookies[i] = schemas.HARCookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  expiresStr,
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
		}
	}
	return schemaCookies
}

func isTextMime(mimeType string) bool {
	lowerMime := strings.ToLower(mimeType)
	return strings.HasPrefix(lowerMime, "text/") ||
		strings.Contains(lowerMime, "javascript") ||
		strings.Contains(lowerMime, "json") ||
		strings.Contains(lowerMime, "xml")
}

