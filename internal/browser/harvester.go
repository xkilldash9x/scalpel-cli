// internal/browser/harvester.go
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
const bodyFetchTimeout = 15 * time.Second

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
	ctx           context.Context // Session lifecycle context.
	logger        *zap.Logger
	captureBodies bool
	page          playwright.Page // Store page to manage listeners.

	mu            sync.RWMutex
	requests      map[playwright.Request]*requestState // Keyed by Request object pointer.
	consoleLogs   []schemas.ConsoleLog
	pageTitle     string
	pageStartTime time.Time
	pageTimings   schemas.PageTimings

	activeReqs int64 // Counter for active requests, including body fetching time.

	stopOnce sync.Once

	// Event handlers are stored to be able to remove them in Stop().
	requestHandler          func(playwright.Request)
	responseHandler         func(playwright.Response)
	requestFinishedHandler  func(playwright.Request)
	requestFailedHandler    func(playwright.Request)
	consoleMessageHandler   func(playwright.ConsoleMessage)
	pageLoadHandler         func(playwright.Page)
	domContentLoadedHandler func(playwright.Page)
}

// NewHarvester creates a new network harvester instance.
func NewHarvester(ctx context.Context, logger *zap.Logger, captureBodies bool) *Harvester {
	h := &Harvester{
		ctx:           ctx,
		logger:        logger.Named("harvester"),
		captureBodies: captureBodies,
		requests:      make(map[playwright.Request]*requestState),
		consoleLogs:   make([]schemas.ConsoleLog, 0),
		pageStartTime: time.Now(),
	}
	// Assign handlers to struct fields so they can be referenced in Stop().
	h.requestHandler = h.handleRequest
	h.responseHandler = h.handleResponse
	h.requestFinishedHandler = h.handleRequestFinished
	h.requestFailedHandler = h.handleRequestFailed
	h.consoleMessageHandler = h.handleConsoleMessage
	h.pageLoadHandler = h.handlePageLoad
	h.domContentLoadedHandler = h.handleDOMContentLoaded
	return h
}

// Start begins listening to network and console events from the Playwright Page.
func (h *Harvester) Start(page playwright.Page) {
	h.logger.Debug("Starting harvester event listeners.")
	h.page = page // Store page to remove listeners later.

	// -- Network Events --
	page.On("request", h.requestHandler)
	page.On("response", h.responseHandler)
	page.On("requestfinished", h.requestFinishedHandler)
	page.On("requestfailed", h.requestFailedHandler)

	// -- Console Events --
	page.On("console", h.consoleMessageHandler)

	// -- Page Lifecycle Events --
	page.On("load", h.pageLoadHandler)
	page.On("domcontentloaded", h.domContentLoadedHandler)

	// Capture the accurate start time upon the first main frame navigation.
	page.Once("framenavigated", func(frame playwright.Frame) {
		if frame == page.MainFrame() {
			h.mu.Lock()
			h.pageStartTime = time.Now()
			h.mu.Unlock()
		}
	})
}

// Stop halts the event listeners.
func (h *Harvester) Stop() {
	h.stopOnce.Do(func() {
		h.logger.Debug("Stopping harvester event listeners.")
		if h.page != nil && !h.page.IsClosed() {
			h.page.Off("request", h.requestHandler)
			h.page.Off("response", h.responseHandler)
			h.page.Off("requestfinished", h.requestFinishedHandler)
			h.page.Off("requestfailed", h.requestFailedHandler)
			h.page.Off("console", h.consoleMessageHandler)
			h.page.Off("load", h.pageLoadHandler)
			h.page.Off("domcontentloaded", h.domContentLoadedHandler)
		}
	})
}

// GetConsoleLogs returns the collected console logs.
func (h *Harvester) GetConsoleLogs() []schemas.ConsoleLog {
	h.mu.RLock()
	defer h.mu.RUnlock()
	logs := make([]schemas.ConsoleLog, len(h.consoleLogs))
	copy(logs, h.consoleLogs)
	return logs
}

// WaitNetworkIdle blocks until the network has been quiet for a specified duration.
// Robust implementation tracking last activity time.
func (h *Harvester) WaitNetworkIdle(ctx context.Context, quietPeriod time.Duration) error {
	h.logger.Debug("Waiting for network to become idle.", zap.Duration("quiet_period", quietPeriod))

	ticker := time.NewTicker(networkIdleCheckFrequency)
	defer ticker.Stop()

	lastActiveTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.ctx.Done():
			return h.ctx.Err()
		case now := <-ticker.C:
			h.mu.RLock()
			active := h.activeReqs
			h.mu.RUnlock()

			if active == 0 {
				// If network is idle, check how long it has been idle.
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

func (h *Harvester) handleResponse(resp playwright.Response) {
	h.mu.Lock()
	defer h.mu.Unlock()

	req := resp.Request()
	if reqState, ok := h.requests[req]; ok {
		reqState.response = resp
	}
}

// handleRequestFinished processes the request completion, including fetching the body synchronously.
func (h *Harvester) handleRequestFinished(req playwright.Request) {
	h.processRequestCompletion(req, nil)
}

// handleRequestFailed processes request failures.
func (h *Harvester) handleRequestFailed(req playwright.Request) {
	failure, err := req.Failure()
	if err != nil {
		h.processRequestCompletion(req, fmt.Errorf("could not get request failure reason: %w", err))
		return
	}
	var failureErr error
	if failure != nil {
		failureErr = fmt.Errorf("request failed: %s", failure.Error())
	} else {
		failureErr = fmt.Errorf("request failed (unknown reason)")
	}
	h.processRequestCompletion(req, failureErr)
}

// processRequestCompletion handles the logic for both finished and failed requests.
// Crucially, it fetches the body synchronously before decrementing activeReqs.
func (h *Harvester) processRequestCompletion(req playwright.Request, failureErr error) {
	h.mu.RLock()
	reqState, ok := h.requests[req]
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

func (h *Harvester) handlePageLoad(page playwright.Page) {
	if page.MainFrame() != page.MainFrame() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pageTitle, _ = page.Title()
	h.pageTimings.OnLoad = float64(time.Since(h.pageStartTime).Milliseconds())
}

func (h *Harvester) handleDOMContentLoaded(page playwright.Page) {
	if page.MainFrame() != page.MainFrame() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
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

		// Playwright timings are crucial.
		timing, _ := reqState.request.Timing()

		// Calculate duration. If ResponseEnd is missing (e.g., failure), use time since start approximation.
		totalTime := float64(-1)
		if timing.ResponseEnd > 0 && timing.RequestStart > 0 {
			totalTime = timing.ResponseEnd - timing.RequestStart
		} else {
			totalTime = time.Since(reqState.startTime).Seconds() * 1000
		}

		entry := schemas.Entry{
			Pageref:         pageID,
			StartedDateTime: reqState.startTime, // Use the recorded start time.
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

func (h *Harvester) buildHARRequest(req playwright.Request) schemas.Request {
	headers, _ := req.Headers()
	headersSize := calculateHeaderSize(headers)

	postData, _ := req.PostData()
	bodySize := int64(len(postData))

	harReq := schemas.Request{
		Method:      req.Method(),
		URL:         req.URL(),
		HTTPVersion: "HTTP/1.1", // Approximation
		Cookies:     extractCookiesFromHeaders(headers),
		Headers:     convertPWHeaders(headers),
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

	headers, _ := resp.Headers()
	headersSize := calculateHeaderSize(headers)

	contentType, _ := resp.HeaderValue("content-type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	content := schemas.Content{
		Size:     int64(len(body)),
		MimeType: contentType,
	}

	if isTextMime(contentType) {
		content.Text = string(body)
	} else if len(body) > 0 {
		content.Encoding = "base64"
		content.Text = base64.StdEncoding.EncodeToString(body)
	}

	bodySize := int64(len(body)) // Approximation of transferred size.

	// Determine protocol.
	protocol := "HTTP/1.1"
	sd, err := resp.SecurityDetails()
	if err == nil && sd != nil && sd.Protocol != "" {
		protocol = sd.Protocol
	}

	redirectURL, _ := resp.HeaderValue("location")
	return schemas.Response{
		Status:      resp.Status(),
		StatusText:  resp.StatusText(),
		HTTPVersion: protocol,
		Cookies:     extractCookiesFromHeaders(headers), // Handles Set-Cookie
		Headers:     headers,
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
	duration := func(start, end float64) float64 {
		if start <= 0 || end <= 0 || start > end {
			return -1
		}
		return end - start
	}

	dnsTime := duration(t.DomainLookupStart, t.DomainLookupEnd)
	connectTime := duration(t.ConnectStart, t.ConnectEnd)
	// SSL time is the duration of the secure connection handshake, part of the total connect time.
	sslTime := duration(t.SecureConnectionStart, t.ConnectEnd)

	// Send: Time taken to issue the request.
	sendTime := duration(t.RequestStart, t.RequestEnd)
	// Wait (TTFB): Time waiting for the response.
	waitTime := duration(t.RequestEnd, t.ResponseStart)
	// Receive: Time taken to download the response body.
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

func convertPWHeaders(headers map[string]string) []schemas.NVPair {
	pairs := make([]schemas.NVPair, 0, len(headers))
	for k, v := range headers {
		pairs = append(pairs, schemas.NVPair{Name: k, Value: v})
	}
	return pairs
}

func calculateHeaderSize(headers map[string]string) int64 {
	var size int64
	for k, v := range headers {
		size += int64(len(k) + len(v) + 4) // Key + Value + ": " + "\r\n"
	}
	return size
}

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

// extractCookiesFromHeaders robustly parses cookies from "Cookie" or "Set-Cookie" headers.
func extractCookiesFromHeaders(headers map[string]string) []schemas.Cookie {
	// Playwright combines multiple 'set-cookie' headers into a single string separated by newlines.
	if setCookieHeader, ok := headers["set-cookie"]; ok {
		header := http.Header{}
		for _, line := range strings.Split(setCookieHeader, "\n") {
			header.Add("Set-Cookie", line)
		}
		resp := http.Response{Header: header}
		return convertHttpCookiesToSchema(resp.Cookies())
	}

	// Check for "Cookie" header (Requests).
	if cookieHeader, ok := headers["cookie"]; ok {
		header := http.Header{}
		header.Add("Cookie", cookieHeader)
		req := http.Request{Header: header}
		return convertHttpCookiesToSchema(req.Cookies())
	}

	return []schemas.Cookie{}
}

func convertHttpCookiesToSchema(cookies []*http.Cookie) []schemas.Cookie {
	schemaCookies := make([]schemas.Cookie, len(cookies))
	for i, c := range cookies {
		expires := float64(-1)
		if !c.Expires.IsZero() {
			// Unix time (seconds) for HAR compatibility.
			expires = float64(c.Expires.Unix())
		}
		schemaCookies[i] = schemas.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  expires,
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
